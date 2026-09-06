import http.client
import json
import socket
import struct
from urllib.parse import quote


LABEL = "io.lan-telemetry.sandbox"
POLICY = "1"


class DockerError(RuntimeError):
    def __init__(self, status, message):
        self.status = status
        super().__init__(message)


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout=15):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class Docker:
    def __init__(self, config):
        self.config = config

    def request(self, method, path, body=None):
        conn = UnixConnection(self.config.docker_socket)
        try:
            conn.request(method, "/v1.45" + path, body=None if body is None else json.dumps(body), headers={"Content-Type": "application/json"})
            response = conn.getresponse()
            raw = response.read()
            if response.status >= 300:
                raise DockerError(response.status, raw.decode(errors="replace"))
            return json.loads(raw) if raw else None
        finally:
            conn.close()

    def inspect(self):
        return self.request("GET", "/containers/" + quote(self.config.sandbox_name, safe="") + "/json")

    def verify(self, info):
        host, config = info["HostConfig"], info["Config"]
        if config.get("Labels", {}).get(LABEL) != POLICY:
            raise DockerError(409, "Container name is occupied by a container this application does not own")
        safe = (config.get("Image") == self.config.sandbox_image and config.get("User") == "10001:10001"
                and host.get("NetworkMode") == "none" and host.get("ReadonlyRootfs")
                and not host.get("Privileged") and not host.get("Binds") and not host.get("Devices")
                and not host.get("CapAdd") and not host.get("PortBindings")
                and "ALL" in host.get("CapDrop", [])
                and any(s in ("no-new-privileges", "no-new-privileges:true") for s in host.get("SecurityOpt", []))
                and 0 < host.get("Memory", 0) <= 128 * 1024 * 1024
                and 0 < host.get("PidsLimit", 0) <= 64
                and 0 < host.get("NanoCpus", 0) <= 500_000_000
                and host.get("PidMode", "") == "" and host.get("IpcMode") == "private"
                and not any(m.get("Type") != "tmpfs" for m in info.get("Mounts", [])))
        if not safe:
            raise DockerError(409, "Sandbox isolation configuration does not match policy; refusing to execute")

    def create(self):
        return self.request("POST", "/containers/create?name=" + quote(self.config.sandbox_name, safe=""), {
            "Image": self.config.sandbox_image, "Hostname": "fileserver", "User": "10001:10001",
            "Labels": {LABEL: POLICY}, "WorkingDir": "/home/guest",
            "Env": ["HOME=/home/guest", "TERM=xterm", "PATH=/usr/local/bin:/usr/bin:/bin"],
            "Healthcheck": {"Test": ["CMD", "/bin/true"], "Interval": 10_000_000_000, "Timeout": 3_000_000_000, "Retries": 3},
            "HostConfig": {"NetworkMode": "none", "ReadonlyRootfs": True, "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges:true"], "Memory": 128 * 1024 * 1024,
                "MemorySwap": 128 * 1024 * 1024, "PidsLimit": 64, "NanoCpus": 500_000_000,
                "IpcMode": "private", "Init": True, "RestartPolicy": {"Name": "no"},
                "Tmpfs": {"/tmp": "rw,noexec,nosuid,nodev,size=16m,mode=1777", "/home/guest": "rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0700"},
                "LogConfig": {"Type": "local", "Config": {"max-size": "1m", "max-file": "2"}}}})

    def reconcile(self):
        actions = []
        try:
            try:
                info = self.inspect()
            except DockerError as error:
                if error.status != 404:
                    raise
                self.create()
                actions.append("created")
                info = self.inspect()
            self.verify(info)
            cid = info["Id"]
            state = info["State"]
            if not state.get("Running"):
                self.request("POST", f"/containers/{cid}/start")
                actions.append("started")
            elif state.get("Health", {}).get("Status") == "unhealthy":
                self.request("POST", f"/containers/{cid}/restart?t=3")
                actions.append("restarted-unhealthy")
            info = self.inspect()
            health = info["State"].get("Health", {}).get("Status", "unknown")
            status = "healthy" if info["State"].get("Running") and health == "healthy" else "starting"
            return dict(status=status, container_id=cid, health=health, actions=actions)
        except (DockerError, OSError, ValueError, http.client.HTTPException) as error:
            return dict(status="failed", error=str(error), actions=actions)

    def exec(self, command=None, tty=False):
        info = self.inspect()
        self.verify(info)
        if not info["State"].get("Running"):
            raise DockerError(503, "Sandbox is not running")
        # Command bytes are decoded only for Docker's JSON API. Originals stay in events.
        cmd = ["/usr/bin/timeout", "-s", "KILL", str(self.config.session_seconds), "/bin/sh"]
        cmd += ["-i"] if command is None else ["-c", command.decode("utf-8", errors="strict")]
        created = self.request("POST", f"/containers/{info['Id']}/exec", {
            "AttachStdin": True, "AttachStdout": True, "AttachStderr": True, "Tty": tty,
            "User": "10001:10001", "WorkingDir": "/home/guest", "Cmd": cmd})
        return ExecStream(self, created["Id"], tty)


class ExecStream:
    def __init__(self, docker, exec_id, tty):
        self.docker, self.id, self.tty = docker, exec_id, tty
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(15)
        self.buffer = b""
        try:
            self.socket.connect(docker.config.docker_socket)
            body = json.dumps({"Detach": False, "Tty": tty}).encode()
            self.socket.sendall((f"POST /v1.45/exec/{exec_id}/start HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: {len(body)}\r\n\r\n").encode() + body)
            header = b""
            while not header.endswith(b"\r\n\r\n"):
                chunk = self.socket.recv(1)
                if not chunk or len(header) > 16384:
                    raise DockerError(502, "Invalid Docker exec response")
                header += chunk
            if header.split(b" ", 2)[1] not in (b"101", b"200"):
                raise DockerError(502, header.decode(errors="replace"))
            self.socket.settimeout(1)
        except BaseException:
            self.socket.close()
            raise

    def receive(self):
        """Yield decoded Docker stdout/stderr frames; retain partial frames on timeout."""
        chunk = self.socket.recv(32768)
        if not chunk:
            if self.buffer:
                raise DockerError(502, "Truncated Docker output frame")
            return None
        if self.tty:
            return [("stdout", chunk)]
        self.buffer += chunk
        output = []
        while len(self.buffer) >= 8:
            size = struct.unpack(">I", self.buffer[4:8])[0]
            if size > 16 * 1024 * 1024:
                raise DockerError(502, "Invalid Docker output frame size")
            if len(self.buffer) < 8 + size:
                break
            output.append(("stderr" if self.buffer[0] == 2 else "stdout", self.buffer[8:8+size]))
            self.buffer = self.buffer[8+size:]
        return output

    def resize(self, width, height):
        self.docker.request("POST", f"/exec/{self.id}/resize?w={max(1, min(width, 500))}&h={max(1, min(height, 500))}")

    def exit_code(self):
        return self.docker.request("GET", f"/exec/{self.id}/json").get("ExitCode", 0)

    def close(self):
        self.socket.close()
