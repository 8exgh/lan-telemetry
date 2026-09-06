import base64
import queue
import socket
import threading
import time

import paramiko


class SSHServer(paramiko.ServerInterface):
    def __init__(self, capture, password_required):
        self.capture, self.password_required = capture, password_required
        self.requests = queue.Queue()
        self.tty = False
        self.width, self.height = 80, 24
        self.opened = False
        self.requested = False

    def auth(self, username, method, accepted, **details):
        self.capture.record("AuthenticationAttempted", dict(username=username, method=method, accepted=accepted, **details))
        return paramiko.AUTH_SUCCESSFUL if accepted else paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password" if self.password_required else "none,password"

    def check_auth_none(self, username):
        return self.auth(username, "none", not self.password_required)

    def check_auth_password(self, username, password):
        return self.auth(username, "password", not self.password_required or password == "password", password=password)

    def check_auth_publickey(self, username, key):
        return self.auth(username, "publickey", False, algorithm=key.get_name(), public_key=key.get_base64())

    def check_auth_interactive(self, username, submethods):
        return self.auth(username, "keyboard-interactive", False, submethods=submethods)

    def check_channel_request(self, kind, chanid):
        accepted = kind == "session" and not self.opened
        self.capture.record("SshChannelRequested", dict(kind=kind, channel=chanid, accepted=accepted))
        if accepted:
            self.opened = True
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        self.tty, self.width, self.height = True, width, height
        self.capture.record("SshPtyRequested", dict(term=base64.b64encode(term).decode(), width=width, height=height, pixelwidth=pixelwidth, pixelheight=pixelheight), modes)
        return True

    def check_channel_window_change_request(self, channel, width, height, pixelwidth, pixelheight):
        self.width, self.height = width, height
        self.capture.record("SshWindowChanged", dict(width=width, height=height, pixelwidth=pixelwidth, pixelheight=pixelheight))
        self.requests.put(("resize", (width, height)))
        return True

    def check_channel_shell_request(self, channel):
        return self.start(None)

    def check_channel_exec_request(self, channel, command):
        return self.start(command)

    def start(self, command):
        if self.requested:
            return False
        self.requested = True
        self.capture.record("SshShellRequested" if command is None else "SshCommandRequested",
                            {"tty": self.tty}, command)
        self.requests.put(("start", command))
        return True

    def denied(self, kind, data=None):
        self.capture.record("SshRequestDenied", {"kind": kind, **(data or {})})
        return False

    def check_channel_env_request(self, channel, name, value):
        return self.denied("env", {"name_base64": base64.b64encode(name).decode(), "value_base64": base64.b64encode(value).decode()})

    def check_channel_subsystem_request(self, channel, name):
        return self.denied("subsystem", {"name": name})

    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        self.denied("direct-tcpip", {"origin": origin, "destination": destination})
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_port_forward_request(self, address, port):
        return self.denied("tcpip-forward", {"address": address, "port": port})

    def check_channel_forward_agent_request(self, channel):
        return self.denied("agent-forward")

    def check_channel_x11_request(self, channel, single_connection, auth_protocol, auth_cookie, screen_number):
        return self.denied("x11", {"auth_protocol": str(auth_protocol), "auth_cookie": str(auth_cookie), "screen_number": screen_number})

    def check_global_request(self, kind, msg):
        self.capture.record("SshRequestDenied", {"kind": kind}, msg.asbytes())
        return False


def handle_ssh(sock, capture, config, host_key, docker, password_required):
    transport = paramiko.Transport(sock)
    # Capture decoded protocol payloads before Paramiko interprets their fields,
    # including unsupported requests and auth bytes that may not be valid UTF-8.
    read_message = transport.packetizer.read_message
    send_message = transport.packetizer.send_message

    def read_packet():
        kind, message = read_message()
        capture.record("SshPacketCaptured", {"direction": "in", "layer": "ssh-message", "message_type": kind,
            "packet_sequence": message.seqno}, bytes([kind]) + message.asbytes())
        return kind, message

    def send_packet(message):
        payload = message.asbytes() if hasattr(message, "asbytes") else bytes(message)
        capture.record("SshPacketCaptured", {"direction": "out", "layer": "ssh-message", "message_type": payload[0]}, payload)
        return send_message(message)

    transport.packetizer.read_message = read_packet
    transport.packetizer.send_message = send_packet
    transport.local_version = "SSH-2.0-OpenSSH_9.6"
    transport.banner_timeout = min(config.idle_seconds, 30)
    transport.auth_timeout = min(config.idle_seconds, 60)
    transport.add_server_key(host_key)
    server = SSHServer(capture, password_required)
    stream = None
    channel = None
    done = threading.Event()
    pump = None
    try:
        transport.start_server(server=server)
        capture.record("SshHandshakeCompleted", {"client_version": transport.remote_version,
            "inbound_cipher": transport.remote_cipher, "outbound_cipher": transport.local_cipher,
            "inbound_mac": transport.remote_mac, "outbound_mac": transport.local_mac})
        channel = transport.accept(config.idle_seconds)
        if channel is None:
            return
        deadline = time.monotonic() + config.idle_seconds
        command = None
        while time.monotonic() < deadline and transport.is_active():
            try:
                kind, value = server.requests.get(timeout=0.25)
                if kind == "start":
                    command = value
                    break
            except queue.Empty:
                pass
        else:
            return
        stream = docker.exec(command, tty=server.tty)
        capture.record("ContainerSessionStarted", {"exec_id": stream.id, "tty": server.tty})
        if server.tty:
            stream.resize(server.width, server.height)
        channel.settimeout(1)

        def input_pump():
            try:
                while not done.is_set() and transport.is_active():
                    try:
                        data = channel.recv(32768)
                    except socket.timeout:
                        continue
                    if not data:
                        try:
                            stream.socket.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        return
                    capture.bytes("in", data, "terminal", "stdin")
                    stream.socket.sendall(data)
            except Exception as error:
                capture.record("ContainerInputFailed", {"error": str(error)})
                done.set()

        pump = threading.Thread(target=input_pump, daemon=True)
        pump.start()
        while transport.is_active() and not channel.closed and not done.is_set():
            try:
                kind, value = server.requests.get_nowait()
                if kind == "resize" and server.tty:
                    stream.resize(*value)
            except queue.Empty:
                pass
            try:
                output = stream.receive()
            except socket.timeout:
                continue
            if output is None:
                break
            for name, data in output:
                capture.bytes("out", data, "terminal", name)
                (channel.sendall_stderr if name == "stderr" else channel.sendall)(data)
        code = stream.exit_code()
        capture.record("ContainerSessionEnded", {"exit_code": code, "exec_id": stream.id})
        if transport.is_active() and not channel.closed:
            channel.send_exit_status(code)
    except Exception as error:
        capture.record("SshSessionFailed", {"error": str(error), "error_type": type(error).__name__})
        if channel and not channel.closed:
            try:
                message = b"Service temporarily unavailable.\r\n"
                capture.bytes("out", message, "terminal", "stderr")
                channel.sendall_stderr(message)
                channel.send_exit_status(1)
            except Exception:
                pass
    finally:
        done.set()
        if stream:
            stream.close()
        if channel:
            channel.close()
        transport.close()
        if pump:
            pump.join(timeout=2)
