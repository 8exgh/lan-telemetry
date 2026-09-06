#!/usr/bin/env python3
"""Real TCP + SSH + Docker integration, with an isolated test container and event DB.

Run after building sandbox/Dockerfile. Requires a working local Docker socket.
"""
import os
import socket
import sys
import tempfile
import time
import uuid
from pathlib import Path

import paramiko

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from telemetry.config import Config, load_env
from telemetry.docker import Docker
from telemetry.main import Application
from telemetry.processor import Processor


def main():
    load_env(Path(__file__).resolve().parents[1] / ".env")
    with tempfile.TemporaryDirectory(prefix="lan-telemetry-smoke-") as directory:
        config = Config(host="127.0.0.1", raw_port=0, ssh_open_port=0, ssh_password_port=0, web_port=0, api_port=0,
            data_dir=directory, min_free_bytes=0, processor_password="smoke-processor-" + uuid.uuid4().hex,
            query_password="smoke-query-" + uuid.uuid4().hex, sandbox_name="lan-telemetry-test-" + uuid.uuid4().hex[:12],
            docker_socket=os.environ.get("DOCKER_SOCKET", "/var/run/docker.sock"),
            sandbox_image=os.environ.get("SANDBOX_IMAGE", "lan-telemetry-sandbox:local"), session_seconds=30)
        docker = Docker(config)
        # Check Docker before creating listeners, so permission errors are explicit.
        docker.request("GET", "/version")
        app = Application(config, docker)
        started = False
        try:
            app.start()
            started = True
            ports = {getattr(s, "protocol", "api"): s.server_address[1] for s in app.servers}
            processor = Processor(config, docker)
            processor.base = f"http://127.0.0.1:{ports['api']}"
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                processor.tick()
                state = app.store.runtime()
                if state["status"] == "failed":
                    raise RuntimeError(state["error"])
                if state["status"] == "healthy":
                    break
                time.sleep(1)
            else:
                raise RuntimeError("Sandbox did not become healthy")
            with socket.create_connection(("127.0.0.1", ports["raw"])) as sock:
                assert sock.recv(4) == b"OK\r\n"
                sock.sendall(b"smoke\x00\xff\n")
                sock.shutdown(socket.SHUT_WR)
                assert sock.recv(1) == b""
            for protocol in ("ssh-open", "ssh-password"):
                transport = paramiko.Transport(("127.0.0.1", ports[protocol]))
                try:
                    transport.start_client(timeout=10)
                    if protocol == "ssh-open":
                        transport.auth_none("root")
                    else:
                        try:
                            transport.auth_password("root", "incorrect")
                        except paramiko.AuthenticationException:
                            pass
                        else:
                            raise AssertionError("Wrong password was accepted")
                        transport.auth_password("root", "password")
                    channel = transport.open_session(timeout=10)
                    channel.settimeout(15)
                    channel.exec_command("id -u; printf 'container-smoke\\n'; printf 'stderr-smoke\\n' >&2; test ! -S /var/run/docker.sock; test ! -e /host")
                    output = channel.makefile("rb").read()
                    error = channel.makefile_stderr("rb").read()
                    assert b"10001" in output and b"container-smoke" in output, (output, error)
                    assert b"stderr-smoke" in error
                    assert channel.recv_exit_status() == 0
                finally:
                    transport.close()
            # PTY path, input, output and resize use Docker's real exec API.
            transport = paramiko.Transport(("127.0.0.1", ports["ssh-open"]))
            try:
                transport.start_client(timeout=10)
                transport.auth_none("guest")
                channel = transport.open_session(timeout=10)
                channel.settimeout(15)
                channel.get_pty(width=100, height=30)
                channel.invoke_shell()
                channel.resize_pty(width=120, height=40)
                channel.sendall(b"printf 'pty-smoke\\n'\nexit\n")
                assert b"pty-smoke" in channel.makefile("rb").read()
            finally:
                transport.close()
            with socket.create_connection(("127.0.0.1", ports["http"])) as sock:
                sock.sendall(b"GET /files HTTP/1.1\r\nHost: decoy\r\nConnection: close\r\n\r\n")
                assert b"200 OK" in sock.recv(65536)
            deadline = time.monotonic() + 10
            while app.active and time.monotonic() < deadline:
                time.sleep(0.05)
            assert not app.active, "Sessions did not close"
            info = docker.inspect()
            docker.verify(info)
            docker.request("POST", f"/containers/{info['Id']}/stop?t=1")
            app.commands.request_reconcile()
            processor.tick()
            assert docker.inspect()["State"]["Running"], "Processor did not recover stopped container"
            snapshot = app.store.sessions()
            integrity = app.store.verify()
            app.store.catch_up(rebuild=True)
            assert snapshot == app.store.sessions()
            assert integrity == app.store.verify()
            print(f"PASS: TCP, both SSH auth modes, container exec and PTY, HTTP, recovery, replay and {integrity['events']} event hashes")
        finally:
            if started:
                app.stop()
            try:
                info = docker.inspect()
                docker.verify(info)
                docker.request("DELETE", f"/containers/{info['Id']}?force=true")
            except Exception as error:
                print(f"Test container cleanup: {error}", file=sys.stderr)


if __name__ == "__main__":
    main()
