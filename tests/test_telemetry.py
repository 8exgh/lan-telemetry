import base64
import http.client
import json
import logging
import os
import socket
import sqlite3
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

import paramiko

from telemetry.commands import Commands
from telemetry.config import Config
from telemetry.docker import Docker, DockerError, ExecStream
from telemetry.main import Application
from telemetry.processor import Processor
from telemetry.store import EventStore
from telemetry.main import Handler
from telemetry.api import APIHandler
from memory_socket import memory_pair


logging.getLogger("paramiko").setLevel(logging.CRITICAL)


def eventually(fn, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = fn()
        if result:
            return result
        time.sleep(0.02)
    raise AssertionError("Timed out waiting for expected event")


class FakeExec:
    def __init__(self, command, tty):
        self.id = "fake-exec"
        self.tty = tty
        self.command = command
        self.socket, self.peer = memory_pair()
        self.socket.settimeout(0.1)
        self.output = [("stdout", b"shell-output\x00\xff\n"), ("stderr", b"error-output\n")] if command is not None else []
        if command is None:
            def echo():
                try:
                    while True:
                        data = self.peer.recv(32768)
                        if not data:
                            break
                        self.peer.sendall(b"echo:" + data)
                        if b"exit\n" in data:
                            break
                finally:
                    self.peer.close()
            threading.Thread(target=echo, daemon=True).start()

    def receive(self):
        if self.command is not None:
            time.sleep(0.05)
            output, self.output = self.output, []
            return output or None
        data = self.socket.recv(32768)
        return [("stdout", data)] if data else None

    def resize(self, *args):
        pass

    def exit_code(self):
        return 0

    def close(self):
        self.socket.close()
        if self.command is not None:
            self.peer.close()


class FakeDocker:
    def __init__(self):
        self.calls = []

    def exec(self, command, tty):
        self.calls.append((command, tty))
        return FakeExec(command, tty)

    def reconcile(self):
        return {"status": "healthy", "container_id": "fake", "health": "healthy", "actions": ["created", "started"]}


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = EventStore(Path(self.directory.name) / "events.db")
        self.commands = Commands(self.store)

    def tearDown(self):
        self.store.close()
        self.directory.cleanup()

    def test_replay_idempotency_and_immutability(self):
        meta = dict(session_id="s1", protocol="raw", ip="192.168.1.1", source_port=44000, destination_port=9000, mac=None)
        self.commands.record("ConnectionOpened", meta)
        self.commands.record("BytesCaptured", meta, {"direction": "in"}, b"\0\xffbytes")
        state = self.commands.request_reconcile()
        self.assertEqual(state, self.commands.request_reconcile())
        result = {"request_id": state["request_id"], "status": "healthy", "actions": ["created"]}
        self.commands.complete_reconcile(result)
        length = self.store.summary()["events"]
        self.commands.complete_reconcile(result)
        self.assertEqual(length, self.store.summary()["events"])
        before = self.store.summary(), self.store.sessions(), self.store.runtime(), self.store.verify()
        self.store.catch_up(rebuild=True)
        self.assertEqual(before, (self.store.summary(), self.store.sessions(), self.store.runtime(), self.store.verify()))
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.db.execute("UPDATE events SET type='Changed'")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.db.execute("DELETE FROM events")
        with self.assertRaises(ValueError):
            self.commands.complete_reconcile({**result, "request_id": "stale"})

    def test_transaction_rollback_and_restart_recovery(self):
        with self.assertRaises(RuntimeError):
            with self.store.transaction():
                self.store.append("test", "RolledBack")
                raise RuntimeError()
        self.assertEqual(0, self.store.summary()["events"])
        self.commands.record("ConnectionOpened", dict(session_id="crashed", protocol="raw", ip="127.0.0.1", source_port=1, destination_port=2))
        self.commands.recover_sessions()
        self.assertEqual("closed", self.store.sessions()[0]["status"])
        self.assertEqual("collector-restarted", self.store.events()[0]["data"]["reason"])


class NetworkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            with socket.socket():
                pass
        except PermissionError:
            raise unittest.SkipTest("OS sockets are blocked by this environment; equivalent protocol tests run over memory streams")
        cls.directory = tempfile.TemporaryDirectory()
        cls.config = Config(host="127.0.0.1", raw_port=0, ssh_open_port=0, ssh_password_port=0, web_port=0, api_port=0,
                            data_dir=cls.directory.name, min_free_bytes=0, idle_seconds=4, session_seconds=20,
                            processor_password="processor-secret-is-long", query_password="dashboard-secret-is-long")
        cls.docker = FakeDocker()
        cls.app = Application(cls.config, cls.docker)
        cls.app.start()
        cls.ports = {getattr(s, "protocol", "api"): s.server_address[1] for s in cls.app.servers}

    @classmethod
    def tearDownClass(cls):
        cls.app.stop()
        cls.directory.cleanup()

    def connect(self, name):
        return socket.create_connection(("127.0.0.1", self.ports[name]), timeout=5)

    def session_events(self, source_port):
        sessions = eventually(lambda: [s for s in self.app.store.sessions(limit=200) if s["source_port"] == source_port and s["status"] == "closed"])
        return sorted(self.app.store.events(session=sessions[0]["id"], limit=200), key=lambda e: e["seq"])

    def bytes_for(self, events, direction, kind="BytesCaptured"):
        return b"".join(self.app.store.payload(e["seq"]) for e in events if e["type"] == kind and e["data"]["direction"] == direction)

    def test_raw_exact_bytes_both_directions(self):
        with self.connect("raw") as sock:
            source = sock.getsockname()[1]
            greeting = sock.recv(4)
            self.assertEqual(b"OK\r\n", greeting)
            data = bytes(range(256)) * 300
            sock.sendall(data[:123])
            sock.sendall(data[123:])
            sock.shutdown(socket.SHUT_WR)
            self.assertEqual(b"", sock.recv(1))
        events = self.session_events(source)
        self.assertEqual(data, self.bytes_for(events, "in"))
        self.assertEqual(greeting, self.bytes_for(events, "out"))
        self.assertTrue(all(e["metadata"]["ip"] == "127.0.0.1" and "mac" in e["metadata"] and e["at"] for e in events))

    def test_http_chunked_duplicate_headers_trailers_and_binary(self):
        request = b"POST /login?probe=%00 HTTP/1.1\r\nHost: decoy\r\nX-Test: one\r\nX-Test: two\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\n\x00\xffAB\r\n3\r\nxyz\r\n0\r\nX-Trailer: recorded\r\n\r\n"
        with self.connect("http") as sock:
            source = sock.getsockname()[1]
            sock.sendall(request)
            response = b""
            while chunk := sock.recv(32768):
                response += chunk
        events = self.session_events(source)
        self.assertEqual(request, self.bytes_for(events, "in"))
        self.assertEqual(response, self.bytes_for(events, "out"))
        self.assertIn(b"200 OK", response)
        parsed = next(e for e in events if e["type"] == "HttpRequestReceived")
        self.assertEqual([["X-Test", "one"], ["X-Test", "two"]], [h for h in parsed["data"]["headers"] if h[0] == "X-Test"])
        self.assertEqual(b"\0\xffABxyz", b"".join(self.app.store.payload(e["seq"]) for e in events if e["type"] == "HttpBodyReceived"))
        self.assertTrue(any(e["type"] == "HttpTrailersReceived" for e in events))

    def test_http_malformed_and_pipelined_requests(self):
        request = b"GET / HTTP/1.1\r\nHost: decoy\r\n\r\nGET /files HTTP/1.1\r\nHost: decoy\r\nConnection: close\r\n\r\n"
        with self.connect("http") as sock:
            source = sock.getsockname()[1]
            sock.sendall(request)
            response = b""
            while data := sock.recv(32768):
                response += data
        events = self.session_events(source)
        self.assertEqual(2, len([e for e in events if e["type"] == "HttpRequestReceived"]))
        self.assertEqual(request, self.bytes_for(events, "in"))
        self.assertEqual(response, self.bytes_for(events, "out"))
        with self.connect("http") as sock:
            source = sock.getsockname()[1]
            raw = b"POST / HTTP/1.1\r\nHost: decoy\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\nxx"
            sock.sendall(raw)
            self.assertIn(b"400", sock.recv(32768))
        events = self.session_events(source)
        self.assertEqual(raw, self.bytes_for(events, "in"))
        self.assertTrue(any(e["type"] == "HttpRequestMalformed" for e in events))

    def ssh(self, name, password=None):
        sock = self.connect(name)
        port = sock.getsockname()[1]
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=5)
        if password is None:
            transport.auth_none("visitor")
        else:
            transport.auth_password("visitor", password)
        return transport, port

    def test_passwordless_ssh_exec_and_forwarding_denied(self):
        transport, source = self.ssh("ssh-open")
        try:
            with self.assertRaises(paramiko.ChannelException):
                transport.open_channel("direct-tcpip", ("192.168.1.1", 80), ("127.0.0.1", 40000))
            channel = transport.open_session()
            channel.exec_command(b"printf 'test' ; uname -a")
            stdout, stderr = channel.makefile("rb").read(), channel.makefile_stderr("rb").read()
            self.assertEqual(b"shell-output\0\xff\n", stdout)
            self.assertEqual(b"error-output\n", stderr)
            self.assertEqual(0, channel.recv_exit_status())
        finally:
            transport.close()
        events = self.session_events(source)
        auth = next(e for e in events if e["type"] == "AuthenticationAttempted")
        self.assertTrue(auth["data"]["accepted"])
        self.assertEqual("none", auth["data"]["method"])
        self.assertIn((b"printf 'test' ; uname -a", False), self.docker.calls)
        self.assertEqual(stdout + stderr, self.bytes_for(events, "out", "TerminalBytesCaptured"))
        self.assertTrue(any(e["type"] == "SshRequestDenied" for e in events))
        self.assertIn(b"SSH-2.0", self.bytes_for(events, "in"))

    def test_password_attempts_then_interactive_shell(self):
        sock = self.connect("ssh-password")
        source = sock.getsockname()[1]
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=5)
        with self.assertRaises(paramiko.AuthenticationException):
            transport.auth_none("root")
        with self.assertRaises(paramiko.AuthenticationException):
            transport.auth_password("root", "wrong-secret")
        transport.auth_password("root", "password")
        channel = transport.open_session()
        channel.get_pty()
        channel.invoke_shell()
        channel.sendall(b"whoami\nexit\n")
        self.assertEqual(b"echo:whoami\nexit\n", channel.makefile("rb").read())
        transport.close()
        events = self.session_events(source)
        attempts = [e["data"] for e in events if e["type"] == "AuthenticationAttempted"]
        self.assertEqual([False, False, True], [a["accepted"] for a in attempts])
        self.assertEqual("wrong-secret", attempts[1]["password"])
        self.assertEqual("password", attempts[2]["password"])
        self.assertEqual(b"whoami\nexit\n", self.bytes_for(events, "in", "TerminalBytesCaptured"))

    def api(self, method, path, user=None, password=None, body=None):
        headers = {}
        if user:
            headers["Authorization"] = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        conn = http.client.HTTPConnection("127.0.0.1", self.ports["api"], timeout=5)
        conn.request(method, path, body=json.dumps(body) if body is not None else None, headers=headers)
        response = conn.getresponse()
        result = response.status, json.loads(response.read())
        conn.close()
        return result

    def test_cqrs_auth_and_processor_retries(self):
        path = "/api/queries/summary"
        self.assertEqual(401, self.api("GET", path)[0])
        self.assertEqual(200, self.api("GET", path, "dashboard", self.config.query_password)[0])
        command = "/api/commands/request-container-reconcile"
        self.assertEqual(401, self.api("POST", command, "dashboard", self.config.query_password, {})[0])
        processor = Processor(self.config, self.docker)
        processor.base = f"http://127.0.0.1:{self.ports['api']}"
        processor.tick()
        self.assertEqual("healthy", self.app.store.runtime()["status"])
        count = self.app.store.summary()["events"]
        processor.tick()
        self.assertEqual(count, self.app.store.summary()["events"])
        self.assertGreater(self.app.store.verify()["events"], 0)


class MemoryNetworkTests(NetworkTests):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.config = Config(host="127.0.0.1", data_dir=cls.directory.name, min_free_bytes=0,
                            idle_seconds=4, session_seconds=20,
                            processor_password="processor-secret-is-long", query_password="dashboard-secret-is-long")
        cls.docker = FakeDocker()
        cls.app = Application(cls.config, cls.docker)
        cls.app.commands.request_reconcile()
        cls.port_counter = 40000

    def connect(self, name):
        type(self).port_counter += 1
        client, server_socket = memory_pair(type(self).port_counter)
        server = SimpleNamespace(app=self.app, protocol=name)
        def run():
            try:
                Handler(server_socket, client.address, server)
            finally:
                server_socket.close()
        thread = threading.Thread(target=run, daemon=True)
        self.app.threads.append(thread)
        thread.start()
        return client

    def api(self, method, path, user=None, password=None, body=None):
        client, server_socket = memory_pair()
        server = SimpleNamespace(config=self.config, commands=self.app.commands)
        def run():
            try:
                APIHandler(server_socket, client.address, server)
            finally:
                server_socket.close()
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        raw = json.dumps(body).encode() if body is not None else b""
        headers = f"{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {len(raw)}\r\n"
        if user:
            headers += "Authorization: Basic " + base64.b64encode(f"{user}:{password}".encode()).decode() + "\r\n"
        client.sendall(headers.encode() + b"\r\n" + raw)
        response = http.client.HTTPResponse(client)
        response.begin()
        result = response.status, json.loads(response.read())
        client.close()
        thread.join(timeout=2)
        return result

    def test_cqrs_auth_and_processor_retries(self):
        self.assertEqual(401, self.api("GET", "/api/queries/summary")[0])
        self.assertEqual(200, self.api("GET", "/api/queries/summary", "dashboard", self.config.query_password)[0])
        self.assertEqual(401, self.api("POST", "/api/commands/request-container-reconcile", "dashboard", self.config.query_password, {})[0])
        processor = Processor(self.config, self.docker)
        def api(path, body=None):
            status, data = self.api("GET" if body is None else "POST", path, "processor", self.config.processor_password, body)
            if status != 200:
                raise ValueError(data)
            return data
        processor.api = api
        processor.tick()
        self.assertEqual("healthy", self.app.store.runtime()["status"])
        count = self.app.store.summary()["events"]
        processor.tick()
        self.assertEqual(count, self.app.store.summary()["events"])
        self.assertGreater(self.app.store.verify()["events"], 0)

    def test_capture_limit_records_triggering_chunk_and_closes(self):
        previous = self.config.max_session_bytes
        self.config.max_session_bytes = 1024
        try:
            with self.connect("raw") as sock:
                source = sock.getsockname()[1]
                sock.recv(4)
                data = b"A" * 2000
                sock.sendall(data)
                self.assertEqual(b"", sock.recv(1))
            events = self.session_events(source)
            self.assertEqual(data, self.bytes_for(events, "in"))
            self.assertTrue(any(e["type"] == "CaptureLimitReached" for e in events))
        finally:
            self.config.max_session_bytes = previous


class DockerTests(unittest.TestCase):
    def test_exec_upgrade_and_fragmented_stdout_stderr_frames(self):
        client, server = memory_pair()
        client.connect = lambda path: None
        requests = []
        docker = SimpleNamespace(config=Config(), request=lambda *args: requests.append(args) or {"ExitCode": 7})

        def engine():
            header = b""
            while not header.endswith(b"\r\n\r\n"):
                header += server.recv(1)
            size = int(next(line.split(b": ")[1] for line in header.split(b"\r\n") if line.startswith(b"Content-Length:")))
            body = server.recv(size)
            self.assertEqual({"Detach": False, "Tty": False}, json.loads(body))
            server.sendall(b"HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
            for kind, payload in ((1, b"out\0\xff"), (2, b"error")):
                frame = bytes([kind, 0, 0, 0]) + struct.pack(">I", len(payload)) + payload
                for part in (frame[:3], frame[3:9], frame[9:]):
                    server.sendall(part)
                    time.sleep(0.005)
            server.shutdown(socket.SHUT_WR)

        thread = threading.Thread(target=engine, daemon=True)
        thread.start()
        with patch("telemetry.docker.socket.socket", return_value=client):
            stream = ExecStream(docker, "exec-test", False)
        output = []
        while (batch := stream.receive()) is not None:
            output.extend(batch)
        self.assertEqual([("stdout", b"out\0\xff"), ("stderr", b"error")], output)
        self.assertEqual(7, stream.exit_code())
        stream.resize(100, 40)
        self.assertIn(("POST", "/exec/exec-test/resize?w=100&h=40"), requests)
        stream.close()
        server.close()
        thread.join(timeout=2)

    def test_reconcile_creates_starts_and_recovers_unhealthy(self):
        class Engine(Docker):
            def __init__(self):
                super().__init__(Config())
                self.info = None
                self.actions = []

            def request(self, method, path, body=None):
                self.actions.append(path)
                if path.startswith("/containers/create"):
                    self.info = {"Id": "abc", "HostConfig": body["HostConfig"], "Config": body, "Mounts": [], "State": {"Running": False}}
                    return {"Id": "abc"}
                if path.endswith("/json"):
                    if self.info is None:
                        raise DockerError(404, "Missing")
                    return self.info
                self.info["State"] = {"Running": True, "Health": {"Status": "healthy"}}
        engine = Engine()
        result = engine.reconcile()
        self.assertEqual(["created", "started"], result["actions"])
        self.assertEqual("healthy", result["status"])
        engine.info["State"]["Health"]["Status"] = "unhealthy"
        self.assertEqual(["restarted-unhealthy"], engine.reconcile()["actions"])
        engine.info["HostConfig"]["NetworkMode"] = "host"
        self.assertEqual("failed", engine.reconcile()["status"])
        engine.info["Config"]["Labels"] = {}
        self.assertIn("does not own", engine.reconcile()["error"])


if __name__ == "__main__":
    unittest.main()
