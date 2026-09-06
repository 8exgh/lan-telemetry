import argparse
import fcntl
import logging
import os
import signal
import socket
import socketserver
import threading
import time
from pathlib import Path

import paramiko

from .api import make_api
from .capture import Capture, RecordingSocket
from .commands import Commands
from .config import Config
from .docker import Docker
from .peers import Neighbors
from .ssh import handle_ssh
from .store import EventStore
from .web import DecoyHandler


class Listener(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128

    def process_request(self, request, address):
        if not self.app.slots.acquire(blocking=False):
            try:
                capture = Capture(request, self.protocol, self.app.commands, self.app.neighbors, self.app.config)
                capture.record("ConnectionRejected", {"reason": "connection-limit"})
                capture.close("connection-limit")
            except Exception:
                self.app.failed.set()
                logging.exception("Unable to record rejected connection")
            finally:
                request.close()
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.app.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.app.slots.release()

    def handle_error(self, request, client_address):
        logging.exception("Listener failed for %s", client_address)


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        app, sock = self.server.app, self.request
        capture = None
        timer = None
        reason = "peer-disconnected"
        try:
            sock.settimeout(app.config.idle_seconds)
            capture = Capture(sock, self.server.protocol, app.commands, app.neighbors, app.config)
            with app.active_lock:
                app.active[sock] = capture
            capture.check_space()

            def expire():
                nonlocal reason
                reason = "session-time-limit"
                try:
                    capture.record("CaptureLimitReached", {"reason": reason, "seconds": app.config.session_seconds})
                except Exception:
                    app.failed.set()
                finally:
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

            timer = threading.Timer(app.config.session_seconds, expire)
            timer.daemon = True
            timer.start()
            recorded = RecordingSocket(sock, capture)
            if self.server.protocol == "raw":
                recorded.sendall(b"OK\r\n")
                while recorded.recv(32768):
                    pass
            elif self.server.protocol == "http":
                DecoyHandler(recorded, self.client_address, self.server)
            else:
                handle_ssh(recorded, capture, app.config, app.host_key, app.docker, self.server.protocol == "ssh-password")
        except Exception as error:
            reason = type(error).__name__
            if capture:
                try:
                    capture.record("ConnectionError", {"error": str(error), "error_type": reason})
                except Exception:
                    app.failed.set()
                    logging.exception("Event persistence failed; stopping the collector")
            else:
                app.failed.set()
        finally:
            if timer:
                timer.cancel()
            if capture:
                try:
                    capture.close(reason)
                except Exception:
                    app.failed.set()
                    logging.exception("Unable to persist connection closure")
            with app.active_lock:
                app.active.pop(sock, None)


class Application:
    def __init__(self, config, docker=None):
        self.config = config
        directory = Path(config.data_dir)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(directory, 0o700)
        self.lockfile = open(directory / "collector.lock", "a")
        fcntl.flock(self.lockfile, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.store = EventStore(directory / "events.sqlite3")
        self.commands = Commands(self.store, config.health_interval_seconds)
        self.docker = docker or Docker(config)
        self.neighbors = Neighbors()
        self.slots = threading.BoundedSemaphore(config.max_connections)
        self.active, self.active_lock = {}, threading.Lock()
        self.failed = threading.Event()
        self.servers, self.threads = [], []
        key_path = directory / "ssh_host_rsa_key"
        if not key_path.exists():
            paramiko.RSAKey.generate(3072).write_private_key_file(str(key_path))
            os.chmod(key_path, 0o600)
        self.host_key = paramiko.RSAKey.from_private_key_file(str(key_path))

    def start(self):
        self.commands.recover_sessions()
        self.commands.request_reconcile()
        try:
            for protocol, port in (("raw", self.config.raw_port), ("ssh-open", self.config.ssh_open_port),
                                   ("ssh-password", self.config.ssh_password_port), ("http", self.config.web_port)):
                cls = type("IPv6Listener", (Listener,), {"address_family": socket.AF_INET6}) if ":" in self.config.host else Listener
                server = cls((self.config.host, port), Handler)
                server.protocol, server.app = protocol, self
                self.servers.append(server)
            self.servers.append(make_api(self.config, self.commands))
        except BaseException:
            for server in self.servers:
                server.server_close()
            raise
        self.neighbors.refresh()
        neighbor_thread = threading.Thread(target=self.neighbors.run, daemon=True)
        neighbor_thread.start()
        self.threads.append(neighbor_thread)
        for server in self.servers:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.threads.append(thread)
        self.commands.record("CollectorStarted", {}, {"pid": os.getpid(), "listeners": [dict(protocol=getattr(s, "protocol", "cqrs"), address=s.server_address) for s in self.servers]})

    def stop(self):
        for server in self.servers:
            server.shutdown()
            server.server_close()
        self.neighbors.stopped.set()
        with self.active_lock:
            sockets = list(self.active)
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        deadline = time.monotonic() + 20
        while self.active and time.monotonic() < deadline:
            time.sleep(0.05)
        try:
            self.commands.record("CollectorStopped", {}, {"remaining_sessions": len(self.active)})
        except Exception:
            logging.exception("Unable to persist collector shutdown")
        for thread in self.threads:
            thread.join(timeout=2)
        if not self.active:
            self.store.close()
        self.lockfile.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--replay", action="store_true", help="Rebuild query models from events; stop the collector first")
    parser.add_argument("--verify", action="store_true", help="Verify every event hash and byte payload")
    args = parser.parse_args()
    os.umask(0o077)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logging.getLogger("paramiko").setLevel(logging.CRITICAL)
    config = Config.from_env()
    app = Application(config)
    if args.verify or args.replay:
        if args.verify:
            print(app.store.verify())
        if args.replay:
            app.store.catch_up(rebuild=True)
            print("Query models rebuilt from immutable events")
        app.store.close()
        app.lockfile.close()
        return
    stopped = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stopped.set())
    app.start()
    logging.info("Collector running: raw=%s SSH open=%s SSH password=%s web=%s API=%s", config.raw_port, config.ssh_open_port, config.ssh_password_port, config.web_port, config.api_port)
    try:
        while not stopped.wait(0.5):
            if app.failed.is_set():
                raise RuntimeError("Event persistence failed; collector stopped")
    finally:
        app.stop()


if __name__ == "__main__":
    main()
