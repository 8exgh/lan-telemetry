import io
import shutil
import socket
import threading
import time
import uuid


class CaptureLimit(OSError):
    pass


class Capture:
    def __init__(self, sock, protocol, commands, neighbors, config):
        self.socket, self.commands, self.neighbors, self.config = sock, commands, neighbors, config
        remote, local = sock.getpeername(), sock.getsockname()
        self.meta = dict(session_id=str(uuid.uuid4()), protocol=protocol, ip=remote[0],
                         source_port=remote[1], destination_ip=local[0], destination_port=local[1],
                         address_family="IPv6" if sock.family == socket.AF_INET6 else "IPv4")
        self.offsets, self.total = {}, 0
        self.started = time.monotonic()
        self.lock = threading.RLock()
        self.closed = False
        self.record("ConnectionOpened")

    def record(self, kind, data=None, payload=None):
        with self.lock:
            self.meta.update(self.neighbors.lookup(self.meta["ip"]))
            self.commands.record(kind, self.meta, data, payload)
            if payload:
                self.total += len(payload)
                if self.total > self.config.max_session_bytes:
                    self.record("CaptureLimitReached", {"reason": "session-bytes", "limit": self.config.max_session_bytes, "captured": self.total})
                    raise CaptureLimit("session-bytes")
                self.check_space()

    def check_space(self):
        if shutil.disk_usage(self.config.data_dir).free < self.config.min_free_bytes:
            self.record("CaptureLimitReached", {"reason": "disk-reserve", "minimum_free_bytes": self.config.min_free_bytes})
            raise CaptureLimit("disk-reserve")

    def bytes(self, direction, data, layer="wire", channel=None):
        if not data:
            return
        with self.lock:
            key = (layer, direction, channel)
            offset = self.offsets.get(key, 0)
            self.record("BytesCaptured" if layer == "wire" else "TerminalBytesCaptured",
                        {"direction": direction, "layer": layer, "channel": channel, "offset": offset, "length": len(data)}, bytes(data))
            self.offsets[key] = offset + len(data)

    def close(self, reason="peer-disconnected"):
        with self.lock:
            if not self.closed:
                self.closed = True
                self.record("ConnectionClosed", {"reason": reason, "duration_ms": round((time.monotonic()-self.started)*1000), "captured_bytes": self.total})


class RecordingSocket:
    """Capture bytes where protocol libraries read/write the socket, before parsing.

    Received bytes are durable before delivery to a parser. Outbound events
    describe bytes accepted by the local kernel, not a remote acknowledgement.
    """
    def __init__(self, sock, capture):
        self.sock, self.capture = sock, capture
        self._io_refs = 0

    def __getattr__(self, name):
        return getattr(self.sock, name)

    def recv(self, size, flags=0):
        data = self.sock.recv(size, flags)
        self.capture.bytes("in", data)
        return data

    def recv_into(self, buffer, nbytes=0, flags=0):
        count = self.sock.recv_into(buffer, nbytes or len(buffer), flags)
        self.capture.bytes("in", memoryview(buffer)[:count])
        return count

    def send(self, data, flags=0):
        count = self.sock.send(data, flags)
        self.capture.bytes("out", memoryview(data)[:count])
        return count

    def sendall(self, data, flags=0):
        view = memoryview(data)
        while view:
            count = self.send(view, flags)
            if not count:
                raise OSError("socket closed during write")
            view = view[count:]

    def makefile(self, mode="r", buffering=-1, **kwargs):
        if mode not in ("rb", "wb"):
            raise ValueError("Only binary socket files are supported")
        raw = socket.SocketIO(self, mode)
        self._io_refs += 1
        if buffering == 0:
            return raw
        size = io.DEFAULT_BUFFER_SIZE if buffering < 0 else buffering
        return io.BufferedReader(raw, size) if "r" in mode else io.BufferedWriter(raw, size)

    def _decref_socketios(self):
        self._io_refs -= 1

    def close(self):
        self.sock.close()
