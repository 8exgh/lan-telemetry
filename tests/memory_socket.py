"""A duplex byte stream for protocol tests when OS sockets are unavailable.

This performs no networking. The actual Paramiko and HTTP parsers run unchanged.
"""
import socket
import threading
import time


class MemorySocket:
    family = socket.AF_INET
    type = socket.SOCK_STREAM
    _io_refs = 0

    def __init__(self, address):
        self.address = address
        self.timeout = 5
        self.buffer = bytearray()
        self.condition = threading.Condition()
        self.eof = False
        self._closed = False
        self.peer = None

    def send(self, data, flags=0):
        if self._closed or self.peer._closed:
            raise OSError("Stream closed")
        size = min(len(data), 8192)
        with self.peer.condition:
            self.peer.buffer.extend(data[:size])
            self.peer.condition.notify_all()
        return size

    def sendall(self, data, flags=0):
        view = memoryview(data)
        while view:
            size = self.send(view)
            view = view[size:]

    def recv(self, size, flags=0):
        deadline = time.monotonic() + self.timeout if self.timeout is not None else None
        with self.condition:
            while not self.buffer and not self.eof and not self._closed:
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    raise socket.timeout()
                self.condition.wait(remaining)
            data = bytes(self.buffer[:size])
            del self.buffer[:size]
            return data

    def recv_into(self, buffer, nbytes=0, flags=0):
        data = self.recv(nbytes or len(buffer))
        buffer[:len(data)] = data
        return len(data)

    def shutdown(self, how):
        if how in (socket.SHUT_WR, socket.SHUT_RDWR):
            with self.peer.condition:
                self.peer.eof = True
                self.peer.condition.notify_all()
        if how in (socket.SHUT_RD, socket.SHUT_RDWR):
            with self.condition:
                self.eof = True
                self.condition.notify_all()

    def close(self):
        self._closed = True
        self.shutdown(socket.SHUT_RDWR)

    def settimeout(self, value):
        self.timeout = value

    def gettimeout(self):
        return self.timeout

    def setblocking(self, value):
        self.timeout = None if value else 0

    def getpeername(self):
        return self.peer.address

    def getsockname(self):
        return self.address

    def setsockopt(self, *args):
        pass

    def makefile(self, mode="rb", buffering=-1):
        from telemetry.capture import RecordingSocket
        return RecordingSocket.makefile(self, mode, buffering)

    def _decref_socketios(self):
        self._io_refs -= 1

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def memory_pair(port=40000):
    first, second = MemorySocket(("127.0.0.1", port)), MemorySocket(("127.0.0.1", 9000))
    first.peer, second.peer = second, first
    return first, second
