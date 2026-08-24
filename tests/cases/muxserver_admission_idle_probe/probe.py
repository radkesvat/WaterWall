#!/usr/bin/env python3

import socket
import socketserver
import struct
import threading
import time


ADDRESS = ("127.0.0.1", 26780)
ECHO_ADDRESS = ("127.0.0.1", 26781)
HEADER = struct.Struct("!HBBI")
OPEN = 0
CLOSE = 1
DATA = 4


class EchoHandler(socketserver.BaseRequestHandler):
    def setup(self) -> None:
        self.server.register_connection(self.request)

    def handle(self) -> None:
        while True:
            payload = self.request.recv(4096)
            if not payload:
                return
            self.request.sendall(payload)

    def finish(self) -> None:
        self.server.unregister_connection(self.request)


class EchoServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = False
    block_on_close = True

    def __init__(self, address: tuple[str, int], handler: type[EchoHandler]) -> None:
        self._connections: set[socket.socket] = set()
        self._condition = threading.Condition()
        super().__init__(address, handler)

    def register_connection(self, connection: socket.socket) -> None:
        with self._condition:
            self._connections.add(connection)

    def unregister_connection(self, connection: socket.socket) -> None:
        with self._condition:
            self._connections.discard(connection)
            self._condition.notify_all()

    def wait_for_idle(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        with self._condition:
            while self._connections:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
            return True

    def abort_connections(self) -> None:
        with self._condition:
            connections = list(self._connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()


def connect_with_retry() -> socket.socket:
    deadline = time.monotonic() + 5.0
    while True:
        try:
            sock = socket.create_connection(ADDRESS, timeout=0.5)
            sock.settimeout(0.25)
            return sock
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.05)


def send_frame(sock: socket.socket, cid: int, flags: int, payload: bytes = b"") -> None:
    sock.sendall(HEADER.pack(len(payload), flags, 0, cid) + payload)


def read_frame(sock: socket.socket, pending: bytearray) -> tuple[int, int, bytes]:
    while len(pending) < HEADER.size:
        chunk = sock.recv(4096)
        if not chunk:
            raise AssertionError("Mux parent closed while waiting for a frame")
        pending.extend(chunk)
    length, flags, _pad, cid = HEADER.unpack(pending[: HEADER.size])
    total = HEADER.size + length
    while len(pending) < total:
        chunk = sock.recv(4096)
        if not chunk:
            raise AssertionError("Mux parent closed inside a frame")
        pending.extend(chunk)
    payload = bytes(pending[HEADER.size:total])
    del pending[:total]
    return flags, cid, payload


def await_frames(
    sock: socket.socket,
    pending: bytearray,
    expected_close: set[int],
    expected_data: dict[int, bytes],
    timeout: float,
) -> None:
    deadline = time.monotonic() + timeout
    while expected_close or expected_data:
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out waiting for Close={sorted(expected_close)} Data={sorted(expected_data)}"
            )
        try:
            flags, cid, payload = read_frame(sock, pending)
        except socket.timeout:
            continue
        if flags == CLOSE and cid in expected_close and not payload:
            expected_close.remove(cid)
            continue
        if flags == DATA and cid in expected_data and payload == expected_data[cid]:
            del expected_data[cid]
            continue
        raise AssertionError(f"unexpected MUX response flags={flags} cid={cid} payload={payload!r}")


def main() -> None:
    responder = EchoServer(ECHO_ADDRESS, EchoHandler)
    responder_thread = threading.Thread(target=responder.serve_forever, name="mux-idle-echo")
    responder_thread.start()

    sock = connect_with_retry()
    pending = bytearray()
    try:
        send_frame(sock, 1, OPEN)
        send_frame(sock, 1, DATA, b"first-before-cap")
        await_frames(sock, pending, set(), {1: b"first-before-cap"}, 2.0)

        send_frame(sock, 2, OPEN)
        rejected_at = time.monotonic()
        send_frame(sock, 3, OPEN)
        await_frames(sock, pending, {3}, {}, 0.75)
        if time.monotonic() - rejected_at > 0.75:
            raise AssertionError("resource-rejected Open did not receive a prompt Close")

        send_frame(sock, 1, DATA, b"first-after-cap")
        await_frames(sock, pending, set(), {1: b"first-after-cap"}, 2.0)

        # Child 1's nonempty traffic promoted it to the longer active timeout.
        # Socket receive blocks until the silent child alone reaches its
        # initial-idle deadline; no sleep drives the state transition.
        await_frames(sock, pending, {2}, {}, 2.0)

        send_frame(sock, 4, OPEN)
        send_frame(sock, 4, DATA, b"fourth-used-reclaimed-slot")
        await_frames(sock, pending, set(), {4: b"fourth-used-reclaimed-slot"}, 2.0)

        send_frame(sock, 1, CLOSE)
        send_frame(sock, 4, CLOSE)
    finally:
        sock.close()
        responder.shutdown()
        responder_idle = responder.wait_for_idle(2.0)
        if not responder_idle:
            responder.abort_connections()
        responder.server_close()
        responder_thread.join(timeout=2.0)
        if responder_thread.is_alive():
            raise AssertionError("loopback echo responder did not shut down cleanly")
        if not responder_idle:
            raise AssertionError("loopback echo connections were retained during shutdown")


if __name__ == "__main__":
    main()
