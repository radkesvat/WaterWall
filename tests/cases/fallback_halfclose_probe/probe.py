"""Exercise real local fallback half/full closes for TLS, VLESS and Trojan, plus
an ordinary connector control. Check response draining, local discard, backend
retirement and idle expiry. CTest: waterwall.fallback_halfclose_probe. The existing
runner supplies a private Linux network namespace and owns the runtime.
"""

import os
from pathlib import Path
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parents[2] / "support" / "python")))
from wwtest.sockets import exact


HOST = "127.0.0.1"
TARGET_PORT = 26634
REQUEST = b"GET /close HTTP/1.1\r\nHost: fallback.integration.test\r\n\r\n"
BODY = bytes(range(256)) * 4096
RESPONSE = (b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: "
            + str(len(BODY)).encode("ascii") + b"\r\n\r\n" + BODY)
EXTRA = b"discard-after-fin" * 256
TCP_CLOSE = 7
TCP_CLOSE_WAIT = 8


def connect_listener(port):
    deadline = time.monotonic() + 5
    while True:
        try:
            client = socket.create_connection((HOST, port), timeout=3)
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            return client
        except ConnectionRefusedError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.02)


def tcp_state(client):
    return client.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 1)[0]


def serve_target(listener, halfclose):
    peer, _ = listener.accept()
    with peer:
        peer.settimeout(5)
        if exact(peer, len(REQUEST)) != REQUEST:
            raise AssertionError("fallback changed the request")
        peer.sendall(RESPONSE)
        if halfclose:
            peer.shutdown(socket.SHUT_WR)
            if peer.recv(4096) != b"":
                raise AssertionError("connector forwarded data after target EOF")


def expect_discard(client, label):
    for _ in range(8):
        client.sendall(EXTRA)
        time.sleep(0.03)
        if tcp_state(client) != TCP_CLOSE_WAIT:
            raise AssertionError(f"{label}: client reset during local discard")


def expect_reset(client, label):
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        try:
            client.sendall(EXTRA)
        except (BrokenPipeError, ConnectionResetError):
            return
        time.sleep(0.02)
        if tcp_state(client) == TCP_CLOSE:
            return
    raise AssertionError(f"{label}: still accepting data after full close")


def run_case(listener, executor, label, port, halfclose, fallback=True, idle=False):
    backend = executor.submit(serve_target, listener, halfclose)
    with connect_listener(port) as client:
        client.sendall(REQUEST)
        # A small listener send buffer leaves queued response data when the
        # connector observes EOF; the final FIN must follow all response bytes.
        time.sleep(0.15)
        if exact(client, len(RESPONSE)) != RESPONSE:
            raise AssertionError(f"{label}: response changed")
        if client.recv(1) != b"":
            raise AssertionError(f"{label}: missing EOF after response")
        backend.result(timeout=5)

        if halfclose and fallback:
            expect_discard(client, label)
            if idle:
                time.sleep(5.5)
                expect_reset(client, f"{label} idle expiry")
        else:
            expect_reset(client, label)
    print(f"{label}: passed", flush=True)


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((HOST, TARGET_PORT))
        listener.listen()
        listener.settimeout(5)
        with ThreadPoolExecutor(max_workers=1) as executor:
            for name, port in (("tls", 26630), ("vless", 26631), ("trojan", 26632)):
                run_case(listener, executor, f"{name} half-close", port, True,
                         idle=name == "tls")
                run_case(listener, executor, f"{name} full close", port, False)
            run_case(listener, executor, "ordinary connector half-close", 26633,
                     True, fallback=False)


if __name__ == "__main__":
    main()
