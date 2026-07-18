#!/usr/bin/env python3

import socket
import time


HOST = "127.0.0.1"
PORT = 24250


def wait_for_listener(timeout=5.0):
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            with socket.create_connection((HOST, PORT), timeout=0.2):
                return
        except OSError as exc:
            last_error = exc
            time.sleep(0.05)
    raise RuntimeError(f"listener did not become ready: {last_error}")


def expect_closed(sock, timeout=2.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            data = sock.recv(1)
            if data == b"":
                return
        except (ConnectionResetError, BrokenPipeError):
            return
        except socket.timeout:
            pass
    raise RuntimeError("malformed identity was not closed")


def main():
    wait_for_listener()
    with socket.create_connection((HOST, PORT), timeout=2.0) as sock:
        sock.settimeout(0.2)
        sock.sendall(b"\x01not-a-vless-request")
        expect_closed(sock)


if __name__ == "__main__":
    main()
