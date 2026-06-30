#!/usr/bin/env python3

import socket
import time
import uuid


HOST = "127.0.0.1"
PORT = 42940
IDENTITY = uuid.UUID("5783a3e7-e373-51cd-8642-c83782b807c5").bytes
VLESS_EARLY_IDENTITY = bytes([0]) + IDENTITY


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


def open_bound(source_ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2.0)
    sock.bind((source_ip, 0))
    sock.connect((HOST, PORT))
    return sock


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
    raise RuntimeError("second source IP was not rejected")


def main():
    wait_for_listener()

    first = open_bound("127.0.0.1")
    try:
        first.sendall(VLESS_EARLY_IDENTITY)
        time.sleep(0.2)

        second = open_bound("127.0.0.2")
        try:
            second.sendall(VLESS_EARLY_IDENTITY)
            expect_closed(second)
        finally:
            second.close()

        first.settimeout(0.1)
        try:
            first.sendall(b"\x00")
        except OSError as exc:
            raise RuntimeError(f"first admitted source IP closed unexpectedly: {exc}") from exc
    finally:
        first.close()


if __name__ == "__main__":
    main()

