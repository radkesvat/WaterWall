#!/usr/bin/env python3
"""Coalesced SOCKS CONNECT header plus a large application body, with auth/response and real echo
peers. Exact negotiation/payload bytes and no lost tail; original unexpected-EOF policy. Runs inside
the namespace harness. CTest: waterwall.socks5_connect_large_body_probe."""
import sys
from pathlib import Path
import os
import socket
import struct
import threading
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parents[2] / "support" / "python")))
from wwtest.sockets import exact as read_exact

HOST = "127.0.0.1"
TARGET = 24802
BODY = bytes(range(256)) * 32


def exact(sock, count):
    return read_exact(sock, count, timeout_context=False, eof_error=lambda: AssertionError('unexpected EOF'))


def echo(listener):
    for _ in range(6):
        conn, _ = listener.accept()
        with conn:
            conn.settimeout(5)
            data = exact(conn, len(BODY))
            assert data == BODY
            conn.sendall(data)


def negotiate(auth):
    deadline = time.monotonic() + 5
    while True:
        sock = socket.socket()
        sock.settimeout(3)
        try:
            sock.connect((HOST, 24801 if auth else 24800))
            sock.sendall(bytes([5, 1, 2 if auth else 0]))
            assert exact(sock, 2) == bytes([5, 2 if auth else 0])
            if auth:
                sock.sendall(b"\x01\x01u\x01p")
                if exact(sock, 2) != b"\x01\x00":
                    raise ConnectionError("authentication snapshot is not ready")
            return sock
        except (OSError, ConnectionError):
            sock.close()
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.05)


with socket.socket() as listener:
    listener.bind((HOST, TARGET))
    listener.listen()
    listener.settimeout(10)
    thread = threading.Thread(target=echo, args=(listener,), daemon=True)
    thread.start()
    request = b"\x05\x01\x00\x01" + socket.inet_aton(HOST) + struct.pack("!H", TARGET)
    for auth in (False, True):
        for mode in range(3):
            with negotiate(auth) as client:
                if mode == 0:
                    client.sendall(request + BODY)
                elif mode == 1:
                    client.sendall(request)
                    client.sendall(BODY)
                else:
                    client.sendall(request[:5])
                    client.sendall(request[5:] + BODY)
                assert exact(client, 10) == b"\x05\x00\x00\x01" + bytes(6)
                assert exact(client, len(BODY)) == BODY
    thread.join(5)
    assert not thread.is_alive()
print("SOCKS CONNECT large-body probe passed in both auth modes")
