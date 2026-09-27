#!/usr/bin/env python3
"""CONNECT metadata and a large body in one write, through both auth modes."""
import socket
import struct
import threading
import time

HOST = "127.0.0.1"
TARGET = 24802
BODY = bytes(range(256)) * 32


def exact(sock, count):
    data = bytearray()
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise AssertionError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)


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
