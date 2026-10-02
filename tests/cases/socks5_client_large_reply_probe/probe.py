#!/usr/bin/env python3
"""Large SOCKS reply extension fields are consumed before the application response. Fixed loopback
peers and fragmented control reads; exact bytes/EOF, with the original unexpected-EOF failure
policy. CTest: waterwall.socks5_client_large_reply_probe."""
import sys
from pathlib import Path
import os
import socket
import threading
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parents[2] / "support" / "python")))
from wwtest.sockets import exact as read_exact

BODY = bytes(range(256)) * 32
errors = []


def exact(sock, length):
    return read_exact(sock, length, timeout_context=False, eof_error=lambda: AssertionError('unexpected EOF'))


def proxy(listener):
    try:
        for case in range(6):
            conn, _ = listener.accept()
            with conn:
                conn.settimeout(5)
                version, count = exact(conn, 2)
                assert version == 5
                methods = exact(conn, count)
                auth = case >= 3
                assert (2 if auth else 0) in methods
                conn.sendall(bytes([5, 2 if auth else 0]))
                if auth:
                    assert exact(conn, 5) == b"\x01\x01u\x01p"
                    conn.sendall(b"\x01\x00")
                assert exact(conn, 10) == b"\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50"
                reply = b"\x05\x00\x00\x01" + bytes(6)
                mode = case % 3
                if mode == 0:
                    conn.sendall(reply + BODY)
                elif mode == 1:
                    conn.sendall(reply)
                    conn.sendall(BODY)
                else:
                    conn.sendall(reply[:5])
                    conn.sendall(reply[5:] + BODY)
                assert exact(conn, 1) == b"Q"
    except BaseException as error:
        errors.append(error)


def connect(port):
    deadline = time.monotonic() + 5
    while True:
        sock = socket.socket()
        sock.settimeout(5)
        try:
            sock.connect(("127.0.0.1", port))
            return sock
        except OSError:
            sock.close()
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.05)


with socket.socket() as listener:
    listener.bind(("127.0.0.1", 24812))
    listener.listen()
    listener.settimeout(10)
    thread = threading.Thread(target=proxy, args=(listener,), daemon=True)
    thread.start()
    for port in (24810, 24811):
        for mode in range(3):
            with connect(port) as application:
                application.sendall(b"Q")
                assert exact(application, len(BODY)) == BODY
    thread.join(5)
    assert not thread.is_alive()
    if errors:
        raise errors[0]
print("SOCKS5 client large-reply probe passed in both auth modes")
