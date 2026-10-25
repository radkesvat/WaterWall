#!/usr/bin/env python3
"""Exact UDP boundaries through the real Trojan client/server TLS chain."""

from pathlib import Path
import socket
import time


def payload(size):
    return bytes(range(256)) * (size // 256) + bytes(range(size % 256))


READY = b"trojan-udp-size-readiness"


def establish(client, target):
    # Connecting TLS can pause UdpListener during Init and drop its triggering
    # datagram. Retry only this distinct readiness token, never measured payloads.
    deadline = time.monotonic() + 5
    target.settimeout(.1)
    client.settimeout(.1)
    while time.monotonic() < deadline:
        client.sendto(READY, ("127.0.0.1", 28430))
        try:
            data, remote = target.recvfrom(65535)
            assert data == READY, "readiness request changed"
            target.sendto(READY, remote)
            data, _ = client.recvfrom(65535)
            assert data == READY, "readiness reply changed"
            return
        except socket.timeout:
            continue
    raise AssertionError("Trojan UDP/TLS association did not become ready")


def receive_payload(sock):
    deadline = time.monotonic() + 5
    while True:
        remaining = deadline - time.monotonic()
        assert remaining > 0, "measured UDP receive timed out"
        sock.settimeout(remaining)
        data, remote = sock.recvfrom(65535)
        if data != READY:
            return data, remote


deadline = time.monotonic() + 10
log = Path("stdout.log")
while not log.exists() or "127.0.0.1:[28430] (UDP)" not in log.read_text():
    assert time.monotonic() < deadline, "application UDP listener did not become ready"
    time.sleep(.02)

# 65507 is the ordinary IPv4 UDP payload maximum. The native fixtures exercise
# the larger protocol length-field boundary without asking a UDP socket to send it.
sizes = [1, 0, 8191, 8192, 8193, 32768, 65400, 65507]
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, \
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as target:
    client.settimeout(5)
    target.settimeout(5)
    target.bind(("127.0.0.1", 28432))
    establish(client, target)
    for request_size, reply_size in zip(sizes, reversed(sizes)):
        request, reply = payload(request_size), payload(reply_size)
        assert client.sendto(request, ("127.0.0.1", 28430)) == request_size
        received, remote = receive_payload(target)
        assert received == request, f"request boundary/content changed at {request_size} bytes"
        assert target.sendto(reply, remote) == reply_size
        received, _ = receive_payload(client)
        assert received == reply, f"reply boundary/content changed at {reply_size} bytes"
        print(f"Trojan UDP: {request_size}-byte request / {reply_size}-byte reply passed", flush=True)
