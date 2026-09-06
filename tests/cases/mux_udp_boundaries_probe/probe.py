#!/usr/bin/env python3
"""Check direct UDP/MUX frame boundaries across a real TCP carrier in both directions."""

import contextlib
import socket
import time


INGRESS = ("127.0.0.1", 26790)
CARRIER = ("127.0.0.1", 26791)
SERVICE = ("127.0.0.1", 26792)


def wait_for_listener() -> None:
    deadline = time.monotonic() + 5.0
    while True:
        try:
            with socket.create_connection(CARRIER, timeout=0.25):
                return
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.02)


def response(payload: bytes) -> bytes:
    return b"" if not payload else b"\xff" + payload[::-1] + b"\x00"


def require_no_datagram(sock: socket.socket) -> None:
    sock.settimeout(0.1)
    try:
        extra, _ = sock.recvfrom(65535)
    except socket.timeout:
        return
    raise AssertionError(f"unexpected extra datagram of {len(extra)} bytes")


def main() -> None:
    with contextlib.ExitStack() as stack:
        service = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        service.bind(SERVICE)
        service.settimeout(2.0)
        clients = [stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) for _ in range(2)]
        for client in clients:
            client.bind(("127.0.0.1", 0))
            client.settimeout(2.0)

        wait_for_listener()

        # The first child opens with an empty payload: OPEN must still be
        # followed by a distinct zero-length DATA frame and a UDP send.
        peers = {}
        for index, client in enumerate(clients):
            first = b"" if index == 0 else b"ready"
            client.sendto(first, INGRESS)
            actual, peer = service.recvfrom(65535)
            assert actual == first, "initial datagram changed"
            assert peer not in peers, "different MUX children shared an ambiguous UDP reply endpoint"
            peers[peer] = index
            service.sendto(response(actual), peer)
            assert client.recvfrom(65535)[0] == response(first), "initial reply changed"

        payloads = [
            [b"", b"A\x00B", bytes(range(256)) * 5, b"client-zero-tail", b""],
            [b"", b"other-child", b"Z" * 1500, b"\x00", b""],
        ]
        for position in range(len(payloads[0])):
            for index, client in enumerate(clients):
                client.sendto(payloads[index][position], INGRESS)

        received = [0, 0]
        for _ in range(sum(map(len, payloads))):
            actual, peer = service.recvfrom(65535)
            assert peer in peers, "MUX changed the child-to-service association"
            index = peers[peer]
            position = received[index]
            assert position < len(payloads[index]), "extra datagram on a child"
            assert actual == payloads[index][position], "request boundary, child, order, or bytes changed"
            received[index] += 1
            service.sendto(response(actual), peer)

        for index, client in enumerate(clients):
            for payload in payloads[index]:
                actual, _ = client.recvfrom(65535)
                assert actual == response(payload), "reply boundary, child, order, or bytes changed"

        for sock in [service, *clients]:
            require_no_datagram(sock)

    print("MUX preserved separate and empty UDP payloads in both directions")


if __name__ == "__main__":
    main()
