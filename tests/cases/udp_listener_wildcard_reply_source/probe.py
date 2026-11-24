"""Delay two replies until one client has contacted both local listener addresses."""

import socket
import time


def check_reply(backend, client, peer, reply, expected_source):
    backend.sendto(reply, peer)
    data, source = client.recvfrom(64)
    if (data, source[:2]) != (reply, expected_source):
        raise RuntimeError(f"expected {reply!r} from {expected_source}, got {data!r} from {source}")


def check_ipv4_aliases(backend, listen_port, client_port):
    first = ("127.0.0.2", listen_port)
    second = ("127.0.0.3", listen_port)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.bind(("127.0.0.1", client_port))
        client.settimeout(2)
        backend.settimeout(0.2)

        # The probe and the runtime start concurrently. The first delivery also
        # proves the listener is accepting traffic before the second request.
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            client.sendto(b"first", first)
            try:
                payload, first_peer = backend.recvfrom(64)
                break
            except socket.timeout:
                continue
        else:
            raise RuntimeError("first request never reached the backend")
        if payload != b"first":
            raise RuntimeError(f"unexpected first request {payload!r}")

        client.sendto(b"second", second)
        backend.settimeout(2)
        while True:
            payload, second_peer = backend.recvfrom(64)
            if payload != b"first":  # Ignore a late retry during startup.
                break
        if payload != b"second":
            raise RuntimeError(f"unexpected second request {payload!r}")

        check_reply(backend, client, second_peer, b"second reply", second)
        check_reply(backend, client, first_peer, b"first reply", first)


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as backend:
        backend.bind(("127.0.0.1", 26753))
        check_ipv4_aliases(backend, 26752, 26755)
        check_ipv4_aliases(backend, 26754, 26756)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as exact, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            exact.bind(("127.0.0.1", 26757))
            exact.settimeout(2)
            client.bind(("127.0.0.1", 26755))
            client.settimeout(2)
            client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            for destination, expected_backend in (("127.0.0.1", exact), ("127.255.255.255", backend)):
                request = destination.encode("ascii")
                client.sendto(request, (destination, 26752))
                payload, peer = expected_backend.recvfrom(64)
                if payload != request:
                    raise RuntimeError(f"expected {request!r} at the selected backend, got {payload!r}")
                check_reply(expected_backend, client, peer, request, ("127.0.0.1", 26752))

        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as client:
            endpoint = ("::1", 26754)
            client.bind(("::1", 26755))
            client.settimeout(2)
            client.sendto(b"ipv6", endpoint)
            payload, peer = backend.recvfrom(64)
            if payload != b"ipv6":
                raise RuntimeError(f"unexpected IPv6 request {payload!r}")
            check_reply(backend, client, peer, b"ipv6 reply", endpoint)


if __name__ == "__main__":
    main()
