import socket
import sys
import time


HOST = "127.0.0.1"
REALITY_PORT = 25140
VISITOR_PORT = 25141


def fail(message):
    print(message, file=sys.stderr)
    raise SystemExit(1)


def connect_with_retry():
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        try:
            return socket.create_connection((HOST, REALITY_PORT), timeout=1.0)
        except OSError:
            time.sleep(0.05)
    fail("RealityServer listener did not open")


def accept_visitor(listener):
    listener.settimeout(3.0)
    try:
        connection, _ = listener.accept()
    except socket.timeout:
        fail("visitor destination did not receive a connection")
    connection.settimeout(2.0)
    return connection


def recv_exact(connection, length):
    result = b""
    deadline = time.monotonic() + 2.0
    while len(result) < length and time.monotonic() < deadline:
        try:
            chunk = connection.recv(length - len(result))
        except socket.timeout:
            continue
        if not chunk:
            break
        result += chunk
    return result


def recv_until_eof(connection):
    result = b""
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        try:
            chunk = connection.recv(4096)
        except socket.timeout:
            continue
        if not chunk:
            return result
        result += chunk
    fail("visitor destination did not receive EOF")


def require_held_while_open(connection, name):
    connection.settimeout(0.15)
    try:
        unexpected = connection.recv(1)
    except socket.timeout:
        unexpected = None
    finally:
        connection.settimeout(2.0)
    if unexpected is not None:
        fail(f"{name}: plausible prefix was forwarded before upstream FIN: {unexpected!r}")


def run_immediate_invalid(listener):
    with connect_with_retry() as client:
        with accept_visitor(listener) as visitor:
            start = time.monotonic()
            client.sendall(b"\x01")
            received = recv_exact(visitor, 1)
            elapsed = time.monotonic() - start
            if received != b"\x01":
                fail(f"invalid type was not forwarded immediately: {received!r}")
            if elapsed > 1.5:
                fail(f"invalid type forwarding was delayed for {elapsed:.3f}s")

            client.shutdown(socket.SHUT_WR)
            trailing = recv_until_eof(visitor)
            if trailing:
                fail(f"invalid type was duplicated after FIN: {trailing!r}")


def run_plausible_prefix(listener, prefix):
    name = f"plausible-{len(prefix)}-byte-prefix"
    with connect_with_retry() as client:
        with accept_visitor(listener) as visitor:
            client.sendall(prefix)
            require_held_while_open(visitor, name)
            client.shutdown(socket.SHUT_WR)
            received = recv_until_eof(visitor)
            if received != prefix:
                fail(f"{name}: expected exact bytes before EOF, got {received!r}")


def run_invalid_with_fin(listener):
    with connect_with_retry() as client:
        with accept_visitor(listener) as visitor:
            client.sendall(b"\x01")
            client.shutdown(socket.SHUT_WR)
            received = recv_until_eof(visitor)
            if received != b"\x01":
                fail(f"invalid prefix plus FIN was not delivered exactly once: {received!r}")


def main():
    plausible_prefixes = (
        b"\x16",
        b"\x16\x03",
        b"\x16\x03\x04",
        b"\x16\x03\x04\x00",
    )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((HOST, VISITOR_PORT))
        listener.listen(8)

        run_immediate_invalid(listener)
        for prefix in plausible_prefixes:
            run_plausible_prefix(listener, prefix)
        run_invalid_with_fin(listener)

    print("RealityServer short visitor prefixes were preserved before destination EOF")


if __name__ == "__main__":
    main()
