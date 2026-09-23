import select
import socket
import time

HOST = "127.0.0.1"
LISTENER_PORT = 26620
TARGET_PORT = 26621
PENDING_SECONDS = 12
REQUEST = b"GET /delayed HTTP/1.1\r\nHost: fallback.integration.test\r\n\r\n"


def connect_listener():
    deadline = time.monotonic() + 5
    while True:
        try:
            return socket.create_connection((HOST, LISTENER_PORT), timeout=1)
        except ConnectionRefusedError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.05)


def receive_exact(sock, size):
    received = b""
    while len(received) < size:
        data = sock.recv(size - len(received))
        if not data:
            raise RuntimeError("connection closed before the queued payload arrived")
        received += data
    return received


def main():
    # Linux allows one completed connection with listen(0). Fill that accept
    # queue so the fallback TCP handshake stays pending, without firewall rules.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as target:
        target.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        target.bind((HOST, TARGET_PORT))
        target.listen(0)
        with socket.create_connection((HOST, TARGET_PORT), timeout=1) as filler:
            if not select.select([target], [], [], 1)[0]:
                raise RuntimeError("target accept queue was not filled")

            with connect_listener() as client:
                client.sendall(REQUEST)
                started = time.monotonic()
                client.settimeout(PENDING_SECONDS)
                try:
                    data = client.recv(1)
                except socket.timeout:
                    pass
                else:
                    elapsed = time.monotonic() - started
                    raise RuntimeError(
                        f"fallback closed or replied while connect was pending: {elapsed:.3f}s, {data!r}"
                    )

                queued, _ = target.accept()
                queued.close()
                filler.close()
                target.settimeout(25)
                connected, _ = target.accept()
                with connected:
                    connected.settimeout(3)
                    if receive_exact(connected, len(REQUEST)) != REQUEST:
                        raise RuntimeError("fallback changed the queued request")
                    connected.sendall(REQUEST)
                    client.settimeout(3)
                    if receive_exact(client, len(REQUEST)) != REQUEST:
                        raise RuntimeError("fallback changed the target reply")

                if client.recv(1) != b"":
                    raise RuntimeError("target close did not propagate to the client")
                print("Delayed fallback connected after the old 10-second limit and forwarded payload and close.")


if __name__ == "__main__":
    main()
