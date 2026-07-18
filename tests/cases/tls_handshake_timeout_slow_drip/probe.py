import socket
import sys
import threading
import time

HOST = "127.0.0.1"
LISTENER_PORT = 25200
FALLBACK_PORT = 25201
SENTINEL = b"WATERWALL-FALLBACK-SENTINEL\n"


def fail(message):
    print(message, file=sys.stderr)
    raise SystemExit(1)


def start_sentinel():
    state = {"ready": False, "hit": False, "received": b""}

    def run():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((HOST, FALLBACK_PORT))
            srv.listen(1)
            srv.settimeout(5.0)
            state["ready"] = True
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                return
            with conn:
                state["hit"] = True
                try:
                    state["received"] = conn.recv(4096)
                    conn.sendall(SENTINEL)
                except OSError:
                    pass

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 2.0
    while not state["ready"]:
        if time.monotonic() > deadline:
            fail("fallback sentinel did not start")
        time.sleep(0.01)
    return state


def wait_for_listener():
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((HOST, LISTENER_PORT), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    fail("Waterwall listener did not open")


def main():
    sentinel = start_sentinel()
    wait_for_listener()

    payload = b"\x16\x03\x03\x40\x00" + (b"\x00" * 64)
    start = time.monotonic()
    closed_at = None
    received = b""

    with socket.create_connection((HOST, LISTENER_PORT), timeout=1.0) as sock:
        sock.settimeout(0.03)
        index = 0
        while time.monotonic() - start < 2.5:
            try:
                sock.sendall(payload[index % len(payload):index % len(payload) + 1])
            except OSError:
                closed_at = time.monotonic()
                break
            index += 1

            try:
                chunk = sock.recv(4096)
                if chunk == b"":
                    closed_at = time.monotonic()
                    break
                received += chunk
                if SENTINEL in received:
                    fail("TLS-looking slow-drip probe reached fallback")
            except socket.timeout:
                pass

            time.sleep(0.15)

        if closed_at is None:
            try:
                sock.settimeout(0.5)
                chunk = sock.recv(4096)
                if chunk == b"":
                    closed_at = time.monotonic()
                else:
                    received += chunk
            except socket.timeout:
                pass

    if SENTINEL in received or sentinel["hit"]:
        fail("TLS-looking slow-drip probe reached fallback")
    if closed_at is None:
        fail("TLS-looking slow-drip probe stayed open beyond handshake timeout")

    elapsed = closed_at - start
    if elapsed < 0.35:
        fail(f"connection closed too early to prove deadline behavior: {elapsed:.3f}s")
    if elapsed > 2.2:
        fail(f"connection closed too late for handshake timeout: {elapsed:.3f}s")


if __name__ == "__main__":
    main()
