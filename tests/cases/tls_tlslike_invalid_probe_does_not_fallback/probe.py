import socket
import sys
import threading
import time

HOST = "127.0.0.1"
LISTENER_PORT = 25300
FALLBACK_PORT = 25301
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
            srv.settimeout(4.0)
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


def recv_until_done(sock, seconds):
    data = b""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            sock.settimeout(0.1)
            chunk = sock.recv(4096)
            if chunk == b"":
                return data, True
            data += chunk
        except socket.timeout:
            continue
        except OSError:
            return data, True
    return data, False


def main():
    sentinel = start_sentinel()
    wait_for_listener()

    with socket.create_connection((HOST, LISTENER_PORT), timeout=1.0) as sock:
        sock.sendall(b"\x16\x03\x03\x00\x04\x01\x00\x00\x00")
        data, closed = recv_until_done(sock, 2.0)

    if SENTINEL in data or sentinel["hit"]:
        fail("TLS-looking invalid probe reached fallback")
    if not data.startswith(b"\x15\x03"):
        fail(f"TLS-looking invalid probe did not receive a TLS alert before close: {data!r}")
    if not closed:
        fail("TLS-looking invalid probe did not close")


if __name__ == "__main__":
    main()
