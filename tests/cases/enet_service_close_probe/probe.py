"""Close the service right after a large response, through EnetClient and EnetServer
over UDP sockets and chained directly. Every response byte and then EOF must reach the client.
CTest: waterwall.enet_service_close_probe. The existing runner supplies a private Linux
network namespace and owns the runtime.
"""

import os
from pathlib import Path
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parents[2] / "support" / "python")))
from wwtest.sockets import exact


HOST = "127.0.0.1"
SERVICE_PORT = 26673
REQUEST = b"send-then-close"
# Far more than ENet keeps in flight, so most of it is still queued when the service closes.
BODY = bytes(range(256)) * 16384
ROUNDS = 3


def connect_listener(port):
    deadline = time.monotonic() + 5
    while True:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Room for what ENet delivers in one burst keeps TcpListener writes from blocking.
        client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        client.settimeout(10)
        try:
            client.connect((HOST, port))
            return client
        except ConnectionRefusedError:
            client.close()
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.02)


def serve_service(listener):
    peer, _ = listener.accept()
    with peer:
        peer.settimeout(5)
        if exact(peer, len(REQUEST)) != REQUEST:
            raise AssertionError("Enet changed the request")
        peer.sendall(BODY)


def run_case(listener, executor, label, port):
    service = executor.submit(serve_service, listener)
    with connect_listener(port) as client:
        client.sendall(REQUEST)
        if exact(client, len(BODY), max_chunk=1 << 20) != BODY:
            raise AssertionError(f"{label}: response changed")
        if client.recv(1) != b"":
            raise AssertionError(f"{label}: missing EOF after response")
    service.result(timeout=5)
    print(f"{label}: passed", flush=True)


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((HOST, SERVICE_PORT))
        listener.listen()
        listener.settimeout(10)
        with ThreadPoolExecutor(max_workers=1) as executor:
            for round_number in range(1, ROUNDS + 1):
                run_case(listener, executor, f"udp path round {round_number}", 26670)
                run_case(listener, executor, f"direct chain round {round_number}", 26672)


if __name__ == "__main__":
    main()
