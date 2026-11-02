"""Close the service right after a large response, through HttpClient and HttpServer over HTTP/2.
Every response byte and then EOF must reach the client.
CTest: waterwall.http2_service_close_probe. The existing runner supplies a private Linux network
namespace and owns the runtime.
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
LISTENER_PORT = 26700
SERVICE_PORT = 26702
REQUEST = b"send-then-close"
# More than the HTTP/2 windows, so most of it is still queued when the service closes.
BODY = bytes(range(256)) * 65536
ROUNDS = 3


def connect_listener():
    deadline = time.monotonic() + 5
    while True:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(10)
        try:
            client.connect((HOST, LISTENER_PORT))
            return client
        except ConnectionRefusedError:
            client.close()
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.02)


def serve_service(listener):
    peer, _ = listener.accept()
    with peer:
        peer.settimeout(10)
        if exact(peer, len(REQUEST)) != REQUEST:
            raise AssertionError("HTTP/2 changed the request")
        peer.sendall(BODY)


def run_round(listener, executor, round_number):
    service = executor.submit(serve_service, listener)
    with connect_listener() as client:
        client.sendall(REQUEST)
        # A slow start leaves the HTTP/2 windows closed while the service finishes writing.
        time.sleep(0.2)
        if exact(client, len(BODY), max_chunk=1 << 20) != BODY:
            raise AssertionError(f"round {round_number}: response changed")
        if client.recv(1) != b"":
            raise AssertionError(f"round {round_number}: missing EOF after response")
    service.result(timeout=10)
    print(f"round {round_number}: passed", flush=True)


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((HOST, SERVICE_PORT))
        listener.listen()
        listener.settimeout(10)
        with ThreadPoolExecutor(max_workers=1) as executor:
            for round_number in range(1, ROUNDS + 1):
                run_round(listener, executor, round_number)


if __name__ == "__main__":
    main()
