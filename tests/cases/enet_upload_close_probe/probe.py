"""Upload then close through the direct pair and the real UDP sandwich.

The service must receive the exact upload and EOF after the caller destroys its
socket. The namespace probe runner owns WaterWall and the loopback endpoints.
CTest: waterwall.enet_upload_close_probe.
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
SERVICE_PORT = 26677
BODY = bytes(range(256)) * 16384
ROUNDS = 3


def connect_listener(port):
    deadline = time.monotonic() + 5
    while True:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
        peer.settimeout(10)
        if exact(peer, len(BODY), max_chunk=1 << 20) != BODY:
            raise AssertionError("Enet changed or truncated the upload")
        if peer.recv(1) != b"":
            raise AssertionError("missing EOF after upload")


def run_case(listener, executor, label, port):
    service = executor.submit(serve_service, listener)
    with connect_listener(port) as client:
        client.sendall(BODY)
    service.result(timeout=15)
    print(f"{label}: passed", flush=True)


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((HOST, SERVICE_PORT))
        listener.listen()
        listener.settimeout(10)
        with ThreadPoolExecutor(max_workers=1) as executor:
            for round_number in range(1, ROUNDS + 1):
                run_case(listener, executor, f"udp path round {round_number}", 26674)
                run_case(listener, executor, f"direct chain round {round_number}", 26676)


if __name__ == "__main__":
    main()
