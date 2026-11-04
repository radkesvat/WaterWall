"""Carry VLESS over MUX with a carrier that splits every read, so a child's first DATA frame reaches
MuxServer in small pieces. VlessServer must still receive the UUID as one payload.
CTest: waterwall.mux_first_frame_probe. The existing runner supplies a private Linux network
namespace and owns the runtime.
"""

import os
from pathlib import Path
import socket
import sys
import threading
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parents[2] / "support" / "python")))
from wwtest.sockets import exact


HOST = "127.0.0.1"
APPLICATION_PORT = 26720
RELAY_PORT = 26721
CARRIER_IN_PORT = 26722
SERVICE_PORT = 26723
REQUEST = b"first-bytes-of-a-child"
RESPONSE = b"response-through-mux"
ROUNDS = 3


def connect_retry(port):
    deadline = time.monotonic() + 5
    while True:
        peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        peer.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        peer.settimeout(10)
        try:
            peer.connect((HOST, port))
            return peer
        except ConnectionRefusedError:
            peer.close()
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.02)


def forward(source, target, split):
    try:
        while True:
            data = source.recv(65536)
            if not data:
                break
            if split:
                # Separate reads on the far side: the delay outlasts its event loop's batch.
                for offset in range(0, len(data), 3):
                    target.sendall(data[offset:offset + 3])
                    time.sleep(0.002)
            else:
                target.sendall(data)
    except OSError:
        pass
    finally:
        for peer in (source, target):
            try:
                peer.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def relay(listener):
    while True:
        try:
            incoming, _ = listener.accept()
        except OSError:
            return
        incoming.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        outgoing = connect_retry(CARRIER_IN_PORT)
        threading.Thread(target=forward, args=(incoming, outgoing, True), daemon=True).start()
        threading.Thread(target=forward, args=(outgoing, incoming, False), daemon=True).start()


def run_round(service, round_number):
    with connect_retry(APPLICATION_PORT) as client:
        client.sendall(REQUEST)
        peer, _ = service.accept()
        with peer:
            peer.settimeout(10)
            if exact(peer, len(REQUEST)) != REQUEST:
                raise AssertionError(f"round {round_number}: request changed")
            peer.sendall(RESPONSE)
            if exact(client, len(RESPONSE)) != RESPONSE:
                raise AssertionError(f"round {round_number}: response changed")
    print(f"round {round_number}: passed", flush=True)


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener, socket.socket(socket.AF_INET, socket.SOCK_STREAM) as service:
        for sock, port in ((listener, RELAY_PORT), (service, SERVICE_PORT)):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((HOST, port))
            sock.listen()
        service.settimeout(10)
        threading.Thread(target=relay, args=(listener,), daemon=True).start()
        for round_number in range(1, ROUNDS + 1):
            run_round(service, round_number)


if __name__ == "__main__":
    main()
