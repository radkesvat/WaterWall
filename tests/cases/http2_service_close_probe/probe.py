"""Close the service right after a large response, through HttpClient and HttpServer over HTTP/2.
Every response byte and then EOF must reach the client.
CTest: waterwall.http2_service_close_probe. The existing runner supplies a private Linux network
namespace and owns the runtime.
"""

import os
from pathlib import Path
import select
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parents[2] / "support" / "python")))
from wwtest.sockets import exact


HOST = "127.0.0.1"
LISTENER_PORT = 26700
CARRIER_PORT = 26701
SERVICE_PORT = 26702
TIMED_CARRIER_PORT = 26703
CLOSE_DRAIN_TIMEOUT = 1.0
REQUEST = b"send-then-close"
# More than the HTTP/2 windows, so most of it is still queued when the service closes.
BODY = bytes(range(256)) * 65536
ROUNDS = 3
DRAIN_BODY = bytes(range(256)) * 512
RECEIVE_WINDOW = 1024


def connect_listener(port=LISTENER_PORT):
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


def serve_service(listener, body=BODY):
    peer, _ = listener.accept()
    with peer:
        peer.settimeout(10)
        if exact(peer, len(REQUEST)) != REQUEST:
            raise AssertionError("HTTP/2 changed the request")
        peer.sendall(body)


def h2_frame(kind, flags, stream, payload=b""):
    return (len(payload).to_bytes(3, "big") + bytes([kind, flags])
            + struct.pack("!I", stream) + payload)


def receive_h2_frame(client):
    header = exact(client, 9)
    size = int.from_bytes(header[:3], "big")
    if size > 16384:
        raise AssertionError(f"server exceeded the default HTTP/2 frame size: {size}")
    kind, flags = header[3:5]
    stream = int.from_bytes(header[5:], "big") & 0x7fffffff
    payload = exact(client, size)
    if kind == 4 and not flags & 1:  # Acknowledge server SETTINGS.
        client.sendall(h2_frame(4, 1, 0))
    if kind == 3 or (kind == 7 and int.from_bytes(payload[4:8], "big") != 0):
        raise AssertionError(f"server rejected the stream: frame={kind}, payload={payload!r}")
    return kind, flags, stream, payload


def service_close_count():
    # The case runner enables DEBUG logs. A protocol round trip after this marker
    # ensures the event loop has completed the service's Finish callback.
    return Path("stdout.log").read_text().count("TcpConnector: received close")


def begin_blocked_response(client, listener, executor):
    before = service_close_count()
    service = executor.submit(serve_service, listener, DRAIN_BODY)
    # Static HPACK indexes: POST, http, then literal :authority and :path.
    headers = (b"\x83\x86\x01\x0fh2.example.test\x04\x06/ww/h2")
    client.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                   + h2_frame(4, 0, 0, struct.pack("!HI", 4, RECEIVE_WINDOW))
                   + h2_frame(1, 4, 1, headers)
                   + h2_frame(0, 0, 1, REQUEST))
    service.result(timeout=10)
    deadline = time.monotonic() + 5
    while service_close_count() == before:
        if time.monotonic() >= deadline:
            raise AssertionError("runtime did not process the service close")
        time.sleep(0.01)

    client.sendall(h2_frame(6, 0, 0, b"barrier!"))
    received = bytearray()
    while True:
        kind, flags, stream, payload = receive_h2_frame(client)
        if kind == 0:
            if stream != 1 or flags != 0:
                raise AssertionError("response ended before its receive window was reopened")
            received.extend(payload)
        if kind == 6 and flags & 1 and payload == b"barrier!":
            break
    if len(received) != RECEIVE_WINDOW:
        raise AssertionError(f"expected a window-blocked response, got {len(received)} bytes")
    return received


def run_late_upload(listener, executor):
    with connect_listener(CARRIER_PORT) as client:
        received = begin_blocked_response(client, listener, executor)
        # Request DATA arrives after the service has finished. It must be discarded,
        # while subsequent connection/stream WINDOW_UPDATE frames still drain output.
        client.sendall(h2_frame(0, 0, 1, b"continued upload after service close")
                       + h2_frame(6, 0, 0, b"latebody"))
        while True:
            kind, flags, stream, payload = receive_h2_frame(client)
            if kind == 0:
                raise AssertionError("server sent response DATA without receive credit")
            if kind == 6 and flags & 1 and payload == b"latebody":
                break
        client.sendall(h2_frame(8, 0, 0, struct.pack("!I", len(DRAIN_BODY)))
                       + h2_frame(8, 0, 1, struct.pack("!I", len(DRAIN_BODY))))
        while True:
            kind, flags, stream, payload = receive_h2_frame(client)
            if kind == 0:
                if stream != 1 or flags & ~1:
                    raise AssertionError("unexpected response DATA framing")
                received.extend(payload)
                if flags & 1:
                    break
        if received != DRAIN_BODY:
            raise AssertionError(f"late upload changed the response ({len(received)} bytes)")
        if client.recv(1) != b"":
            raise AssertionError("missing EOF after response END_STREAM")
    print("late upload during response drain: passed", flush=True)


def run_abort_during_drain(listener, executor):
    with connect_listener(CARRIER_PORT) as client:
        begin_blocked_response(client, listener, executor)
        # Close with the response still blocked. The following large-response rounds
        # must continue to work; focused native tests verify exact state reclamation.
    print("client disconnect during response drain: completed", flush=True)


def run_drain_timeout(listener, executor, active):
    with connect_listener(TIMED_CARRIER_PORT) as client:
        received = begin_blocked_response(client, listener, executor)
        started = time.monotonic()
        next_update = started
        ping_acks = 0
        while True:
            now = time.monotonic()
            if now - started > CLOSE_DRAIN_TIMEOUT + 1.0:
                raise AssertionError("response drain did not close at its fixed deadline")
            if active and now >= next_update:
                # Both inbound activity and actual response progress must leave the
                # original deadline unchanged. One-byte grants cannot drain the body.
                client.sendall(h2_frame(6, 0, 0, b"deadline")
                               + h2_frame(8, 0, 0, struct.pack("!I", 1))
                               + h2_frame(8, 0, 1, struct.pack("!I", 1)))
                next_update = now + 0.1
            if not select.select([client], [], [], 0.02)[0]:
                continue
            if client.recv(1, socket.MSG_PEEK) == b"":
                break
            kind, flags, stream, payload = receive_h2_frame(client)
            if kind == 0:
                if stream != 1 or flags != 0:
                    raise AssertionError("blocked response unexpectedly completed")
                received.extend(payload)
            if kind == 6 and flags & 1 and payload == b"deadline":
                ping_acks += 1
        elapsed = time.monotonic() - started
        if elapsed < CLOSE_DRAIN_TIMEOUT * 0.6:
            raise AssertionError(f"response drain closed too soon: {elapsed:.3f}s")
        if received != DRAIN_BODY[:len(received)] or len(received) >= len(DRAIN_BODY):
            raise AssertionError("drain timeout did not preserve the partial response")
        if active and (ping_acks < 3 or len(received) <= RECEIVE_WINDOW):
            raise AssertionError("deadline case did not exercise ongoing control traffic and progress")
        if not active and len(received) != RECEIVE_WINDOW:
            raise AssertionError("silent peer received DATA without granting credit")
    mode = "with control traffic and progress" if active else "without further client traffic"
    print(f"response drain timeout {mode}: passed ({elapsed:.3f}s)", flush=True)


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
            run_drain_timeout(listener, executor, active=False)
            run_drain_timeout(listener, executor, active=True)
            run_late_upload(listener, executor)
            run_abort_during_drain(listener, executor)
            for round_number in range(1, ROUNDS + 1):
                run_round(listener, executor, round_number)


if __name__ == "__main__":
    main()
