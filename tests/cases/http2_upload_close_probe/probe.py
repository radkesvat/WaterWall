"""Exercise HTTP/2 upload completion and cancellation through the real runtime.

The case runner owns WaterWall and supplies private namespace loopback. A raw
HTTP/2 peer controls request windows; a production pair checks the full chain.
CTest: waterwall.http2_upload_close_probe.
"""

import os
from pathlib import Path
import re
import select
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parents[2] / "support" / "python")))
from wwtest.sockets import configure_listener, exact


HOST = "127.0.0.1"
APPLICATION_PORT = 26800
PEER_PORT = 26801
TIMED_APPLICATION_PORT = 26802
PAIR_APPLICATION_PORT = 26803
SERVICE_PORT = 26805
UPGRADE_APPLICATION_PORT = 26806
WEBSOCKET_APPLICATION_PORT = 26807
RECEIVE_WINDOW = 1024
DRAIN_TIMEOUT = 1.0
BODY = bytes(range(256)) * 512
PAIR_BODY = bytes(range(256)) * 16384
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def connect_application(port=APPLICATION_PORT):
    deadline = time.monotonic() + 5
    while True:
        try:
            application = socket.create_connection((HOST, port), timeout=5)
            application.settimeout(10)
            return application
        except ConnectionRefusedError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.01)


def frame(kind, flags, stream, payload=b""):
    return (len(payload).to_bytes(3, "big") + bytes([kind, flags])
            + struct.pack("!I", stream) + payload)


def receive_frame(peer, allow_upgrade_cancel=False):
    header = exact(peer, 9)
    size = int.from_bytes(header[:3], "big")
    assert size <= 16384, f"client exceeded peer's default frame size: {size}"
    kind, flags = header[3:5]
    stream = int.from_bytes(header[5:], "big") & 0x7fffffff
    payload = exact(peer, size)
    if kind == 4 and not flags & 1:
        peer.sendall(frame(4, 1, 0))
    assert kind != 3 or (allow_upgrade_cancel and stream == 1
                         and payload == struct.pack("!I", 8)), f"client reset stream: {payload!r}"
    assert kind != 7 or int.from_bytes(payload[4:8], "big") == 0, \
        f"client rejected connection: {payload!r}"
    return kind, flags, stream, payload


def logs():
    return Path("stdout.log").read_text(errors="replace")


def wait_for(predicate, failure, timeout=5):
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, failure
        time.sleep(0.01)


def begin(listener, port=APPLICATION_PORT, websocket=False, tls_context=None):
    application = connect_application(port)
    try:
        peer, _ = listener.accept()
        peer.settimeout(5)
        if tls_context is not None:
            peer = tls_context.wrap_socket(peer, server_side=True)
            assert peer.selected_alpn_protocol() == "h2"
        assert exact(peer, len(PREFACE)) == PREFACE
        settings = struct.pack("!HI", 4, RECEIVE_WINDOW)
        if websocket:
            settings += struct.pack("!HI", 8, 1)  # SETTINGS_ENABLE_CONNECT_PROTOCOL.
        peer.sendall(frame(4, 0, 0, settings))
        stream, acknowledged = None, False
        while stream is None or not acknowledged:
            kind, flags, sid, payload = receive_frame(peer)
            if kind == 4 and flags & 1:
                acknowledged = True
            if kind == 1:
                stream = sid
        return application, peer, stream
    except BaseException:
        application.close()
        if "peer" in locals():
            peer.close()
        raise


def read_upload_frame(peer, stream, received):
    kind, flags, sid, payload = receive_frame(peer)
    if kind == 0:
        assert sid == stream and not flags & ~1, "unexpected upload DATA framing"
        received.extend(payload)
    return kind, flags, payload


def barrier(peer, stream, received, token):
    peer.sendall(frame(6, 0, 0, token))
    while True:
        kind, flags, payload = read_upload_frame(peer, stream, received)
        assert not (kind == 0 and flags & 1), "upload ended before all bytes were sent"
        if kind == 6 and flags & 1 and payload == token:
            return


def begin_blocked_upload(listener, port=APPLICATION_PORT, tls_context=None):
    application, peer, stream = begin(listener, port, tls_context=tls_context)
    try:
        offset = len(logs())
        application.sendall(BODY)
        received = bytearray()
        while len(received) < RECEIVE_WINDOW:
            kind, flags, payload = read_upload_frame(peer, stream, received)
            assert not (kind == 0 and flags & 1), "upload ended before application close"
        assert received == BODY[:RECEIVE_WINDOW]

        # TCP sendall only proves kernel admission. The existing verbose diagnostic
        # proves the entire body reached HttpClient before the application closes.
        def accepted():
            return sum(map(int, re.findall(
                r"HttpClient: queueing HTTP/2 DATA stream_id=\d+ payload_len=(\d+)",
                logs()[offset:])))
        wait_for(lambda: accepted() >= len(BODY), "HttpClient did not accept the full upload")
        assert accepted() == len(BODY)
        before_close = logs().count("TcpListener: received close")
        started = time.monotonic()
        application.close()
        wait_for(lambda: logs().count("TcpListener: received close") > before_close,
                 "application close did not reach WaterWall")
        barrier(peer, stream, received, b"finished")
        assert received == BODY[:RECEIVE_WINDOW], "DATA escaped the closed stream window"
        return peer, stream, received, started
    except BaseException:
        application.close()
        peer.close()
        raise


def run_complete_upload(listener, tls_context=None):
    peer, stream, received, _ = begin_blocked_upload(listener, tls_context=tls_context)
    with peer:
        # A response arriving after application Finish must be consumed without
        # calling the closed application. Its END_STREAM does not cancel upload.
        peer.sendall(frame(1, 4, stream, b"\x88")  # HPACK static :status 200.
                     + frame(0, 1, stream, b"response after application close"))
        barrier(peer, stream, received, b"response")
        peer.sendall(frame(8, 0, 0, struct.pack("!I", len(BODY)))
                     + frame(8, 0, stream, struct.pack("!I", len(BODY))))
        while True:
            kind, flags, payload = read_upload_frame(peer, stream, received)
            if kind == 0 and flags & 1:
                break
        assert received == BODY, f"upload changed or truncated: {len(received)} bytes"
        assert peer.recv(1) == b"", "missing TCP EOF after upload END_STREAM"
    print("blocked upload, late response, and response END_STREAM: passed", flush=True)


def run_close_before_upgrade(listener):
    application = connect_application(UPGRADE_APPLICATION_PORT)
    peer, _ = listener.accept()
    with peer:
        peer.settimeout(5)
        headers = bytearray()
        while not headers.endswith(b"\r\n\r\n"):
            headers.extend(exact(peer, 1))
            assert len(headers) < 16384, "oversized upgrade request"
        assert b"upgrade: h2c\r\n" in headers.lower()
        before_close = logs().count("TcpListener: received close")
        with application:
            application.sendall(BODY)
        wait_for(lambda: logs().count("TcpListener: received close") > before_close,
                 "application close before upgrade was not processed")
        # Delay protocol readiness until the application line has already closed.
        # Accepted pre-handshake bytes must survive on the owned carrier line.
        peer.sendall(b"HTTP/1.1 101 Switching Protocols\r\n"
                     b"Connection: Upgrade\r\nUpgrade: h2c\r\n\r\n"
                     + frame(4, 0, 0, struct.pack("!HI", 4, 262144))
                     + frame(8, 0, 0, struct.pack("!I", len(BODY))))
        assert exact(peer, len(PREFACE)) == PREFACE
        stream = None
        received = bytearray()
        ended = False
        while not ended:
            kind, flags, sid, payload = receive_frame(peer, allow_upgrade_cancel=True)
            if kind == 1:
                assert stream is None
                stream = sid
            if kind == 0:
                assert sid == stream and not flags & ~1
                received.extend(payload)
                ended = bool(flags & 1)
        assert received == BODY, f"pre-handshake upload changed: {len(received)} bytes"
        assert peer.recv(1) == b"", "missing EOF after upgraded upload completed"
    print("application close before h2c handshake: exact upload and END_STREAM", flush=True)


def run_close_before_websocket_handshake(listener):
    application, peer, stream = begin(listener, WEBSOCKET_APPLICATION_PORT, websocket=True)
    with peer:
        before_close = logs().count("TcpListener: received close")
        with application:
            application.sendall(BODY)
        wait_for(lambda: logs().count("TcpListener: received close") > before_close,
                 "application close before WebSocket handshake was not processed")
        peer.sendall(frame(1, 4, stream, b"\x88")
                     + frame(8, 0, 0, struct.pack("!I", len(BODY) * 2))
                     + frame(8, 0, stream, struct.pack("!I", len(BODY) * 2)))
        wire = bytearray()
        while True:
            kind, flags, payload = read_upload_frame(peer, stream, wire)
            if kind == 0 and flags & 1:
                break
        assert peer.recv(1) == b"", "missing EOF after WebSocket upload completed"

    # Decode independently of WaterWall's WebSocket helper. Binary frames must
    # precede one close frame and all client payloads must carry the RFC mask.
    offset = 0
    received = bytearray()
    closed = False
    while offset < len(wire):
        assert offset + 2 <= len(wire), "truncated WebSocket header"
        first, second = wire[offset:offset + 2]
        offset += 2
        opcode, size = first & 0x0f, second & 0x7f
        assert first & 0xf0 == 0x80 and second & 0x80, "invalid client WebSocket framing"
        if size in (126, 127):
            width = 2 if size == 126 else 8
            assert offset + width <= len(wire)
            size = int.from_bytes(wire[offset:offset + width], "big")
            offset += width
        assert offset + 4 + size <= len(wire), "truncated WebSocket payload"
        mask = wire[offset:offset + 4]
        offset += 4
        payload = bytes(value ^ mask[index % 4]
                        for index, value in enumerate(wire[offset:offset + size]))
        offset += size
        assert not closed, "WebSocket data followed the close frame"
        if opcode == 2:
            received.extend(payload)
        else:
            assert opcode == 8 and size <= 125, "unexpected WebSocket control frame"
            closed = True
    assert received == BODY and closed, "WebSocket upload was lost or closed out of order"
    print("application close before WebSocket-over-HTTP/2 handshake: exact upload and close", flush=True)


def run_timeout(listener, active):
    peer, stream, received, started = begin_blocked_upload(listener, TIMED_APPLICATION_PORT)
    with peer:
        next_update = time.monotonic()
        ping_acks = 0
        while True:
            now = time.monotonic()
            assert now - started < DRAIN_TIMEOUT + 1, "upload drain exceeded its fixed deadline"
            if active and now >= next_update:
                peer.sendall(frame(6, 0, 0, b"deadline")
                             + frame(8, 0, 0, struct.pack("!I", 1))
                             + frame(8, 0, stream, struct.pack("!I", 1)))
                next_update = now + 0.1
            if not select.select([peer], [], [], 0.02)[0]:
                continue
            if not peer.recv(1, socket.MSG_PEEK):
                break
            kind, flags, payload = read_upload_frame(peer, stream, received)
            assert not (kind == 0 and flags & 1), "blocked upload unexpectedly completed"
            if kind == 6 and flags & 1 and payload == b"deadline":
                ping_acks += 1
        elapsed = time.monotonic() - started
        assert elapsed >= DRAIN_TIMEOUT * 0.6, f"upload drain expired early: {elapsed:.3f}s"
        assert received == BODY[:len(received)] and len(received) < len(BODY)
        if active:
            assert ping_acks >= 3 and len(received) > RECEIVE_WINDOW, \
                "active deadline case did not exercise control traffic and upload progress"
        else:
            assert len(received) == RECEIVE_WINDOW, "silent peer received DATA without credit"
    mode = "with PING and upload progress" if active else "without further peer traffic"
    print(f"fixed upload drain timeout {mode}: passed ({elapsed:.3f}s)", flush=True)


def expect_eof(peer, message, timeout=2):
    peer.settimeout(timeout)
    assert peer.recv(1) == b"", message


def run_reset(listener, application_closed):
    if application_closed:
        peer, stream, received, _ = begin_blocked_upload(listener)
        application = None
    else:
        application, peer, stream = begin(listener)
    try:
        peer.sendall(frame(3, 0, stream, struct.pack("!I", 8)))  # CANCEL.
        # Connection-level control output is allowed before the final TCP EOF.
        peer.settimeout(2)
        while peer.recv(1, socket.MSG_PEEK):
            kind, flags, sid, payload = receive_frame(peer)
            assert kind != 0, "canceled upload continued sending DATA"
        if application is not None:
            expect_eof(application, "stream reset left application open")
    finally:
        peer.close()
        if application is not None:
            application.close()
    state = "during drain" if application_closed else "with application open"
    print(f"stream cancellation {state}: passed", flush=True)


def run_carrier_disconnect(listener):
    peer, stream, received, _ = begin_blocked_upload(listener)
    peer.close()
    # A live application must also be finished when its carrier disappears.
    application, peer, stream = begin(listener)
    with application:
        peer.close()
        expect_eof(application, "carrier disconnect left application open")
    print("carrier disconnect during drain and with application open: passed", flush=True)


def receive_pair_upload(listener):
    service, _ = listener.accept()
    with service:
        service.settimeout(10)
        assert exact(service, len(PAIR_BODY), max_chunk=65536) == PAIR_BODY
        assert service.recv(1) == b"", "production pair did not deliver EOF after upload"


def run_production_pair():
    with socket.socket() as listener:
        configure_listener(listener, (HOST, SERVICE_PORT), timeout=10)
        with ThreadPoolExecutor(max_workers=1) as executor:
            receipt = executor.submit(receive_pair_upload, listener)
            with connect_application(PAIR_APPLICATION_PORT) as application:
                application.sendall(PAIR_BODY)
            receipt.result(timeout=15)
    print("production HttpClient/HttpServer pair: exact 4 MiB upload and EOF", flush=True)


def main():
    with socket.socket() as listener:
        configure_listener(listener, (HOST, PEER_PORT), timeout=10)
        run_complete_upload(listener)
        run_close_before_upgrade(listener)
        run_close_before_websocket_handshake(listener)
        run_timeout(listener, active=False)
        run_timeout(listener, active=True)
        run_reset(listener, application_closed=False)
        run_reset(listener, application_closed=True)
        run_carrier_disconnect(listener)
        run_production_pair()



if __name__ == "__main__":
    main()
