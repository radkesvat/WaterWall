#!/usr/bin/env python3
"""Raw QUIC transforms through direct, UDP and explicitly framed TCP carriers.

Loopback tests use the namespace runner and the canonical local TLS certificate;
they verify server-first delivery with zero client bytes, binary byte order in
both directions, deterministic UDP loss/duplication/reordering and shutdown143.
The speed case runs the exact VLESS/QUIC chain in speedtests/quic_vless_udp and
reports verified upload/download Mbit/s from the fixed measured byte interval.
CTest: waterwall.quic_direct, waterwall.quic_udp, waterwall.quic_stream,
waterwall.quic_udp_impaired, waterwall.quic_shutdown, waterwall.quic_failures,
waterwall.quic_speedtest_vless_udp. No internet, timing performance gate or HTTP/3.
"""

import concurrent.futures
import contextlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import socket
import sys
import threading
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parent / "support" / "python")))
from wwtest.config import core_config
from wwtest.process import Process, close_on_error, install_termination_handler
from wwtest.run_directory import RunDirectory
from wwtest.sockets import configure_listener, connect_when_ready, exact


TESTS = Path(__file__).resolve().parent
HOST = "127.0.0.1"
APP_PORT, CARRIER_PORT, RELAY_PORT, BACKEND_PORT = 29841, 29842, 29843, 29844
CERTIFICATES = TESTS / "speedtests" / "_shared"


def client_settings(**overrides):
    return {"sni": "tls.integration.test", "verify": True, "ca-file": "server.crt",
            "handshake-timeout-ms": 5000, **overrides}


def server_settings(**overrides):
    return {"cert-file": "server.crt", "key-file": "server.key",
            "handshake-timeout-ms": 5000, **overrides}


def write_inputs(root, nodes, *, workers=1):
    for name in ("server.crt", "server.key"):
        shutil.copyfile(CERTIFICATES / name, root / name)
    (root / "core.json").write_text(json.dumps(core_config(workers=workers, splice=True)))
    (root / "config.json").write_text(json.dumps({"name": "quic-integration", "nodes": nodes}))


def orderly_stop(process):
    process.send_signal(signal.SIGTERM)
    assert process.wait(timeout=10) == 128 + signal.SIGTERM, "QUIC runtime shutdown failed"


class DatagramRelay:
    """One explicit peer, bounded held packet, fixed packet ordinal impairment."""

    def __enter__(self):
        self.front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.back = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.front.bind((HOST, RELAY_PORT))
        self.back.connect((HOST, CARRIER_PORT))
        self.stop = threading.Event()
        self.errors = []
        self.counts = [0, 0]
        self.applied = {"dropped": 0, "duplicated": 0, "reordered": 0}
        self.thread = threading.Thread(target=self.run, name="quic-datagram-relay")
        self.thread.start()
        return self

    def run(self):
        peer = None
        held = [None, None]
        try:
            while not self.stop.is_set():
                for source in select.select([self.front, self.back], [], [], 0.01)[0]:
                    direction = 0 if source is self.front else 1
                    payload, address = source.recvfrom(65535)
                    if direction == 0:
                        if peer is None:
                            peer = address
                        assert peer == address, "impairment fixture received an unexpected second peer"
                    assert peer is not None
                    target = self.back.send if direction == 0 else lambda data: self.front.sendto(data, peer)
                    self.counts[direction] += 1
                    ordinal = self.counts[direction]
                    if direction == 0 and ordinal == 1:
                        self.applied["dropped"] += 1  # First Initial must be retransmitted by a QUIC alarm.
                        continue
                    if ordinal == 5:
                        held[direction] = (payload, target, time.monotonic())
                        continue
                    target(payload)
                    if ordinal == 4:
                        target(payload)
                        self.applied["duplicated"] += 1
                    if held[direction] is not None:
                        pending, send, _ = held[direction]
                        held[direction] = None
                        send(pending)
                        self.applied["reordered"] += 1
                for direction, pending in enumerate(held):
                    if pending is not None and time.monotonic() - pending[2] >= 0.025:
                        held[direction] = None
                        pending[1](pending[0])
        except BaseException as error:
            self.errors.append(error)

    def stop_forwarding(self):
        self.stop.set()
        self.thread.join(timeout=2)
        assert not self.thread.is_alive(), "datagram relay did not stop"

    def __exit__(self, exc_type, exc, traceback):
        try:
            self.stop_forwarding()
        finally:
            self.front.close()
            self.back.close()
        if exc_type is None:
            assert not self.errors, self.errors
            assert all(self.applied.values()), f"impairment was not exercised: {self.applied}"


class StreamRelay:
    """Force split prefixes/bodies and join complete frames on a TCP carrier."""

    def __enter__(self):
        self.listener = socket.socket()
        configure_listener(self.listener, (HOST, RELAY_PORT), timeout=10)
        self.stop = threading.Event()
        self.transfer_complete = threading.Event()
        self.errors = []
        self.connections = []
        self.fragmented = [0, 0]
        self.coalesced = [0, 0]
        self.thread = threading.Thread(target=self.run, name="quic-stream-relay")
        self.thread.start()
        return self

    def forward(self, source, target, direction):
        def frame():
            prefix = exact(source, 4, eof_error=EOFError)
            length = int.from_bytes(prefix, "big")
            assert 0 < length <= 1472, "encoder emitted an invalid stream carrier length"
            return prefix + exact(source, length, eof_error=EOFError)

        try:
            while not self.stop.is_set():
                packet = frame()
                if self.fragmented[direction] < 2:
                    # The first four writes split every prefix boundary. A
                    # delayed first body byte additionally forces partial body.
                    for offset in range(5):
                        target.sendall(packet[offset:offset + 1])
                        time.sleep(0.005)
                    target.sendall(packet[5:])
                    self.fragmented[direction] += 1
                else:
                    if select.select([source], [], [], 0.002)[0]:
                        following = frame()
                        packet += following
                        self.coalesced[direction] += 1
                    target.sendall(packet)
        except BaseException as error:
            expected_close = self.transfer_complete.is_set() and isinstance(error, (ConnectionResetError, BrokenPipeError, EOFError))
            if not self.stop.is_set() and not expected_close:
                self.errors.append(error)

    def run(self):
        try:
            with self.listener.accept()[0] as incoming, socket.create_connection((HOST, CARRIER_PORT), timeout=10) as outgoing:
                incoming.settimeout(15)
                outgoing.settimeout(15)
                incoming.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                outgoing.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                self.connections = [incoming, outgoing]
                peer = threading.Thread(target=self.forward, args=(outgoing, incoming, 1))
                peer.start()
                self.forward(incoming, outgoing, 0)
                peer.join(timeout=17)
                assert not peer.is_alive(), "stream relay peer did not settle"
        except BaseException as error:
            if not self.stop.is_set():
                self.errors.append(error)

    def __exit__(self, exc_type, exc, traceback):
        self.stop.set()
        for connection in self.connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.thread.join(timeout=20)
        self.listener.close()
        assert not self.thread.is_alive(), "stream relay did not stop"
        if exc_type is None:
            assert not self.errors, self.errors
            assert all(self.fragmented), "stream prefix/body fragmentation was not exercised"
            assert sum(self.coalesced) > 0, "stream coalescing was not exercised"


def roundtrip_nodes(mode):
    stream = mode == "stream"
    carrier_mode = "stream" if stream else "datagram"
    return [
        {"name": "application", "type": "TcpListener", "next": "quic-client",
         "settings": {"address": HOST, "port": APP_PORT, "nodelay": True}},
        {"name": "quic-client", "type": "QuicClient", "next": "carrier-out",
         "settings": client_settings(**{"carrier-mode": carrier_mode})},
        {"name": "carrier-out", "type": "TcpConnector" if stream else "UdpConnector",
         "settings": {"address": HOST, "port": RELAY_PORT if mode in ("udp-impaired", "stream") else CARRIER_PORT,
                      **({"nodelay": True, "fastopen": False} if stream else {"balance-mode": "packet"})}},
        {"name": "carrier-in", "type": "TcpListener" if stream else "UdpListener", "next": "quic-server",
         "settings": {"address": HOST, "port": CARRIER_PORT}},
        {"name": "quic-server", "type": "QuicServer", "next": "application-out",
         "settings": server_settings(**{"carrier-mode": carrier_mode})},
        {"name": "application-out", "type": "TcpConnector",
         "settings": {"address": HOST, "port": BACKEND_PORT, "nodelay": True, "fastopen": False}},
    ]


def roundtrip(binary, mode):
    # Leading NUL bytes are application data; neither private opening byte may leak.
    greeting = b"\0server-first-with-no-client-data\xff"
    upload = bytes(range(256)) * 4096
    download = upload[::-1]
    with RunDirectory("waterwall-quic-" + mode + "-") as root:
        write_inputs(root, roundtrip_nodes(mode), workers=2)
        with socket.socket() as backend:
            configure_listener(backend, (HOST, BACKEND_PORT), timeout=15)
            relay_context = (DatagramRelay() if mode == "udp-impaired" else StreamRelay() if mode == "stream"
                             else contextlib.nullcontext())
            with relay_context as relay, Process([binary], cwd=root, log_path=root / "stdout.log") as process:
                client = connect_when_ready(process, (HOST, APP_PORT), deadline=time.monotonic() + 10,
                    failure=lambda: AssertionError("QUIC runtime exited before application connection"))

                def peer():
                    with backend.accept()[0] as connection:
                        connection.settimeout(15)
                        connection.sendall(greeting)
                        assert exact(connection, len(upload)) == upload, "QUIC upload changed byte order"
                        # Split application writes as well as QUIC's independent packetization.
                        for offset in range(0, len(download), 8191):
                            connection.sendall(download[offset:offset + 8191])
                        # Every byte is received before Finish. Runtime owner
                        # drain closes this socket even if a final QUIC packet
                        # is lost or local Finish retires its borrowed carrier.
                        assert connection.recv(1) == b"", "application emitted trailing bytes"

                with client, concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor, close_on_error(client):
                    client.settimeout(15)
                    task = executor.submit(peer)
                    assert exact(client, len(greeting)) == greeting, "server-first data or opening marker changed"
                    for offset in range(0, len(upload), 10007):
                        client.sendall(upload[offset:offset + 10007])
                    assert exact(client, len(download)) == download, "QUIC download changed byte order"
                    if isinstance(relay, StreamRelay):
                        relay.transfer_complete.set()
                    elif isinstance(relay, DatagramRelay):
                        # Both payloads are verified. Stop forwarding while the
                        # runtime's carrier sockets are still open, so a late
                        # datagram cannot turn orderly shutdown into ECONNREFUSED.
                        # Keep the relay sockets open until the runtime exits.
                        relay.stop_forwarding()
                    client.shutdown(socket.SHUT_RDWR)
                    orderly_stop(process)
                    task.result(timeout=20)
    print(f"QUIC {mode}: server-first, verified bidirectional binary bytes and owner shutdown passed")


def direct(binary):
    nodes = [
        {"name": "test-client", "type": "TesterClient", "next": "quic-client",
         "settings": {"allow-early-response": True, "chunk-count": 10}},
        {"name": "quic-client", "type": "QuicClient", "next": "quic-server", "settings": client_settings()},
        {"name": "quic-server", "type": "QuicServer", "next": "test-server", "settings": server_settings()},
        {"name": "test-server", "type": "TesterServer",
         "settings": {"streaming-response": True, "chunk-count": 10}},
    ]
    with RunDirectory("waterwall-quic-direct-") as root:
        write_inputs(root, nodes, workers=2)
        with Process([binary], cwd=root, log_path=root / "stdout.log") as process:
            assert process.wait(timeout=30) == 0, "direct QUIC test runtime failed"
            assert "TesterClient: all 2 worker lines completed successfully" in (root / "stdout.log").read_text(), \
                "direct QUIC chain did not complete both worker lines"
    print("QUIC direct: production transforms, verified binary streams and two workers passed")


def shutdown(binary):
    nodes = [
        {"name": "application", "type": "TcpListener", "next": "quic-client",
         "settings": {"address": HOST, "port": APP_PORT}},
        {"name": "quic-client", "type": "QuicClient", "next": "carrier",
         "settings": client_settings(**{"carrier-mode": "stream"})},
        {"name": "carrier", "type": "TcpConnector",
         "settings": {"address": HOST, "port": BACKEND_PORT, "fastopen": False}},
    ]
    with RunDirectory("waterwall-quic-shutdown-") as root:
        write_inputs(root, nodes, workers=2)
        with socket.socket() as backend:
            configure_listener(backend, (HOST, BACKEND_PORT), timeout=10)
            with Process([binary], cwd=root, log_path=root / "stdout.log") as process:
                client = connect_when_ready(process, (HOST, APP_PORT), deadline=time.monotonic() + 10,
                    failure=lambda: AssertionError("QUIC shutdown fixture startup failed"))
                with client, backend.accept()[0] as carrier:
                    client.settimeout(10)
                    carrier.settimeout(10)
                    assert carrier.recv(4096), "client did not emit a real QUIC handshake"
                    client.sendall(b"pending application data" * 1024)
                    # A partial carrier frame and uncompleted handshake remain live at quiescence.
                    carrier.sendall(b"\0\0")
                    orderly_stop(process)
                    # Shutdown may close either socket before reading its pending bytes,
                    # which legitimately produces a TCP reset instead of EOF.
                    with contextlib.suppress(ConnectionResetError):
                        assert client.recv(1) == b"", "application owner survived runtime shutdown"
                    with contextlib.suppress(ConnectionResetError):
                        while carrier.recv(65535):
                            pass
    print("QUIC shutdown: pending handshake, plaintext, partial frame and owned sockets settled")


def failures(binary):
    for mismatch in ("protocol", "hostname", "trust", "carrier-mode"):
        nodes = roundtrip_nodes("udp")
        client, server = nodes[1]["settings"], nodes[4]["settings"]
        client["handshake-timeout-ms"] = server["handshake-timeout-ms"] = 500
        if mismatch == "protocol":
            server["protocol"] = "other-raw-protocol"
        elif mismatch == "hostname":
            client["sni"] = "wrong.integration.test"
        elif mismatch == "trust":
            del client["ca-file"]  # The local self-signed certificate is absent from bundled roots.
        else:
            server["carrier-mode"] = "stream"
        with RunDirectory("waterwall-quic-mismatch-" + mismatch + "-") as root:
            write_inputs(root, nodes)
            with socket.socket() as backend:
                configure_listener(backend, (HOST, BACKEND_PORT), timeout=3)
                with Process([binary], cwd=root, log_path=root / "stdout.log") as process:
                    client_socket = connect_when_ready(process, (HOST, APP_PORT), deadline=time.monotonic() + 10,
                        failure=lambda: AssertionError("QUIC mismatch runtime failed startup"))
                    with client_socket:
                        client_socket.settimeout(3)
                        client_socket.sendall(b"application must wait for authenticated readiness")
                        assert client_socket.recv(1) == b"", f"{mismatch}: failed peer exposed application data"
                    orderly_stop(process)
    print("QUIC ALPN, hostname, trust and explicit-carrier mismatches close within finite deadline")


def speed(binary):
    fixture = TESTS / "speedtests" / "quic_vless_udp"
    config = json.loads((fixture / "config.json").read_text())
    settings = config["nodes"][0]["settings"]
    with RunDirectory("waterwall-quic-vless-speed-") as root:
        write_inputs(root, config["nodes"], workers=1)
        with Process([binary], cwd=root, log_path=root / "stdout.log") as process:
            assert process.wait(timeout=40) == 0, "VLESS/QUIC verified speed workload failed"
            output = (root / "stdout.log").read_text(errors="replace")
            reports = re.findall(r"SpeedTestClient: json-summary (\{[^\r\n]+\})", output)
            assert len(reports) == 1, "missing or duplicate aggregate SpeedTestClient report"
            report = json.loads(reports[0])
            assert report["success"] and report["verification_enabled"]
            assert report["failed"] == report["validation_errors"] == report["lost_packets"] == 0
            assert report["streams"] == settings["connection-count"]
            assert report["sent_bytes"] > 0 and report["received_bytes"] > 0
            seconds = settings["duration-ms"] / 1000
            result = {**report, "duration_ms": settings["duration-ms"],
                      "upload_mbps": report["sent_bytes"] * 8 / seconds / 1_000_000,
                      "download_mbps": report["received_bytes"] * 8 / seconds / 1_000_000}
            (root / "throughput.json").write_text(json.dumps(result, indent=2) + "\n")
            print("QUIC VLESS UDP throughput " + json.dumps(result), flush=True)


if __name__ == "__main__":
    install_termination_handler()
    binary = str(Path(sys.argv[1]).resolve())
    mode = sys.argv[2]
    if mode == "direct":
        direct(binary)
    elif mode == "shutdown":
        shutdown(binary)
    elif mode == "speed":
        speed(binary)
    elif mode == "failures":
        failures(binary)
    else:
        assert mode in ("udp", "stream", "udp-impaired"), mode
        roundtrip(binary, mode)
