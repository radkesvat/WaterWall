#!/usr/bin/env python3
"""HalfDuplexServer pairing between TLS/TCP and KCP or QUIC/UDP ingress chains.

The primary feeds VlessServer -> TcpUdpConnector; the secondary has only pair.
Four workers carry concurrent, distinct binary streams through both upload-path
orientations. Two batches check pair retirement/reuse, service-close response
draining and client-first EOF. A final active session checks owner shutdown.
All sockets use the private loopback namespace and the existing local TLS fixture.
CTest: waterwall.halfduplex_pair_{kcp,quic}_{tls,udp}_upload.
"""

import argparse
import concurrent.futures
import contextlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parent / "support" / "python")))
from wwtest.config import core_config
from wwtest.process import Process, install_termination_handler
from wwtest.run_directory import RunDirectory
from wwtest.sockets import configure_listener, connect_when_ready, exact


HOST = "127.0.0.1"
APP_PORT, TLS_PORT, UDP_PORT, BACKEND_PORT = 29871, 29872, 29873, 29874
UUID = "5783a3e7-e373-51cd-8642-c83782b807c5"
CERTIFICATES = Path(__file__).resolve().parent / "speedtests" / "_shared"
CONNECTIONS = 4
BODY_SIZE = 1 << 20


def topology(carrier, upload):
    udp_client = "KcpClient" if carrier == "kcp" else "QuicClient"
    udp_server = "KcpServer" if carrier == "kcp" else "QuicServer"
    udp_client_settings = {}
    udp_server_settings = {}
    if carrier == "quic":
        udp_client_settings = {"sni": "tls.integration.test", "verify": True, "ca-file": "server.crt",
                               "handshake-timeout-ms": 5000}
        udp_server_settings = {"cert-file": "server.crt", "key-file": "server.key",
                               "handshake-timeout-ms": 5000}
    nodes = [
        {"name": "application", "type": "TcpListener", "next": "vless-client",
         "settings": {"address": HOST, "port": APP_PORT, "nodelay": True}},
        {"name": "vless-client", "type": "VlessClient", "next": "split",
         "settings": {"uuid": UUID, "address": HOST, "port": BACKEND_PORT, "protocol": "tcp"}},
        {"name": "split", "type": "HalfDuplexClient",
         "settings": {"upload": "tls-client" if upload == "tls" else "udp-client",
                      "download": "udp-client" if upload == "tls" else "tls-client"}},
        {"name": "tls-client", "type": "TlsClient", "next": "tcp-out",
         "settings": {"sni": "tls.integration.test", "verify": False, "alpns": ["http/1.1"]}},
        {"name": "tcp-out", "type": "TcpConnector",
         "settings": {"address": HOST, "port": TLS_PORT, "nodelay": True, "fastopen": False}},
        {"name": "udp-client", "type": udp_client, "next": "udp-out", "settings": udp_client_settings},
        {"name": "udp-out", "type": "UdpConnector",
         "settings": {"address": HOST, "port": UDP_PORT, "balance-mode": "packet"}},
        {"name": "udp-in", "type": "UdpListener", "next": "udp-server",
         "settings": {"address": HOST, "port": UDP_PORT}},
        {"name": "udp-server", "type": udp_server, "next": "hs2", "settings": udp_server_settings},
        # Put the reference before its target to exercise forward name resolution.
        {"name": "hs2", "type": "HalfDuplexServer", "settings": {"pair": "hs1"}},
        {"name": "tcp-in", "type": "TcpListener", "next": "tls-server",
         "settings": {"address": HOST, "port": TLS_PORT, "nodelay": True}},
        {"name": "tls-server", "type": "TlsServer", "next": "hs1",
         "settings": {"cert-file": "server.crt", "key-file": "server.key", "sni": "tls.integration.test"}},
        {"name": "hs1", "type": "HalfDuplexServer", "next": "vless-server"},
        {"name": "vless-server", "type": "VlessServer", "next": "backend",
         "settings": {"uuid": UUID, "connect": True, "udp": True}},
        {"name": "backend", "type": "TcpUdpConnector",
         "settings": {"address": "dest_context->address", "port": "dest_context->port",
                      "nodelay": True, "fastopen": False}},
    ]
    return nodes


def body(identifier):
    return bytes((value + identifier) % 256 for value in range(256)) * (BODY_SIZE // 256)


def fragmented_send(connection, payload, chunk_size):
    for offset in range(0, len(payload), chunk_size):
        connection.sendall(payload[offset:offset + chunk_size])


def service(connection, identifiers):
    with connection:
        connection.settimeout(15)
        marker = exact(connection, 4)
        identifier = int.from_bytes(marker, "big")
        assert identifier in identifiers, f"unexpected application session {identifier}"
        connection.sendall(b"ready" + marker)
        expected = body(identifier)
        assert exact(connection, len(expected)) == expected, f"session {identifier}: upload corrupted or crossed"
        fragmented_send(connection, expected[::-1] + marker, 8191)
        if identifier % CONNECTIONS == 0:
            assert exact(connection, 8) == b"finished", "client completion marker changed"
            connection.sendall(b"ack")
            assert connection.recv(1) == b"", "backend did not observe client-first EOF"
        # Other sessions close immediately after queuing their whole response.
        return identifier


def application(connection, identifier):
    with connection:
        connection.settimeout(15)
        marker = identifier.to_bytes(4, "big")
        fragmented_send(connection, marker, 1)
        assert exact(connection, 9) == b"ready" + marker, "response reached the wrong paired application"
        payload = body(identifier)
        fragmented_send(connection, payload, 10007)
        assert exact(connection, len(payload) + 4) == payload[::-1] + marker, \
            f"session {identifier}: download corrupted, truncated or crossed"
        if identifier % CONNECTIONS == 0:
            connection.sendall(b"finished")
            assert exact(connection, 3) == b"ack", "client completion acknowledgement changed"
            connection.shutdown(socket.SHUT_RDWR)
        else:
            assert connection.recv(1) == b"", "complete response was not followed by server-first EOF"


def connect(process):
    return connect_when_ready(process, (HOST, APP_PORT), deadline=time.monotonic() + 10,
        failure=lambda: AssertionError("paired HalfDuplex runtime exited before application connection"))


def run(binary, carrier, upload):
    with RunDirectory(f"waterwall-halfduplex-pair-{carrier}-{upload}-") as root:
        for name in ("server.crt", "server.key"):
            shutil.copyfile(CERTIFICATES / name, root / name)
        (root / "config.json").write_text(json.dumps({"name": "halfduplex-pair", "nodes": topology(carrier, upload)}))
        (root / "core.json").write_text(json.dumps(core_config(workers=4, ram_profile="minimal", splice=True)))
        with socket.socket() as backend:
            configure_listener(backend, (HOST, BACKEND_PORT), timeout=15)
            with Process([binary], cwd=root, log_path=root / "stdout.log") as process:
                for batch in range(2):
                    identifiers = set(range(batch * CONNECTIONS, (batch + 1) * CONNECTIONS))
                    with concurrent.futures.ThreadPoolExecutor(max_workers=CONNECTIONS * 2) as executor, \
                            contextlib.ExitStack() as sockets:
                        clients = [sockets.enter_context(connect(process)) for _ in identifiers]
                        applications = [executor.submit(application, connection, identifier)
                                        for connection, identifier in zip(clients, sorted(identifiers))]
                        services = [executor.submit(service, sockets.enter_context(backend.accept()[0]), identifiers)
                                    for _ in identifiers]
                        for task in applications:
                            task.result(timeout=20)
                        assert {task.result(timeout=20) for task in services} == identifiers, \
                            "backend sessions were duplicated or missing"
                    process.check_running("paired HalfDuplex runtime failed after session retirement")

                # Leave an established pair alive when the runtime drains owners.
                with connect(process) as client:
                    client.settimeout(10)
                    client.sendall(b"live")
                    with backend.accept()[0] as peer:
                        peer.settimeout(10)
                        assert exact(peer, 4) == b"live"
                        peer.sendall(b"ready")
                        assert exact(client, 5) == b"ready"
                        process.send_signal(signal.SIGTERM)
                        assert process.wait(timeout=10) == 128 + signal.SIGTERM, "paired runtime shutdown failed"
                        assert client.recv(1) == b"", "application owner survived shutdown"
                        assert peer.recv(1) == b"", "backend owner survived shutdown"
    print(f"HalfDuplex pair {carrier}, {upload} upload: concurrent binary streams, both EOF directions and shutdown passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("carrier", choices=("kcp", "quic"))
    parser.add_argument("upload", choices=("tls", "udp"))
    args = parser.parse_args()
    install_termination_handler()
    run(str(Path(args.binary).resolve()), args.carrier, args.upload)
