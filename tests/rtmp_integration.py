#!/usr/bin/env python3
"""Exercise RTMP tunnel pairs in a private loopback network."""

import concurrent.futures
import json
import os
from pathlib import Path
import random
import shutil
import signal
import socket
import sys
import time

sys.dont_write_bytecode = True
TESTS = Path(__file__).resolve().parent
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR", str(TESTS / "support" / "python")))
from wwtest.config import core_config
from wwtest.process import Process, close_on_error, install_termination_handler
from wwtest.run_directory import RunDirectory
from wwtest.sockets import configure_listener, connect_when_ready, exact


HOST = "127.0.0.1"
APP_PORT, WIRE_PORT, SERVICE_PORT = 29861, 29862, 29863
BANNER = b"\x00\xff@setDataFrame\xfe\x01server first\x00"
SOCKET_TIMEOUT = 15


def node(name, kind, settings=None, next_node=None):
    entry = {"name": name, "type": kind, "settings": settings or {}}
    if next_node is not None:
        entry["next"] = next_node
    return entry


def tcp(port):
    return {"address": HOST, "port": port, "nodelay": True}


def write_inputs(root, mode):
    tls = mode == "tls_bidirectional_tcp_loopback"
    udp = mode == "udp_over_tcp_roundtrip"
    scheme = "rtmps" if tls else "rtmp"
    server = {"payload-block-size": 65536}
    if mode == "negotiation_timeout":
        server["handshake-timeout-ms"] = 1000

    app_next, server_next = "rtmp-client", "service"
    service = {"address": HOST, "port": SERVICE_PORT} if udp else {**tcp(SERVICE_PORT), "fastopen": False}
    application_nodes = []
    if udp:
        app_next, server_next = "uot-client", "uot-server"
        application_nodes = [node(app_next, "UdpOverTcpClient", next_node="rtmp-client"),
                             node(server_next, "UdpOverTcpServer", next_node="service")]
    elif mode == "vless_tcp_loopback":
        app_next, server_next = "vless-client", "vless-server"
        uuid = "c83a79ce-a225-4419-99c4-ba56f002bf64"
        application_nodes = [
            node(app_next, "VlessClient", {"uuid": uuid, "address": HOST, "port": SERVICE_PORT,
                                           "protocol": "tcp"}, "rtmp-client"),
            node(server_next, "VlessServer", {"uuid": uuid, "connect": True, "udp": False}, "service"),
        ]
        service = {"address": "dest_context->address", "port": "dest_context->port", "fastopen": False}

    nodes = [
        node("application", "UdpListener" if udp else "TcpListener",
             {"address": HOST, "port": APP_PORT} if udp else tcp(APP_PORT), app_next),
        node("rtmp-client", "RtmpClient", {"tc-url": f"{scheme}://{HOST}:{WIRE_PORT}/waterwall"},
             "tls-client" if tls else "carrier-out"),
        node("carrier-out", "TcpConnector", {**tcp(WIRE_PORT), "fastopen": False}),
        node("carrier-in", "TcpListener", tcp(WIRE_PORT), "tls-server" if tls else "rtmp-server"),
        node("rtmp-server", "RtmpServer", server, server_next),
        node("service", "UdpConnector" if udp else "TcpConnector", service),
        *application_nodes,
    ]
    if tls:
        for filename in ("server.crt", "server.key"):
            shutil.copyfile(TESTS / "speedtests" / "_shared" / filename, root / filename)
        nodes += [
            node("tls-client", "TlsClient", {"sni": "tls.integration.test", "verify": False}, "carrier-out"),
            node("tls-server", "TlsServer", {"cert-file": "server.crt", "key-file": "server.key",
                                             "sni": "tls.integration.test"}, "rtmp-server"),
        ]
    (root / "core.json").write_text(json.dumps(core_config(workers=2, splice=True)))
    (root / "config.json").write_text(json.dumps({"name": "rtmp-integration", "nodes": nodes}))


def connect(process, port):
    connection = connect_when_ready(process, (HOST, port), deadline=time.monotonic() + 8,
                                    failure=lambda: AssertionError("WaterWall exited before connection"))
    connection.settimeout(SOCKET_TIMEOUT)
    return connection


def stop(process):
    process.send_signal(signal.SIGTERM)
    assert process.wait(timeout=10) == 128 + signal.SIGTERM, "RTMP shutdown failed"


def send_blocks(connection, payload, block_size):
    for offset in range(0, len(payload), block_size):
        connection.sendall(payload[offset:offset + block_size])


def duplex(process, client, service):
    upload = bytes(range(256)) + random.Random(0x1935).randbytes((1024 * 1024) + 7)
    download = BANNER + random.Random(0x1936).randbytes((1024 * 1024) + 41)
    # Queue accepts while the client is still negotiating. The server sends
    # a banner immediately on backend acceptance, before reading any request.
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor, close_on_error(client):
        sending_up = executor.submit(send_blocks, client, upload, 10007)
        with service.accept()[0] as backend, close_on_error(backend):
            backend.settimeout(SOCKET_TIMEOUT)
            backend.sendall(BANNER)
            sending_down = executor.submit(send_blocks, backend, download[len(BANNER):], 7919)
            receiving_up = executor.submit(exact, backend, len(upload))
            assert exact(client, len(download)) == download, "reverse RTMP data changed"
            assert receiving_up.result(timeout=SOCKET_TIMEOUT) == upload, "forward RTMP data changed"
            sending_up.result(timeout=SOCKET_TIMEOUT)
            sending_down.result(timeout=SOCKET_TIMEOUT)
            stop(process)


def udpover_tcp(process, service):
    payloads = [random.Random(0x1939 + size).randbytes(size) for size in (1, 61, 63, 64, 511, 1200)]
    # The test runs in a Linux network namespace. Wait for the actual UDP bind
    # before sending so lost startup probes cannot be mistaken for datagram loss.
    port_field = f":{APP_PORT:04X}"
    deadline = time.monotonic() + 8
    while not any(line.split()[1].endswith(port_field) for line in Path("/proc/net/udp").read_text().splitlines()[1:]):
        process.check_running("WaterWall exited before UDP listener bound")
        assert time.monotonic() < deadline, "UDP listener did not bind"
        time.sleep(0.02)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.connect((HOST, APP_PORT))
        client.settimeout(SOCKET_TIMEOUT)
        for payload in payloads:
            client.send(payload)
            observed, address = service.recvfrom(65535)
            assert observed == payload, "UDP payload or boundary changed"
            service.sendto(payload[::-1], address)
            assert client.recv(65535) == payload[::-1], "reverse UDP datagram changed"


def timeout(process, backend):
    with connect(process, WIRE_PORT) as wire:
        started = time.monotonic()
        wire.sendall(b"\x03\x00")
        wire.settimeout(4)
        assert wire.recv(1) == b"", "partial handshake did not expire"
        assert time.monotonic() - started >= 0.4, "handshake ended without waiting for its deadline"
    backend.setblocking(False)
    try:
        unexpected, _ = backend.accept()
    except BlockingIOError:
        pass
    else:
        unexpected.close()
        raise AssertionError("backend initialized without publication")
    # Leave a second incomplete handshake live when the runtime quiesces.
    with connect(process, WIRE_PORT) as wire:
        wire.sendall(b"\x03" + bytes(1536))
        assert exact(wire, 3073)[0] == 3, "second handshake did not start"
        stop(process)


def run(binary, mode):
    with RunDirectory(f"waterwall-rtmp-{mode}-") as root:
        write_inputs(root, mode)
        if mode == "udp_over_tcp_roundtrip":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as service:
                service.bind((HOST, SERVICE_PORT))
                service.settimeout(SOCKET_TIMEOUT)
                with Process([binary], cwd=root, log_path=root / "stdout.log") as process:
                    udpover_tcp(process, service)
                    stop(process)
            return
        with socket.socket() as service:
            configure_listener(service, (HOST, SERVICE_PORT), timeout=SOCKET_TIMEOUT)
            with Process([binary], cwd=root, log_path=root / "stdout.log") as process:
                if mode == "negotiation_timeout":
                    timeout(process, service)
                    return
                with connect(process, APP_PORT) as client:
                    duplex(process, client, service)


if __name__ == "__main__":
    install_termination_handler()
    run(sys.argv[1], sys.argv[2])
