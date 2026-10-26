#!/usr/bin/env python3
"""Exercise VmessClient against pinned VMess peers and WaterWall in private netns.

The registered functional matrix checks exact TCP bytes, server-first bootstrap,
UDP boundaries, selectable body framing, destinations, existing TLS/WebSocket
composition, authenticated-response corruption, managed admission and credential
rotation. Peers and certificates are local; provision references before entering the
namespace. Native tests own deterministic callback, nonce and budget boundaries.
"""

import argparse
import concurrent.futures
import contextlib
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import subprocess
import sys
import threading
import uuid
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parent / "support" / "python")))
from vmess_reference import command as reference_command, environment as reference_environment, validate_reference, write_reference, packetaddr_payload_size
from vmess_reference import check_udp_size_probe, receive_udp_size_probe
from wwtest.config import core_config
from wwtest.process import Process, close_on_error, install_termination_handler
from wwtest.run_directory import RunDirectory
from wwtest.sockets import configure_listener, connect_when_ready, exact


TESTS = Path(__file__).resolve().parent
HOST = "127.0.0.1"
APP_PORT, WIRE_PORT, TARGET_PORT, RELAY_PORT, API_PORT, NEW_PORT = range(29941, 29947)
UUID = "5783a3e7-e373-51cd-8642-c83782b807c5"
SHORT_ID = "waterwall-maturity"
SHORT_UUID = str(uuid.uuid5(uuid.UUID(int=0), SHORT_ID))
LONG_RECORDS = 65540
ROTATED_UUID = "6783a3e7-e373-51cd-8642-c83782b807c5"
TOKEN = "0123456789abcdef" * 4
REJECT = ("wrong_uuid", "disabled", "expired", "quota")
STRATEGIES = (
    "do-not-resolve-domains", "resolve-domains-and-accept-dns-returned-order",
    "resolve-domains-and-prefer-ipv4", "resolve-domains-and-prefer-ipv6",
    "resolve-domains-and-use-only-ipv4", "resolve-domains-and-use-only-ipv6",
    "resolve-domains-with-core-settings",
)


def wait_log(process, path, marker, timeout=10):
    deadline = time.monotonic() + timeout
    while marker not in path.read_text(errors="replace"):
        process.check_running(f"process exited while waiting for {marker}")
        if time.monotonic() >= deadline:
            raise TimeoutError(f"did not observe {marker}")
        time.sleep(0.02)


def node(name, kind, settings, next_node=None):
    result = {"name": name, "type": kind, "settings": settings}
    if next_node is not None:
        result["next"] = next_node
    return result


def target_address(args):
    return {"ipv4": HOST, "ipv6": "::1", "domain": "localhost"}[args.target]


def inputs(root, args):
    nodes = []
    credential = SHORT_UUID if args.short_id else UUID
    if args.peer == "waterwall" and args.auth == "database":
        auth = json.loads((TESTS / "cases/vless_auth_tcp_loopback/config.json").read_text())["nodes"][:2]
        auth[0]["settings"].update({"pull-interval-ms": 100, "ping-interval-ms": 100})
        nodes.extend(auth)
        user = {"id": 2001, "name": "vmess-user", "password": credential, "enabled": True}
        if args.scenario == "disabled":
            user["enabled"] = False
        elif args.scenario == "expired":
            user["time"] = {"expire-at-ms": 1}
        elif args.scenario == "quota":
            user["limit"] = {"traffic": {"total": 1}}
            user["stats"] = {"traffic": {"up": 1}}
        (root / "users.json").write_text(json.dumps({"users": [user]}))
    if args.scenario in ("rotation", "stats"):
        allowed = ([{"config": "vmess-client-interop", "node": name, "operations": ["stats"]}
                    for name in ("vmess-client", "vmess-server")] if args.scenario == "stats" else [
            {"config": "vmess-client-interop", "node": "auth-db",
             "operations": ["get-user", "change-user-password"]},
            {"config": "vmess-client-interop", "node": "auth-client", "operations": ["status"]},
        ])
        nodes.extend([
            node("admin-listener", "TcpListener", {"address": HOST, "port": API_PORT}, "admin"),
            node("admin", "APIServer", {"clients": [{"name": "admin", "token": TOKEN, "allow": allowed}]}),
        ])
    wire_port = RELAY_PORT if args.scenario in ("split", "tamper", "long", "strict") else WIRE_PORT
    entry = "wire-connector"
    nodes.append(node(entry, "TcpConnector", {"address": HOST, "port": wire_port,
                                               "nodelay": True, "fastopen": False}))
    if args.transport in ("tls", "wss"):
        nodes.append(node("tls-client", "TlsClient", {"sni": "tls.integration.test", "verify": False,
                                                        "alpns": ["http/1.1"]}, entry))
        entry = "tls-client"
    if args.transport in ("ws", "wss"):
        nodes.append(node("websocket-client", "HttpClient", {"http-version": 1, "websocket": True,
                                                               "host": "vmess.integration.test",
                                                               "path": "/vmess"}, entry))
        entry = "websocket-client"
    settings = {"uuid": ROTATED_UUID if args.scenario == "wrong_uuid" else (SHORT_ID if args.short_id else UUID),
                "address": target_address(args), "port": TARGET_PORT, "protocol": args.protocol,
                "security": args.cipher, "domain-strategy": args.dns, "first-payload-timeout-ms": 40,
                "encrypted-counter-policy": args.counter_policy,
                "send-termination": args.send_termination == "true", "packet-encoding": args.packet_encoding}
    if args.destination == "context":
        settings.update({"address": "dest_context->address", "port": "dest_context->port",
                         "protocol": "dest_context->protocol"})
    if args.options is not None:
        settings.update({"chunk-masking": bool(args.options & 4), "global-padding": bool(args.options & 8),
                         "authenticated-length": bool(args.options & 16)})
    nodes.append(node("vmess-client", "VmessClient", settings, entry))
    if args.destination == "context":
        nodes.append(node("application", "Socks5Server", {"no-auth": True, "connect": True,
                                                           "udp": args.protocol == "udp", "ipv4": HOST},
                          "vmess-client"))
        nodes.append(node("application-listener", "TcpUdpListener" if args.protocol == "udp" else "TcpListener",
                          {"address": HOST, "port": APP_PORT, "nodelay": True}, "application"))
    else:
        nodes.append(node("application-listener", "UdpListener" if args.protocol == "udp" else "TcpListener",
                          {"address": HOST, "port": APP_PORT}, "vmess-client"))
    if args.scenario == "rotation":
        nodes.extend([
            node("wire-new", "TcpConnector", {"address": HOST, "port": WIRE_PORT, "nodelay": True,
                                               "fastopen": False}),
            node("vmess-new", "VmessClient", {**settings, "uuid": ROTATED_UUID}, "wire-new"),
            node("application-new", "TcpListener", {"address": HOST, "port": NEW_PORT}, "vmess-new"),
        ])
    if args.peer == "waterwall":
        server_settings = {"uuid": credential, "connect": True, "udp": True, "handshake-timeout-ms": 3000}
        if args.auth == "database":
            server_settings.pop("uuid")
            server_settings["auth-client-node-name"] = "auth-client"
        nodes.append(node("vmess-server", "VmessServer", server_settings, "target-connector"))
        nodes.append(node("target-connector", "UdpConnector" if args.protocol == "udp" else "TcpConnector",
                          {"address": "dest_context->address", "port": "dest_context->port",
                           "domain-strategy": "only-ipv4"}))
        server_entry = "vmess-server"
        if args.transport in ("ws", "wss"):
            nodes.append(node("websocket-server", "HttpServer", {"http-version": "1.1", "websocket": True,
                                                                   "status": 200, "host": "vmess.integration.test",
                                                                   "path": "/vmess"}, server_entry))
            server_entry = "websocket-server"
        if args.transport in ("tls", "wss"):
            nodes.append(node("tls-server", "TlsServer", {"cert-file": "server.crt", "key-file": "server.key",
                                                           "handshake-timeout-ms": 3000}, server_entry))
            server_entry = "tls-server"
        nodes.append(node("wire-listener", "TcpListener", {"address": HOST, "port": WIRE_PORT,
                                                           "nodelay": True}, server_entry))
    if args.transport in ("tls", "wss"):
        for name in ("server.crt", "server.key"):
            shutil.copyfile(TESTS / "speedtests/_shared" / name, root / name)
    (root / "core.json").write_text(json.dumps(core_config(workers=args.workers, splice=True)))
    (root / "config.json").write_text(json.dumps({"name": "vmess-client-interop", "nodes": nodes}))
    stream = {"network": "ws" if args.transport in ("ws", "wss") else "tcp", "security": "none"}
    if args.transport in ("ws", "wss"):
        stream["wsSettings"] = {"path": "/vmess"}
    if args.transport in ("tls", "wss"):
        stream.update({"security": "tls", "tlsSettings": {"alpn": ["http/1.1"], "certificates": [
            {"certificateFile": str(root / "server.crt"), "keyFile": str(root / "server.key")}]}})
    reference = {"log": {"loglevel": "debug"}, "inbounds": [{"listen": HOST, "port": WIRE_PORT,
        "protocol": "vmess", "settings": {"clients": [{"id": credential, "alterId": 0}],
                                               "disableInsecureEncryption": False}, "streamSettings": stream}],
        "outbounds": [{"protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}}]}
    write_reference(root, args.reference_kind, reference, server=True)


class Backend:
    """Accept localhost on either family without depending on DNS answer order."""

    def __init__(self, protocol):
        self.protocol = protocol

    def __enter__(self):
        self.sockets = []
        try:
            for family, host in ((socket.AF_INET, HOST), (socket.AF_INET6, "::1")):
                sock = socket.socket(family, socket.SOCK_DGRAM if self.protocol == "udp" else socket.SOCK_STREAM)
                self.sockets.append(sock)
                if family == socket.AF_INET6:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                if self.protocol == "udp":
                    sock.bind((host, TARGET_PORT))
                else:
                    configure_listener(sock, (host, TARGET_PORT), timeout=15)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def ready(self, timeout=15):
        ready = select.select(self.sockets, [], [], timeout)[0]
        if not ready:
            raise TimeoutError("backend was not contacted")
        return ready[0]

    def accept(self):
        peer, _ = self.ready().accept()
        peer.settimeout(15)
        return peer

    def assert_uncontacted(self):
        assert not select.select(self.sockets, [], [], 0.3)[0], "rejected UUID/account contacted target"

    def __exit__(self, *_):
        for sock in self.sockets:
            sock.close()


class ResponseRelay:
    """Fragment response bytes or corrupt its authenticated length before delivery."""

    def __init__(self, scenario):
        self.scenario = scenario
        self.accepted = 0

    def __enter__(self):
        self.listener = socket.socket()
        configure_listener(self.listener, (HOST, RELAY_PORT), timeout=15)
        self.connections, self.errors = [], []
        self.changed = False
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run)
        self.thread.start()
        return self

    def forward(self, source, target, response):
        try:
            first = True
            while not self.stop.is_set():
                data = source.recv(65536)
                if not data:
                    with contextlib.suppress(OSError):
                        target.shutdown(socket.SHUT_WR)
                    return
                if response and first and self.scenario in ("split", "tamper"):
                    first = False
                    if self.scenario == "tamper":
                        data = bytes([data[0] ^ 1]) + data[1:]
                    else:
                        for byte in data[:64]:
                            target.sendall(bytes([byte]))
                            time.sleep(0.001)
                        data = data[64:]
                    self.changed = True
                if data:
                    target.sendall(data)
        except (ConnectionResetError, BrokenPipeError):
            return
        except BaseException as error:
            if not self.stop.is_set():
                self.errors.append(error)

    def run(self):
        try:
            with self.listener.accept()[0] as client, socket.create_connection((HOST, WIRE_PORT), timeout=15) as server:
                self.accepted += 1
                self.connections = [client, server]
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                    jobs = [executor.submit(self.forward, client, server, False),
                            executor.submit(self.forward, server, client, True)]
                    for job in jobs:
                        job.result(timeout=75)
        except BaseException as error:
            if not self.stop.is_set():
                self.errors.append(error)

    def __exit__(self, exc_type, *_):
        self.stop.set()
        for sock in self.connections:
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
        self.listener.close()
        self.thread.join(timeout=17)
        assert not self.thread.is_alive(), "response relay did not stop"
        if exc_type is None:
            if self.scenario in ("split", "tamper"):
                assert self.changed, "response manipulation never occurred"
            assert not self.errors, self.errors


def application(process, args, port=APP_PORT):
    sock = connect_when_ready(process, (HOST, port), deadline=time.monotonic() + 10,
                              failure=lambda: AssertionError("WaterWall exited before application readiness"), timeout=10)
    if args.destination != "context":
        return sock, None
    try:
        sock.sendall(b"\x05\x01\x00")
        assert exact(sock, 2) == b"\x05\x00", "SOCKS negotiation failed"
        address = target_address(args)
        if args.target == "domain":
            encoded = address.encode("ascii")
            target = b"\x03" + bytes([len(encoded)]) + encoded
        elif args.target == "ipv6":
            target = b"\x04" + socket.inet_pton(socket.AF_INET6, address)
        else:
            target = b"\x01" + socket.inet_aton(address)
        if args.protocol == "udp":
            request = b"\x05\x03\x00\x01" + bytes(6)
        else:
            request = b"\x05\x01\x00" + target + TARGET_PORT.to_bytes(2, "big")
        sock.sendall(request)
        response = exact(sock, 4)
        assert response[:3] == b"\x05\x00\x00", f"SOCKS CONNECT/ASSOCIATE failed: {response.hex()}"
        assert response[3] in (1, 4), "unexpected SOCKS bound address type"
        exact(sock, 4 if response[3] == 1 else 16)
        bound_port = int.from_bytes(exact(sock, 2), "big")
        return sock, (bound_port, b"\x00\x00\x00" + target + TARGET_PORT.to_bytes(2, "big"))
    except BaseException:
        sock.close()
        raise


def expect_eof(sock):
    try:
        assert sock.recv(1) == b"", "closed/rejected connection delivered application bytes"
    except ConnectionResetError:
        pass


def stop_waterwall(process):
    process.send_signal(signal.SIGTERM)
    assert process.wait(timeout=10) == 128 + signal.SIGTERM, "WaterWall orderly shutdown failed"


def admin(root, node_name, arguments, *, stdin=None):
    environment = os.environ.copy()
    environment["WW_VMESS_TEST_ADMIN_TOKEN"] = TOKEN
    result = subprocess.run([sys.executable, str(TESTS.parent / "tunnels/APIServer/client/ww_admin.py"),
        "--host", HOST, "--port", str(API_PORT), "--timeout", "5", "--client", "admin",
        "--token-env", "WW_VMESS_TEST_ADMIN_TOKEN", "--config", "vmess-client-interop", "--node", node_name,
        *arguments], input=stdin, capture_output=True, timeout=8, cwd=root, env=environment)
    assert result.returncode == 0, f"admin operation failed: {result.stderr.decode(errors='replace')}"
    return json.loads(result.stdout)


def rotate(root, args, waterwall, backend):
    sys.path.insert(0, str(TESTS.parent / "tunnels/APIServer/client"))
    from ww_api import call, decode_result

    with application(waterwall, args)[0] as old, backend.accept() as target:
        old.sendall(b"before-rotation")
        assert exact(target, 15) == b"before-rotation"
        target.sendall(b"accepted")
        assert exact(old, 8) == b"accepted"
    current = admin(root, "auth-db", ["users", "get", "2001"])
    updated = admin(root, "auth-db", ["users", "change-password", "2001", "--if-match", current["edit_token"],
                                     "--password-stdin"], stdin=ROTATED_UUID.encode())
    deadline = time.monotonic() + 10
    while True:
        response = call(HOST, API_PORT, {"id": "refresh", "auth": {"client": "admin", "token": TOKEN},
            "selector": {"config": "vmess-client-interop", "node": "auth-client"}, "operation": "status",
            "content_type": "application/json", "body_encoding": "utf8", "body": "{}"}, timeout=5)
        assert response["error"] is None and response["result"]["code"] == 0, "client status query failed"
        if int(json.loads(decode_result(response["result"]))["applied_config_revision"]) >= int(updated["config_revision"]):
            break
        waterwall.check_running("WaterWall exited during credential refresh")
        if time.monotonic() >= deadline:
            raise TimeoutError("AuthenticationClient did not apply rotated credential revision")
        time.sleep(0.05)
    with application(waterwall, args)[0] as old:
        old.sendall(b"old-uuid-must-fail")
        expect_eof(old)
    backend.assert_uncontacted()
    with application(waterwall, args, NEW_PORT)[0] as new, backend.accept() as target:
        new.sendall(b"after-rotation")
        assert exact(target, 14) == b"after-rotation"
        target.sendall(b"accepted-new")
        assert exact(new, 12) == b"accepted-new"
        stop_waterwall(waterwall)
        expect_eof(new)
        expect_eof(target)


def tcp_case(root, args, waterwall, backend):
    if args.scenario == "rotation":
        rotate(root, args, waterwall, backend)
        return
    with application(waterwall, args)[0] as client:
        if args.scenario in REJECT:
            # The pinned server deliberately drains several kilobytes after
            # an invalid identity. Supply a bounded record so rejection can
            # finish without a peer timeout; stay below WaterWall's 64 KiB
            # unauthenticated-input admission limit.
            client.sendall(b"must-not-reach-target" + bytes(8192))
            expect_eof(client)
            backend.assert_uncontacted()
            stop_waterwall(waterwall)
            return
        if args.scenario in ("long", "strict"):
            long_case(args, client, waterwall, backend)
            return
        payload = bytes(range(256)) * 1024 + b"vmess-client-final"
        greeting = b"vmess-server-first"

        def target():
            with backend.accept() as peer:
                if args.scenario == "early_close":
                    return
                if args.scenario == "silent":
                    time.sleep(0.7)
                peer.sendall(greeting)
                if args.scenario == "tamper":
                    expect_eof(peer)
                    return
                assert exact(peer, len(payload)) == payload, "upstream TCP bytes changed"
                peer.sendall(payload[::-1])
                expect_eof(peer)

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor, close_on_error(client):
            result = executor.submit(target)
            if args.scenario in ("early_close", "tamper"):
                expect_eof(client)
            else:
                assert exact(client, len(greeting)) == greeting, "server-first bootstrap changed bytes"
                for offset in range(0, len(payload), 7919):
                    client.sendall(payload[offset:offset + 7919])
                assert exact(client, len(payload)) == payload[::-1], "downstream TCP bytes changed"
                if args.scenario == "stats":
                    stats_case(args)
            stop_waterwall(waterwall)
            expect_eof(client)
            result.result(timeout=10)


def stats_case(args):
    sys.path.insert(0, str(TESTS.parent / "tunnels/APIServer/client"))
    from ww_api import call, decode_result

    for name in ("vmess-client", "vmess-server"):
        envelope = {"id": "stats", "auth": {"client": "admin", "token": TOKEN},
                    "selector": {"config": "vmess-client-interop", "node": name},
                    "operation": "stats", "content_type": "application/json",
                    "body_encoding": "utf8", "body": "{}"}
        response = call(HOST, API_PORT, envelope, timeout=5)
        assert response["error"] is None and response["result"]["code"] == 0, response
        stats = json.loads(decode_result(response["result"]))
        if name == "vmess-client":
            assert stats["snapshot"] == "approximate"
            configuration = stats["configuration"]
            application_key, carrier_key = "active_applications", "active_carriers"
            extra_counters = ("tx_wraps", "rx_wraps")
        else:
            assert stats["approximate"] is True
            configuration = stats
            application_key, carrier_key = "applications", "carriers"
            extra_counters = ("wrap_events", "strict_exhaustion")
        assert configuration["encrypted_counter_policy"] == args.counter_policy
        assert configuration["send_termination"] == (args.send_termination == "true")
        for key in (application_key, carrier_key, "tx_records", "rx_records", "tx_application_bytes",
                    "rx_application_bytes", "tx_wire_bytes", "rx_wire_bytes", *extra_counters):
            value = stats[key]
            assert isinstance(value, str) and value.isascii() and value.isdecimal(), (key, value)
            assert int(value) <= (1 << 64) - 1, (key, value)
        assert int(stats[application_key]) >= 1, (name, application_key, stats[application_key])
        if name == "vmess-client":
            assert int(stats[carrier_key]) == 0, "direct TCP has no separate owned UDP carrier"
        else:
            assert int(stats[carrier_key]) >= 1, (name, carrier_key, stats[carrier_key])
        assert int(stats["tx_records"]) > 0 and int(stats["rx_records"]) > 0
        assert isinstance(stats["reasons"], dict) and stats["reasons"]
        serialized = json.dumps(stats)
        assert UUID not in serialized and SHORT_ID not in serialized, "stats exposed credential material"
        denied = call(HOST, API_PORT, {**envelope, "operation": "reset"}, timeout=5)
        assert denied["error"] is not None, "read-only stats grant admitted a mutation operation"


def long_case(args, client, waterwall, backend):
    # Each request waits for its echo, forcing distinct nonempty VMess records
    # in both directions. One accepted relay transport excludes reconnection.
    count = 65535 if args.scenario == "strict" else LONG_RECORDS
    started = time.monotonic()
    deadline = started + 65
    client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def target():
        with backend.accept() as peer:
            peer.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            for ordinal in range(count):
                payload = ordinal.to_bytes(4, "big")
                assert exact(peer, 4) == payload, f"long input changed at record {ordinal}"
                peer.sendall(payload)
            expect_eof(peer)

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor, close_on_error(client):
        result = executor.submit(target)
        for ordinal in range(count):
            payload = ordinal.to_bytes(4, "big")
            client.sendall(payload)
            assert exact(client, 4) == payload, f"long reply changed at record {ordinal}"
            now = time.monotonic()
            assert now < deadline, ("long session exceeded its fixed 65-second workload deadline "
                                    f"after {ordinal + 1}/{count} completed exchanges in {now - started:.3f}s")
        if args.scenario == "strict":
            with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                client.sendall(b"last")
            expect_eof(client)
        stop_waterwall(waterwall)
        result.result(timeout=10)
    print(f"Verified {count} stop-and-wait nonempty records each way on one transport", flush=True)


def udp_case(args, waterwall, backend, reference=None):
    control = contextlib.nullcontext()
    prefix = b""
    port = APP_PORT
    if args.destination == "context":
        control, (port, prefix) = application(waterwall, args)
    with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(10)
        if args.udp_size_probe:
            def exchange(payload):
                client.sendto(prefix + payload, (HOST, port))
                target = backend.ready()
                origin = receive_udp_size_probe(target, payload, "backend receive")
                target.sendto(payload[::-1], origin)
                receive_udp_size_probe(client, prefix + payload[::-1], "reply receive")

            check_udp_size_probe(args, exchange, waterwall, reference)
            stop_waterwall(waterwall)
            return
        payloads = [b"a", bytes(range(31)), bytes(range(256)) * 2, bytes(range(240)) * 5, b"last"]
        if args.packet_encoding == "packetaddr":
            large = packetaddr_payload_size(args)
            payloads += [b"", bytes(range(256)) * (large // 256) + bytes(range(large % 256))]
        for payload in payloads:
            client.sendto(prefix + payload, (HOST, port))
            target = backend.ready()
            received, origin = target.recvfrom(65535)
            assert received == payload, f"upstream UDP boundary changed: expected {len(payload)} bytes, received {len(received)} bytes"
            target.sendto(received[::-1], origin)
            received, _ = client.recvfrom(65535)
            assert received == prefix + payload[::-1], "downstream UDP boundary/content changed"
        stop_waterwall(waterwall)


def run(args):
    if args.udp_size_probe and args.protocol != "udp":
        raise ValueError("UDP size probes require --protocol udp")
    if args.peer == "reference":
        validate_reference(args.reference, args.reference_kind)
    with RunDirectory("waterwall-vmess-client-interop-") as directory:
        root = Path(directory)
        inputs(root, args)
        with Backend(args.protocol) as backend:
            peer = (Process(reference_command(args.reference, root), cwd=root,
                            log_path=root / "v2ray.log", env=reference_environment(args.reference_kind)) if args.peer == "reference" else contextlib.nullcontext())
            relay = ResponseRelay(args.scenario) if args.scenario in ("split", "tamper", "long", "strict") else contextlib.nullcontext()
            with peer as reference, relay:
                if reference is not None:
                    wait_log(reference, root / "v2ray.log", "started")
                with Process([str(args.waterwall)], cwd=root, log_path=root / "waterwall.log") as waterwall:
                    wait_log(waterwall, root / "waterwall.log", "Core: starting workers ...")
                    if args.peer == "waterwall" and args.auth == "database":
                        wait_log(waterwall, root / "waterwall.log", "AuthenticationClient: pulled 1 users")
                    if args.protocol == "tcp":
                        tcp_case(root, args, waterwall, backend)
                    else:
                        wait_log(waterwall, root / "waterwall.log", f"127.0.0.1:[{APP_PORT}] (UDP)")
                        udp_case(args, waterwall, backend, reference)
                    if args.scenario in ("long", "strict"):
                        assert relay.accepted == 1, "long session reconnected its transport"
    print(f"VmessClient {args.peer}/{args.auth}/{args.cipher}/{args.protocol}/{args.transport}/"
          f"{args.target}/{args.destination}/{args.scenario}/options={args.options} passed")


if __name__ == "__main__":
    install_termination_handler()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("waterwall", type=lambda value: Path(value).resolve())
    parser.add_argument("reference", type=lambda value: Path(value).resolve())
    parser.add_argument("--peer", choices=("reference", "waterwall"), default="reference")
    parser.add_argument("--auth", choices=("local", "database"), default="local")
    parser.add_argument("--cipher", choices=("aes-128-gcm", "chacha20-poly1305", "none", "zero", "auto"), default="aes-128-gcm")
    parser.add_argument("--protocol", choices=("tcp", "udp"), default="tcp")
    parser.add_argument("--udp-size-probe", choices=("supported", "limited"))
    parser.add_argument("--options", type=int, choices=(0, 1, 5, 13, 17, 21, 29))
    parser.add_argument("--transport", choices=("tcp", "tls", "ws", "wss"), default="tcp")
    parser.add_argument("--target", choices=("ipv4", "ipv6", "domain"), default="ipv4")
    parser.add_argument("--destination", choices=("fixed", "context"), default="fixed")
    parser.add_argument("--dns", choices=STRATEGIES, default=STRATEGIES[0])
    parser.add_argument("--scenario", choices=("roundtrip", "split", "tamper", "early_close", "silent", "rotation", "stats", "long", "strict", *REJECT),
                        default="roundtrip")
    parser.add_argument("--reference-kind", choices=("v2ray", "xray", "sing-box"), default="v2ray")
    parser.add_argument("--counter-policy", choices=("wrap", "strict"), default="wrap")
    parser.add_argument("--send-termination", choices=("true", "false"), default="true")
    parser.add_argument("--short-id", action="store_true")
    parser.add_argument("--packet-encoding", choices=("none", "packetaddr"), default="none")
    parser.add_argument("--workers", type=int, choices=(1, 2), default=1)
    sys.exit(run(parser.parse_args()))
