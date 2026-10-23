#!/usr/bin/env python3
"""Pinned V2Ray client interoperability against the real WaterWall VMess server.

The CTest vmess family runs this inside the existing loopback-only namespace.
Each invocation owns its WaterWall/V2Ray children, generated inputs, TCP or UDP
peer and optional splitting relay. It verifies exact bidirectional application
data, authentication mode, transport composition and orderly server shutdown.
Provision V2Ray explicitly with provision_vmess_reference.py before running.
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
import subprocess
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
SOCKS_PORT, WIRE_PORT, TARGET_PORT, RELAY_PORT = 29931, 29932, 29933, 29934
UUID = "5783a3e7-e373-51cd-8642-c83782b807c5"
WRONG_UUID = "6783a3e7-e373-51cd-8642-c83782b807c5"


def wait_log(process, path, marker, timeout=10):
    deadline = time.monotonic() + timeout
    while marker not in path.read_text(errors="replace"):
        process.check_running(f"process exited while waiting for {marker}")
        if time.monotonic() >= deadline:
            raise TimeoutError(f"did not observe {marker}")
        time.sleep(0.02)


def inputs(root, args):
    settings = {"uuid": UUID, "connect": True, "udp": True, "handshake-timeout-ms": 3000}
    nodes = []
    if args.auth == "database":
        settings.pop("uuid")
        settings["auth-client-node-name"] = "auth-client"
        auth = json.loads((TESTS / "cases/vless_auth_tcp_loopback/config.json").read_text())["nodes"][:2]
        nodes.extend(auth)
        user = {"id": 2001, "name": "vmess-user", "password": UUID, "enabled": True}
        if args.scenario == "connection_limit":
            user["limit"] = {"connections-out": 1}
        (root / "users.json").write_text(json.dumps({"users": [user]}))
    entry = "vmess"
    if args.transport in ("ws", "wss"):
        nodes.append({"name": "websocket", "type": "HttpServer", "next": entry,
                      "settings": {"http-version": "1.1", "websocket": True, "status": 200,
                                   "host": "vmess.integration.test", "path": "/vmess"}})
        entry = "websocket"
    if args.transport in ("tls", "wss"):
        for name in ("server.crt", "server.key"):
            shutil.copyfile(TESTS / "speedtests/_shared" / name, root / name)
        nodes.append({"name": "tls", "type": "TlsServer", "next": entry,
                      "settings": {"cert-file": "server.crt", "key-file": "server.key",
                                   "handshake-timeout-ms": 3000}})
        entry = "tls"
    nodes.append({"name": "listener", "type": "TcpListener", "next": entry,
                  "settings": {"address": HOST, "port": WIRE_PORT, "nodelay": True}})
    if args.scenario in ("fallback", "tamper"):
        settings.update({"fallback-node-name": "fallback", "fallback-intentional-delay-ms": 7,
                         "fallback-intentional-delay-jitter-ms": 1})
        nodes.append({"name": "fallback", "type": "TcpConnector",
                      "settings": {"address": HOST, "port": TARGET_PORT, "fastopen": False}})
    nodes.extend([
        {"name": "vmess", "type": "VmessServer", "settings": settings, "next": "outbound"},
        {"name": "outbound", "type": "UdpConnector" if args.protocol == "udp" else "TcpConnector",
         "settings": {"address": "dest_context->address", "port": "dest_context->port"}},
    ])
    (root / "core.json").write_text(json.dumps(core_config(workers=args.workers, splice=True)))
    (root / "config.json").write_text(json.dumps({"name": "vmess-interop", "nodes": nodes}))
    stream = {"network": "ws" if args.transport in ("ws", "wss") else "tcp", "security": "none"}
    if args.transport in ("ws", "wss"):
        stream["wsSettings"] = {"path": "/vmess", "headers": {"Host": "vmess.integration.test"}}
    if args.transport in ("tls", "wss"):
        # This fixture tests VMess transport composition; certificate validation
        # has separate TLS tests. The peer still connects only to loopback.
        stream.update({"security": "tls", "tlsSettings": {
            "serverName": "tls.integration.test", "allowInsecure": True}})
    reference = {
        "log": {"loglevel": "debug"},
        "inbounds": [{"listen": HOST, "port": SOCKS_PORT, "protocol": "socks",
                      "settings": {"auth": "noauth", "udp": True, "ip": HOST}}],
        "outbounds": [{"protocol": "vmess", "streamSettings": stream,
                       "settings": {"vnext": [{"address": HOST,
                           "port": RELAY_PORT if args.scenario in ("split", "tamper") else WIRE_PORT,
                           "users": [{"id": WRONG_UUID if args.scenario == "wrong_uuid" else UUID,
                                      "alterId": 0, "security": args.cipher}]}]}}],
    }
    (root / "v2ray.json").write_text(json.dumps(reference))


def socks_request(process, udp=False):
    sock = connect_when_ready(process, (HOST, SOCKS_PORT), deadline=time.monotonic() + 10,
                              failure=lambda: AssertionError("V2Ray exited before SOCKS readiness"), timeout=10)
    try:
        sock.sendall(b"\x05\x01\x00")
        assert exact(sock, 2) == b"\x05\x00", "SOCKS authentication failed"
        address = socket.inet_aton("0.0.0.0" if udp else HOST)
        port = 0 if udp else TARGET_PORT
        sock.sendall(bytes([5, 3 if udp else 1, 0, 1]) + address + port.to_bytes(2, "big"))
        header = exact(sock, 4)
        assert header[:3] == b"\x05\x00\x00", f"SOCKS request failed: {header.hex()}"
        if header[3] == 1:
            bound = socket.inet_ntoa(exact(sock, 4))
        elif header[3] == 4:
            bound = socket.inet_ntop(socket.AF_INET6, exact(sock, 16))
        elif header[3] == 3:
            bound = exact(sock, exact(sock, 1)[0]).decode("ascii")
        else:
            raise AssertionError("invalid SOCKS bound address")
        bound_port = int.from_bytes(exact(sock, 2), "big")
        return sock, (HOST if bound == "0.0.0.0" else bound, bound_port)
    except BaseException:
        sock.close()
        raise


class SplittingRelay:
    """Split the first wire bytes in both directions without interpreting VMess."""

    def __init__(self, waterwall, *, tamper=False):
        self.waterwall = waterwall
        self.tamper = tamper
        self.tampered = False

    def __enter__(self):
        self.listener = socket.socket()
        configure_listener(self.listener, (HOST, RELAY_PORT), timeout=10)
        self.connections = []
        self.stop = threading.Event()
        self.errors = []
        self.split = [0, 0]
        self.thread = threading.Thread(target=self.run)
        self.thread.start()
        return self

    def forward(self, source, target, direction):
        try:
            first = True
            while not self.stop.is_set():
                data = source.recv(65536)
                if not data:
                    target.shutdown(socket.SHUT_WR)
                    return
                if first:
                    first = False
                    if direction == 0 and self.tamper:
                        # Preserve the valid 16-byte AuthID and corrupt the
                        # independently authenticated encrypted header length.
                        if len(data) < 42:
                            data += exact(source, 42 - len(data))
                        data = data[:16] + bytes([data[16] ^ 1]) + data[17:]
                        self.tampered = True
                    for byte in data[:64]:
                        target.sendall(bytes([byte]))
                        self.split[direction] += 1
                        time.sleep(0.001)
                    data = data[64:]
                if data:
                    target.sendall(data)
        except (ConnectionResetError, BrokenPipeError):
            return
        except BaseException as error:
            if not self.stop.is_set():
                self.errors.append(error)

    def run(self):
        try:
            with self.listener.accept()[0] as client, connect_when_ready(
                    self.waterwall, (HOST, WIRE_PORT), deadline=time.monotonic() + 10,
                    failure=lambda: AssertionError("WaterWall exited before relay target readiness"),
                    timeout=10) as server:
                self.connections = [client, server]
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                    jobs = [executor.submit(self.forward, client, server, 0),
                            executor.submit(self.forward, server, client, 1)]
                    for job in jobs:
                        job.result(timeout=30)
        except BaseException as error:
            if not self.stop.is_set():
                self.errors.append(error)

    def __exit__(self, exc_type, exc, traceback):
        self.stop.set()
        for sock in self.connections:
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
        self.listener.close()
        self.thread.join(timeout=12)
        assert not self.thread.is_alive(), "VMess splitting relay did not stop"
        if exc_type is None:
            assert not self.errors, self.errors
            if self.tamper:
                assert self.tampered, "authenticated header corruption was not applied"
            else:
                assert min(self.split) >= 16, f"both VMess headers were not split: {self.split}"


def stop_waterwall(process):
    process.send_signal(signal.SIGTERM)
    assert process.wait(timeout=10) == 128 + signal.SIGTERM, "WaterWall shutdown failed"


def tcp_case(root, args, reference, waterwall, backend):
    client, _ = socks_request(reference)
    with client:
        if args.scenario in ("wrong_uuid", "tamper"):
            client.sendall(b"must-not-reach-the-target")
            try:
                assert client.recv(1) == b"", "rejected VMess request received application data"
            except ConnectionResetError:
                pass
            backend.settimeout(0.3)
            try:
                unexpected, _ = backend.accept()
            except socket.timeout:
                pass
            else:
                unexpected.close()
                raise AssertionError("rejected VMess request opened a protected or fallback target")
            stop_waterwall(waterwall)
            return
        payload = bytes(range(256)) * 1024 + b"vmess-final-chunk"
        greeting = b"vmess-server-first"

        def target():
            with backend.accept()[0] as peer:
                peer.settimeout(15)
                peer.sendall(greeting)
                assert exact(peer, len(payload)) == payload, "VMess changed upstream application bytes"
                peer.sendall(payload[::-1])
                assert peer.recv(1) == b"", "backend survived carrier shutdown"

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor, close_on_error(client):
            target_result = executor.submit(target)
            assert exact(client, len(greeting)) == greeting, "server-first reply changed"
            if args.scenario == "connection_limit":
                rejected, _ = socks_request(reference)
                with rejected:
                    rejected.sendall(b"second-connection")
                    try:
                        assert rejected.recv(1) == b"", "second managed connection was admitted"
                    except ConnectionResetError:
                        pass
                wait_log(waterwall, root / "waterwall.log", "connection limit reached")
            for offset in range(0, len(payload), 7919):
                client.sendall(payload[offset:offset + 7919])
            assert exact(client, len(payload)) == payload[::-1], "VMess changed downstream application bytes"
            # Leave the authenticated connection live for the source owner's drain.
            stop_waterwall(waterwall)
            assert client.recv(1) == b"", "VMess client did not observe shutdown"
            target_result.result(timeout=10)


def udp_case(reference, waterwall, backend):
    control, relay = socks_request(reference, udp=True)
    with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(10)
        prefix = b"\x00\x00\x00\x01" + socket.inet_aton(HOST) + TARGET_PORT.to_bytes(2, "big")
        # Empty VMess records terminate the carrier; they are not UDP datagrams.
        for payload in (b"a", bytes(range(31)), bytes(range(256)) * 2, bytes(range(240)) * 5, b"last"):
            client.sendto(prefix + payload, relay)
            data, origin = backend.recvfrom(65535)
            assert data == payload, "VMess changed UDP input boundary/content"
            backend.sendto(data[::-1], origin)
            received, _ = client.recvfrom(65535)
            assert received == prefix + payload[::-1], "VMess changed UDP reply boundary/content"
        stop_waterwall(waterwall)


def fallback_case(waterwall, backend):
    # Remain below the 64 KiB pre-authentication retention limit while still
    # exercising replay of a suffix much larger than the inspected AuthID.
    probe = b"\x00" * 16 + b"unauthenticated-vmess-fallback\r\n" + bytes(range(256)) * 128
    with connect_when_ready(waterwall, (HOST, WIRE_PORT), deadline=time.monotonic() + 10,
                            failure=lambda: AssertionError("WaterWall exited before fallback listener readiness"),
                            timeout=10) as client:
        client.settimeout(10)

        def target():
            with backend.accept()[0] as peer:
                peer.settimeout(10)
                assert exact(peer, len(probe)) == probe, "fallback changed inspected prefix or retained suffix"
                peer.sendall(probe[::-1])

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor, close_on_error(client):
            result = executor.submit(target)
            for offset in range(0, 16):
                client.sendall(probe[offset:offset + 1])
                time.sleep(0.001)
            client.sendall(probe[16:])
            assert exact(client, len(probe)) == probe[::-1], "fallback changed downstream bytes"
            result.result(timeout=10)
    stop_waterwall(waterwall)


def run(args):
    if args.scenario != "fallback":
        if not args.reference.is_file():
            raise RuntimeError("pinned V2Ray reference missing; build target waterwall_vmess_reference first")
        version = subprocess.run([str(args.reference), "version"], check=True, capture_output=True,
                                 text=True, timeout=5).stdout
        assert version.startswith("V2Ray 5.53.0 "), f"unexpected interoperability reference: {version.splitlines()[0]}"
    with RunDirectory("waterwall-vmess-interop-") as directory:
        root = Path(directory)
        inputs(root, args)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if args.protocol == "udp" else socket.SOCK_STREAM) as backend:
            if args.protocol == "udp":
                backend.bind((HOST, TARGET_PORT))
                backend.settimeout(15)
            else:
                configure_listener(backend, (HOST, TARGET_PORT), timeout=15)
            with Process([str(args.waterwall)], cwd=root, log_path=root / "waterwall.log") as waterwall:
                wait_log(waterwall, root / "waterwall.log", "Core: starting workers ...")
                if args.auth == "database":
                    wait_log(waterwall, root / "waterwall.log", "AuthenticationClient: pulled 1 users")
                if args.scenario == "fallback":
                    fallback_case(waterwall, backend)
                else:
                    relay = (SplittingRelay(waterwall, tamper=args.scenario == "tamper")
                             if args.scenario in ("split", "tamper") else contextlib.nullcontext())
                    with relay, Process([str(args.reference), "run", "-c", str(root / "v2ray.json")],
                                        cwd=root, log_path=root / "v2ray.log") as reference:
                        if args.protocol == "udp":
                            udp_case(reference, waterwall, backend)
                        else:
                            tcp_case(root, args, reference, waterwall, backend)
    print(f"VMess {args.cipher}/{args.protocol}/{args.auth}/{args.transport}/{args.scenario} passed")


if __name__ == "__main__":
    install_termination_handler()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("waterwall", type=lambda value: Path(value).resolve())
    parser.add_argument("reference", type=lambda value: Path(value).resolve())
    parser.add_argument("--cipher", choices=("aes-128-gcm", "chacha20-poly1305", "none", "zero"), default="aes-128-gcm")
    parser.add_argument("--protocol", choices=("tcp", "udp"), default="tcp")
    parser.add_argument("--auth", choices=("local", "database"), default="local")
    parser.add_argument("--transport", choices=("tcp", "tls", "ws", "wss"), default="tcp")
    parser.add_argument("--scenario", choices=("roundtrip", "wrong_uuid", "connection_limit", "split", "fallback", "tamper"), default="roundtrip")
    parser.add_argument("--workers", type=int, choices=(1, 2), default=1)
    run(parser.parse_args())
