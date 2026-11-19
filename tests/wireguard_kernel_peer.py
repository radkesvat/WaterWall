#!/usr/bin/env python3
"""Kernel WireGuard peer, authenticated TCP/UDP, inner IP slots and roaming in netns."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent / "support" / "python"))
from wwtest.config import core_config
from wwtest.process import Process, install_termination_handler
from wwtest.run_directory import RunDirectory
from wwtest.sockets import exact

SERVER_KEY = "EBJOHctLU2w8uteyTE+WU0hruB09Ub0vwVS+Gt9wAls="
SERVER_PUBLIC = "GnRcOavdc180YrXak138cZxWlMoEUZL0Mg/ZyWhLBgo="
SECRET = "kernel-wireguard-account"
WIRE, TCP, UDP, API = 29710, 29711, 29712, 29715
API_TOKEN = "0123456789abcdef" * 4

sys.path.insert(0, str(Path(__file__).resolve().parent))
from api_server_probe import frame, response


def command(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, timeout=10).strip()


def node(name, kind, settings, next_node=None):
    result = {"name": name, "type": kind, "settings": settings}
    if next_node:
        result["next"] = next_node
    return result


class TcpEcho(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while data := self.request.recv(32768):
                self.request.sendall(data)
        except ConnectionResetError:
            pass


class UdpEcho(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)


def tcp(source):
    sock = socket.socket()
    sock.settimeout(2)
    try:
        sock.bind((source, 0))
        sock.connect(("10.90.0.2", TCP))
        echo(sock)
        return sock
    except BaseException:
        sock.close()
        raise


def echo(sock):
    data = bytes(range(256)) * 16
    sock.sendall(data)
    assert exact(sock, len(data)) == data, "TCP payload changed"


def admitted(source, runtime, timeout=20):
    deadline = time.monotonic() + timeout
    while True:
        runtime.check_running("kernel peer admission")
        try:
            return tcp(source)
        except (OSError, AssertionError):
            if time.monotonic() >= deadline:
                print(command(os.environ.get("WATERWALL_WG") or "wg", "show"), flush=True)
                print(command("ip", "-s", "link", "show", "wg-test"), flush=True)
                raise
            time.sleep(.05)


def denied(source):
    try:
        sock = tcp(source)
    except (OSError, AssertionError):
        return
    sock.close()
    raise AssertionError("a second active inner source bypassed IP limit 1")


def api(operation, body):
    request = {"id": operation, "auth": {"client": "editor", "token": API_TOKEN},
               "selector": {"config": "wireguard-kernel", "node": "database"}, "operation": operation,
               "content_type": "application/json", "body_encoding": "utf8", "body": json.dumps(body)}
    with socket.create_connection(("127.0.0.1", API), timeout=2) as stream, stream.makefile("rb") as reader:
        stream.sendall(frame(request))
        reply = response(reader, operation)
    assert reply["error"] is None and reply["result"]["code"] == 0, reply
    return json.loads(reply["result"]["body"])


def run(args):
    wg = os.environ.get("WATERWALL_WG") or shutil.which("wg")
    parent = os.environ.get("WATERWALL_TEST_PARENT_NETNS")
    if not wg or not parent or os.readlink("/proc/self/ns/net") == parent:
        print("SKIP: requires wg and the private namespace harness")
        return 77
    try:
        command("ip", "link", "add", "wg-test", "type", "wireguard")
    except subprocess.CalledProcessError as error:
        print("SKIP: kernel WireGuard interface unavailable:", error.output)
        return 77
    with RunDirectory("waterwall-wireguard-kernel-") as directory:
        root = Path(directory)
        private = root / "client.key"
        private.write_text(base64.b64encode(hashlib.sha256(SECRET.encode()).digest()).decode() + "\n")
        nodes = [
            node("auth", "AuthenticationClient", {"name": "edge", "secret": "local-test", "ping-interval-ms": 0,
                 "pull-interval-ms": 200, "push-interval-ms": 0}, "database"),
            node("database", "AuthenticationServer", {"db-path": "users.json", "file-save-rate-ms": 60000,
                 "auth-clients": [{"name": "edge", "secret": "local-test", "allow-user-pull": True,
                                   "allow-stats-push": True, "allow-user-write": False}]}),
            node("ingress", "UdpListener", {"address": "127.0.0.1", "port": WIRE}, "server"),
            node("server", "WireGuardServer", {"mode": "connection", "privatekey": SERVER_KEY,
                 "auth-client-node-name": "auth", "udp-idle-timeout-ms": 2000}, "identity"),
            node("outbound", "TcpUdpConnector", {"address": "127.0.0.1", "port": "dest_context->port"})]
        nodes.extend([
            node("identity", "Router", {"rules": [
                {"username": "kernel-user", "password": SECRET, "target": "outbound"},
                {"username": "reassigned-user", "password": SECRET, "target": "outbound"}]}, "reject"),
            node("reject", "BlackHole", {"mode": "passive"}),
            node("api-listener", "TcpListener", {"address": "127.0.0.1", "port": API}, "api"),
            node("api", "APIServer", {"clients": [{"name": "editor", "token": API_TOKEN,
                "allow": [{"config": "wireguard-kernel", "node": "database",
                           "operations": ["get-user", "update-user", "change-user-password", "create-user"]}]}]})])
        (root / "config.json").write_text(json.dumps({"name": "wireguard-kernel", "nodes": nodes}))
        (root / "core.json").write_text(json.dumps(core_config(workers=args.workers)))
        (root / "users.json").write_text(json.dumps({"users": [{"id": 71, "name": "kernel-user",
            "password": SECRET, "wireguard-allowed-ips": "10.90.0.0/30", "limit": {"ips": 1, "cons-out": 8}}]}))
        with socketserver.ThreadingTCPServer(("127.0.0.1", TCP), TcpEcho) as tcp_server, \
             socketserver.UDPServer(("127.0.0.1", UDP), UdpEcho) as udp_server:
            threads = [threading.Thread(target=server.serve_forever, daemon=True)
                       for server in (tcp_server, udp_server)]
            for thread in threads:
                thread.start()
            try:
                with Process([str(args.waterwall)], cwd=root, log_path=root / "waterwall.log") as runtime:
                    ready_deadline = time.monotonic() + 8
                    while "AuthenticationClient: pulled" not in (root / "waterwall.log").read_text():
                        runtime.check_running("waiting for installed account cache")
                        assert time.monotonic() < ready_deadline, "account cache did not initialize"
                        time.sleep(.02)
                    command(wg, "set", "wg-test", "private-key", str(private), "listen-port", "29713", "peer", SERVER_PUBLIC,
                            "allowed-ips", "10.90.0.2/32", "endpoint", f"127.0.0.1:{WIRE}", "persistent-keepalive", "1")
                    for address in ("10.90.0.1/32", "10.90.0.3/32"):
                        command("ip", "address", "add", address, "dev", "wg-test")
                    command("ip", "link", "set", "wg-test", "up")
                    command("ip", "route", "add", "10.90.0.2/32", "dev", "wg-test")
                    with admitted("10.90.0.1", runtime) as first, admitted("10.90.0.1", runtime) as second:
                        denied("10.90.0.3")
                        command(wg, "set", "wg-test", "listen-port", "29714")
                        echo(first)
                        with admitted("10.90.0.1", runtime) as after_roaming:
                            echo(after_roaming)
                        denied("10.90.0.3")
                        echo(second)
                    with admitted("10.90.0.3", runtime) as released:
                        echo(released)
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                        udp.bind(("10.90.0.3", 0))
                        udp.settimeout(2)
                        udp.connect(("10.90.0.2", UDP))
                        payload = bytes(range(256)) * 4
                        udp.send(payload)
                        assert udp.recv(65535) == payload, "UDP datagram changed"
                    denied("10.90.0.1")
                    time.sleep(2.5)
                    with admitted("10.90.0.1", runtime) as final:
                        if args.rekey:
                            initial = command(wg, "show", "wg-test", "latest-handshakes")
                            deadline = time.monotonic() + 145
                            report = time.monotonic() + 20
                            while command(wg, "show", "wg-test", "latest-handshakes") == initial:
                                assert time.monotonic() < deadline, "independent peer did not rekey"
                                echo(final)
                                if time.monotonic() >= report:
                                    print("Kernel peer: traffic continues while waiting for protocol rekey", flush=True)
                                    report += 20
                                time.sleep(1)
                            echo(final)
                            print("Kernel peer rekey observed", flush=True)
                    # Keep both protocols active while credentials and ranges change.
                    with admitted("10.90.0.1", runtime) as old_tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as old_udp:
                        old_udp.bind(("10.90.0.1", 0))
                        old_udp.settimeout(.4)
                        old_udp.connect(("10.90.0.2", UDP))
                        old_udp.send(b"before-update")
                        assert old_udp.recv(1024) == b"before-update"
                        # Unchanged installed refreshes must preserve existing flows.
                        for _ in range(5):
                            time.sleep(.25)
                            echo(old_tcp)
                        edit = api("get-user", {"id": "71"})["edit_token"]
                        api("update-user", {"id": "71", "if_match": edit,
                            "patch": {"wireguard_allowed_ips": "10.91.0.0/30"}})
                        deadline = time.monotonic() + 4
                        while True:
                            try:
                                echo(old_tcp)
                            except (OSError, AssertionError):
                                break
                            assert time.monotonic() < deadline, "range change did not retire TCP"
                            time.sleep(.05)
                        old_udp.send(b"after-update")
                        try:
                            old_udp.recv(1024)
                        except OSError:
                            pass
                        else:
                            raise AssertionError("range change retained an old UDP association")
                    # Reassign the credential/range to a new durable account without restarting.
                    edit = api("get-user", {"id": "71"})["edit_token"]
                    api("change-user-password", {"id": "71", "if_match": edit, "password": SECRET + "-rotated"})
                    api("create-user", {"id": "72", "password": SECRET, "config": {
                        "name": "reassigned-user", "wireguard_allowed_ips": "10.90.0.0/30",
                        "limit": {"ips": "1", "cons_out": "8"}}})
                    time.sleep(.8)
                    # Reset the independent peer to require a fresh proof for the new owner.
                    command(wg, "set", "wg-test", "peer", SERVER_PUBLIC, "remove")
                    command(wg, "set", "wg-test", "peer", SERVER_PUBLIC, "allowed-ips", "10.90.0.2/32",
                            "endpoint", f"127.0.0.1:{WIRE}", "persistent-keepalive", "1")
                    with admitted("10.90.0.3", runtime) as replacement:
                        echo(replacement)
                        denied("10.90.0.1")
                    print("Live refresh, range retirement and credential reassignment passed", flush=True)
                    runtime.check_running("completed independent WireGuard workload")
                    runtime.send_signal(signal.SIGTERM)
                    assert runtime.wait(timeout=10) == 143, "orderly shutdown failed"
            finally:
                tcp_server.shutdown()
                udp_server.shutdown()
                for thread in threads:
                    thread.join(timeout=5)
    command("ip", "link", "delete", "wg-test")
    print("Kernel WireGuard handshake, TCP/UDP, roaming and inner-IP reservation lifecycle passed", flush=True)
    return 0


if __name__ == "__main__":
    install_termination_handler()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("waterwall", type=lambda value: Path(value).resolve())
    parser.add_argument("--workers", type=int, choices=(1, 4), default=1)
    parser.add_argument("--rekey", action="store_true")
    sys.exit(run(parser.parse_args()))
