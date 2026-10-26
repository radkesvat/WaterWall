#!/usr/bin/env python3
"""Short Trojan/TLS and base VLESS exchanges with pinned sing-box in private netns."""

import argparse
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
from vmess_reference import command as reference_command, validate_reference
from wwtest.config import core_config
from wwtest.process import Process, install_termination_handler
from wwtest.run_directory import RunDirectory
from wwtest.sockets import configure_listener, connect_when_ready, exact


TESTS = Path(__file__).resolve().parent
HOST = "127.0.0.1"
APP_PORT, WIRE_PORT, TARGET_PORT = 29661, 29662, 29663
UUID = "5783a3e7-e373-51cd-8642-c83782b807c5"
PASSWORD = "sing-box-local-interop"
READY = b"sing-box-proxy-udp-readiness"


def node(name, kind, settings, next_node=None):
    result = {"name": name, "type": kind, "settings": settings}
    if next_node is not None:
        result["next"] = next_node
    return result


def inputs(root, args):
    trojan = args.proxy == "trojan"
    protocol = "Trojan" if trojan else "Vless"
    credentials = {"password": PASSWORD} if trojan else {"uuid": UUID}
    nodes = []
    if args.role == "client":
        nodes.append(node("carrier", "TcpConnector", {"address": HOST, "port": WIRE_PORT,
                                                         "nodelay": True, "fastopen": False}))
        entry = "carrier"
        if trojan:
            # TlsClient has no custom CA setting for the local fixture certificate.
            nodes.append(node("tls-client", "TlsClient", {"sni": "tls.integration.test",
                                                              "verify": False}, entry))
            entry = "tls-client"
        nodes.append(node("proxy", protocol + "Client", {**credentials, "address": HOST,
                          "port": TARGET_PORT, "protocol": args.network,
                          "first-payload-timeout-ms": 40}, entry))
        nodes.append(node("application", "UdpListener" if args.network == "udp" else "TcpListener",
                          {"address": HOST, "port": APP_PORT}, "proxy"))
        inbound = {"type": args.proxy, "listen": HOST, "listen_port": WIRE_PORT,
                   "users": [{"name": "fixture", **credentials}]}
        reference = {"inbounds": [inbound], "outbounds": [{"type": "direct"}]}
        if trojan:
            inbound["tls"] = {"enabled": True, "certificate_path": str(root / "server.crt"),
                              "key_path": str(root / "server.key")}
        else:
            inbound["users"][0]["flow"] = ""
        inbound["multiplex"] = {"enabled": False}
    else:
        nodes.append(node("target", "UdpConnector" if args.network == "udp" else "TcpConnector",
                          {"address": "dest_context->address", "port": "dest_context->port"}))
        nodes.append(node("proxy", protocol + "Server", {**credentials,
                          "connect": args.network == "tcp", "udp": args.network == "udp"}, "target"))
        entry = "proxy"
        if trojan:
            nodes.append(node("tls-server", "TlsServer", {"cert-file": "server.crt",
                              "key-file": "server.key", "sni": "tls.integration.test"}, entry))
            entry = "tls-server"
        nodes.append(node("carrier", "TcpListener", {"address": HOST, "port": WIRE_PORT,
                                                        "nodelay": True}, entry))
        outbound = {"type": args.proxy, "server": HOST, "server_port": WIRE_PORT,
                    **credentials, "multiplex": {"enabled": False}}
        # A raw direct ingress avoids a SOCKS UDP envelope around measured bytes.
        # The destination is still carried by Trojan or VLESS.
        reference = {"inbounds": [{"type": "direct", "listen": HOST, "listen_port": APP_PORT,
                      "network": args.network, "override_address": HOST, "override_port": TARGET_PORT}],
                     "outbounds": [outbound]}
        if trojan:
            outbound["tls"] = {"enabled": True, "server_name": "tls.integration.test",
                               "insecure": False, "certificate_path": str(root / "server.crt")}
        else:
            # sing-box otherwise defaults to XUDP, outside base VLESS coverage.
            outbound.update({"packet_encoding": "", "flow": ""})
    if trojan:
        for name in ("server.crt", "server.key"):
            shutil.copyfile(TESTS / "speedtests/_shared" / name, root / name)
    (root / "core.json").write_text(json.dumps(core_config(splice=True)))
    (root / "config.json").write_text(json.dumps({"name": "sing-box-proxy-interop", "nodes": nodes}))
    (root / "reference.json").write_text(json.dumps({"log": {"level": "debug"}, **reference}))


def wait_log(process, marker):
    deadline = time.monotonic() + 5
    while marker not in process.log_path.read_text(errors="replace"):
        process.check_running(f"waiting for {marker}")
        assert time.monotonic() < deadline, f"did not observe {marker}"
        time.sleep(.02)


def payload(size, seed):
    block = bytes((index + seed) % 256 for index in range(256))
    return (block * (size // 256 + 1))[:size]


def tcp_case(application, target):
    with connect_when_ready(application, (HOST, APP_PORT), deadline=time.monotonic() + 5,
                            failure=lambda: AssertionError("application listener exited")) as client:
        client.settimeout(5)
        # Sending before accept bootstraps proxy protocols that delay their header
        # until the first application bytes arrive. This is measured traffic.
        client.sendall(payload(1, 1))
        peer, _ = target.accept()
        with peer:
            peer.settimeout(5)
            sizes = [1, 8192, 8193, 65536]
            for index, (request_size, reply_size) in enumerate(zip(sizes, reversed(sizes))):
                request, reply = payload(request_size, index + 1), payload(reply_size, index + 101)
                if index:
                    client.sendall(request)
                assert exact(peer, request_size) == request, f"TCP request changed at {request_size} bytes"
                peer.sendall(reply)
                assert exact(client, reply_size) == reply, f"TCP reply changed at {reply_size} bytes"
                print(f"TCP: {request_size}-byte request / {reply_size}-byte reply passed", flush=True)


def establish_udp(client, target, waterwall, reference):
    # TLS Init can pause UdpListener and drop the triggering datagram. Retry only
    # this distinct readiness token; no measured datagram is ever retransmitted.
    deadline = time.monotonic() + 5
    target.settimeout(.1)
    client.settimeout(.1)
    while time.monotonic() < deadline:
        waterwall.check_running("UDP readiness")
        reference.check_running("UDP readiness")
        client.send(READY)
        try:
            received, origin = target.recvfrom(65535)
            assert received == READY, "UDP readiness request changed"
            target.sendto(READY, origin)
            assert client.recv(65535) == READY, "UDP readiness reply changed"
            return
        except socket.timeout:
            continue
    raise AssertionError("UDP proxy association did not become ready")


def receive_udp(sock, expected, deadline, phase):
    while True:
        remaining = deadline - time.monotonic()
        assert remaining > 0, f"{phase}: timed out waiting for {len(expected)} bytes"
        sock.settimeout(remaining)
        received, origin = sock.recvfrom(65535)
        if received == READY:
            continue
        assert received == expected, (f"{phase}: expected an intact {len(expected)}-byte datagram, "
                                      f"received {len(received)} bytes")
        return origin


def udp_case(args, target, waterwall, reference):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.connect((HOST, APP_PORT))
        establish_udp(client, target, waterwall, reference)
        # The pinned peer reserves protocol headroom in a 16 KiB UDP read buffer.
        # WaterWall pair/native fixtures separately exercise the larger limits.
        # The direct sing-box ingress cannot forward an empty application request;
        # its server can receive one. Empty replies are exercised in both roles.
        if args.role == "server":
            print("sing-box direct ingress excludes empty requests; empty replies remain checked", flush=True)
        request_sizes = [1, 0 if args.role == "client" else 31, 8191, 8192, 8193, 15000]
        reply_sizes = [15000, 8193, 8192, 8191, 0, 1]
        deadline = time.monotonic() + 5
        for index, (request_size, reply_size) in enumerate(zip(request_sizes, reply_sizes)):
            request, reply = payload(request_size, index + 1), payload(reply_size, index + 101)
            assert client.send(request) == request_size
            origin = receive_udp(target, request, deadline, "UDP request")
            assert target.sendto(reply, origin) == reply_size
            receive_udp(client, reply, deadline, "UDP reply")
            print(f"UDP: {request_size}-byte request / {reply_size}-byte reply passed", flush=True)


def run(args):
    validate_reference(args.reference, "sing-box", provision_target="waterwall_vmess_SING_BOX_reference")
    with RunDirectory("waterwall-sing-box-proxy-interop-") as directory:
        root = Path(directory)
        inputs(root, args)
        kind = socket.SOCK_DGRAM if args.network == "udp" else socket.SOCK_STREAM
        with socket.socket(socket.AF_INET, kind) as target:
            if args.network == "udp":
                target.bind((HOST, TARGET_PORT))
            else:
                configure_listener(target, (HOST, TARGET_PORT), timeout=5)
            with Process(reference_command(args.reference, root), cwd=root,
                         log_path=root / "sing-box.log") as reference, \
                    Process([str(args.waterwall)], cwd=root, log_path=root / "waterwall.log") as waterwall:
                wait_log(reference, "sing-box started")
                wait_log(waterwall, "Core: starting workers ...")
                listener_port = APP_PORT if args.role == "client" else WIRE_PORT
                listener_network = args.network.upper() if args.role == "client" else "TCP"
                wait_log(waterwall, f"127.0.0.1:[{listener_port}] ({listener_network})")
                if args.network == "udp":
                    udp_case(args, target, waterwall, reference)
                else:
                    tcp_case(waterwall if args.role == "client" else reference, target)
                waterwall.check_running("completed interoperability workload")
                reference.check_running("completed interoperability workload")
                waterwall.send_signal(signal.SIGTERM)
                assert waterwall.wait(timeout=10) == 128 + signal.SIGTERM, "WaterWall orderly shutdown failed"
                reference.send_signal(signal.SIGTERM)
                assert reference.wait(timeout=5) == 0, "sing-box orderly shutdown failed"
    print(f"{args.proxy} WaterWall {args.role} / sing-box 1.12.0 / {args.network} passed", flush=True)


if __name__ == "__main__":
    install_termination_handler()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("waterwall", type=lambda value: Path(value).resolve())
    parser.add_argument("reference", type=lambda value: Path(value).resolve())
    parser.add_argument("--proxy", choices=("trojan", "vless"), required=True)
    parser.add_argument("--role", choices=("client", "server"), required=True)
    parser.add_argument("--network", choices=("tcp", "udp"), required=True)
    sys.exit(run(parser.parse_args()))
