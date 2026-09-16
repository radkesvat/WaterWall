#!/usr/bin/env python3
"""Exercise real capture/conntrack rules inside run_in_network_namespace.sh."""

import json
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys
import tempfile
import time


def command(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, timeout=10)


def iptables(*args):
    return command("iptables", "-w", "5", *args)


def counters():
    rules = iptables("-t", "mangle", "-L", "WWCAP_TEST_CT", "-n", "-v", "-x", "--line-numbers")
    return tuple(int(match[1]) for match in re.finditer(r"^\s*\d+\s+(\d+)\s+\d+\s", rules, re.MULTILINE))


def expect_counters(expected):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        actual = counters()
        if actual == expected:
            return
        time.sleep(0.02)
    raise AssertionError(f"conntrack counters: expected {expected}, got {actual}")


def send_packet(sender, source, destination, port, payload, ident, fragmented=False, ttl=64):
    udp = struct.pack("!HHHH", 41000 + ident, port, len(payload) + 8, 0) + payload
    pieces = [(0, 0, udp)]
    if fragmented:
        pieces = [(0, 0x2000, udp[:800]), (100, 0, udp[800:])]
    for offset, flags, body in pieces:
        header = struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), ident, flags | offset,
            ttl, socket.IPPROTO_UDP, 0, socket.inet_aton(source), socket.inet_aton(destination),
        )
        checksum = sum(struct.unpack("!10H", header))
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        header = header[:10] + struct.pack("!H", ~checksum & 0xFFFF) + header[12:]
        sender.send(bytes(12) + b"\x08\x00" + header + body)


def expect_no_delivery(receiver):
    try:
        packet = receiver.recv(65535)
    except TimeoutError:
        return
    raise AssertionError(f"captured packet reached the host UDP socket: {packet!r}")


def run(binary, directory):
    # Link-layer loopback injection starts at ingress, with no OUTPUT conntrack
    # attachment. These namespace-local settings admit its local source/route.
    command("sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.lo.rp_filter=0",
            "net.ipv4.conf.lo.accept_local=1", "net.ipv4.conf.lo.route_localnet=1")
    command("ip", "route", "add", "203.0.113.0/24", "dev", "lo")

    config = {"name": "capture-notrack", "nodes": [
        {"name": "capture", "type": "RawSocket", "next": "sink", "settings": {
            "capture-device-name": "notrack-test", "capture-ips": ["127.0.0.2"],
            "capture-filter-mode": "source-ip", "skip-sysctl": True,
        }},
        {"name": "sink", "type": "BlackHole", "settings": {"mode": "passive"}},
    ]}
    core = {
        "configs": ["config.json"],
        "misc": {"workers": 1, "ram-profile": "client", "mtu": 1500, "try-enabling-bbr": False},
        "log": {"path": "log/", **{
            name: {"loglevel": "DEBUG", "file": name + ".log", "console": True}
            for name in ("internal", "core", "network", "dns")
        }},
    }
    (directory / "config.json").write_text(json.dumps(config))
    (directory / "core.json").write_text(json.dumps(core))

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver, \
            socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as sender:
        receiver.bind(("127.0.0.1", 0))
        receiver.settimeout(0.3)
        port = receiver.getsockname()[1]
        sender.bind(("lo", 0))
        iptables("-t", "mangle", "-N", "WWCAP_TEST_CT")
        iptables("-t", "mangle", "-A", "PREROUTING", "-p", "udp", "--dport", str(port), "-j", "WWCAP_TEST_CT")
        iptables("-t", "mangle", "-A", "WWCAP_TEST_CT", "-m", "conntrack", "--ctstate", "UNTRACKED")
        iptables("-t", "mangle", "-A", "WWCAP_TEST_CT", "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED")

        send_packet(sender, "127.0.0.2", "127.0.0.1", port, b"before", 1)
        assert receiver.recv(65535) == b"before"
        expect_counters((0, 1))

        with (directory / "stdout.log").open("w") as log:
            process = subprocess.Popen([binary], cwd=directory, stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 10
                while "CaptureDevice: device notrack-test is now up" not in (directory / "stdout.log").read_text():
                    if process.poll() is not None or time.monotonic() >= deadline:
                        raise AssertionError("capture did not become ready")
                    time.sleep(0.05)

                send_packet(sender, "127.0.0.2", "127.0.0.1", port, b"captured", 2)
                expect_counters((1, 1))
                expect_no_delivery(receiver)

                # Reassembly still precedes NOTRACK and capture: one datagram,
                # two wire fragments, one additional untracked observation.
                send_packet(sender, "127.0.0.2", "127.0.0.1", port, bytes(1400), 3, fragmented=True)
                expect_counters((2, 1))
                expect_no_delivery(receiver)

                send_packet(sender, "127.0.0.3", "127.0.0.1", port, b"unrelated", 4)
                assert receiver.recv(65535) == b"unrelated"
                expect_counters((2, 2))

                # Same capture source, nonlocal destination: keep tracking.
                # TTL 1 prevents recirculation if this namespace forwards on lo.
                send_packet(sender, "127.0.0.2", "203.0.113.1", port, b"transit", 5, ttl=1)
                expect_counters((2, 3))
                assert "WWCAP" not in iptables("-t", "raw", "-S", "OUTPUT")

                process.terminate()
                assert process.wait(timeout=15) in (0, 143)
                assert "WWCAP" not in iptables("-t", "raw", "-S", "PREROUTING")
                assert "WWCAP" not in iptables("-S", "INPUT")
                send_packet(sender, "127.0.0.2", "127.0.0.1", port, b"restored", 6)
                assert receiver.recv(65535) == b"restored"
                expect_counters((2, 4))
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)


def main():
    binary = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix="waterwall-capture-notrack-") as temporary:
        directory = Path(temporary)
        try:
            run(binary, directory)
        except Exception:
            log = directory / "stdout.log"
            if log.exists():
                print(log.read_text()[-20000:], file=sys.stderr)
            raise
    print("Capture NOTRACK, fragment reassembly, scope, and shutdown restoration passed")


if __name__ == "__main__":
    main()
