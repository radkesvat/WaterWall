#!/usr/bin/env python3
"""Exercise real capture/conntrack rules inside run_in_network_namespace.sh."""

import argparse
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


def counters(chain="WWCAP_TEST_CT"):
    rules = iptables("-t", "mangle", "-L", chain, "-n", "-v", "-x", "--line-numbers")
    return tuple(int(match[1]) for match in re.finditer(r"^\s*\d+\s+(\d+)\s+\d+\s", rules, re.MULTILINE))


def expect_counters(expected):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        actual = counters()
        if actual == expected:
            return
        time.sleep(0.02)
    raise AssertionError(f"conntrack counters: expected {expected}, got {actual}")


def checksum(data):
    data += bytes(len(data) % 2)
    value = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while value >> 16:
        value = (value & 0xFFFF) + (value >> 16)
    return ~value & 0xFFFF


def send_ipv4(sender, source, destination, protocol, payload, ident, fragmented=False, ttl=64):
    pieces = [(0, 0, payload)]
    if fragmented:
        pieces = [(0, 0x2000, payload[:800]), (100, 0, payload[800:])]
    for offset, flags, body in pieces:
        header = struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), ident, flags | offset,
            ttl, protocol, 0, socket.inet_aton(source), socket.inet_aton(destination),
        )
        header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
        sender.send(bytes(12) + b"\x08\x00" + header + body)


def send_packet(sender, source, destination, port, payload, ident, fragmented=False, ttl=64):
    udp = struct.pack("!HHHH", 41000 + ident, port, len(payload) + 8, 0) + payload
    send_ipv4(sender, source, destination, socket.IPPROTO_UDP, udp, ident, fragmented, ttl)


def exercise_protocol_exclusions(sender):
    # Count only packets injected from the capture source, after conntrack.
    iptables("-t", "mangle", "-N", "WWCAP_EXCLUDED_CT")
    iptables("-t", "mangle", "-A", "PREROUTING", "-s", "127.0.0.2", "-d", "127.0.0.1",
             "-j", "WWCAP_EXCLUDED_CT")
    iptables("-t", "mangle", "-A", "WWCAP_EXCLUDED_CT", "-m", "conntrack", "--ctstate", "UNTRACKED")
    iptables("-t", "mangle", "-A", "WWCAP_EXCLUDED_CT", "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED,RELATED")
    command("sysctl", "-qw", "net.ipv4.icmp_ratelimit=0")

    def require_tracked(before):
        after = counters("WWCAP_EXCLUDED_CT")
        assert after[0] == 0 and after[1] > before[1], (before, after)

    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as receiver:
        receiver.bind(("127.0.0.2", 0))
        receiver.settimeout(3)
        echo = struct.pack("!BBHHH", 8, 0, 0, 0x4321, 1) + bytes(1400)
        echo = echo[:2] + struct.pack("!H", checksum(echo)) + echo[4:]
        before = counters("WWCAP_EXCLUDED_CT")
        send_ipv4(sender, "127.0.0.2", "127.0.0.1", 1, echo, 10, fragmented=True)
        reply = receiver.recv(4096)
        body = reply[(reply[0] & 15) * 4:]
        assert body[0] == 0 and body[4:] == echo[4:], "excluded fragmented ICMP did not reach host echo handling"
        require_tracked(before)

        # Exclusion must continue through the administrator's INPUT rules.
        iptables("-A", "INPUT", "-s", "127.0.0.2", "-p", "icmp", "-j", "DROP")
        send_ipv4(sender, "127.0.0.2", "127.0.0.1", 1, echo, 11)
        receiver.settimeout(0.3)
        expect_no_delivery(receiver)
        iptables("-D", "INPUT", "-s", "127.0.0.2", "-p", "icmp", "-j", "DROP")
        receiver.settimeout(3)

        # Zero reaches the host's protocol-unreachable handler. Protocol 255 is
        # delivered to IPPROTO_RAW sockets, so observe its host delivery directly.
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as raw_receiver:
            raw_receiver.bind(("127.0.0.1", 0))
            raw_receiver.settimeout(3)
            for protocol in (0, 255):
                before = counters("WWCAP_EXCLUDED_CT")
                send_ipv4(sender, "127.0.0.2", "127.0.0.1", protocol, bytes(8), 100 + protocol)
                if protocol == 0:
                    reply = receiver.recv(4096)
                    body = reply[(reply[0] & 15) * 4:]
                    assert body[:2] == bytes((3, 2)) and body[8 + 9] == 0, "protocol zero did not reach host stack"
                else:
                    reply = raw_receiver.recv(4096)
                    assert reply[9] == 255 and reply[20:] == bytes(8), "protocol 255 did not reach host raw socket"
                require_tracked(before)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        iptables("-t", "mangle", "-N", "WWCAP_HOST_SYNACK")
        iptables("-t", "mangle", "-A", "OUTPUT", "-s", "127.0.0.1", "-d", "127.0.0.2", "-p", "tcp",
                 "--sport", str(port), "--dport", "44007", "--tcp-flags", "SYN,ACK", "SYN,ACK", "-j", "WWCAP_HOST_SYNACK")
        iptables("-t", "mangle", "-A", "WWCAP_HOST_SYNACK")
        tcp = struct.pack("!HHIIBBHHH", 44007, port, 12345, 0, 0x50, 2, 32768, 0, 0)
        pseudo = socket.inet_aton("127.0.0.2") + socket.inet_aton("127.0.0.1") + struct.pack("!BBH", 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
        before = counters("WWCAP_EXCLUDED_CT")
        send_ipv4(sender, "127.0.0.2", "127.0.0.1", 6, tcp, 12)
        deadline = time.monotonic() + 3
        while counters("WWCAP_HOST_SYNACK")[0] == 0:
            assert time.monotonic() < deadline, "excluded TCP did not reach the host listener"
            time.sleep(0.02)
        require_tracked(before)


def expect_no_delivery(receiver):
    try:
        packet = receiver.recv(65535)
    except TimeoutError:
        return
    raise AssertionError(f"captured packet reached the host UDP socket: {packet!r}")


def run(binary, directory, bypass_conntrack, exclude_protocols):
    # Link-layer loopback injection starts at ingress, with no OUTPUT conntrack
    # attachment. These namespace-local settings admit its local source/route.
    command("sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.lo.rp_filter=0",
            "net.ipv4.conf.lo.accept_local=1", "net.ipv4.conf.lo.route_localnet=1")
    command("ip", "route", "add", "203.0.113.0/24", "dev", "lo")

    config = {"name": "capture-notrack", "nodes": [
        {"name": "capture", "type": "RawSocket", "next": "sink", "settings": {
            "fragment-policy": "preserve-fragments", "capture-device-name": "notrack-test", "capture-ips": ["127.0.0.2"],
            "capture-filter-mode": "source-ip", "skip-sysctl": True,
        }},
        {"name": "sink", "type": "BlackHole", "settings": {"mode": "passive"}},
    ]}
    if not bypass_conntrack:
        config["nodes"][0]["settings"]["bypass-conntrack"] = False
    if exclude_protocols:
        config["nodes"][0]["settings"]["dont-capture-protocols"] = [0, 1, 6, 6, 255]
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

                assert "WWCAP_" in iptables("-S", "INPUT")
                assert ("WWCAP_NOTRACK_" in iptables("-t", "raw", "-S", "PREROUTING")) == bypass_conntrack
                assert ("WWRAW_NOTRACK_" in iptables("-t", "raw", "-S", "OUTPUT")) == bypass_conntrack

                send_packet(sender, "127.0.0.2", "127.0.0.1", port, b"captured", 2)
                expect_counters((1, 1) if bypass_conntrack else (0, 2))
                expect_no_delivery(receiver)

                # Reassembly still precedes capture with either policy: two
                # wire fragments produce one additional datagram observation.
                send_packet(sender, "127.0.0.2", "127.0.0.1", port, bytes(1400), 3, fragmented=True)
                expect_counters((2, 1) if bypass_conntrack else (0, 3))
                expect_no_delivery(receiver)

                send_packet(sender, "127.0.0.3", "127.0.0.1", port, b"unrelated", 4)
                assert receiver.recv(65535) == b"unrelated"
                expect_counters((2, 2) if bypass_conntrack else (0, 4))

                # Same capture source, nonlocal destination: keep tracking.
                # TTL 1 prevents recirculation if this namespace forwards on lo.
                send_packet(sender, "127.0.0.2", "203.0.113.1", port, b"transit", 5, ttl=1)
                expect_counters((2, 3) if bypass_conntrack else (0, 5))
                assert "WWCAP" not in iptables("-t", "raw", "-S", "OUTPUT")

                if exclude_protocols:
                    exercise_protocol_exclusions(sender)

                process.terminate()
                assert process.wait(timeout=15) in (0, 143)
                assert "WWCAP" not in iptables("-t", "raw", "-S", "PREROUTING")
                assert "WWCAP" not in iptables("-S", "INPUT")
                assert "WWRAW_NOTRACK_" not in iptables("-t", "raw", "-S", "OUTPUT")
                send_packet(sender, "127.0.0.2", "127.0.0.1", port, b"restored", 6)
                assert receiver.recv(65535) == b"restored"
                expect_counters((2, 4) if bypass_conntrack else (0, 6))
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary")
    parser.add_argument("--tracked", action="store_true", help="disable bypass-conntrack on both paths")
    parser.add_argument("--exclude-protocols", action="store_true", help="exclude ICMP, TCP, and protocol-byte boundaries")
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    with tempfile.TemporaryDirectory(prefix="waterwall-capture-notrack-") as temporary:
        directory = Path(temporary)
        try:
            run(binary, directory, not args.tracked, args.exclude_protocols)
        except Exception:
            log = directory / "stdout.log"
            if log.exists():
                print(log.read_text()[-20000:], file=sys.stderr)
            raise
    print(f"Capture with bypass-conntrack={not args.tracked}, exclusions={args.exclude_protocols}, fragments, scope, and cleanup passed")


if __name__ == "__main__":
    main()
