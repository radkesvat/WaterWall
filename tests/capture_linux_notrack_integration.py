#!/usr/bin/env python3
"""Exercise real capture/conntrack rules inside run_in_network_namespace.sh. CTest:
waterwall.capture_linux_conntrack_enabled, waterwall.capture_linux_notrack,
waterwall.capture_linux_protocols_bypass, waterwall.capture_linux_protocols_tracked,
waterwall.capture_linux_queues_multi, waterwall.capture_linux_queues_single."""

import argparse
import contextlib
import json
from pathlib import Path
import re
import selectors
import socket
import struct
import sys
import signal
import os
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parent / "support" / "python")))
from wwtest.run_directory import RunDirectory
from wwtest.process import Process, install_termination_handler
from wwtest.linux_commands import command, iptables






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
    sent_packets = []
    for offset, flags, body in pieces:
        header = struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), ident, flags | offset,
            ttl, protocol, 0, socket.inet_aton(source), socket.inet_aton(destination),
        )
        header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
        sender.send(bytes(12) + b"\x08\x00" + header + body)
        sent_packets.append(header + body)
    return sent_packets


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
            with Process([binary], cwd=directory, log=log, cleanup_signal=signal.SIGTERM, terminate_timeout=15) as process:
                deadline = time.monotonic() + 10
                while "CaptureDevice: notrack-test up with 1 worker-owned receive queue(s)" not in (directory / "stdout.log").read_text():
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


def queue_statistics():
    # NFQUEUE's proc row reports queue number, peer, backlog, copy settings,
    # kernel drops, userspace drops and the monotonically assigned packet ID.
    rows = {}
    for line in Path("/proc/net/netfilter/nfnetlink_queue").read_text().splitlines():
        fields = [int(value) for value in line.split()]
        assert len(fields) >= 8, line
        rows[fields[0]] = {"pending": fields[2], "dropped": fields[5],
                           "user_dropped": fields[6], "sequence": fields[7]}
    return rows


def queue_burst(queues, send, expected, timeout=10):
    """Run send(), then wait until the kernel has assigned `expected` packet ids; return the per-queue counts."""
    before = queue_statistics()
    send()
    deadline = time.monotonic() + timeout
    while True:
        after = queue_statistics()
        deltas = {queue: after[queue]["sequence"] - before[queue]["sequence"] for queue in queues}
        if sum(deltas.values()) >= expected or time.monotonic() > deadline:
            return deltas
        time.sleep(0.01)


def wait_queues_drained(queues, timeout=10):
    deadline = time.monotonic() + timeout
    while True:
        after = queue_statistics()
        if all(after[queue]["pending"] == 0 for queue in queues) or time.monotonic() > deadline:
            return after
        time.sleep(0.01)


class PacketCollector:
    """Read the ordinary IPv4 framing on every real worker-owned TCP carrier."""

    def __init__(self, stack):
        self.stack = stack
        self.listener = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.listener.setblocking(False)
        self.selector = stack.enter_context(selectors.DefaultSelector())
        self.selector.register(self.listener, selectors.EVENT_READ)
        self.buffers = {}
        self.packets = {}
        self.delivered = {}

    def wait(self, process, predicate, deadline):
        while not predicate():
            process.check_running("capture exited while collecting worker output")
            remaining = deadline - time.monotonic()
            assert remaining > 0, ("capture collector timed out", len(self.buffers), len(self.packets))
            for key, _ in self.selector.select(min(remaining, 0.1)):
                stream = key.fileobj
                if stream is self.listener:
                    stream, _ = self.listener.accept()
                    self.stack.enter_context(stream)
                    stream.setblocking(False)
                    self.selector.register(stream, selectors.EVENT_READ)
                    self.buffers[stream] = bytearray()
                    self.delivered[stream] = 0
                    continue
                data = stream.recv(65535)
                assert data, "worker carrier closed before capture finished"
                buffer = self.buffers[stream]
                buffer.extend(data)
                while len(buffer) >= 20:
                    length = struct.unpack_from("!H", buffer, 2)[0]
                    assert buffer[0] >> 4 == 4 and length >= 20, bytes(buffer[:20])
                    if len(buffer) < length:
                        break
                    packet = bytes(buffer[:length])
                    del buffer[:length]
                    ident = struct.unpack_from("!H", packet, 4)[0]
                    assert ident not in self.packets, ("duplicate captured packet", ident)
                    self.packets[ident] = packet
                    self.delivered[stream] += 1


def run_queue_receive(binary, directory, single_queue):
    command("sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.lo.rp_filter=0",
            "net.ipv4.conf.lo.accept_local=1", "net.ipv4.conf.lo.route_localnet=1")
    workers = 4
    baseline_tasks = None
    # The write-only baseline has the same worker/carrier topology and avoids
    # assuming how many unrelated runtime service threads an installation uses.
    for capture in (False, True):
        case = directory / ("capture" if capture else "write-only")
        case.mkdir()
        with contextlib.ExitStack() as stack:
            collector = PacketCollector(stack)
            settings = {"raw-device-name": "queue-writer", "capture-device-name": "queue-test",
                        "fragment-policy": "preserve-fragments", "skip-sysctl": True}
            if capture:
                settings.update({"capture-ips": ["127.0.0.2"], "capture-filter-mode": "source-ip",
                                 "multi-queue": not single_queue, "dont-capture-protocols": [253]})
            nodes = [
                {"name": "capture", "type": "RawSocket", "next": "packets", "settings": settings},
                {"name": "packets", "type": "PacketsToStream", "next": "output"},
                {"name": "output", "type": "TcpConnector", "settings": {
                    "address": "127.0.0.1", "port": collector.listener.getsockname()[1]}},
            ]
            core = {"configs": ["config.json"],
                    "misc": {"workers": workers, "ram-profile": "client", "mtu": 1500,
                             "try-enabling-bbr": False},
                    "log": {"path": "log/", **{
                        name: {"loglevel": "DEBUG", "file": name + ".log", "console": True}
                        for name in ("internal", "core", "network", "dns")}}}
            (case / "config.json").write_text(json.dumps({"name": "capture-queues", "nodes": nodes}))
            (case / "core.json").write_text(json.dumps(core))
            log = stack.enter_context((case / "stdout.log").open("w"))
            with Process([binary], cwd=case, log=log, cleanup_signal=signal.SIGTERM,
                         terminate_timeout=15) as process:
                deadline = time.monotonic() + 15
                collector.wait(process, lambda: len(collector.buffers) == workers, deadline)
                task_count = len(list(Path(f"/proc/{process.child.pid}/task").iterdir()))
                if not capture:
                    baseline_tasks = task_count
                    assert "WWCAP_" not in iptables("-S", "INPUT")
                else:
                    assert task_count == baseline_tasks, ("capture added a reader thread", baseline_tasks, task_count)
                    rules = [line for line in iptables("-S", "INPUT").splitlines() if "WWCAP_" in line]
                    queue_numbers = {int(re.search(r"--queue-num (\d+)", line)[1]) for line in rules}
                    assert len(queue_numbers) == (1 if single_queue else workers), rules
                    assert len(rules) == (1 if single_queue else workers * 2), rules
                    if not single_queue:
                        opaque_rules = [line for line in rules if "WWCAP_OPAQUE_" in line]
                        assert len(opaque_rules) == workers and sum("--mode random" in line for line in opaque_rules) == workers - 1, rules
                        assert all("--mode nth" not in line for line in opaque_rules), rules
                    before = queue_statistics()
                    assert queue_numbers == set(before), before

                    sender = stack.enter_context(socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                                                socket.htons(0x0800)))
                    sender.bind(("lo", 0))
                    expected = {}
                    # Fixed IP pair and destination ports: only source ports
                    # change within each protocol's 128 independent flows.
                    for protocol in (socket.IPPROTO_UDP, socket.IPPROTO_TCP):
                        protocol_before = queue_statistics()
                        for number in range(128):
                            ident = 1000 + protocol * 128 + number
                            payload = struct.pack("!I", ident) + b"worker-owned-capture"
                            if protocol == socket.IPPROTO_UDP:
                                body = struct.pack("!HHHH", 20000 + number, 49000, len(payload) + 8, 0) + payload
                            else:
                                body = struct.pack("!HHIIBBHHH", 22000 + number, 49001,
                                                   ident, 0, 0x50, 2, 32768, 0, 0) + payload
                            expected[ident] = send_ipv4(sender, "127.0.0.2", "127.0.0.1",
                                                        protocol, body, ident)[0]
                            if (number + 1) % 16 == 0:
                                collector.wait(process, lambda: len(collector.packets) == len(expected),
                                               time.monotonic() + 5)
                        protocol_after = queue_statistics()
                        protocol_deltas = {queue: protocol_after[queue]["sequence"]
                                           - protocol_before[queue]["sequence"] for queue in queue_numbers}
                        assert all(delta > 0 for delta in protocol_deltas.values()), \
                            ("protocol ports did not spread receive work", protocol, protocol_deltas)
                        assert sum(protocol_deltas.values()) == 128, (protocol, protocol_deltas)
                    # Opaque traffic uses random receive queues and retains its
                    # receiving worker. Check spread and exact delivery/count
                    # correspondence, without requiring exact random balance.
                    opaque_packets = 128
                    for protocol in (1, 49, 50, 132):
                        protocol_before = queue_statistics()
                        delivery_before = collector.delivered.copy()
                        for number in range(opaque_packets):
                            ident = 10000 + protocol * opaque_packets + number
                            body = struct.pack("!HHI", 12000, 443, ident) + b"opaque-distribution"
                            expected[ident] = send_ipv4(sender, "127.0.0.2", "127.0.0.1", protocol, body, ident)[0]
                            if (number + 1) % 16 == 0:
                                collector.wait(process, lambda: len(collector.packets) == len(expected), time.monotonic() + 5)
                        protocol_after = queue_statistics()
                        queue_deltas = {queue: protocol_after[queue]["sequence"] - protocol_before[queue]["sequence"]
                                        for queue in queue_numbers}
                        assert sum(queue_deltas.values()) == opaque_packets and all(queue_deltas.values()), \
                            ("opaque receive lost packets or did not spread across queues", protocol, queue_deltas)
                        processing_deltas = [count - delivery_before[stream] for stream, count in collector.delivered.items()]
                        expected_processing = ([opaque_packets // workers] * workers if single_queue
                                               else sorted(queue_deltas.values()))
                        assert sorted(processing_deltas) == expected_processing, \
                            ("opaque processing collapsed onto a coarse flow owner", protocol, processing_deltas)
                    assert collector.packets == expected, "captured payload changed or was lost"
                    assert len(collector.delivered) == workers and all(collector.delivered.values()), \
                        ("packet processing did not use every configured worker", collector.delivered)
                    after = queue_statistics()
                    deltas = {queue: after[queue]["sequence"] - before[queue]["sequence"]
                              for queue in queue_numbers}
                    assert all(delta > 0 for delta in deltas.values()), ("ports did not spread receive work", deltas)
                    assert sum(deltas.values()) == len(expected), ("unexpected capture count", deltas, len(expected))
                    assert all(after[queue]["pending"] == 0 and after[queue]["dropped"] == 0
                               and after[queue]["user_dropped"] == 0 for queue in queue_numbers), after
                    print(f"receive queues={len(queue_numbers)} packets={deltas} processing workers={workers} "
                          f"threads={task_count} (write-only={baseline_tasks})")
                process.terminate()
                assert process.wait(timeout=15) in (0, 143)
                assert "WWCAP" not in iptables("-S", "INPUT")
                assert "WWCAP_NOTRACK" not in iptables("-t", "raw", "-S", "PREROUTING")
                assert "WWRAW_NOTRACK" not in iptables("-t", "raw", "-S", "OUTPUT")
                if capture:
                    assert not queue_statistics(), "capture left a bound NFQUEUE after shutdown"


def run_ported_protocol_queues(binary, directory):
    """A real IpManipulator registers its swap number; the kernel steers that protocol by the inner port pair."""
    command("sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.lo.rp_filter=0",
            "net.ipv4.conf.lo.accept_local=1", "net.ipv4.conf.lo.route_localnet=1")
    workers = 4
    swapped, plain = 143, 144
    case = directory / "ported"
    case.mkdir()
    with contextlib.ExitStack() as stack:
        collector = PacketCollector(stack)
        settings = {"raw-device-name": "queue-writer", "capture-device-name": "queue-test",
                    "fragment-policy": "preserve-fragments", "skip-sysctl": True, "multi-queue": True,
                    "capture-ips": ["127.0.0.2"], "capture-filter-mode": "source-ip"}
        nodes = [
            {"name": "capture", "type": "RawSocket", "next": "swap", "settings": settings},
            {"name": "swap", "type": "IpManipulator", "next": "packets", "settings": {"protoswap-tcp": swapped}},
            {"name": "packets", "type": "PacketsToStream", "next": "output"},
            {"name": "output", "type": "TcpConnector", "settings": {
                "address": "127.0.0.1", "port": collector.listener.getsockname()[1]}},
        ]
        core = {"configs": ["config.json"],
                "misc": {"workers": workers, "ram-profile": "client", "mtu": 1500, "try-enabling-bbr": False},
                "log": {"path": "log/", **{name: {"loglevel": "DEBUG", "file": name + ".log", "console": True}
                                           for name in ("internal", "core", "network", "dns")}}}
        (case / "config.json").write_text(json.dumps({"name": "capture-ported", "nodes": nodes}))
        (case / "core.json").write_text(json.dumps(core))
        log = stack.enter_context((case / "stdout.log").open("w"))
        with Process([binary], cwd=case, log=log, cleanup_signal=signal.SIGTERM, terminate_timeout=15) as process:
            collector.wait(process, lambda: len(collector.buffers) == workers, time.monotonic() + 15)
            rules = [line for line in iptables("-S", "INPUT").splitlines() if "WWCAP_" in line]
            queue_numbers = {int(re.search(r"--queue-num (\d+)", line)[1]) for line in rules}
            assert len(queue_numbers) == workers and len(rules) == workers * 2, rules
            sender = stack.enter_context(socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)))
            sender.bind(("lo", 0))
            ident = [20000]

            def burst(protocol, source_port, destination_port, count):
                def send():
                    for number in range(count):
                        ident[0] += 1
                        # A TCP-style header: the swapped protocol keeps it at the start of the payload.
                        body = struct.pack("!HHIIBBHHH", source_port, destination_port, number, 0, 0x50, 2, 32768, 0, 0)
                        send_ipv4(sender, "127.0.0.2", "127.0.0.1", protocol, body + b"ported-flow", ident[0])
                return queue_burst(queue_numbers, send, count)

            used = set()
            for flow in range(48):
                deltas = burst(swapped, 30000 + flow, 443, 6)
                nonzero = [queue for queue, delta in deltas.items() if delta]
                assert len(nonzero) == 1 and sum(deltas.values()) == 6, ("swapped flow split across queues", flow, deltas)
                used.add(nonzero[0])
            assert len(used) >= 3, ("different swapped flows did not spread over the queues", used)
            forward = [queue for queue, delta in burst(swapped, 30007, 443, 4).items() if delta]
            reverse = [queue for queue, delta in burst(swapped, 443, 30007, 4).items() if delta]
            assert len(forward) == 1 and forward == reverse, ("both directions of a flow must share a queue", forward, reverse)
            # An unregistered protocol with the same bytes stays opaque: random kernel queue selection.
            deltas = burst(plain, 30000, 443, 64)
            assert sum(deltas.values()) == 64 and sum(1 for delta in deltas.values() if delta) >= 2, \
                ("an unregistered protocol was not spread across queues", deltas)
            after = wait_queues_drained(queue_numbers)
            assert all(after[queue]["pending"] == 0 and after[queue]["dropped"] == 0
                       and after[queue]["user_dropped"] == 0 for queue in queue_numbers), after
            print(f"swapped flows spread over {len(used)} of {workers} queues, one queue per flow and direction")
        assert not queue_statistics(), "capture left a bound NFQUEUE after shutdown"


def run_ported_protocol_isolation(binary, directory):
    """Two chains in one process. Only chain A declares a swap number; chain B never does, so for chain B that
    number is opaque and keeps the per-packet random queue selection, constant-key traffic included."""
    command("sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.lo.rp_filter=0",
            "net.ipv4.conf.lo.accept_local=1", "net.ipv4.conf.lo.route_localnet=1")
    workers, swapped = 4, 143
    case = directory / "isolation"
    case.mkdir()
    with contextlib.ExitStack() as stack:
        collector = PacketCollector(stack)
        port = collector.listener.getsockname()[1]

        def capture(name, address, following):
            return {"name": name, "type": "RawSocket", "next": following, "settings": {
                "raw-device-name": name + "-w", "capture-device-name": name + "-c",
                "fragment-policy": "preserve-fragments", "skip-sysctl": True, "multi-queue": True,
                "capture-ips": [address], "capture-filter-mode": "source-ip"}}

        nodes = [
            capture("capa", "127.0.0.2", "swapa"),
            {"name": "swapa", "type": "IpManipulator", "next": "ptsa", "settings": {"protoswap-tcp": swapped}},
            {"name": "ptsa", "type": "PacketsToStream", "next": "outa"},
            {"name": "outa", "type": "TcpConnector", "settings": {"address": "127.0.0.1", "port": port}},
            capture("capb", "127.0.0.3", "ptsb"),
            {"name": "ptsb", "type": "PacketsToStream", "next": "outb"},
            {"name": "outb", "type": "TcpConnector", "settings": {"address": "127.0.0.1", "port": port}},
        ]
        core = {"configs": ["config.json"],
                "misc": {"workers": workers, "ram-profile": "client", "mtu": 1500, "try-enabling-bbr": False},
                "log": {"path": "log/", **{name: {"loglevel": "DEBUG", "file": name + ".log", "console": True}
                                           for name in ("internal", "core", "network", "dns")}}}
        (case / "config.json").write_text(json.dumps({"name": "capture-isolation", "nodes": nodes}))
        (case / "core.json").write_text(json.dumps(core))
        log = stack.enter_context((case / "stdout.log").open("w"))
        with Process([binary], cwd=case, log=log, cleanup_signal=signal.SIGTERM, terminate_timeout=15) as process:
            collector.wait(process, lambda: len(collector.buffers) == 2 * workers, time.monotonic() + 20)
            rules = [line for line in iptables("-S", "INPUT").splitlines() if "WWCAP_" in line]

            def queues_of(address):
                return {int(re.search(r"--queue-num (\d+)", line)[1]) for line in rules if address + "/32" in line}

            queues_a, queues_b = queues_of("127.0.0.2"), queues_of("127.0.0.3")
            assert len(queues_a) == workers and len(queues_b) == workers and not queues_a & queues_b, rules
            sender = stack.enter_context(socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)))
            sender.bind(("lo", 0))
            ident = [40000]

            def burst(address, queues, source_port, destination_port, count, constant_spi=False):
                def send():
                    for number in range(count):
                        ident[0] += 1
                        if constant_spi:
                            body = struct.pack("!II", 0xC0FFEE01, number + 1) + bytes(48)
                        else:
                            body = struct.pack("!HHIIBBHHH", source_port, destination_port, number, 0, 0x50, 2,
                                               32768, 0, 0) + b"isolation"
                        send_ipv4(sender, address, "127.0.0.1", swapped, body, ident[0])
                return queue_burst(queues, send, count)

            # Chain A declared the number: one queue per inner flow.
            used_a = set()
            for flow in range(24):
                deltas = burst("127.0.0.2", queues_a, 30000 + flow, 443, 6)
                nonzero = [queue for queue, delta in deltas.items() if delta]
                assert len(nonzero) == 1 and sum(deltas.values()) == 6, ("declared flow split across queues", deltas)
                used_a.add(nonzero[0])
            assert len(used_a) >= 3, ("declared flows did not spread", used_a)
            # Chain B declared nothing: the same number and bytes stay per-packet random.
            used_b, single = set(), 0
            for flow in range(24):
                deltas = burst("127.0.0.3", queues_b, 30000 + flow, 443, 8)
                assert sum(deltas.values()) == 8, deltas
                nonzero = [queue for queue, delta in deltas.items() if delta]
                used_b.update(nonzero)
                single += len(nonzero) == 1
            assert single <= 2 and len(used_b) == workers, \
                ("an undeclared chain steered another chain's protocol by ports", single, used_b)
            # Constant-SPI ESP-like traffic of that number must keep spreading over the undeclared chain's queues.
            deltas = burst("127.0.0.3", queues_b, 0, 0, 192, constant_spi=True)
            assert sum(deltas.values()) == 192 and sum(1 for delta in deltas.values() if delta) >= 3, \
                ("constant-SPI traffic collapsed onto too few queues in an undeclared chain", deltas)
            after = wait_queues_drained(queues_a | queues_b)
            assert all(after[queue]["pending"] == 0 and after[queue]["dropped"] == 0
                       and after[queue]["user_dropped"] == 0 for queue in queues_a | queues_b), after
            print(f"declared chain: one queue per flow over {len(used_a)} queues; undeclared chain: {single}/24 flows "
                  f"on one queue, {len(used_b)} queues used, constant-SPI spread {list(deltas.values())}")
        assert not queue_statistics(), "capture left a bound NFQUEUE after shutdown"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary")
    parser.add_argument("--tracked", action="store_true", help="disable bypass-conntrack on both paths")
    parser.add_argument("--exclude-protocols", action="store_true", help="exclude ICMP, TCP, and protocol-byte boundaries")
    parser.add_argument("--queue-mode", choices=("multi", "single", "ported", "isolated"), help="exercise four worker capture and queue steering")
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    with RunDirectory(prefix="waterwall-capture-notrack-") as temporary:
        directory = Path(temporary)
        try:
            if args.queue_mode == "ported":
                run_ported_protocol_queues(binary, directory)
            elif args.queue_mode == "isolated":
                run_ported_protocol_isolation(binary, directory)
            elif args.queue_mode:
                run_queue_receive(binary, directory, args.queue_mode == "single")
            else:
                run(binary, directory, not args.tracked, args.exclude_protocols)
        except Exception:
            for log in directory.rglob("stdout.log"):
                print(f"{log}:\n{log.read_text()[-20000:]}", file=sys.stderr)
            raise
    if args.queue_mode == "ported":
        print("Capture ported-protocol queues, inner-flow steering and cleanup passed")
    elif args.queue_mode == "isolated":
        print("Capture ported-protocol declaration stays inside its chain and cleanup passed")
    elif args.queue_mode:
        print(f"Capture {args.queue_mode} queues, port steering, exact delivery, processing workers and cleanup passed")
    else:
        print(f"Capture with bypass-conntrack={not args.tracked}, exclusions={args.exclude_protocols}, fragments, scope, and cleanup passed")


if __name__ == "__main__":
    install_termination_handler()
    main()
