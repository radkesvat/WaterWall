#!/usr/bin/env python3
"""Exercise RawSocket output through real raw sockets in a private network namespace."""

import contextlib
import json
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys
import tempfile
import time

from capture_linux_notrack_integration import command, iptables


def packets(port, payload, ident, fragmented=False):
    udp = struct.pack("!HHHH", 42000 + ident, port, len(payload) + 8, 0) + payload
    pieces = [(0, udp)] if not fragmented else [(0x2000, udp[:800]), (100, udp[800:])]
    for fragment, body in pieces:
        yield struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), ident, fragment, 64,
            socket.IPPROTO_UDP, 0, socket.inet_aton("127.0.0.2"), socket.inet_aton("127.0.0.1"),
        ) + body


def expect_counts(expected):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        rules = iptables("-t", "mangle", "-L", "WWRAW_TEST_CT", "-n", "-v", "-x", "--line-numbers")
        actual = tuple(int(m[1]) for m in re.finditer(r"^\s*\d+\s+(\d+)\s+\d+\s", rules, re.MULTILINE))
        if actual == expected:
            return
        time.sleep(0.02)
    raise AssertionError(f"output conntrack/mark counters: expected {expected}, got {actual}")


def connect_listener(process, port, deadline):
    # Raw writers start before SocketManager opens its TCP listeners. Keep the
    # successful connection for the test instead of opening a disposable probe.
    while process.poll() is None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError(f"TCP listener 127.0.0.1:{port} did not become ready")
        try:
            stream = socket.create_connection(("127.0.0.1", port), timeout=min(0.25, remaining))
        except (ConnectionRefusedError, TimeoutError):
            time.sleep(min(0.05, remaining))
            continue
        stream.settimeout(3)
        return stream
    raise AssertionError(f"Waterwall exited with status {process.returncode} before TCP listener {port} was ready")


def run(binary, directory):
    # Exact/masked policies must keep their unmarked match result. These rules
    # deliberately reserve bit 31 and require bits 16..23 to remain zero.
    command("ip", "-4", "rule", "add", "priority", "110", "fwmark", "0x80000000/0x80000000", "prohibit")
    command("ip", "-4", "rule", "add", "priority", "111", "fwmark", "0/0x00ff0000", "lookup", "main")
    iptables("-t", "raw", "-A", "OUTPUT", "-m", "mark", "--mark", "0x55550000",
             "-m", "comment", "--comment", "foreign-notrack", "-j", "CT", "--notrack")
    iptables("-t", "mangle", "-N", "WWRAW_TEST_CT")

    with contextlib.ExitStack() as stack:
        receiver = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        receiver.bind(("127.0.0.1", 0))
        receiver.settimeout(3)
        port = receiver.getsockname()[1]
        iptables("-t", "mangle", "-A", "OUTPUT", "-p", "udp", "--dport", str(port), "-j", "WWRAW_TEST_CT")
        iptables("-t", "mangle", "-A", "WWRAW_TEST_CT", "-m", "conntrack", "--ctstate", "UNTRACKED")
        iptables("-t", "mangle", "-A", "WWRAW_TEST_CT", "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED")
        iptables("-t", "mangle", "-A", "WWRAW_TEST_CT", "-m", "mark", "--mark", "0x13572468")

        names = ("auto-default", "auto-explicit", "custom-mark")
        policies = ({}, {"bypass-conntrack": True}, {"bypass-conntrack": False, "mark": 0x13572468})
        nodes = []
        listeners = []
        reservations = []
        for name, policy in zip(names, policies):
            listener = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            listener.bind(("127.0.0.1", 0))
            reservations.append(listener)
            listeners.append(listener.getsockname()[1])
            nodes.extend([
                {"name": name + "-tcp", "type": "TcpListener", "next": name + "-packets",
                 "settings": {"address": "127.0.0.1", "port": listeners[-1]}},
                {"name": name + "-packets", "type": "StreamToPackets", "next": name},
                {"name": name, "type": "RawSocket", "settings": {"fragment-policy": "preserve-fragments", "raw-device-name": name, **policy}},
            ])
            # The namespace contains no competing applications; reserve distinct
            # ephemeral ports until all three have been selected.

        core = {
            "configs": ["config.json"],
            "misc": {"workers": 1, "ram-profile": "client", "mtu": 1500, "try-enabling-bbr": False},
            "log": {"path": "log/", **{
                name: {"loglevel": "DEBUG", "file": name + ".log", "console": True}
                for name in ("internal", "core", "network", "dns")
            }},
        }
        (directory / "config.json").write_text(json.dumps({"name": "raw-notrack", "nodes": nodes}))
        (directory / "core.json").write_text(json.dumps(core))

        # Release only TCP reservations, keeping the receiving UDP socket open.
        # Sockets are closed idempotently again by ExitStack.
        for listener in reservations:
            listener.close()

        with (directory / "stdout.log").open("w") as log:
            process = subprocess.Popen([binary], cwd=directory, stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 15
                while not all(f"RawDevice: device {name} is now up" in (directory / "stdout.log").read_text()
                              for name in names):
                    if process.poll() is not None or time.monotonic() >= deadline:
                        raise AssertionError("raw writers did not become ready")
                    time.sleep(0.05)
                rules = iptables("-t", "raw", "-S", "OUTPUT")
                owned = [line for line in rules.splitlines() if "WWRAW_NOTRACK_" in line]
                marks = [int(re.search(r"--mark (0x[0-9a-f]+)", line)[1], 16) for line in owned]
                assert len(marks) == len(set(marks)) == 2, rules
                assert all(mark >= 0x10000 and mark & 0x80ff0000 == 0 for mark in marks), marks
                assert "WWCAP" not in iptables("-S", "INPUT")
                streams = [stack.enter_context(connect_listener(process, p, deadline))
                           for p in listeners]
                for index, stream in enumerate(streams):
                    payload = names[index].encode()
                    stream.sendall(b"".join(packets(port, payload, index + 1)))
                    assert receiver.recv(65535) == payload
                expect_counts((2, 1, 1))

                # The normal OUTPUT defrag hook still reassembles fragments,
                # and the reassembled datagram retains the NOTRACK mark.
                payload = bytes(1400)
                streams[0].sendall(b"".join(packets(port, payload, 4, fragmented=True)))
                assert receiver.recv(65535) == payload
                expect_counts((3, 1, 1))
                unrelated = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
                unrelated.sendto(b"unrelated", receiver.getsockname())
                assert receiver.recv(65535) == b"unrelated"
                expect_counts((3, 2, 1))

                process.terminate()
                assert process.wait(timeout=15) in (0, 143)
                remaining = iptables("-t", "raw", "-S", "OUTPUT")
                assert "WWRAW_NOTRACK_" not in remaining and "foreign-notrack" in remaining, remaining
                assert "WWCAP" not in iptables("-t", "raw", "-S", "PREROUTING")
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
    with tempfile.TemporaryDirectory(prefix="waterwall-raw-notrack-") as temporary:
        directory = Path(temporary)
        try:
            run(binary, directory)
        except Exception:
            log = directory / "stdout.log"
            if log.exists():
                print(log.read_text()[-20000:], file=sys.stderr)
            raise
    print("Raw output NOTRACK, opt-out, mark allocation, fragments, and cleanup passed")


if __name__ == "__main__":
    main()
