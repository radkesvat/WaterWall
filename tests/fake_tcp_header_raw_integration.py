#!/usr/bin/env python3
"""Two raw-socket peers with UDP-listener or TUN input and wire checks.

CTest: waterwall.fake_tcp_header_{raw,tun,raw_multiqueue}_roundtrip. Run only
through the network namespace wrapper; all addresses and firewall mutations
stay isolated. Options: --tun (TUN client input), --multi-queue (RawSocket
"multi-queue": true on both peers, which must bring up one queue per worker).
"""
import contextlib
import errno
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parent / "support" / "python")))
from wwtest.linux_commands import command, iptables
from wwtest.process import Process, install_termination_handler
from wwtest.run_directory import RunDirectory

WORKERS = 2
FLOWS = 6


def checksum(data):
    data += bytes(len(data) % 2)
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def flow_index(packet, count):
    """Reference for deviceFlowWorkerHash(packet) % count on one IPv4 packet."""
    ihl = (packet[0] & 15) * 4
    total, fragment = struct.unpack_from("!H2xH", packet, 2)
    protocol = packet[9]
    source, destination = struct.unpack_from("!II", packet, 12)
    source_word = destination_word = fragment_key = 0
    if fragment & 0x3FFF:
        fragment_key = 0x10000 | struct.unpack_from("!H", packet, 4)[0]
    elif protocol in (6, 17, 132) and total >= ihl + 4:
        source_word, destination_word = struct.unpack_from("!HH", packet, ihl)

    def endpoint(address, word):
        value = address ^ ((word * 0x9E3779B1) & 0xFFFFFFFF)
        value ^= value >> 16
        value = (value * 0x85EBCA6B) & 0xFFFFFFFF
        return value ^ (value >> 13)

    value = ((endpoint(source, source_word) + endpoint(destination, destination_word)) & 0xFFFFFFFF)
    value = ((value ^ protocol ^ fragment_key) * 0x9E3779B1) & 0xFFFFFFFF
    return (value ^ (value >> 16)) % count


# The codec unit's known answer: 10.0.0.1:5000 -> 10.0.0.2:53 UDP selects index 1 of 16.
assert flow_index(bytes.fromhex("452e002412344000401114650a0000010a000002138800350010"
                                "756366616b652d746370"), 16) == 1, "flow hash reference diverged from the codec"


def prepare(directory, role, listener_port, target_port, tun, multi_queue):
    example_role = "client-tun" if tun and role == "client" else role
    node_directory = "FakeTcpHeaderClient" if role == "client" else "FakeTcpHeaderServer"
    examples = Path(__file__).resolve().parent.parent / "tunnels" / node_directory / "examples" / example_role
    config = json.loads((examples / "config.json").read_text())
    core = json.loads((examples / "core.json").read_text())
    core["misc"].update(workers=WORKERS, mtu=1456)
    core["log"].update({name: {"loglevel": "DEBUG", "file": name + ".log", "console": True}
                         for name in ("core", "internal", "network", "dns")})
    carrier_ports = None
    for node in config["nodes"]:
        settings = node.setdefault("settings", {})
        if node["type"] == "RawSocket":
            settings.update({"capture-device-name": "fake-tcp-" + role, "skip-sysctl": True,
                             "multi-queue": multi_queue})
        elif node["type"] in ("FakeTcpHeaderClient", "FakeTcpHeaderServer"):
            settings["options"] = "01010101"
            carrier_ports = tuple(settings.get(key, default) for key, default in
                                  (("server-port", 40000), ("client-port", 40001), ("client-port-count", 16)))
        elif node["type"] == "ConnectionToPackets":
            settings["mtu"] = 1456
        elif node["type"] == "TunDevice":
            settings.update({"device-ip": "10.253.90.1/24", "device-mtu": 1456, "multi-queue": False})
        elif node["type"] == "UdpListener":
            settings["port"] = listener_port
        elif node["type"] == "UdpConnector":
            settings["port"] = target_port
    directory.mkdir()
    (directory / "config.json").write_text(json.dumps(config))
    (directory / "core.json").write_text(json.dumps(core))
    return carrier_ports


def run(binary, directory, tun, multi_queue):
    for address in ("192.0.2.10", "198.51.100.10"):
        command("ip", "address", "add", address + "/32", "dev", "lo")
    with contextlib.ExitStack() as stack:
        backend = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        backend.bind(("127.0.0.1", 0))
        backend.settimeout(5)
        reservation = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        reservation.bind(("127.0.0.1", 0))
        listener_port = reservation.getsockname()[1]
        reservation.close()
        processes, carrier_ports = [], set()
        for role in ("server", "client"):
            work = directory / role
            carrier_ports.add(prepare(work, role, listener_port, backend.getsockname()[1], tun, multi_queue))
            process = stack.enter_context(Process([binary], cwd=work, log_path=work / "stdout.log",
                                                   cleanup_signal=signal.SIGTERM, terminate_timeout=15))
            processes.append(process)
            deadline = time.monotonic() + 15
            # Multi-queue must not fall back to one queue, or it tests nothing new.
            queues = WORKERS if multi_queue else 1
            markers = [f"CaptureDevice: fake-tcp-{role} up with {queues} worker-owned receive queue(s)"]
            # Capture activates before workers bind normal listeners. A UDP
            # request sent in that gap is lost before entering the chain.
            if role == "client" and not tun:
                markers.append(f"SocketManager: listening on 127.0.0.1:[{listener_port}] (UDP)")
            while not all(marker in (work / "stdout.log").read_text() for marker in markers):
                process.check_running(role + " exited before capture activation")
                assert time.monotonic() < deadline, role + " input did not activate"
                time.sleep(0.05)
        assert len(carrier_ports) == 1, "example peers disagree on carrier ports"
        server_port, client_port, client_port_count = carrier_ports.pop()

        if tun:
            deadline = time.monotonic() + 10
            while True:
                processes[-1].check_running("client exited before TUN activation")
                result = subprocess.run(["ip", "-j", "address", "show", "dev", "wwfake0"],
                                        capture_output=True, text=True, timeout=10)
                interfaces = json.loads(result.stdout) if result.returncode == 0 else []
                if any("UP" in item["flags"] and item["mtu"] == 1456 and
                       any(address.get("local") == "10.253.90.1" for address in item.get("addr_info", []))
                       for item in interfaces):
                    break
                assert time.monotonic() < deadline, "TUN did not activate"
                time.sleep(0.05)

        # Genuine TCP from either captured peer IP must stay in the host stack.
        # It differs from the reserved fake carrier tuple only in its TCP ports.
        for local, peer in (("192.0.2.10", "198.51.100.10"), ("198.51.100.10", "192.0.2.10")):
            with socket.socket() as listener, socket.socket() as ordinary:
                listener.bind((peer, 0))
                listener.listen(1)
                listener.settimeout(5)
                ordinary.settimeout(5)
                ordinary.bind((local, 0))
                ordinary.connect(listener.getsockname())
                accepted, _ = listener.accept()
                with accepted:
                    accepted.settimeout(5)
                    ordinary.sendall(b"ordinary-tcp-request")
                    assert accepted.recv(128) == b"ordinary-tcp-request", "filter stole genuine TCP"
                    accepted.sendall(b"ordinary-tcp-reply")
                    assert ordinary.recv(128) == b"ordinary-tcp-reply", "filter stole genuine TCP reply"

        # These source addresses match the capture ranges, but protocol 17 must
        # still reach the ordinary host UDP socket on each receive side.
        for address in ("192.0.2.10", "198.51.100.10"):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as ordinary:
                ordinary.bind((address, 0))
                ordinary.sendto(b"unrelated-udp", backend.getsockname())
                assert backend.recv(65535) == b"unrelated-udp", "allowlist captured ordinary UDP"

        wire = stack.enter_context(socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)))
        wire.bind(("lo", 0))
        wire.settimeout(0.2)
        requests, responses = set(), set()
        seen = {"192.0.2.10": set(), "198.51.100.10": set()}
        observed_client_ports = set()

        def inspect(frame):
            packet = frame[14:]
            if len(packet) < 44 or packet[9] != 6:
                return
            source = socket.inet_ntoa(packet[12:16])
            if source not in seen:
                return
            packet = packet[:struct.unpack_from("!H", packet, 2)[0]]
            ihl = (packet[0] & 15) * 4
            tcp = packet[ihl:]
            ports = struct.unpack_from("!HH", tcp)
            # Every carrier has the server port on one side; anything else is genuine TCP.
            if server_port not in ports:
                return
            # Client -> server carriers run client range -> server port; replies are reversed.
            client_side, server_side = ports if source == "192.0.2.10" else ports[::-1]
            assert server_side == server_port, "carrier server port is on the wrong side"
            assert client_port <= client_side < client_port + client_port_count, \
                "carrier client port outside the configured range"
            assert len(packet) <= 1500, "carrier exceeded configured MTU"
            assert checksum(packet[:ihl]) == 0, "invalid IPv4 wire checksum"
            pseudo = packet[12:20] + struct.pack("!BBH", 0, 6, len(tcp))
            assert checksum(pseudo + tcp) == 0, "invalid TCP wire checksum"
            assert tcp[12] == 0x60 and tcp[13] == 0x18 and tcp[20:24] == bytes((1, 1, 1, 1)), \
                "configured TCP header/options or native flag setting did not reach wire"
            inner = tcp[24:]
            inner_ihl = (inner[0] & 15) * 4
            assert checksum(inner[:inner_ihl]) == 0 and inner[9] == 17, "invalid inner IPv4 UDP packet"
            assert len(inner) == struct.unpack_from("!H", inner, 2)[0] <= 1456
            assert client_side == client_port + flow_index(inner, client_port_count), \
                "carrier client port does not follow the inner flow mapping"
            udp = inner[inner_ihl:]
            assert struct.unpack_from("!H", udp, 4)[0] == len(udp)
            pseudo = inner[12:20] + struct.pack("!BBH", 0, 17, len(udp))
            assert udp[6:8] == bytes(2) or checksum(pseudo + udp) == 0, "invalid inner UDP checksum"
            if tun:
                expected_ips = ("10.253.90.1", "10.253.90.2")
                if source != "192.0.2.10":
                    expected_ips = expected_ips[::-1]
                assert (socket.inet_ntoa(inner[12:16]), socket.inet_ntoa(inner[16:20])) == expected_ips
            observed_client_ports.add(client_side)
            seen[source].add(udp[8:])

        def drain():
            while True:
                try:
                    inspect(wire.recv(65535))
                except TimeoutError:
                    return

        # Each user forces an independent UDP association, so an independent
        # inner flow and carrier port; boundary/odd lengths and binary bytes
        # cross both complete header conversion paths. With FLOWS users the
        # chance that every flow hashes to one client port is
        # client-port-count ** -(FLOWS - 1). Draining after each user keeps
        # the wire socket's receive buffer from overflowing.
        for user in range(FLOWS):
            application = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            application.bind(("10.253.90.1" if tun else "127.0.0.1", 0))
            application.settimeout(5)
            destination = ("10.253.90.2", listener_port) if tun else ("127.0.0.1", listener_port)
            if tun:
                application.setsockopt(socket.IPPROTO_IP, 10, 2)  # IP_MTU_DISCOVER, IP_PMTUDISC_DO
                try:
                    application.sendto(bytes(1429), destination)
                except OSError as error:
                    assert error.errno == errno.EMSGSIZE, "wrong oversized TUN datagram refusal"
                else:
                    raise AssertionError("TUN MTU admitted an oversized UDP datagram")
            for length in (1, 513, 1428):
                payload = bytes((i * 37 + user) & 255 for i in range(length))
                reply = bytes(value ^ 0xa5 for value in payload)
                application.sendto(payload, destination)
                actual, peer = backend.recvfrom(65535)
                assert actual == payload, "server did not deliver exact UDP payload"
                backend.sendto(reply, peer)
                actual, reply_peer = application.recvfrom(65535)
                assert actual == reply, "client did not restore exact UDP reply"
                assert reply_peer == destination, "client changed the original UDP source tuple"
                requests.add(payload)
                responses.add(reply)
            drain()

        deadline = time.monotonic() + 5
        while (seen["192.0.2.10"] != requests or seen["198.51.100.10"] != responses):
            assert time.monotonic() < deadline, "missing protocol-6 wire packets"
            try:
                inspect(wire.recv(65535))
            except TimeoutError:
                continue
        assert len(observed_client_ports) >= 2, \
            f"{FLOWS} inner flows shared client carrier port(s) {sorted(observed_client_ports)}"

        for process in reversed(processes):
            process.terminate()
            assert process.wait(timeout=15) in (0, 143), "peer failed orderly shutdown"
        assert "WWCAP" not in iptables("-S", "INPUT"), "capture rules survived shutdown"
        assert "WWCAP_NOTRACK" not in iptables("-t", "raw", "-S", "PREROUTING")
        assert "WWRAW_NOTRACK" not in iptables("-t", "raw", "-S", "OUTPUT")


def main():
    binary = str(Path(sys.argv[1]).resolve())
    options = sys.argv[2:]
    assert set(options) <= {"--tun", "--multi-queue"}, f"unknown options {options}"
    with RunDirectory(prefix="waterwall-fake-tcp-") as temporary:
        directory = Path(temporary)
        try:
            run(binary, directory, "--tun" in options, "--multi-queue" in options)
        except Exception:
            for log in directory.rglob("stdout.log"):
                print(f"{log}:\n{log.read_text()[-12000:]}", file=sys.stderr)
            raise
    print("Fake TCP wire headers, per-flow carrier ports, UDP/TUN request/reply, MTU, exact port filters "
          "and cleanup passed")


if __name__ == "__main__":
    install_termination_handler()
    main()
