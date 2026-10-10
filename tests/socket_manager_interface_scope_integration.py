#!/usr/bin/env python3
"""TCP/UDP interface dispatch through two real veth ingress paths in private namespaces.

Both registration orders and balancing modes must reach the interface's marker.
Clients live outside the listener namespace; loopback destination aliases cannot
establish this regression. CTest: waterwall.socket_manager_{tcp,udp}_interface_scope.
"""
import contextlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parent / "support" / "python")))
from wwtest.config import STARTED_MARKER, core_config
from wwtest.fixtures.socket_manager import (MarkerServers, TcpMarkerServer, UdpMarkerServer,
                                           expect_tcp_marker, expect_udp_marker)
from wwtest.linux_commands import command
from wwtest.process import Process, install_termination_handler, stop_process
from wwtest.run_directory import RunDirectory

PORT = 23920
ADDRESSES = ("10.254.230.1", "10.254.230.5")


@contextlib.contextmanager
def ingress_interfaces():
    peers = []
    try:
        for index in range(2):
            peer = subprocess.Popen(["unshare", "--net", sys.executable, "-c",
                                     "import sys; sys.stdin.read()"], stdin=subprocess.PIPE)
            peers.append(peer)
            # Wait for unshare to enter its namespace before moving the veth.
            deadline = time.monotonic() + 3
            while os.readlink(f"/proc/{peer.pid}/ns/net") == os.readlink("/proc/self/ns/net"):
                assert peer.poll() is None and time.monotonic() < deadline, "client namespace did not start"
                time.sleep(0.01)
            inside, outside = f"wwin{index}", f"wwpeer{index}"
            command("ip", "link", "add", inside, "type", "veth", "peer", "name", outside)
            command("ip", "addr", "add", ADDRESSES[index] + "/30", "dev", inside)
            command("ip", "link", "set", inside, "up")
            command("ip", "link", "set", outside, "netns", str(peer.pid))
            prefix = ("nsenter", "-t", str(peer.pid), "-n", "ip")
            command(*prefix, "link", "set", "lo", "up")
            command(*prefix, "addr", "add", f"10.254.230.{2 + index * 4}/30", "dev", outside)
            command(*prefix, "link", "set", outside, "up")
        yield peers
    finally:
        for peer in peers:
            peer.stdin.close()
            stop_process(peer)
        for index in range(len(peers)):
            subprocess.run(["ip", "link", "del", f"wwin{index}"], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=3, check=False)


def run(binary, protocol):
    parent_netns = os.environ.get("WATERWALL_TEST_PARENT_NETNS")
    assert parent_netns and os.readlink("/proc/self/ns/net") != parent_netns, \
        "run this case through run_in_network_namespace.sh"
    server_type = TcpMarkerServer if protocol == "tcp" else UdpMarkerServer
    markers = [f"{protocol}-interface-{index}\n".encode() for index in range(2)]
    with ingress_interfaces() as peers, MarkerServers(*[
            server_type("127.0.0.1", PORT + 1 + index, markers[index]) for index in range(2)]):
        for reverse in (False, True):
            for balanced in (False, True):
                nodes = []
                for index in ((1, 0) if reverse else (0, 1)):
                    settings = {"address": "0.0.0.0", "port": PORT, "interface": f"wwin{index}"}
                    if balanced:
                        settings["balance-group"] = "interface-scope"
                    nodes.extend([
                        {"name": f"in{index}", "type": protocol.capitalize() + "Listener",
                         "settings": settings, "next": f"out{index}"},
                        {"name": f"out{index}", "type": protocol.capitalize() + "Connector",
                         "settings": {"address": "127.0.0.1", "port": PORT + 1 + index}},
                    ])
                with RunDirectory("waterwall-interface-scope-") as directory:
                    root = Path(directory)
                    (root / "config.json").write_text(json.dumps({"name": "scope", "nodes": nodes}))
                    (root / "core.json").write_text(json.dumps(core_config(
                        workers=2, **{"tcp-tune": False, "splice": False})))
                    with Process([binary], cwd=root, log_path=root / "stdout.log") as runtime:
                        deadline = time.monotonic() + 5
                        while STARTED_MARKER not in (root / "stdout.log").read_text():
                            runtime.check_running("WaterWall exited before interface probe")
                            assert time.monotonic() < deadline, "listener startup timed out"
                            time.sleep(0.02)
                        for index, peer in enumerate(peers):
                            try:
                                command("nsenter", "-t", str(peer.pid), "-n", sys.executable,
                                        str(Path(__file__).resolve()), "--client", protocol,
                                        ADDRESSES[index], str(PORT), markers[index].decode())
                            except subprocess.CalledProcessError as error:
                                raise AssertionError(error.output.strip()) from error
                        runtime.send_signal(signal.SIGTERM)
                        assert runtime.wait(timeout=5) == 128 + signal.SIGTERM, "unclean listener shutdown"
                print(f"{protocol}: order={'reverse' if reverse else 'forward'}, balance={balanced} passed")


if __name__ == "__main__":
    install_termination_handler()
    if sys.argv[1] == "--client":
        expect = expect_tcp_marker if sys.argv[2] == "tcp" else expect_udp_marker
        for _ in range(3):
            expect(sys.argv[3], int(sys.argv[4]), sys.argv[5].encode(), timeout=2)
    else:
        run(str(Path(sys.argv[1]).resolve()), sys.argv[2])
