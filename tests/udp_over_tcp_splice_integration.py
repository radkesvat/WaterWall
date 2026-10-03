#!/usr/bin/env python3
"""UDP-over-TCP datagram boundaries and carrier splice in a private loopback namespace.
Uses real UDP peers and both UdpOverTcp nodes; checks payload sizes through 65,505 bytes,
carrier socket-to-pipe reads in both directions, disabled splice and shutdown 143.
The UDP sender's temporary materialization guard remains enabled.
CTest: waterwall.udpovertcp_udp_splice_false; waterwall.udpovertcp_udp_splice_true.
"""
import concurrent.futures
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parent / "support" / "python")))
from wwtest.config import core_config
from wwtest.process import Process, close_on_error, install_termination_handler
from wwtest.run_directory import RunDirectory
from wwtest.trace import successful_calls

HOST, APP_PORT, PEER_PORT, BACKEND_PORT = "127.0.0.1", 27981, 27982, 27983


def run(binary, enabled):
    tracer = shutil.which("strace")
    if tracer is None:
        raise RuntimeError("strace is required for TCP carrier splice evidence")
    nodes = [
        {"name": "app", "type": "UdpListener", "next": "client",
         "settings": {"address": HOST, "port": APP_PORT}},
        {"name": "client", "type": "UdpOverTcpClient", "next": "carrier"},
        {"name": "carrier", "type": "TcpConnector",
         "settings": {"address": HOST, "port": PEER_PORT, "nodelay": True, "fastopen": False}},
        {"name": "peer", "type": "TcpListener", "next": "server",
         "settings": {"address": HOST, "port": PEER_PORT, "nodelay": True}},
        {"name": "server", "type": "UdpOverTcpServer", "next": "backend"},
        {"name": "backend", "type": "UdpConnector", "settings": {"address": HOST, "port": BACKEND_PORT}},
    ]
    sizes = [1, 63, 1024, 8000, 32768, 65505] * 2
    payloads = [bytes((i * 17 + index * 13) & 255 for i in range(size)) for index, size in enumerate(sizes)]
    probe = b"ready"
    with RunDirectory("waterwall-uot-udp-splice-") as directory:
        root = Path(directory)
        (root / "config.json").write_text(json.dumps({"name": "uot-splice", "nodes": nodes}))
        (root / "core.json").write_text(json.dumps({
            "configs": ["config.json"], "log": core_config()["log"],
            "misc": {"workers": 1, "splice": enabled, "ram-profile": "minimal", "mtu": 1500,
                     "try-enabling-bbr": False, "tcp-tune": False},
        }))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as backend:
            backend.bind((HOST, BACKEND_PORT))
            backend.settimeout(15)
            with Process([tracer, "-D", "-f", "-yy", "-e", "trace=splice", "-o", str(root / "splice.log"), binary],
                         cwd=root, log_path=root / "stdout.log") as process:
                def peer():
                    received = 0
                    while received < len(payloads):
                        data, address = backend.recvfrom(65536)
                        if data != probe:
                            assert data == payloads[received], f"UDP upload boundary/content changed at {received}"
                            received += 1
                        backend.sendto(data[::-1], address)

                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, close_on_error(client), \
                        concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(peer)
                    client.settimeout(0.1)
                    deadline = time.monotonic() + 10
                    while True:
                        process.check_running("WaterWall exited before UDP readiness")
                        client.sendto(probe, (HOST, APP_PORT))
                        try:
                            reply, _ = client.recvfrom(65536)
                            assert reply == probe[::-1], "UDP readiness payload changed"
                            break
                        except TimeoutError:
                            assert time.monotonic() < deadline, "UDP carrier did not become ready"
                    client.settimeout(15)
                    for index, data in enumerate(payloads):
                        client.sendto(data, (HOST, APP_PORT))
                        while True:
                            reply, address = client.recvfrom(65536)
                            if reply != probe[::-1]:
                                break
                        assert address == (HOST, APP_PORT) and reply == data[::-1], \
                            f"UDP download boundary/content changed at {index}"
                    future.result(timeout=20)
                process.send_signal(signal.SIGTERM)
                assert process.wait(timeout=10) == 128 + signal.SIGTERM, "unclean UdpOverTcp shutdown"
                calls = list(successful_calls((root / "splice.log").read_text()))
                if enabled:
                    inputs = set()
                    for call in calls:
                        match = re.match(r"splice\(\d+<TCP:\[([^]]+)\]>, NULL, \d+<pipe:", call)
                        if match:
                            endpoints = match.group(1)
                            if endpoints.startswith(f"{HOST}:{PEER_PORT}->"):
                                inputs.add("server")
                            if endpoints.endswith(f"->{HOST}:{PEER_PORT}"):
                                inputs.add("client")
                    assert inputs == {"client", "server"}, f"missing UDP-mode carrier splice reads: {inputs}"
                else:
                    assert not calls, "disabled UdpOverTcp carrier performed splice I/O"


if __name__ == "__main__":
    install_termination_handler()
    run(str(Path(sys.argv[1]).resolve()), sys.argv[2] == "true")
    print("UDP datagram boundaries, carrier splice policy and orderly shutdown passed")
