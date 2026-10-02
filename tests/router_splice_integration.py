#!/usr/bin/env python3
"""Metadata/resolve/sniff route selection and retained HTTP-prefix replay to selected/default socket
peers. Two workers, staged opaque reverse echo, selected endpoint splice and shutdown143. Requires
strace/network namespaces; actual client connections are retained as readiness. CTest:
waterwall.router_metadata_tcp_splice_false, waterwall.router_metadata_tcp_splice_true,
waterwall.router_resolve_tcp_splice_false, waterwall.router_resolve_tcp_splice_true,
waterwall.router_sniff_tcp_splice_false, waterwall.router_sniff_tcp_splice_true,
waterwall.sniffrouter_tcp_splice_false, waterwall.sniffrouter_tcp_splice_true."""
import concurrent.futures
import json
from pathlib import Path
import re
import shutil
import signal
import socket
import sys
import os
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parent / "support" / "python")))
from wwtest.sockets import configure_listener, connect_when_ready
from wwtest.config import core_config
from wwtest.run_directory import RunDirectory
from wwtest.process import Process, close_on_error, install_termination_handler

from wwtest.sockets import exact
from wwtest.trace import successful_calls


def run(binary, mode, enabled):
    tracer = shutil.which("strace")
    if tracer is None:
        raise RuntimeError("strace is required for pipe-to-socket evidence")
    sniffing = mode in ("router_sniff", "sniffrouter")
    if mode == "sniffrouter":
        settings = {"routes": [{"domain": "route.test", "detection": "http1", "next": "target"}]}
    elif sniffing:
        settings = {"sniffing": ["http1"], "rules": [{"destination-domain": "route.test", "target": "target"}]}
    else:
        settings = {"resolve-domains": mode == "router_resolve",
                    "rules": [{"source-port": 27991, "target": "target"}]}
    with RunDirectory("waterwall-router-splice-") as directory:
        root = Path(directory)
        nodes = [
            {"name": "in", "type": "TcpListener", "next": "router",
             "settings": {"address": "127.0.0.1", "port": 27991, "nodelay": True}},
            {"name": "router", "type": "SniffRouter" if mode == "sniffrouter" else "Router",
             "next": "default", "settings": settings},
            {"name": "target", "type": "TcpConnector",
             "settings": {"address": "127.0.0.1", "port": 27992, "nodelay": True, "fastopen": False}},
            {"name": "default", "type": "TcpConnector",
             "settings": {"address": "127.0.0.1", "port": 27993, "nodelay": True, "fastopen": False}},
        ]
        (root / "config.json").write_text(json.dumps({"name": mode, "nodes": nodes}))
        (root / "core.json").write_text(json.dumps({
            "configs": ["config.json"],
            "log": core_config()["log"],
            "misc": {"workers": 2, "splice": enabled, "ram-profile": "minimal", "mtu": 1500,
                     "try-enabling-bbr": False, "tcp-tune": False},
        }))
        with socket.socket() as target, socket.socket() as fallback, (root / "stdout.log").open("w+") as log:
            peers = {27992: target, 27993: fallback}
            for port, listener in peers.items():
                configure_listener(listener, ('127.0.0.1', port), timeout=15)
            with Process([tracer, '-D', '-f', '-yy', '-e', 'trace=splice', '-o', str(root / 'splice.log'), binary], cwd=root, log=log) as process:
                data = bytes(range(256)) * 4096
                for host, port in [("route.test", 27992)] + ([("other.test", 27993)] if sniffing else []):
                    deadline = time.monotonic() + 10
                    client = connect_when_ready(process, ('127.0.0.1', 27991), deadline=deadline,
                        failure=lambda: AssertionError('WaterWall exited during startup'), timeout=1, pause=0.02)
                    request = f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\ncoalesced-body".encode() if sniffing else b"first"

                    def peer():
                        with peers[port].accept()[0] as conn:
                            conn.settimeout(15)
                            assert exact(conn, len(request)) == request, "initial replay changed bytes"
                            conn.sendall(b"ready")
                            assert exact(conn, len(data)) == data, "opaque upload changed bytes"
                            conn.sendall(data[::-1])
                            assert conn.recv(1) == b"", "unexpected trailing bytes"

                    with client, concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor, close_on_error(client):
                        client.settimeout(15)
                        task = executor.submit(peer)
                        client.sendall(request)
                        assert exact(client, 5) == b"ready"
                        boundary = len((root / "splice.log").read_text())
                        client.sendall(data)
                        assert exact(client, len(data)) == data[::-1], "opaque download changed bytes"
                        client.shutdown(socket.SHUT_RDWR)
                        task.result(timeout=20)
                    calls = list(successful_calls((root / "splice.log").read_text()[boundary:]))
                    outputs = [call for call in calls if re.match(
                        r"splice\(\d+<pipe:\[\d+\]>, NULL, \d+<TCP:", call)]
                    if enabled:
                        assert any(f"->127.0.0.1:{port}" in call for call in outputs), "selected route upload did not splice"
                        assert any("127.0.0.1:27991->" in call for call in outputs), "router download did not splice"
                    else:
                        assert not calls, "splice occurred with misc.splice disabled"
                process.send_signal(signal.SIGTERM)
                assert process.wait(timeout=10) == 128 + signal.SIGTERM, "unclean shutdown"


if __name__ == "__main__":
    install_termination_handler()
    run(str(Path(sys.argv[1]).resolve()), sys.argv[2], sys.argv[3] == "true")
    print("Router staged TCP splice roundtrip passed")
