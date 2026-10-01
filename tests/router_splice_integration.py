#!/usr/bin/env python3
"""Router and SniffRouter replay and opaque TCP transfers in the namespace harness."""
import concurrent.futures
import json
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
from trojanclient_splice_integration import exact
from httpproxyserver_splice_integration import successful_calls


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
    with tempfile.TemporaryDirectory(prefix="waterwall-router-splice-") as directory:
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
            "log": {"path": "log/", **{name: {"loglevel": "DEBUG", "file": name + ".log", "console": True}
                                      for name in ("internal", "core", "network", "dns")}},
            "misc": {"workers": 2, "splice": enabled, "ram-profile": "minimal", "mtu": 1500,
                     "try-enabling-bbr": False, "tcp-tune": False},
        }))
        with socket.socket() as target, socket.socket() as fallback, (root / "stdout.log").open("w+") as log:
            peers = {27992: target, 27993: fallback}
            for port, listener in peers.items():
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(("127.0.0.1", port))
                listener.listen()
                listener.settimeout(15)
            process = subprocess.Popen([tracer, "-D", "-f", "-yy", "-e", "trace=splice", "-o",
                                        str(root / "splice.log"), binary], cwd=root,
                                       stdout=log, stderr=subprocess.STDOUT)
            try:
                data = bytes(range(256)) * 4096
                for host, port in [("route.test", 27992)] + ([("other.test", 27993)] if sniffing else []):
                    deadline = time.monotonic() + 10
                    while True:
                        if process.poll() is not None:
                            raise AssertionError("WaterWall exited during startup")
                        try:
                            client = socket.create_connection(("127.0.0.1", 27991), timeout=1)
                            break
                        except ConnectionRefusedError:
                            if time.monotonic() >= deadline:
                                raise
                            time.sleep(0.02)
                    request = f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\ncoalesced-body".encode() if sniffing else b"first"

                    def peer():
                        with peers[port].accept()[0] as conn:
                            conn.settimeout(15)
                            assert exact(conn, len(request)) == request, "initial replay changed bytes"
                            conn.sendall(b"ready")
                            assert exact(conn, len(data)) == data, "opaque upload changed bytes"
                            conn.sendall(data[::-1])
                            assert conn.recv(1) == b"", "unexpected trailing bytes"

                    with client, concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
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
            except BaseException:
                log.flush()
                print((root / "stdout.log").read_text(), file=sys.stderr)
                raise
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    run(str(Path(sys.argv[1]).resolve()), sys.argv[2], sys.argv[3] == "true")
    print("Router staged TCP splice roundtrip passed")
