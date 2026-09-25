#!/usr/bin/env python3
"""Staged HalfDuplex TCP traffic through real sockets, in the namespace harness."""
import concurrent.futures
import json
from pathlib import Path
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


def run(binary, enabled):
    tracer = shutil.which("strace")
    if tracer is None:
        raise RuntimeError("strace is required for pipe-to-socket evidence")
    with tempfile.TemporaryDirectory(prefix="waterwall-halfduplex-") as directory:
        root = Path(directory)
        nodes = [
            {"name": "in", "type": "TcpListener", "next": "client",
             "settings": {"address": "127.0.0.1", "port": 27981, "nodelay": True}},
            {"name": "client", "type": "HalfDuplexClient", "next": "transport", "settings": {}},
            {"name": "transport", "type": "TcpConnector",
             "settings": {"address": "127.0.0.1", "port": 27982, "nodelay": True, "fastopen": False}},
            {"name": "remote", "type": "TcpListener", "next": "server",
             "settings": {"address": "127.0.0.1", "port": 27982, "nodelay": True}},
            {"name": "server", "type": "HalfDuplexServer", "next": "out", "settings": {}},
            {"name": "out", "type": "TcpConnector",
             "settings": {"address": "127.0.0.1", "port": 27983, "nodelay": True, "fastopen": False}},
        ]
        (root / "config.json").write_text(json.dumps({"name": "halfduplex", "nodes": nodes}))
        (root / "core.json").write_text(json.dumps({
            "configs": ["config.json"],
            "log": {"path": "log/", **{name: {"loglevel": "DEBUG", "file": name + ".log", "console": True}
                                      for name in ("internal", "core", "network", "dns")}},
            "misc": {"workers": 2, "splice": enabled, "ram-profile": "minimal", "mtu": 1500,
                     "try-enabling-bbr": False},
        }))
        with socket.socket() as backend, (root / "stdout.log").open("w+") as log:
            backend.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            backend.bind(("127.0.0.1", 27983))
            backend.listen()
            backend.settimeout(15)
            process = subprocess.Popen([tracer, "-D", "-f", "-yy", "-e", "trace=splice", "-o",
                                        str(root / "splice.log"), binary], cwd=root, stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 10
                while True:
                    if process.poll() is not None:
                        raise AssertionError("WaterWall exited during startup")
                    try:
                        client = socket.create_connection(("127.0.0.1", 27981), timeout=1)
                        break
                    except ConnectionRefusedError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.02)
                data = bytes(range(256)) * 4096

                def peer():
                    with backend.accept()[0] as conn:
                        conn.settimeout(15)
                        assert exact(conn, 5) == b"first"
                        conn.sendall(b"ready")
                        assert exact(conn, len(data)) == data
                        conn.sendall(data[::-1])
                        assert conn.recv(1) == b""

                with client, concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    client.settimeout(15)
                    task = executor.submit(peer)
                    client.sendall(b"first")
                    assert exact(client, 5) == b"ready"
                    boundary = len((root / "splice.log").read_text())
                    client.sendall(data)
                    assert exact(client, len(data)) == data[::-1]
                    client.shutdown(socket.SHUT_RDWR)
                    task.result(timeout=20)
                process.send_signal(signal.SIGTERM)
                assert process.wait(timeout=10) == 128 + signal.SIGTERM
                calls = list(successful_calls((root / "splice.log").read_text()[boundary:]))
                outputs = [c for c in calls if c.startswith("splice(") and "<pipe:" in c.split(", NULL, ")[0]
                           and "<TCP:" in c.split(", NULL, ")[1]]
                assert bool(outputs) == enabled, "pipe-to-socket evidence disagrees with misc.splice"
                if enabled:
                    assert any("->127.0.0.1:27983" in c for c in outputs), "server upload did not splice"
                    assert any("127.0.0.1:27981->" in c for c in outputs), "client download did not splice"
            except BaseException:
                log.flush()
                print((root / "stdout.log").read_text(), file=sys.stderr)
                raise
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    run(str(Path(sys.argv[1]).resolve()), sys.argv[2] == "true")
    print("HalfDuplex staged TCP splice roundtrip passed")
