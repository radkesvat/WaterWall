#!/usr/bin/env python3
"""HalfDuplex TCP ordering and splice evidence in a private loopback namespace. Two workers and
client/server nodes stage first/ready before a 1 MiB reverse echo; checks exact bytes, EOF,
bulk-only pipe-to-socket traces for both endpoints and termination 143. Requires strace and
namespace support. Failed runs retain logs. CTest: waterwall.halfduplex_tcp_splice_{true,false}.
CTest: waterwall.halfduplex_tcp_splice_false, waterwall.halfduplex_tcp_splice_true."""
import concurrent.futures
import json
from pathlib import Path
import shutil
import signal
import socket
import sys
import os
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parent / "support" / "python")))
from wwtest.sockets import configure_listener

from wwtest.sockets import exact
from wwtest.trace import successful_calls
from wwtest.run_directory import RunDirectory
from wwtest.process import Process


def run(binary, enabled):
    tracer = shutil.which("strace")
    if tracer is None:
        raise RuntimeError("strace is required for pipe-to-socket evidence")
    with RunDirectory("waterwall-halfduplex-") as root:
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
        with socket.socket() as backend:
            configure_listener(backend, ('127.0.0.1', 27983), timeout=15)
            with Process([tracer, "-D", "-f", "-yy", "-e", "trace=splice", "-o",
                          str(root / "splice.log"), binary], cwd=root,
                         log_path=root / "stdout.log") as process:
                deadline = time.monotonic() + 10
                while True:
                    process.check_running("WaterWall exited during startup")
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

                # Close the client before joining the peer if a check fails;
                # the existing socket deadlines bound any unfinished exchange.
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor, client:
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



def interrupted(signum, _frame):
    # Let an outer timeout unwind sockets, peer joins and the owned process.
    raise SystemExit(128 + signum)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupted)
    run(str(Path(sys.argv[1]).resolve()), sys.argv[2] == "true")
    print("HalfDuplex staged TCP splice roundtrip passed")
