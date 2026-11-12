#!/usr/bin/env python3
"""HalfDuplex TCP ordering and response completion in a private loopback namespace.
Two workers stage first/ready before a 1 MiB reverse echo. Default mode checks bulk-only
pipe-to-socket traces and client-first closure; it requires strace. The server-close mode
closes the backend immediately after its response and requires every byte followed by EOF,
without first closing the client. Both modes require namespace support and termination 143.
Failed runs retain logs. CTest: waterwall.halfduplex_tcp_splice_{true,false} and
waterwall.halfduplex_tcp_response_close_{true,false}. Native units force cross-connection
Finish ordering; this integration checks the complete backend-close path over real TCP.
The separate/same path variants exercise named branches with real connector DNS helpers.
"""
import concurrent.futures
import argparse
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


def run(binary, enabled, server_closes=False, paths="shared"):
    tracer = None if server_closes else shutil.which("strace")
    if not server_closes and tracer is None:
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
        if paths != "shared":
            del nodes[1]["next"]
            nodes[1]["settings"] = {
                "upload": "transport",
                "download": "download-transport" if paths == "separate" else "transport",
            }
            if paths == "separate":
                nodes.append({"name": "download-transport", "type": "TcpConnector",
                              "settings": dict(nodes[2]["settings"])})
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
            command = ([binary] if server_closes else
                       [tracer, "-D", "-f", "-yy", "-e", "trace=splice", "-o",
                        str(root / "splice.log"), binary])
            with Process(command, cwd=root,
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
                        if not server_closes:
                            assert conn.recv(1) == b""

                # Close the client before joining the peer if a check fails;
                # the existing socket deadlines bound any unfinished exchange.
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor, client:
                    client.settimeout(15)
                    task = executor.submit(peer)
                    client.sendall(b"first")
                    assert exact(client, 5) == b"ready"
                    if not server_closes:
                        boundary = len((root / "splice.log").read_text())
                    client.sendall(data)
                    assert exact(client, len(data)) == data[::-1]
                    if server_closes:
                        assert client.recv(1) == b"", "server response did not end with EOF"
                    else:
                        client.shutdown(socket.SHUT_RDWR)
                    task.result(timeout=20)
                process.send_signal(signal.SIGTERM)
                assert process.wait(timeout=10) == 128 + signal.SIGTERM
                if server_closes:
                    return
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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("splice", choices=("true", "false"))
    parser.add_argument("close_mode", nargs="?", choices=("server-close",))
    parser.add_argument("--paths", choices=("shared", "separate", "same"), default="shared")
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, interrupted)
    server_closes = args.close_mode == "server-close"
    run(str(Path(args.binary).resolve()), args.splice == "true", server_closes, args.paths)
    print("HalfDuplex TCP response-close passed" if server_closes else
          "HalfDuplex staged TCP splice roundtrip passed")
