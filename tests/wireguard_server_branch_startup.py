#!/usr/bin/env python3
"""Each routed WireGuardServer starts its packet output on every worker before any UDP input."""

from contextlib import ExitStack
import json
import os
from pathlib import Path
import select
import signal
import socket
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR", str(HERE / "support" / "python")))
from wwtest.config import core_config
from wwtest.process import Process, install_termination_handler
from wwtest.run_directory import RunDirectory
from wwtest.sockets import configure_listener


WORKERS = 2
BRANCHES = ("default", "rule")


def run(binary):
    with RunDirectory("waterwall-wireguard-branch-startup-") as root, ExitStack() as sockets:
        listeners = {}
        nodes = [
            {"name": "ingress", "type": "UdpListener", "next": "route",
             "settings": {"address": "127.0.0.1", "port": 28970}},
            {"name": "route", "type": "Router", "next": "default-server",
             "settings": {"rules": [{"source-ips": "127.0.0.2/32", "target": "rule-server"}]}},
        ]
        for branch in BRANCHES:
            listener = sockets.enter_context(socket.socket())
            configure_listener(listener, ("127.0.0.1", 0), timeout=2)
            listeners[listener] = branch
            nodes.extend([
                {"name": f"{branch}-server", "type": "WireGuardServer", "next": f"{branch}-bridge",
                 "settings": {"mode": "packet", "privatekey": "EBJOHctLU2w8uteyTE+WU0hruB09Ub0vwVS+Gt9wAls=",
                              "peers": [{"publickey": "dDUfRvZSDy8jZBsB4kQflTO+iwlLbR+jgb840fumqUM=",
                                         "allowedips": "10.44.0.1/32"}]}},
                {"name": f"{branch}-bridge", "type": "PacketsToStream", "next": f"{branch}-tcp",
                 "settings": {"protocol": "tcp"}},
                {"name": f"{branch}-tcp", "type": "TcpConnector",
                 "settings": {"address": "127.0.0.1", "port": listener.getsockname()[1], "fastopen": False}},
            ])

        (root / "core.json").write_text(json.dumps(core_config(workers=WORKERS)))
        (root / "config.json").write_text(json.dumps({"name": "wireguard-branch-startup", "nodes": nodes}))
        with Process([binary], cwd=root, log_path=root / "stdout.log") as process:
            counts = dict.fromkeys(BRANCHES, 0)
            deadline = time.monotonic() + 8
            while min(counts.values()) < WORKERS:
                process.check_running("WaterWall exited before both packet branches started")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AssertionError(f"expected {WORKERS} startup connections per branch, got {counts}")
                for listener in select.select(listeners, [], [], min(remaining, 0.25))[0]:
                    connection, _ = listener.accept()
                    sockets.enter_context(connection)  # Keep every stream open through shutdown.
                    branch = listeners[listener]
                    counts[branch] += 1
                    if counts[branch] > WORKERS:
                        raise AssertionError(f"extra startup connection on {branch}: {counts}")

            # An extra connection can already be queued behind a worker's first connection.
            if select.select(listeners, [], [], 0.25)[0]:
                raise AssertionError(f"additional startup connections after observing {counts}")
            process.send_signal(signal.SIGTERM)
            if process.wait(timeout=5) != 128 + signal.SIGTERM:
                raise AssertionError(f"unexpected shutdown status {process.returncode}")
            if select.select(listeners, [], [], 0)[0]:
                raise AssertionError(f"additional connections queued at shutdown after observing {counts}")


if __name__ == "__main__":
    install_termination_handler()
    run(str(Path(sys.argv[1]).resolve()))
