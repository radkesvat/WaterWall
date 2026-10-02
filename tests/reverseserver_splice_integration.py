#!/usr/bin/env python3
"""Waiting users pair with authenticated reverse peers, including cross-worker pairing. Fixed
secret/handshake bytes, replay/opaque echo and a retained unpaired half during shutdown143; endpoint
splice in both modes. Requires strace/network namespaces. CTest:
waterwall.reverseserver_workers_1_splice_false, waterwall.reverseserver_workers_1_splice_true,
waterwall.reverseserver_workers_2_splice_false, waterwall.reverseserver_workers_2_splice_true."""
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
from wwtest.sockets import connect_when_ready
from wwtest.config import core_config
from wwtest.run_directory import RunDirectory
from wwtest.process import Process, close_on_error, install_termination_handler

from wwtest.sockets import exact
from wwtest.trace import successful_calls


def run(binary, workers, enabled):
    tracer = shutil.which("strace")
    if tracer is None:
        raise RuntimeError("strace is required for pipe-to-socket evidence")
    settings = {"reverse-secret-length": 23, "reverse-secret": "paired"} if workers == 2 else {}
    secret = settings.get("reverse-secret", "").encode()
    handshake = bytes(0xff ^ (secret[i % len(secret)] if secret else 0)
                      for i in range(settings.get("reverse-secret-length", 640)))
    with RunDirectory("waterwall-reverse-splice-") as directory:
        root = Path(directory)
        nodes = [
            {"name": "peers", "type": "TcpListener", "next": "reverse",
             "settings": {"address": "127.0.0.1", "port": 27981, "nodelay": True}},
            {"name": "reverse", "type": "ReverseServer", "next": "bridge-reverse", "settings": settings},
            {"name": "bridge-reverse", "type": "Bridge", "settings": {"pair": "bridge-users"}},
            {"name": "users", "type": "TcpListener", "next": "bridge-users",
             "settings": {"address": "127.0.0.1", "port": 27982, "nodelay": True}},
            {"name": "bridge-users", "type": "Bridge", "settings": {"pair": "bridge-reverse"}},
        ]
        (root / "config.json").write_text(json.dumps({"name": "reverse-splice", "nodes": nodes}))
        (root / "core.json").write_text(json.dumps({
            "configs": ["config.json"],
            "log": core_config()["log"],
            "misc": {"workers": workers, "splice": enabled, "ram-profile": "minimal", "mtu": 1500,
                     "try-enabling-bbr": False, "tcp-tune": False},
        }))
        with (root / "stdout.log").open("w+") as log:
            with Process([tracer, '-D', '-f', '-yy', '-e', 'trace=splice', '-o', str(root / 'splice.log'), binary], cwd=root, log=log) as process:
                deadline = time.monotonic() + 10
                client = connect_when_ready(process, ('127.0.0.1', 27982), deadline=deadline,
                    failure=lambda: AssertionError('WaterWall exited during startup'), timeout=1, pause=0.02)
                with client:
                    client.settimeout(15)
                    client.sendall(b"local-first")
                    while "ReverseServer: no peer left" not in (root / "stdout.log").read_text():
                        if process.poll() is not None or time.monotonic() >= deadline:
                            raise AssertionError("local half did not enter the waiting list")
                        time.sleep(.01)
                    # These are consecutive accepts. With two workers, round-robin
                    # dispatch puts the waiting user and reverse peer on different WIDs.
                    with socket.create_connection(("127.0.0.1", 27981), timeout=5) as peer:
                        peer.settimeout(15)
                        peer.sendall(handshake)
                        assert exact(peer, 11) == b"local-first", "waiting replay changed bytes"
                        peer.sendall(b"ready")
                        assert exact(client, 5) == b"ready", "pair activation stalled"
                        boundary = len((root / "splice.log").read_text())
                        data = bytes(range(256)) * 4096
                        client.sendall(data)
                        assert exact(peer, len(data)) == data, "opaque user-to-peer data changed"
                        peer.sendall(data[::-1])
                        assert exact(client, len(data)) == data[::-1], "opaque peer-to-user data changed"
                        client.shutdown(socket.SHUT_RDWR)
                        assert peer.recv(1) == b"", "unexpected trailing bytes"
                # Keep an unpaired half with retained payload alive during owner drain.
                with socket.create_connection(("127.0.0.1", 27982), timeout=5) as waiting:
                    old_log_length = len((root / "stdout.log").read_text())
                    waiting.sendall(b"waiting during shutdown")
                    deadline = time.monotonic() + 10
                    while "ReverseServer: no peer left" not in (root / "stdout.log").read_text()[old_log_length:]:
                        if process.poll() is not None or time.monotonic() >= deadline:
                            raise AssertionError("shutdown half did not retain input")
                        time.sleep(.01)
                    process.send_signal(signal.SIGTERM)
                    assert process.wait(timeout=10) == 128 + signal.SIGTERM, "unclean reverse shutdown"
                calls = list(successful_calls((root / "splice.log").read_text()[boundary:]))
                outputs = [call for call in calls if re.match(
                    r"splice\(\d+<pipe:\[\d+\]>, NULL, \d+<TCP:", call)]
                if enabled:
                    assert any("127.0.0.1:27981->" in call for call in outputs), "reverse peer writes did not splice"
                    assert any("127.0.0.1:27982->" in call for call in outputs), "local user writes did not splice"
                else:
                    assert not calls, "splice occurred with misc.splice disabled"


if __name__ == "__main__":
    install_termination_handler()
    run(str(Path(sys.argv[1]).resolve()), int(sys.argv[2]), sys.argv[3] == "true")
    print("ReverseServer waiting, pairing, splice and shutdown passed")
