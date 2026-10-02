#!/usr/bin/env python3
"""HTTP authenticated fallback topology validation: absence/inert noauth, duplicate/invalid names,
cycles, conflicting previous and missing next. Namespace loopback listeners with BlackHole
substitutes; startup marker and rejection status, not payload forwarding. CTest:
waterwall.http_proxy_fallback_config."""
import copy
import json
from pathlib import Path
import sys
import signal
import os
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parent / "support" / "python")))
from wwtest.process import Process, install_termination_handler
from wwtest.run_directory import RunDirectory

from wwtest.config import core_config, STARTED_MARKER
from wwtest.process import stop_process


def run(binary, name, config, valid, duplicate=False):
    with RunDirectory(prefix="hps-fallback-") as directory:
        directory = Path(directory)
        (directory / "core.json").write_text(json.dumps(core_config()))
        text = json.dumps(config)
        if duplicate:
            text = text.replace('"fallback-node-name": "fallback"',
                                '"fallback-node-name": "fallback", "fallback-node-name": "fallback"')
        (directory / "config.json").write_text(text)
        with (directory / "output").open("w+") as output:
            with Process([str(binary)], cwd=directory, log=output, cleanup_signal=signal.SIGTERM) as process:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    output.seek(0)
                    log = output.read()
                    if STARTED_MARKER in log or process.poll() is not None:
                        break
                    time.sleep(.02)
                assert (STARTED_MARKER in log) == valid, (name, log)
                if not valid:
                    assert process.wait(timeout=3) != 0, (name, log)


def main():
    binary = Path(sys.argv[1]).resolve()
    base = {"name": "http-fallback-config", "nodes": [
        {"name": "listener", "type": "TcpListener", "settings": {"address": "127.0.0.1", "port": 29901}, "next": "proxy"},
        {"name": "proxy", "type": "HttpProxyServer", "settings": {"users": [{"username": "u", "password": "p"}],
         "fallback-node-name": "fallback"}, "next": "protected"},
        {"name": "protected", "type": "BlackHole", "settings": {"mode": "passive"}},
        {"name": "fallback", "type": "BlackHole", "settings": {"mode": "passive"}},
    ]}
    run(binary, "valid", base, True)
    run(binary, "duplicate", base, False, duplicate=True)
    for value in (None, 1, False, [], {}, "", "missing", "proxy", "protected", "proxy.user-controller"):
        config = copy.deepcopy(base)
        config["nodes"][1]["settings"]["fallback-node-name"] = value
        run(binary, f"invalid {value!r}", config, False)
    config = copy.deepcopy(base)
    del config["nodes"][1]["settings"]["fallback-node-name"]
    run(binary, "absent", config, True)
    config = copy.deepcopy(base)
    config["nodes"][1]["settings"] = {"no-auth": True, "fallback-node-name": "fallback"}
    run(binary, "inert no-auth", config, True)
    config = copy.deepcopy(base)
    config["nodes"][3] = {"name": "fallback", "type": "HttpProxyServer", "settings": {"no-auth": True}, "next": "proxy"}
    run(binary, "cycle", config, False)
    config = copy.deepcopy(base)
    config["nodes"].append({"name": "other-listener", "type": "TcpListener", "settings": {"address": "127.0.0.1", "port": 29902}, "next": "fallback"})
    run(binary, "conflicting previous", config, False)
    config = copy.deepcopy(base)
    del config["nodes"][1]["next"]
    run(binary, "missing protected next", config, False)
    config = copy.deepcopy(base)
    config["nodes"][1]["settings"]["fallback"] = "fallback"
    run(binary, "unknown alias", config, False)
    print("HttpProxyServer fallback configuration passed")


if __name__ == "__main__":
    install_termination_handler()
    main()
