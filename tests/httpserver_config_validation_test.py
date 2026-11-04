#!/usr/bin/env python3
"""HttpServer close-drain timeout constructor coverage through the real runtime.

Accept omission and boundary integers; reject malformed values and embedded-NUL
key aliases, including aliases beside a valid duplicate. Namespace loopback only.
CTest: waterwall.httpserver_close_drain_config.
"""

import json
import os
from pathlib import Path
import signal
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parent / "support" / "python")))
from wwtest.config import core_config, STARTED_MARKER
from wwtest.process import Process, install_termination_handler
from wwtest.run_directory import RunDirectory


SETTING = "close-drain-timeout-ms"


def run_case(binary, name, extra, valid):
    config = {"name": "httpserver-close-drain-config", "nodes": [
        {"name": "listener", "type": "TcpListener", "next": "http",
         "settings": {"address": "127.0.0.1", "port": 29903}},
        {"name": "http", "type": "HttpServer", "next": "sink",
         "settings": {"http-version": "2", "host": "h2.example.test", **extra}},
        {"name": "sink", "type": "BlackHole", "settings": {"mode": "passive"}},
    ]}
    with RunDirectory("waterwall-httpserver-config-" + name + "-") as root:
        (root / "core.json").write_text(json.dumps(core_config()))
        (root / "config.json").write_text(json.dumps(config))
        output_path = root / "stdout.log"
        with Process([str(binary)], cwd=root, log_path=output_path) as process:
            deadline = time.monotonic() + 8
            while process.poll() is None and time.monotonic() < deadline:
                output = output_path.read_text(errors="replace")
                if STARTED_MARKER in output:
                    assert valid, f"{name}: invalid configuration reached startup"
                    process.send_signal(signal.SIGTERM)
                    assert process.wait(timeout=10) == 128 + signal.SIGTERM, name
                    return
                time.sleep(0.01)
            output = output_path.read_text(errors="replace")
            assert not valid, f"{name}: valid configuration failed startup\n{output}"
            assert process.poll() is not None, f"{name}: invalid configuration did not exit"
            assert process.returncode > 0, f"{name}: invalid configuration succeeded or crashed\n{output}"
            assert "HttpServer" in output and SETTING in output, \
                f"{name}: missing setting-specific diagnostic\n{output}"


def main():
    binary = Path(sys.argv[1]).resolve()
    run_case(binary, "omitted", {}, True)
    for value in (1, 30000, 86400000):
        run_case(binary, f"valid-{value}", {SETTING: value}, True)
    invalid = (None, False, True, "1000", [], {}, 0, -1, 1.5, 86400001, 1e20)
    for index, value in enumerate(invalid):
        run_case(binary, f"invalid-{index}", {SETTING: value}, False)
    alias = SETTING + "\0suffix"
    run_case(binary, "nul-alias", {alias: 1000}, False)
    run_case(binary, "nul-alias-after-valid", {SETTING: 1000, alias: 1000}, False)
    run_case(binary, "nul-alias-before-valid", {alias: 1000, SETTING: 1000}, False)
    print("HttpServer close-drain timeout constructor: 18 cases passed")


if __name__ == "__main__":
    install_termination_handler()
    main()
