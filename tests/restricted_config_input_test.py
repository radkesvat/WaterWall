#!/usr/bin/env python3
"""Exercise restricted startup rejection and diagnostic secrecy without OS effects."""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

SECRET = "SECRET_SENTINEL_MUST_NOT_APPEAR"


def run(binary, root, data, expected, *, restricted=True):
    env = os.environ.copy()
    env.pop("WW_CORE_JSON_INPUT", None)
    result = subprocess.run(
        [str(binary), *( ["--restricted-config"] if restricted else []), "--config:stdin"],
        input=data, cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=15, check=False,
    )
    output = result.stdout.decode("utf-8", errors="replace")
    if result.returncode == 0 or expected not in output or SECRET in output:
        raise AssertionError(f"expected failure containing {expected!r}, exit={result.returncode}:\n{output}")
    # Generated logs are also diagnostic emitters; do not check only the console.
    for path in root.glob("log/**/*"):
        if path.is_file() and SECRET.encode() in path.read_bytes():
            raise AssertionError(f"secret leaked to {path}")


def main():
    binary = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="ww-restricted-") as directory:
        root = Path(directory)
        core = json.dumps({"configs": ["nodes.json"], "misc": {
            "workers": 1, "ram-profile": "minimal", "try-enabling-bbr": False}}).encode()
        for data, error in [
            (b'{"x":' + SECRET.encode(), "JSON syntax"),
            (b'{}' + SECRET.encode(), "trailing input"),
            (b'{"x":1,"\\u0078":2}', "duplicate key"),
            (b'{"x":"\\u0000"}', "decoded NUL"),
            (b'{}\0' + SECRET.encode(), "NUL"),
            (b'{"x":"\xc0\xaf"}', "UTF-8"),
            (b' ' * (2 * 1024 * 1024 + 1), "input limit"),
        ]:
            run(binary, root, data, error)
        # Ordinary malformed JSON no longer dumps credentials either.
        run(binary, root, b'{"x":' + SECRET.encode(), "JSON Error at byte", restricted=False)

        node_cases = [
            ('{"variables":{"x":' + SECRET + '}}', "JSON syntax"),
            ('{"name":"x","nodes":[$' + SECRET + '$]}', "undefined variable"),
            ('{"name":"x","nodes":[]}' + SECRET, "trailing input"),
            ('{"name":"x","nodes":[{"name":"' + SECRET + '","type":"' + SECRET + '"}]}',
             "external nodes are disabled"),
            (json.dumps({"name": "x", "nodes": [{"name": "x", "type": "TunDevice", "settings": {
                "device-name": "wwtest", "device-ip": "10.0.0.1/24", "post-up-script": SECRET}}]}),
             "user scripts are disabled"),
            ('{"name":"x","variables":{"script":"' + SECRET + '"},"nodes":['
             '{"name":"x","type":"TunDevice","settings":{"device-name":"wwtest",'
             '"device-ip":"10.0.0.1/24","pre-down-script":$script$}}]}', "user scripts are disabled"),
            ('{"name":"x","nodes":[],' + '"padding":"' + 'x' * (8 * 1024 * 1024) + '"}', "input limit"),
        ]
        for data, error in node_cases:
            (root / "nodes.json").write_text(data, encoding="utf-8")
            run(binary, root, core, error)

        # A resolved 2-to-8 MiB derivative must reach node lookup, not a 2 MiB cap.
        (root / "nodes.json").write_text(json.dumps({"name": "large", "padding": "x" * (3 * 1024 * 1024),
            "nodes": [{"name": "x", "type": "UnknownRestrictedFixture"}]}), encoding="utf-8")
        run(binary, root, core, "external nodes are disabled")
        # User JSON cannot turn off the startup-owned policy.
        override = json.loads(core)
        override["restricted-config"] = False
        run(binary, root, json.dumps(override).encode(), "external nodes are disabled")
    print("restricted config input tests passed")


if __name__ == "__main__":
    main()
