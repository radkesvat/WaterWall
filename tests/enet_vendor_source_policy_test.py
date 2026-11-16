#!/usr/bin/env python3
"""ENet vendor source policy.

ww/vendor/enet must match the pinned upstream base plus the local patches
documented in README.waterwall.md (line endings aside). It must not gain extra C
sources or headers, and tunnels/Internals/EnetCommon/CMakeLists.txt must build the
protocol core without ever naming upstream's socket layer (unix.c, win32.c).
CTest selection: waterwall.enet_vendor_source_policy. Direct run:
python3 tests/enet_vendor_source_policy_test.py
"""

import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / "ww" / "vendor" / "enet"
PINNED_COMMIT = "5a9c537fd464b3c6d3c55e1d3bd47588faf71b42"

# Digests cover the final vendored contents, including documented local patches.
EXPECTED = {
    "LICENSE": "a29cd246638974da7c6edf423a0a69d4a6f7d759940b7cfa9a2bc3442ac3834c",
    "callbacks.c": "0d42c2a191c7d22ed0da2b14617b958cce2efd2a185b3aef9fe51a0fb6704ba2",
    "compress.c": "6af9da787bf5aaeb44befcf4e4a822d6e4d0972279bac73004f628bf06788774",
    "host.c": "396e27689fe5ad6cc88d3a96fb93fa274f951663fe2f627391ab8f48a6d95830",
    "list.c": "c5350bfa7b7d3cc49fa4b2ebab92e359995e4b1ca47c2c17b0fa338dad87e5a4",
    "packet.c": "748eb4df8ec5d4c43476f7cde2d426337be4995e6e4bbca5b7fdba6a5d876fed",
    "peer.c": "8e5433a8432b21b063d9b5ac5113537b29618f00aea31a3c46b1c87b6e179140",
    "protocol.c": "c28b4031dc4556680be9b30016c54f1090a49663988730b389f3a9ad967115f4",
    "unix.c": "00f402d35728971b6c9b0034c4071dd0b500d0fe0ea1dc2d70eb8a57ad3b6c14",
    "win32.c": "f0fac54476f530d83d4ad2936ae8780988c4200ea19ed06093963e8fbde7085b",
    "include/enet/callbacks.h": "7614442f4fda137bbb4969cf6e9286e50bf2f444c9c50a1cecd0f4d7bbddf9cb",
    "include/enet/enet.h": "8ad1fc4d68b2eddae97080d6a5510b561f5a0b776623ec32d757a452b6e63c74",
    "include/enet/list.h": "3e5ab637f767a71fc8027946d10cec291c0d8fc66355169afb208ec9ec2e5c46",
    "include/enet/protocol.h": "32de2a7e94e7dcfdf1b9fae2e4cde44f2e44ef49e9a1c4a9dac2165289da281f",
    "include/enet/time.h": "808d5c402c908c14afd0df385855a1b8713e5f69a04008c341a70928647d3e6e",
    "include/enet/types.h": "543482db06a0086983641f550effec827e0ccf722667d4e1956cc92cb074dca6",
    "include/enet/unix.h": "c37171b9f5f37e813059f6e37f247d32ae96037b6f2165d743fc757c6ea80c83",
    "include/enet/utility.h": "ffa3d79a59c11c5bf043d3f7f49e2524dedd3a4345af605b9c12121e9f4079a8",
    "include/enet/win32.h": "4edb38055710520fa980bac74cc84702bf8d5d43bf0c9a5df0427bd764f41f3a",
}

BUILD_LIST = ROOT / "tunnels" / "Internals" / "EnetCommon" / "CMakeLists.txt"
REQUIRED_CORE = ("callbacks.c", "host.c", "list.c", "packet.c", "peer.c", "protocol.c")
SOCKET_LAYER = ("unix.c", "win32.c")


def vendor_failures():
    failures = []
    for relative, expected in sorted(EXPECTED.items()):
        path = VENDOR / relative
        if not path.is_file():
            failures.append(f"ww/vendor/enet/{relative}: missing")
            continue
        digest = hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
        if digest != expected:
            failures.append(
                f"ww/vendor/enet/{relative}: differs from pinned vendor contents "
                f"(upstream {PINNED_COMMIT[:12]} plus documented local patches)"
            )
    if VENDOR.is_dir():
        for path in sorted(VENDOR.rglob("*")):
            relative = path.relative_to(VENDOR).as_posix()
            if path.suffix in (".c", ".h") and relative not in EXPECTED:
                failures.append(f"ww/vendor/enet/{relative}: not part of the pinned upstream file set")
    return failures


def build_list_failures():
    if not BUILD_LIST.is_file():
        return ["tunnels/Internals/EnetCommon/CMakeLists.txt: missing"]
    text = BUILD_LIST.read_text(encoding="utf-8")
    failures = []
    for name in REQUIRED_CORE:
        if f"/{name}" not in text:
            failures.append(f"tunnels/Internals/EnetCommon/CMakeLists.txt: does not build {name}")
    for name in SOCKET_LAYER:
        if name in text:
            failures.append(f"tunnels/Internals/EnetCommon/CMakeLists.txt: must not mention {name}")
    return failures


def main():
    failures = vendor_failures() + build_list_failures()
    for failure in failures:
        print(failure)
    if failures:
        return 1
    print(
        f"enet vendor policy: {len(EXPECTED)} files match pinned vendor contents "
        f"(upstream {PINNED_COMMIT[:12]} plus documented local patches)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
