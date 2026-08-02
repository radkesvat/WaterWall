#!/usr/bin/env python3
"""Source policy checks for non-blocking IpManipulator packet paths."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "tunnels" / "IpManipulator"


def main() -> int:
    violations: list[str] = []

    for path in sorted(SOURCE_ROOT.rglob("*.c")):
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "wwSleepMS" in line:
                violations.append(f"{path.relative_to(ROOT)}:{line_number}: synchronous wwSleepMS in packet tunnel")

    if violations:
        print("\n".join(violations), file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
