#!/usr/bin/env python3
"""Source policy checks for worker thread identity rules."""

import re
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SEARCH_DIRS = [ROOT / "core", ROOT / "ww", ROOT / "tunnels", ROOT / "scripts", ROOT / "tests"]

TL_WID_ASSIGNMENT_RE = re.compile(r"\btl_wid\s*=")
TEST_BIND_RE = re.compile(r"\btestWorker(?:Unbind|Bind)WID\b")
PROD_BIND_RE = re.compile(r"\bworker(?:Unbind|Bind)CurrentThread\b")

ALLOWED_TL_WID_FILES = {
    (ROOT / "ww" / "instance" / "worker.c").resolve(),
    (ROOT / "ww" / "instance" / "worker.h").resolve(),
}

ALLOWED_PROD_BIND_PRODUCTION_FILES = {
    (ROOT / "ww" / "instance" / "worker.c").resolve(),
    (ROOT / "ww" / "instance" / "worker.h").resolve(),
    (ROOT / "ww" / "instance" / "global_state.c").resolve(),
    (ROOT / "ww" / "lwip" / "contrib" / "ports" / "unix" / "port" / "sys_arch.c").resolve(),
}


def main() -> int:
    violations: list[str] = []

    for sdir in SEARCH_DIRS:
        if not sdir.exists():
            continue
        for ext in ("*.c", "*.h"):
            for path in sdir.rglob(ext):
                resolved_path = path.resolve()
                is_test_file = (ROOT / "tests") in resolved_path.parents or resolved_path.parent == (ROOT / "tests")

                text = path.read_text(encoding="utf-8", errors="replace")
                lines = text.splitlines()

                for line_number, line in enumerate(lines, 1):
                    # Rule 1: No direct assignment to tl_wid outside worker.c and worker.h
                    if TL_WID_ASSIGNMENT_RE.search(line) and resolved_path not in ALLOWED_TL_WID_FILES:
                        violations.append(
                            f"{path.relative_to(ROOT)}:{line_number}: direct assignment to tl_wid outside worker implementation"
                        )

                    # Rule 2: Test binding helpers (testWorkerBindWID/testWorkerUnbindWID) must not be called in production code
                    if TEST_BIND_RE.search(line) and not is_test_file and resolved_path != (ROOT / "ww" / "instance" / "worker.h").resolve():
                        violations.append(
                            f"{path.relative_to(ROOT)}:{line_number}: call to test worker binding helper in production code"
                        )

                    # Rule 3: Production binders must not be called outside approved worker entry/lifecycle files or tests
                    if PROD_BIND_RE.search(line) and not is_test_file and resolved_path not in ALLOWED_PROD_BIND_PRODUCTION_FILES:
                        violations.append(
                            f"{path.relative_to(ROOT)}:{line_number}: production call to workerBindCurrentThread/workerUnbindCurrentThread outside approved lifecycle files"
                        )

    if violations:
        print("\n".join(violations), file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
