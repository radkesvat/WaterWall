#!/usr/bin/env python3
"""Source policy checks for worker thread identity and worker-context rules.

Two families of rules live here:

  * identity  - who may bind a thread to a worker slot at all;
  * context   - how code reaches worker-local state once it is bound.

The context rules exist because the failure mode they prevent is silent: a
`getWorkerBufferPool(getWID())` on an unregistered thread used to index a
shortcut array with the sentinel WID rather than fail. Every allowlist entry
below is a deliberate, reviewed exception - diagnostics that intentionally print
the sentinel, and the low-level identity implementation itself.
"""

import re
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SEARCH_DIRS = [ROOT / "core", ROOT / "ww", ROOT / "tunnels", ROOT / "scripts", ROOT / "tests"]

TL_WID_ASSIGNMENT_RE = re.compile(r"\btl_wid\s*=")
TEST_BIND_RE = re.compile(r"\btestWorker(?:Unbind|Bind)WID\b")
PROD_BIND_RE = re.compile(r"\bworker(?:Unbind|Bind)CurrentThread\b")

# `getWorkerXxx(getWID())` - a current-worker resource fetched by indexing with
# an unvalidated WID. Use the getCurrentEventWorkerXxx() accessors instead.
NESTED_CURRENT_WORKER_RE = re.compile(
    r"\bgetWorker(?:BufferPool|Loop|ContextPool|WiosPool|NowMS|NowUS)?\s*\(\s*getWID\s*\(\s*\)\s*\)"
)

# Raw worker-0 ownership decisions. currentThreadIsEventWorkerWID(0) says the
# same thing and cannot be passed by an unregistered or lwIP thread.
RAW_WORKER_ZERO_RE = re.compile(r"getWID\s*\(\s*\)\s*(?:==|!=)\s*0\b|\b0\s*(?:==|!=)\s*getWID\s*\(\s*\)")

# Raw affinity comparisons between the current thread and some other WID.
RAW_WID_COMPARISON_RE = re.compile(
    r"getWID\s*\(\s*\)\s*(?:==|!=)\s*[A-Za-z_(]|"
    r"\b(?:lineGetWID\s*\([^)]*\)|[A-Za-z_][A-Za-z0-9_.\->]*wid)\s*(?:==|!=)\s*getWID\s*\(\s*\)"
)

# Tunnel APIs must consume their message through the shared helpers in node.h.
TUNNEL_API_RECYCLE_RE = re.compile(r"\bbufferpoolReuseBuffer\s*\(\s*getWorkerBufferPool")

# A tunnel API owns its input buffer. Discarding it without releasing it leaks
# the buffer back to nobody, so the discard idioms are banned outright.
TUNNEL_API_DISCARD_RE = re.compile(r"^\s*(?:discard\s+message|\(\s*void\s*\)\s*message)\s*;")

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

# The checked accessors are implemented in terms of getWID(), so the files that
# define them are exempt from the nesting rule (rule 4).
ALLOWED_NESTED_CURRENT_WORKER_FILES = {
    (ROOT / "ww" / "instance" / "global_state.c").resolve(),
    (ROOT / "ww" / "instance" / "global_state.h").resolve(),
}

# The identity predicates themselves compare getWID() against a WID; that is what
# they exist to encapsulate. This is deliberately narrower than the rule-4 list -
# worker.c is *not* exempt from rule 4, so a getWorkerXxx(getWID()) creeping back
# into it is still caught.
ALLOWED_RAW_WID_COMPARISON_FILES = {
    (ROOT / "ww" / "instance" / "worker.c").resolve(),
    (ROOT / "ww" / "instance" / "worker.h").resolve(),
    (ROOT / "ww" / "instance" / "global_state.c").resolve(),
    (ROOT / "ww" / "instance" / "global_state.h").resolve(),
}

# Tunnel API entry points that legitimately manage their own pool ownership.
ALLOWED_TUNNEL_API_FILES = {
    # TlsClient returns a generated buffer and must keep the exact originating
    # pool for the request and the response through every error path.
    (ROOT / "tunnels" / "TlsClient" / "instance" / "api.c").resolve(),
}


def is_comment(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*")


def main() -> int:
    violations: list[str] = []

    for sdir in SEARCH_DIRS:
        if not sdir.exists():
            continue
        for ext in ("*.c", "*.h"):
            for path in sdir.rglob(ext):
                resolved_path = path.resolve()
                is_test_file = (ROOT / "tests") in resolved_path.parents or resolved_path.parent == (ROOT / "tests")
                is_tunnel_api = path.name == "api.c" and path.parent.name == "instance"

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

                    if is_test_file or is_comment(line):
                        continue

                    # Rule 4: No current-worker resource lookup through an unvalidated WID.
                    if NESTED_CURRENT_WORKER_RE.search(line) and resolved_path not in ALLOWED_NESTED_CURRENT_WORKER_FILES:
                        violations.append(
                            f"{path.relative_to(ROOT)}:{line_number}: getWorkerXxx(getWID()) nesting; "
                            f"use getCurrentEventWorkerXxx() so a non-event thread cannot index worker 0"
                        )

                    # Rule 5: Worker-0 ownership must be a named predicate, not raw equality.
                    if RAW_WORKER_ZERO_RE.search(line) and resolved_path not in ALLOWED_RAW_WID_COMPARISON_FILES:
                        violations.append(
                            f"{path.relative_to(ROOT)}:{line_number}: raw getWID() == 0 worker-0 decision; "
                            f"use currentThreadIsEventWorkerWID(0)"
                        )

                    # Rule 6: Affinity must be a named predicate, not raw equality.
                    if RAW_WID_COMPARISON_RE.search(line) and resolved_path not in ALLOWED_RAW_WID_COMPARISON_FILES:
                        violations.append(
                            f"{path.relative_to(ROOT)}:{line_number}: raw current-WID comparison; use "
                            f"currentThreadIsEventWorkerWID(wid) or lineIsOnCurrentEventWorker(line)"
                        )

                    # Rule 7: Tunnel APIs consume their message through node.h's shared helpers.
                    if is_tunnel_api and TUNNEL_API_RECYCLE_RE.search(line) and resolved_path not in ALLOWED_TUNNEL_API_FILES:
                        violations.append(
                            f"{path.relative_to(ROOT)}:{line_number}: tunnel API recycles its message by hand; "
                            f"use tunnelapiRecycleMessage()/tunnelapiUnsupportedMessage()"
                        )

                    # Rule 8: A tunnel API owns its input buffer and must consume it.
                    if is_tunnel_api and TUNNEL_API_DISCARD_RE.match(line):
                        violations.append(
                            f"{path.relative_to(ROOT)}:{line_number}: tunnel API discards its owned input buffer; "
                            f"consume it with tunnelapiRecycleMessage()/tunnelapiUnsupportedMessage()"
                        )

    if violations:
        print("\n".join(violations), file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
