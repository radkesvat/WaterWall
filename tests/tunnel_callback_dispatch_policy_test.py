#!/usr/bin/env python3
"""Keep tunnel flow delivery on the bypass-aware dispatch helpers.

Scan tunnel C sources and headers for callback-field reads, including calls,
captures and callback arguments. Handler assignments are allowed. Comments and
literals are ignored using the existing lexical scanner; this is not C type
analysis. CTest: waterwall.tunnel_callback_dispatch_policy.
"""

import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests" / "support" / "python"))
from wwtest.source_policy import line_of, mask_source


CALLBACK_FIELD = re.compile(r"(?:->|\.)\s*(fn(?:Init|Est|Payload|Fin|Pause|Resume)[UD])\b")
HANDLER_ASSIGNMENT = re.compile(r"\s*=(?!=)")


def violations(source: str):
    masked = mask_source(source)
    for match in CALLBACK_FIELD.finditer(masked):
        if not HANDLER_ASSIGNMENT.match(masked, match.end()):
            yield line_of(masked, match.start()), match.group(1)


def main() -> int:
    failures = []
    for path in sorted((ROOT / "tunnels").rglob("*")):
        if path.suffix not in {".c", ".h"} or not path.is_file():
            continue
        source = path.read_text(encoding="utf-8")
        # Most files, including vendored dependencies, have no relevant fields.
        if not CALLBACK_FIELD.search(source):
            continue
        for line, field in violations(source):
            failures.append(
                f"{path.relative_to(ROOT)}:{line}: read of {field}; "
                "use tunnelUpStream*/tunnelDownStream* or their Next/Prev helpers"
            )
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("Tunnel flow callbacks use dispatch helpers; no callback-field reads found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
