"""Private artifacts whose lifetime encloses child and peer cleanup."""
import os
from pathlib import Path
import shutil
import sys
import tempfile


class RunDirectory:
    """Announce on creation; retain exceptions/skips and KEEP_RUN_DIR=1 successes.

    Use as the outermost context. Inner process/socket/executor contexts must
    finish cleanup before it exits. Inputs and logs are generated under path.
    """

    def __init__(self, prefix, *, parent=None):
        self.prefix = prefix
        self.parent = parent
        self.path = None

    def __enter__(self):
        return self.create()

    def create(self):
        """Explicit lifecycle for mains that catch failures and return statuses."""
        self.path = Path(tempfile.mkdtemp(prefix=self.prefix, dir=self.parent))
        print(f"Run artifacts: {self.path}", file=sys.stderr, flush=True)
        (self.path / "result.txt").write_text("initialized\n")
        return self.path

    def finish(self, status, *, keep_success=False):
        """Settle a captured enclosing verdict, including skip77/benchmark keep."""
        outcome = "passed" if status == 0 else "skipped" if status == 77 else "failed"
        (self.path / "result.txt").write_text(outcome + "\n")
        if status == 0 and not keep_success and os.environ.get("WATERWALL_TEST_KEEP_RUN_DIR") != "1":
            shutil.rmtree(self.path)
        else:
            print(f"Retained artifacts ({outcome}): {self.path}", file=sys.stderr, flush=True)

    def __exit__(self, exc_type, exc, traceback):
        outcome = "failed" if exc_type is not None else "passed"
        try:
            self.finish(0 if exc_type is None else 1)
        except BaseException as cleanup_error:
            if exc_type is None:
                raise
            print(f"Artifact cleanup also failed: {cleanup_error}; retained: {self.path}",
                  file=sys.stderr, flush=True)
        return False
