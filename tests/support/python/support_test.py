#!/usr/bin/env python3
"""Focused socket/trace and artifact/process failure checks (support lane).

No WaterWall binary or namespace needed. POSIX process-group cleanup is exercised with short private
child fixtures; intentionally failed inner directories live inside this check's own run directory,
retained if the check fails or KEEP=1. CTest: waterwall.python_test_support."""
import argparse
from contextlib import redirect_stderr
import io
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from wwtest.process import Process, close_on_error, run_logged
from wwtest.run_directory import RunDirectory
from wwtest.sockets import exact
from wwtest.trace import successful_calls


class Helpers(unittest.TestCase):
    root = None

    def child(self, mode, directory, cls=Process):
        return cls([sys.executable, "-u", str(Path(__file__).with_name("process_fixture.py")), mode],
                   cwd=directory, log_path=directory / "stdout.log")

    def wait_ready(self, process):
        deadline = time.monotonic() + 3
        while "ready\n" not in process.log_path.read_text():
            process.check_running("fixture startup")
            if time.monotonic() >= deadline:
                self.fail("fixture did not become ready")
            time.sleep(0.01)

    def test_partial_read_and_zero(self):
        class Chunks:
            parts = iter([b"a", b"bc", b"d"])

            def recv(self, size):
                chunk = next(self.parts)
                self.assert_size = size
                return chunk

        chunks = Chunks()
        self.assertEqual(exact(chunks, 4), b"abcd")
        self.assertEqual(exact(chunks, 0), b"")

    def test_partial_eof(self):
        left, right = socket.socketpair()
        with left, right:
            right.sendall(b"ab")
            right.shutdown(socket.SHUT_WR)
            with self.assertRaisesRegex(AssertionError, "EOF after 2 of 4 bytes"):
                exact(left, 4)

    def test_partial_timeout(self):
        left, right = socket.socketpair()
        with left, right:
            left.settimeout(0.05)
            right.sendall(b"ab")
            with self.assertRaisesRegex(TimeoutError, "timed out after receiving 2 of 4 bytes") as caught:
                exact(left, 4)
            self.assertIsInstance(caught.exception.__cause__, socket.timeout)

    def test_probe_eof_policies_and_chunk_limit(self):
        left, right = socket.socketpair()
        with left, right:
            right.sendall(b"abc")
            right.shutdown(socket.SHUT_WR)
            self.assertEqual(exact(left, 3, max_chunk=1, timeout_context=False), b"abc")
            self.assertIsNone(exact(left, 1, timeout_context=False, eof_returns_none=True))
            with self.assertRaisesRegex(RuntimeError, "probe EOF"):
                exact(left, 1, eof_error=lambda: RuntimeError("probe EOF"))

    def test_peer_cleanup_preserves_body_and_normal_lifetime(self):
        left, right = socket.socketpair()
        with left, right:
            with close_on_error(left):
                pass
            self.assertGreaterEqual(left.fileno(), 0)
            error = AssertionError("original peer body")
            with self.assertRaises(AssertionError) as caught:
                with close_on_error(left):
                    raise error
            self.assertIs(caught.exception, error)
            self.assertEqual(right.recv(1), b"")

    def test_command_timeout_retains_complete_capture(self):
        with RunDirectory("commands-", parent=self.root) as root:
            result = run_logged([sys.executable, "-c", "print('complete output')"],
                                cwd=root, capture_output=True, timeout=3, text=True)
            self.assertEqual(result.stdout, "complete output\n")
            self.assertEqual((root / "command-0000.stdout.log").read_text(), result.stdout)
            with self.assertRaises(subprocess.TimeoutExpired):
                run_logged([sys.executable, "-u", "-c", "import time; print('partial'); time.sleep(30)"],
                           cwd=root, capture_output=True, timeout=0.2)
            self.assertEqual((root / "command-0001.stdout.log").read_bytes(), b"partial\n")

    def test_portable_helpers_import_without_posix_signals(self):
        # Windows has no SIGKILL. Use a fresh interpreter so an already imported
        # module cannot hide an import-time dependency on that POSIX constant.
        support = Path(__file__).resolve().parent
        script = (
            "import signal, sys\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "if hasattr(signal, 'SIGKILL'): del signal.SIGKILL\n"
            "from wwtest.process import run_logged, kill_and_reap, stop_process\n"
        )
        result = subprocess.run([sys.executable, "-B", "-c", script, str(support)],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_explicit_skip_directory(self):
        run = RunDirectory("skip-status-", parent=self.root)
        root = run.create()
        run.finish(77)
        self.assertEqual((root / "result.txt").read_text(), "skipped\n")

    def test_trace_interleaving(self):
        trace = """  11 splice(3<pipe:[1]>, NULL, 4<TCP:[a->b]>, NULL, 9, 0 <unfinished ...>
12 recvfrom(5, "x", 1, 0, NULL, NULL) = 1
13 splice(8, NULL, 9, NULL, 2, 0 <unfinished ...>
11 <... splice resumed>) = 9
13 <... splice resumed>) = 0
12 splice(3, NULL, 4, NULL, 1, 0) = -1 EAGAIN
14 recvfrom(5, "", 1, 0, NULL, NULL) = 0
15 splice(3, NULL, 4, NULL, 3, 0) = 3
16 splice(3, NULL, 4, NULL, 3, 0 <unfinished ...>
"""
        self.assertEqual(list(successful_calls(trace)), [
            'recvfrom(5, "x", 1, 0, NULL, NULL) = 1',
            'splice(3<pipe:[1]>, NULL, 4<TCP:[a->b]>, NULL, 9, 0 ) = 9',
            'splice(3, NULL, 4, NULL, 3, 0) = 3',
        ])

    def test_success_removes_directory(self):
        with patch.dict(os.environ, {"WATERWALL_TEST_KEEP_RUN_DIR": "0"}):
            with RunDirectory("success-", parent=self.root) as root:
                self.assertTrue(root.is_dir())
            self.assertFalse(root.exists())

    def test_override_and_early_announcement(self):
        announcement = io.StringIO()
        with patch.dict(os.environ, {"WATERWALL_TEST_KEEP_RUN_DIR": "1"}), redirect_stderr(announcement):
            with RunDirectory("kept-", parent=self.root) as root:
                self.assertIn(str(root), announcement.getvalue())
                self.assertEqual((root / "result.txt").read_text(), "initialized\n")
        self.assertEqual((root / "result.txt").read_text(), "passed\n")

    def test_failure_and_initialized_skip_retention(self):
        for error in (AssertionError("fixture failure"), SystemExit(77), KeyboardInterrupt()):
            run = RunDirectory("failure-", parent=self.root)
            with self.assertRaises(type(error)) as caught:
                with run as root:
                    raise error
            self.assertIs(caught.exception, error)
            self.assertEqual((root / "result.txt").read_text(), "failed\n")

    def test_startup_exit_and_log_capture(self):
        run = RunDirectory("startup-", parent=self.root)
        with self.assertRaisesRegex(AssertionError, "startup.*exit 17"):
            with run as root, self.child("fail", root) as process:
                self.assertEqual(process.child.wait(timeout=3), 17)
                process.check_running("startup failure")
        self.assertEqual(process.child.returncode, 17)
        self.assertTrue(process.log.closed)
        self.assertIn("startup failure fixture", (root / "stdout.log").read_text())
        self.assertTrue(root.exists())

    def test_missing_executable_retains_initialized_run(self):
        run = RunDirectory("missing-", parent=self.root)
        with self.assertRaises(FileNotFoundError):
            with run as root, Process([str(root / "missing")], cwd=root, log_path=root / "stdout.log"):
                self.fail("missing executable passed")
        self.assertTrue(root.exists())

    def test_timeout_reaps_child_and_group(self):
        for mode in ("wait", "descendant"):
            run = RunDirectory("timeout-", parent=self.root)
            with self.assertRaises(subprocess.TimeoutExpired):
                with run as root, self.child(mode, root) as process:
                    self.wait_ready(process)
                    process.wait(timeout=0.05)
            self.assertIsNotNone(process.child.returncode)
            self.assertFalse(process._group_alive())
            self.assertTrue(root.exists())
            self.assertTrue(process.log.closed)
            with self.assertRaises(ChildProcessError):
                os.waitpid(process.child.pid, os.WNOHANG)

    def test_cleanup_failure_keeps_original_exception(self):
        class CleanupFailure(Process):
            def _cleanup(self):
                super()._cleanup()
                raise RuntimeError("cleanup fixture")

        error = AssertionError("original scenario")
        with self.assertRaises(AssertionError) as caught:
            with RunDirectory("cleanup-", parent=self.root) as root, self.child("wait", root, CleanupFailure):
                raise error
        self.assertIs(caught.exception, error)
        self.assertTrue(root.exists())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", required=True)
    args = parser.parse_args()
    parent = Path(args.build_dir).resolve() / "test-runs" / "python-support"
    parent.mkdir(parents=True, exist_ok=True)
    with RunDirectory("helpers-", parent=parent) as root:
        Helpers.root = root
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Helpers))
        if not result.wasSuccessful():
            raise AssertionError("Python support regression failed")


if __name__ == "__main__":
    main()
