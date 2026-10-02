"""Bounded ownership of a POSIX child and its tracing process group."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import json
from contextlib import contextmanager


class Process:
    """Capture merged output and reap the direct child before closing its log.

    The command and scenario deadlines stay at the call site. A private session
    lets cleanup settle a strace -D tracer without changing its arguments or
    making strace the runtime's parent. Cleanup kills an unfinished runtime,
    waits at most five seconds, then allows its group two seconds to drain and
    kills/waits another five seconds if needed. Descendants must stay in this
    group. The direct child is reaped here; detached tracers are reaped by their
    parent after group quiescence. Original scenario exceptions take precedence.
    """

    def __init__(self, command, *, cwd, log_path=None, log=None,
                 cleanup_signal=None, terminate_timeout=5, kill_timeout=5, **kwargs):
        self.command = command
        self.cwd = cwd
        self.log_path = Path(log_path if log_path is not None else log.name)
        self.child = None
        self.log = log
        self.owns_log = log is None
        # Resolve the POSIX default only for this POSIX-only owner. Windows
        # callers import the direct-child helpers from the same module.
        self.cleanup_signal = signal.SIGKILL if cleanup_signal is None else cleanup_signal
        self.terminate_timeout = terminate_timeout
        self.kill_timeout = kill_timeout
        self.kwargs = kwargs

    def __enter__(self):
        if self.owns_log:
            self.log = self.log_path.open("w+")
        try:
            self.child = subprocess.Popen(self.command, cwd=self.cwd, stdout=self.log,
                                          stderr=subprocess.STDOUT, start_new_session=True, **self.kwargs)
        except BaseException:
            if self.owns_log:
                self.log.close()
            raise
        return self

    def check_running(self, message):
        """Reject an early exit without creating a readiness probe/connection."""
        result = self.child.poll()
        if result is not None:
            raise AssertionError(f"{message} (exit {result})")

    def send_signal(self, sig):
        self.child.send_signal(sig)

    def poll(self):
        return self.child.poll()

    @property
    def returncode(self):
        return self.child.returncode

    def terminate(self):
        self.child.terminate()

    def kill(self):
        self.child.kill()

    def wait(self, timeout):
        """Return the actual exit result; expected exits belong to the scenario."""
        result = self.child.wait(timeout=timeout)
        # A -D tracer exits after its tracee. Settle it before reading its trace.
        self._wait_group(2)
        return result

    def _group_alive(self):
        try:
            os.killpg(self.child.pid, 0)
        except ProcessLookupError:
            return False
        return True

    def _wait_group(self, timeout):
        deadline = time.monotonic() + timeout
        while self._group_alive():
            if time.monotonic() >= deadline:
                raise TimeoutError(f"child/tracer group {self.child.pid} did not settle")
            time.sleep(0.02)

    def _cleanup(self):
        if self.child.poll() is None:
            self.child.send_signal(self.cleanup_signal)
            try:
                self.child.wait(timeout=self.terminate_timeout)
            except subprocess.TimeoutExpired:
                self.child.kill()
        self.child.wait(timeout=self.kill_timeout)
        try:
            self._wait_group(2)
        except TimeoutError:
            try:
                os.killpg(self.child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self._wait_group(5)

    def __exit__(self, exc_type, exc, traceback):
        cleanup_error = None
        try:
            self._cleanup()
        except BaseException as error:
            cleanup_error = error
        try:
            self.log.flush()
            if self.owns_log:
                self.log.close()
        except BaseException as error:
            if cleanup_error is None:
                cleanup_error = error
        if exc_type is not None or cleanup_error is not None:
            try:
                print(self.log_path.read_text(errors="replace"), file=sys.stderr, flush=True)
            except BaseException as error:
                if cleanup_error is None:
                    cleanup_error = error
        if cleanup_error is not None:
            if exc_type is None:
                raise cleanup_error
            print(f"Process cleanup also failed: {cleanup_error}", file=sys.stderr, flush=True)
        return False


def install_termination_handler():
    """CLI opt-in: unwind owned resources on outer SIGTERM, with status 143."""
    def interrupted(signum, _frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, interrupted)


def stop_process(process, *, terminate_timeout=5, kill_timeout=5):
    """Platform-neutral direct-child stop; callers keep expected status checks."""
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=terminate_timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=kill_timeout)


def kill_and_reap(process, *, timeout=5):
    """Reap a direct child on POSIX or Windows, without changing stop protocols."""
    if process.poll() is None:
        process.kill()
    return process.wait(timeout=timeout)


def run_logged(command, *, cwd, **kwargs):
    """Run a bounded direct child and retain complete captured output.

    Preserve subprocess.run arguments/results. Commands use numbered receipts
    under cwd; environments and stdin are never dumped. A supplied file stream
    remains its caller's log. subprocess.run owns kill/reap on timeout.
    """
    root = Path(cwd)
    index = 0
    while (root / f"command-{index:04d}.json").exists():
        index += 1
    prefix = root / f"command-{index:04d}"
    receipt = {"command": [str(value) for value in command], "timeout": kwargs.get("timeout")}
    prefix.with_suffix(".json").write_text(json.dumps(receipt) + "\n")
    result = None
    try:
        result = subprocess.run(command, cwd=cwd, **kwargs)
        receipt["returncode"] = result.returncode
        return result
    except subprocess.CalledProcessError as error:
        result = error
        receipt["returncode"] = error.returncode
        raise
    except subprocess.TimeoutExpired as error:
        result = error
        receipt["timed_out"] = True
        raise
    finally:
        if result is not None:
            for name in ("stdout", "stderr"):
                value = getattr(result, name, None)
                if isinstance(value, str):
                    value = value.encode("utf-8")
                if value is not None:
                    prefix.with_suffix("." + name + ".log").write_bytes(value)
        prefix.with_suffix(".json").write_text(json.dumps(receipt) + "\n")


@contextmanager
def close_on_error(sock, before_close=None):
    """Unblock peer futures before executor joins; preserve the body exception.

    Place after the executor in a with statement. Success leaves socket lifetime
    unchanged. before_close can release a scenario event before joining peers.
    """
    try:
        yield
    except BaseException:
        try:
            if before_close is not None:
                before_close()
            sock.close()
        except BaseException as error:
            print(f"Peer socket cleanup also failed: {error}", file=sys.stderr)
        raise
