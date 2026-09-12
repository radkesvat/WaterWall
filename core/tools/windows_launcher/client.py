#!/usr/bin/env python3
"""Public-boundary examples. Run from an already elevated Windows terminal.
The --journal parent directory must already be protected for this controller.
"""
import argparse
import ctypes
from ctypes import wintypes as W
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import uuid


def recover(exe, journal):
    """Historical cleanup is diagnostic; a new launch checks current ownership."""
    try:
        result = subprocess.call([exe, "--recover:" + str(journal.resolve())], timeout=30)
    except (OSError, subprocess.TimeoutExpired) as error:
        print("Recovery diagnostic unavailable:", error, file=sys.stderr)
        return 2
    if result:
        print("Previous cleanup is unverified; keep its record. New startup will check resource ownership.",
              file=sys.stderr)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("independent", "attached", "recover"))
    parser.add_argument("exe", type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--journal", type=Path)
    parser.add_argument("--previous-journal", type=Path, help="request bounded recovery of a previous session before launch")
    parser.add_argument("--console", choices=("hidden", "visible"))
    parser.add_argument("--seconds", type=float, default=5)
    parser.add_argument("--exit-controller", action="store_true", help="exit without signaling stop after readiness")
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("this example requires Windows")
    exe = str(args.exe.resolve())
    if args.mode == "recover":
        if args.journal is None:
            parser.error("recovery needs --journal")
        return recover(exe, args.journal)
    if args.config is None:
        parser.error("launch needs --config")
    args.console = args.console or ("visible" if args.mode == "independent" else "hidden")
    if args.previous_journal is not None:
        recover(exe, args.previous_journal)
    if args.journal is not None:
        # Every launch owns a new record. Never overwrite a crashed session's
        # evidence or make an existing path a permanent launch failure.
        if args.journal.exists():
            args.journal = args.journal.with_name(args.journal.name + "." + uuid.uuid4().hex)
        print("Session record:", args.journal.resolve(), flush=True)
    if args.mode == "independent":
        if args.console == "hidden" and args.journal is None:
            parser.error("hidden independent launch needs --journal for later stop/recovery")
        command = [exe, "-c:" + str(args.config.resolve()), "--console:" + args.console]
        if args.journal is not None:
            command.append("--session-file:" + str(args.journal.resolve()))
        subprocess.Popen(command,
                         creationflags=subprocess.CREATE_NO_WINDOW if args.console == "hidden" else subprocess.CREATE_NEW_CONSOLE,
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         close_fds=True, cwd=args.config.resolve().parent)
        return 0
    if args.journal is None:
        parser.error("attached launch needs a new --journal path in a protected directory")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = W.HANDLE
    kernel.CreateEventW.argtypes = (W.LPVOID, W.BOOL, W.BOOL, W.LPCWSTR)
    kernel.CreateEventW.restype = W.HANDLE
    kernel.DuplicateHandle.argtypes = (W.HANDLE, W.HANDLE, W.HANDLE, ctypes.POINTER(W.HANDLE), W.DWORD, W.BOOL, W.DWORD)
    kernel.DuplicateHandle.restype = W.BOOL
    kernel.SetEvent.argtypes = (W.HANDLE,)
    kernel.SetEvent.restype = W.BOOL
    kernel.WaitForSingleObject.argtypes = (W.HANDLE, W.DWORD)
    kernel.WaitForSingleObject.restype = W.DWORD
    kernel.CloseHandle.argtypes = (W.HANDLE,)
    kernel.CloseHandle.restype = W.BOOL
    process = kernel.GetCurrentProcess()
    stop, ready = kernel.CreateEventW(None, True, False, None), kernel.CreateEventW(None, True, False, None)
    if not stop or not ready:
        raise ctypes.WinError(ctypes.get_last_error())
    copies = []
    child = None
    failure = False
    discarded = [0, 0]
    readers = []
    try:
        for source, access in ((stop, 0x100000), (ready, 2), (process, 0x100000)):
            copy = W.HANDLE()
            if not kernel.DuplicateHandle(process, source, process, ctypes.byref(copy), access, True, 0):
                raise ctypes.WinError(ctypes.get_last_error())
            copies.append(copy.value)
        startup = subprocess.STARTUPINFO()
        startup.lpAttributeList = {"handle_list": copies}
        command = [exe, "--restricted-config", "-c:stdin", "--console:" + args.console,
                   "--session-file:" + str(args.journal.resolve()),
                   "--stop-event:" + str(copies[0]), "--ready-event:" + str(copies[1]),
                   "--controller-process:" + str(copies[2])]
        child = subprocess.Popen(command, startupinfo=startup, close_fds=True, cwd=args.config.resolve().parent,
                                 creationflags=subprocess.CREATE_NO_WINDOW,
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # Continuously drain bounded chunks; retain no unbounded log queue. The
        # count explicitly reports diagnostics discarded by this minimal example.
        def drain(stream, index):
            while True:
                chunk = stream.read(8192)
                if not chunk:
                    return
                discarded[index] += len(chunk)
        readers = [threading.Thread(target=drain, args=(stream, i), daemon=True)
                   for i, stream in enumerate((child.stdout, child.stderr))]
        for thread in readers:
            thread.start()
        def send_config():
            try:
                with child.stdin:
                    with args.config.open("rb") as source:
                        while True:
                            chunk = source.read(8192)
                            if not chunk:
                                break
                            child.stdin.write(chunk)
            except (BrokenPipeError, OSError):
                pass
        threading.Thread(target=send_config, daemon=True).start()
        # EOF transfers configuration; it is not a stop request.
        deadline = time.monotonic() + 60
        while True:
            wait = kernel.WaitForSingleObject(ready, 100)
            if wait == 0:
                break
            if wait != 258:
                raise ctypes.WinError(ctypes.get_last_error())
            if child.poll() is not None:
                raise RuntimeError("WaterWall exited before readiness")
            if time.monotonic() >= deadline:
                raise RuntimeError("startup did not publish readiness within 60 seconds")
        if args.exit_controller:
            os._exit(99)
        threading.Event().wait(max(0, args.seconds))
        if not kernel.SetEvent(stop):
            raise ctypes.WinError(ctypes.get_last_error())
        child.wait(timeout=20)
    except (OSError, RuntimeError, subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        failure = True
        print("Lifecycle client:", error, file=sys.stderr)
    finally:
        if child is not None and child.poll() is None:
            kernel.SetEvent(stop)
        for handle in copies + [stop, ready]:
            kernel.CloseHandle(handle)
        if child is not None:
            # Recover even when readiness, transfer, or graceful waiting failed.
            # The public boundary owns escalation and reports what it can prove.
            recover(exe, args.journal)
            for thread in readers:
                thread.join(timeout=1)
            public_status = child.poll()
            failure = failure or public_status != 0
            print("Public exit:", public_status, "discarded stdout/stderr bytes:", *discarded)
    return int(failure)


if __name__ == "__main__":
    raise SystemExit(main())
