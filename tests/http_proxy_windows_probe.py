"""Run the loopback HTTP probe through the public Windows ready/stop capabilities."""
import argparse
import ctypes
from ctypes import wintypes
import json
from pathlib import Path
import os
import shutil
import socket
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--launcher", type=Path, required=True)
    args = parser.parse_args()
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
    kernel.CreateEventW.restype = wintypes.HANDLE
    kernel.SetEvent.argtypes = [wintypes.HANDLE]
    kernel.ResetEvent.argtypes = [wintypes.HANDLE]
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handles = [kernel.CreateEventW(None, True, False, None) for _ in range(2)]
    assert all(handles), ctypes.get_last_error()
    stop, ready = handles
    for handle in handles:
        os.set_handle_inheritable(handle, True)
    info = subprocess.STARTUPINFO()
    info.lpAttributeList = {"handle_list": handles}
    repo = Path(__file__).resolve().parents[1]
    try:
        with tempfile.TemporaryDirectory(prefix="WaterWall HTTP proxy ") as temporary:
            root = Path(temporary)
            shutil.copytree(repo / "tests/cases/http_proxy", root, dirs_exist_ok=True)
            core = {"log": {"path": "log/"}, "configs": ["config.json"],
                    "misc": {"workers": 2, "ram-profile": "client", "mtu": 1500, "try-enabling-bbr": False}}
            (root / "core.json").write_text(json.dumps(core), encoding="utf-8")
            with (root / "stdout.log").open("wb") as log:
                process = subprocess.Popen([str(args.launcher.resolve()), "--restricted-config", "--console:hidden",
                                            f"--stop-event:{stop}", f"--ready-event:{ready}"], cwd=root,
                                           startupinfo=info, close_fds=True, creationflags=subprocess.CREATE_NO_WINDOW,
                                           stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
                try:
                    assert kernel.WaitForSingleObject(ready, 60000) == 0, "startup did not signal readiness"
                    assert process.poll() is None, "runtime exited during startup"
                    env = dict(os.environ, HTTP_PROXY_STOP_PROBE="1")
                    probe = subprocess.Popen([os.sys.executable, "probe.py"], cwd=root, env=env,
                                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                             creationflags=subprocess.CREATE_NO_WINDOW)
                    deadline = time.monotonic() + 90
                    try:
                        while not (root / "stop-probe-ready").exists() and probe.poll() is None:
                            assert time.monotonic() < deadline, "proxy probe timed out"
                            time.sleep(.02)
                        if (root / "stop-probe-ready").exists():
                            kernel.SetEvent(stop)
                            process.wait(timeout=25)
                            (root / "stop-probe-complete").touch()
                        stdout, stderr = probe.communicate(timeout=10)
                        print(stdout, end="")
                        assert probe.returncode == 0, stderr
                    finally:
                        if probe.poll() is None:
                            probe.kill()
                            probe.wait()
                except BaseException:
                    kernel.SetEvent(stop)
                    process.wait(timeout=25)
                    print((root / "stdout.log").read_text(errors="replace")[-12000:])
                    for path in (root / "log").glob("*.log"):
                        print(path.name, path.read_text(errors="replace")[-8000:])
                    raise
                finally:
                    kernel.SetEvent(stop)
                    try:
                        process.wait(timeout=25)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                        raise AssertionError("public stop did not terminate within its deadline")
                assert process.returncode == 0, process.returncode
                print("Native Windows restricted startup, readiness, proxy traffic, and public stop passed")
            original = json.loads((root / "config.json").read_text())
            example = root / "local-example"
            shutil.copytree(repo / "tunnels/HttpProxyServer/examples/local-users", example)
            shutil.copy(repo / "tests/cases/http_proxy/probe.py", example / "probe.py")
            for handle in handles:
                assert kernel.ResetEvent(handle), "reset example capabilities"
            with (example / "stdout.log").open("wb") as log:
                process = subprocess.Popen([str(args.launcher.resolve()), "--restricted-config", "--console:hidden",
                                            f"--stop-event:{stop}", f"--ready-event:{ready}"], cwd=example,
                                           startupinfo=info, close_fds=True, creationflags=subprocess.CREATE_NO_WINDOW,
                                           stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
                try:
                    assert kernel.WaitForSingleObject(ready, 60000) == 0 and process.poll() is None
                    result = subprocess.run([os.sys.executable, "probe.py"], cwd=example,
                                            env=dict(os.environ, HTTP_PROXY_LOCAL_EXAMPLE="1"),
                                            capture_output=True, text=True, timeout=20,
                                            creationflags=subprocess.CREATE_NO_WINDOW)
                    assert result.returncode == 0, result.stderr
                    print(result.stdout, end="")
                finally:
                    kernel.SetEvent(stop)
                    process.wait(timeout=25)
                assert process.returncode == 0
            assert not (example / "users.json").exists(), "local example created an account database"
            invalid_settings = [
                {}, {"no-auth": False}, {"no-auth": 1},
                {"no-auth": True, "unknown": True},
                {"no-auth": True, "auth-client-node-name": "auth-client"},
                {"auth-client-node-name": "missing"},
                {"no-auth": True, "max-header-bytes": 1023},
                {"no-auth": True, "max-pending-bytes": 65535},
                {"no-auth": True, "header-timeout-ms": 0},
                {"no-auth": True, "connect-timeout-ms": 1.5},
                {"no-auth": True, "verbose": "yes"},
            ]
            pair = {"username": "alice", "password": "one"}
            invalid_settings += [
                {"users": None}, {"users": []}, {"users": {}}, {"users": "alice:one"},
                {"users": [pair], "no-auth": True},
                {"users": [pair], "auth-client-node-name": "auth-client"},
                {"users": None, "no-auth": True}, {"users": [], "auth-client-node-name": None},
                {"users": [pair, {}]}, {"users": [pair, pair]}, {"users": ["alice:one"]},
                {"users": [{"username": "alice"}]}, {"users": [{"password": "one"}]},
                {"users": [{"username": 1, "password": "one"}]},
                {"users": [{"username": "alice", "password": False}]},
            ]
            invalid_settings += [{"users": [dict(pair, **{field: value})]}
                                 for field, value in [("username", ""), ("password", ""),
                                                      ("username", "x" * 256), ("password", "x" * 256),
                                                      ("username", "a:b"), ("username", "a\n"),
                                                      ("password", "p\x7f"), ("limit", 0), ("enabled", True),
                                                      ("expire-at-ms", 0)]]
            for settings in invalid_settings:
                config = json.loads(json.dumps(original))
                next(node for node in config["nodes"] if node["name"] == "http-proxy")["settings"] = settings
                (root / "config.json").write_text(json.dumps(config), encoding="utf-8")
                result = subprocess.run([str(args.launcher.resolve()), "--restricted-config", "--console:hidden"],
                                        cwd=root, timeout=30, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
                assert result.returncode != 0, settings
            print(f"Native restricted startup rejected all {len(invalid_settings)} invalid settings cases")
            config = json.loads(json.dumps(original))
            next(node for node in config["nodes"] if node["name"] == "http-proxy").pop("next")
            (root / "config.json").write_text(json.dumps(config), encoding="utf-8")
            result = subprocess.run([str(args.launcher.resolve()), "--restricted-config", "--console:hidden"],
                                    cwd=root, timeout=30, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
            assert result.returncode != 0, "missing next was accepted"
            (root / "config.json").write_text(json.dumps(original), encoding="utf-8")
            with socket.socket() as occupied:
                occupied.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                occupied.bind(("127.0.0.1", 29080))
                occupied.listen(1)
                result = subprocess.run([str(args.launcher.resolve()), "--restricted-config", "--console:hidden"],
                                        cwd=root, timeout=30, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
                assert result.returncode != 0, "occupied proxy listener did not fail startup"
            print("Native missing-next and occupied-listener startup rejection passed")
    finally:
        for handle in handles:
            kernel.CloseHandle(handle)


if __name__ == "__main__":
    main()
