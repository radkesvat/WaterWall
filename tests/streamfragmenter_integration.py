#!/usr/bin/env python3
"""StreamFragmenter socket roundtrip and splice evidence; namespace harness only."""
import concurrent.futures
import json
from pathlib import Path
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
from httpproxyserver_splice_integration import successful_calls
from tlsclient_fragment_integration import inspect_client_hello
from trojanclient_splice_integration import exact


def run(binary, enabled, mode, wait_for_est=False):
    tracer = shutil.which("strace")
    if tracer is None:
        raise RuntimeError("inconclusive: strace required for splice evidence")
    settings = {"mode": mode, "bypass_chance": 0, "cuts": [[2, 2, 100], [4, 5, 100]],
                "wait-for-est": wait_for_est}
    settings.update({"count": 1} if mode == "counter" else {"duration-ms": 1000})
    with tempfile.TemporaryDirectory(prefix="waterwall-streamfragmenter-") as directory:
        root = Path(directory)
        nodes = [
            {"name": "in", "type": "TcpListener", "next": "fragmenter",
             "settings": {"address": "127.0.0.1", "port": 27991, "nodelay": True}},
            {"name": "fragmenter", "type": "StreamFragmenter", "next": "out", "settings": settings},
            {"name": "out", "type": "TcpConnector",
             "settings": {"address": "127.0.0.1", "port": 27992, "nodelay": True, "fastopen": False}},
        ]
        (root / "config.json").write_text(json.dumps({"name": "fragmenter", "nodes": nodes}))
        (root / "core.json").write_text(json.dumps({
            "configs": ["config.json"],
            "log": {"path": "log/", **{name: {"loglevel": "DEBUG", "file": name + ".log", "console": True}
                                      for name in ("internal", "core", "network", "dns")}},
            "misc": {"workers": 2, "splice": enabled, "ram-profile": "minimal", "mtu": 1500,
                     "try-enabling-bbr": False},
        }))
        with socket.socket() as backend, (root / "stdout.log").open("w+") as log:
            backend.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            backend.bind(("127.0.0.1", 27992))
            backend.listen()
            backend.settimeout(15)
            process = subprocess.Popen([tracer, "-D", "-f", "-yy", "-e", "trace=splice", "-o",
                                        str(root / "splice.log"), binary], cwd=root, stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 10
                while True:
                    if process.poll() is not None:
                        raise AssertionError("WaterWall exited during startup")
                    try:
                        client = socket.create_connection(("127.0.0.1", 27991), timeout=1)
                        break
                    except ConnectionRefusedError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.02)
                data = bytes(range(256)) * 2048

                def peer():
                    with backend.accept()[0] as conn:
                        conn.settimeout(15)
                        assert exact(conn, 8) == b"abcdefgh"
                        conn.sendall(b"ready")
                        assert exact(conn, len(data)) == data
                        conn.sendall(data[::-1])
                        assert conn.recv(1) == b""

                with client, concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    client.settimeout(15)
                    task = executor.submit(peer)
                    client.sendall(b"abcdefgh")
                    assert exact(client, 5) == b"ready"
                    client.sendall(data)
                    assert exact(client, len(data)) == data[::-1]
                    client.shutdown(socket.SHUT_RDWR)
                    task.result(timeout=20)
                process.send_signal(signal.SIGTERM)
                assert process.wait(timeout=10) == 128 + signal.SIGTERM
                calls = list(successful_calls((root / "splice.log").read_text()))
                outputs = [call for call in calls if call.startswith("splice(") and
                           "<pipe:" in call.split(", NULL, ")[0] and "<TCP:" in call.split(", NULL, ")[1]]
                splits = [call for call in calls if call.startswith("splice(") and
                          "<pipe:" in call.split(", NULL, ")[0] and "<pipe:" in call.split(", NULL, ")[1]]
                assert bool(outputs) == enabled, "socket splice evidence disagrees with configuration"
                assert bool(splits) == enabled, "fragment extraction did not preserve pipe-backed bytes"
                if enabled:
                    assert any("->127.0.0.1:27992" in call for call in outputs), "upload did not splice"
                    assert any("127.0.0.1:27991->" in call for call in outputs), "download did not splice"
            except BaseException:
                log.flush()
                print((root / "stdout.log").read_text(), file=sys.stderr)
                raise
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()


def run_tls(binary, enabled, mode):
    tests = Path(__file__).resolve().parent
    settings = {"mode": "counter", "count": 1, "tls-hello-fragment": True,
                "tls-hello-timeout-ms": 1000 if mode == "pending" else 50,
                "cuts": [[100, 0, 100], [150, 0, 100]]}
    with tempfile.TemporaryDirectory(prefix="waterwall-streamfragmenter-tls-") as directory:
        root = Path(directory)
        nodes = [
            {"name": "in", "type": "TcpListener", "next": "fragmenter",
             "settings": {"address": "127.0.0.1", "port": 27991, "nodelay": True}},
            {"name": "fragmenter", "type": "StreamFragmenter", "next": "out", "settings": settings},
            {"name": "out", "type": "TcpConnector",
             "settings": {"address": "127.0.0.1", "port": 27992, "nodelay": True, "fastopen": False}},
        ]
        (root / "config.json").write_text(json.dumps({"name": "fragmenter-tls", "nodes": nodes}))
        (root / "core.json").write_text(json.dumps({
            "configs": ["config.json"],
            "log": {"path": "log/", **{name: {"loglevel": "DEBUG", "file": name + ".log", "console": True}
                                      for name in ("internal", "core", "network", "dns")}},
            "misc": {"workers": 2, "splice": enabled, "ram-profile": "minimal", "try-enabling-bbr": False},
        }))
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.load_cert_chain(tests / "cases/tls_roundtrip/server.crt", tests / "cases/tls_roundtrip/server.key")
        server.minimum_version = server.maximum_version = ssl.TLSVersion.TLSv1_3
        client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_context.check_hostname = False
        client_context.verify_mode = ssl.CERT_NONE
        client_context.minimum_version = client_context.maximum_version = ssl.TLSVersion.TLSv1_3
        data = bytes(range(256)) * 128
        with socket.socket() as backend, (root / "stdout.log").open("w+") as log:
            backend.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            backend.bind(("127.0.0.1", 27992))
            backend.listen()
            backend.settimeout(15)
            process = subprocess.Popen([binary], cwd=root, stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 10
                while True:
                    if process.poll() is not None or time.monotonic() >= deadline:
                        raise AssertionError("standalone TLS fragmenter startup failed")
                    try:
                        client = socket.create_connection(("127.0.0.1", 27991), timeout=1)
                        break
                    except ConnectionRefusedError:
                        time.sleep(.02)
                with client:
                    client.settimeout(15)
                    if mode in ("deadline", "pending"):
                        prefix = b"\x16\x03\x03\x00\x30\x01\x00"
                        client.sendall(prefix)
                        with backend.accept()[0] as peer:
                            peer.settimeout(.2 if mode == "pending" else 3)
                            if mode == "pending":
                                try:
                                    peer.recv(1)
                                except socket.timeout:
                                    pass
                                else:
                                    raise AssertionError("assembly timer emitted before deadline")
                                process.send_signal(signal.SIGTERM)
                                assert process.wait(timeout=10) == 128 + signal.SIGTERM
                                peer.settimeout(3)
                                assert peer.recv(1) == b"", "assembly timer survived shutdown"
                            else:
                                assert exact(peer, len(prefix)) == prefix, "deadline replay changed prefix"
                    else:
                        def echo():
                            with backend.accept()[0] as raw:
                                raw.settimeout(15)
                                hello = inspect_client_hello(raw, [100, 50])
                                assert len(hello) > 150
                                with server.wrap_socket(raw, server_side=True) as peer:
                                    assert exact(peer, len(data)) == data
                                    peer.sendall(data[::-1])

                        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                            task = executor.submit(echo)
                            with client_context.wrap_socket(client, server_hostname="tls.integration.test") as secure:
                                secure.sendall(data)
                                assert exact(secure, len(data)) == data[::-1]
                            task.result(timeout=20)
                if process.poll() is None:
                    process.send_signal(signal.SIGTERM)
                    assert process.wait(timeout=10) == 128 + signal.SIGTERM
            except BaseException:
                log.flush()
                print((root / "stdout.log").read_text(), file=sys.stderr)
                raise
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    if sys.argv[3].startswith("tls_"):
        run_tls(str(Path(sys.argv[1]).resolve()), sys.argv[2] == "true", sys.argv[3][4:])
    else:
        run(str(Path(sys.argv[1]).resolve()), sys.argv[2] == "true", sys.argv[3],
            len(sys.argv) > 4 and sys.argv[4] == "true")
    print("StreamFragmenter socket roundtrip passed")
