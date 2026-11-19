#!/usr/bin/env python3
"""HalfDuplex TCP ordering and response completion in a private loopback namespace.
Two workers stage first/ready before a 1 MiB reverse echo. Default mode checks bulk-only
pipe-to-socket traces and client-first closure; it requires strace. The server-close mode
closes the backend immediately after its response and requires every byte followed by EOF,
without first closing the client. Both modes require namespace support and termination 143.
Failed runs retain logs. CTest: waterwall.halfduplex_tcp_splice_{true,false} and
waterwall.halfduplex_tcp_response_close_{true,false}. Native units force cross-connection
Finish ordering; this integration checks the complete backend-close path over real TCP.
The separate/same path variants exercise named branches with real connector DNS helpers.
The upload-close cases send real upload and download introductions independently, including
upload EOF before the download introduction, pairing before upload EOF, and expiry.
The delayed-upload case places independent TCP relays between a real client and server.
"""
import concurrent.futures
import argparse
from contextlib import ExitStack
import json
from pathlib import Path
import select
import shutil
import signal
import socket
import sys
import os
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parent / "support" / "python")))
from wwtest.config import core_config
from wwtest.sockets import configure_listener, connect_when_ready

from wwtest.sockets import exact
from wwtest.trace import successful_calls
from wwtest.run_directory import RunDirectory
from wwtest.process import Process


def run(binary, enabled, server_closes=False, paths="shared"):
    tracer = None if server_closes else shutil.which("strace")
    if not server_closes and tracer is None:
        raise RuntimeError("strace is required for pipe-to-socket evidence")
    with RunDirectory("waterwall-halfduplex-") as root:
        nodes = [
            {"name": "in", "type": "TcpListener", "next": "client",
             "settings": {"address": "127.0.0.1", "port": 27981, "nodelay": True}},
            {"name": "client", "type": "HalfDuplexClient", "next": "transport", "settings": {}},
            {"name": "transport", "type": "TcpConnector",
             "settings": {"address": "127.0.0.1", "port": 27982, "nodelay": True, "fastopen": False}},
            {"name": "remote", "type": "TcpListener", "next": "server",
             "settings": {"address": "127.0.0.1", "port": 27982, "nodelay": True}},
            {"name": "server", "type": "HalfDuplexServer", "next": "out", "settings": {}},
            {"name": "out", "type": "TcpConnector",
             "settings": {"address": "127.0.0.1", "port": 27983, "nodelay": True, "fastopen": False}},
        ]
        if paths != "shared":
            del nodes[1]["next"]
            nodes[1]["settings"] = {
                "upload": "transport",
                "download": "download-transport" if paths == "separate" else "transport",
            }
            if paths == "separate":
                nodes.append({"name": "download-transport", "type": "TcpConnector",
                              "settings": dict(nodes[2]["settings"])})
        (root / "config.json").write_text(json.dumps({"name": "halfduplex", "nodes": nodes}))
        (root / "core.json").write_text(json.dumps({
            "configs": ["config.json"],
            "log": {"path": "log/", **{name: {"loglevel": "DEBUG", "file": name + ".log", "console": True}
                                      for name in ("internal", "core", "network", "dns")}},
            "misc": {"workers": 2, "splice": enabled, "ram-profile": "minimal", "mtu": 1500,
                     "try-enabling-bbr": False},
        }))
        with socket.socket() as backend:
            configure_listener(backend, ('127.0.0.1', 27983), timeout=15)
            command = ([binary] if server_closes else
                       [tracer, "-D", "-f", "-yy", "-e", "trace=splice", "-o",
                        str(root / "splice.log"), binary])
            with Process(command, cwd=root,
                         log_path=root / "stdout.log") as process:
                deadline = time.monotonic() + 10
                while True:
                    process.check_running("WaterWall exited during startup")
                    try:
                        client = socket.create_connection(("127.0.0.1", 27981), timeout=1)
                        break
                    except ConnectionRefusedError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.02)
                data = bytes(range(256)) * 4096

                def peer():
                    with backend.accept()[0] as conn:
                        conn.settimeout(15)
                        assert exact(conn, 5) == b"first"
                        conn.sendall(b"ready")
                        assert exact(conn, len(data)) == data
                        conn.sendall(data[::-1])
                        if not server_closes:
                            assert conn.recv(1) == b""

                # Close the client before joining the peer if a check fails;
                # the existing socket deadlines bound any unfinished exchange.
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor, client:
                    client.settimeout(15)
                    task = executor.submit(peer)
                    client.sendall(b"first")
                    assert exact(client, 5) == b"ready"
                    if not server_closes:
                        boundary = len((root / "splice.log").read_text())
                    client.sendall(data)
                    assert exact(client, len(data)) == data[::-1]
                    if server_closes:
                        assert client.recv(1) == b"", "server response did not end with EOF"
                    else:
                        client.shutdown(socket.SHUT_RDWR)
                    task.result(timeout=20)
                process.send_signal(signal.SIGTERM)
                assert process.wait(timeout=10) == 128 + signal.SIGTERM
                if server_closes:
                    return
                calls = list(successful_calls((root / "splice.log").read_text()[boundary:]))
                outputs = [c for c in calls if c.startswith("splice(") and "<pipe:" in c.split(", NULL, ")[0]
                           and "<TCP:" in c.split(", NULL, ")[1]]
                assert bool(outputs) == enabled, "pipe-to-socket evidence disagrees with misc.splice"
                if enabled:
                    assert any("->127.0.0.1:27983" in c for c in outputs), "server upload did not splice"
                    assert any("127.0.0.1:27981->" in c for c in outputs), "client download did not splice"


def run_upload_close(binary, enabled, workers, expiry):
    ingress = ("127.0.0.1", 27982)
    service = ("127.0.0.1", 27983)
    nodes = [
        {"name": "carrier", "type": "TcpListener", "next": "server",
         "settings": {"address": ingress[0], "port": ingress[1], "nodelay": True}},
        {"name": "server", "type": "HalfDuplexServer", "next": "service", "settings": {}},
        {"name": "service", "type": "TcpConnector",
         "settings": {"address": service[0], "port": service[1], "nodelay": True, "fastopen": False}},
    ]
    body = bytes((index * 31 + index // 251) & 0xFF for index in range(65536))
    with RunDirectory("waterwall-halfduplex-upload-close-") as root:
        (root / "config.json").write_text(json.dumps({"name": "halfduplex-upload-close", "nodes": nodes}))
        (root / "core.json").write_text(json.dumps(core_config(
            workers=workers, ram_profile="minimal", splice=enabled, **{"try-enabling-bbr": False}
        )))
        log = root / "stdout.log"
        with socket.socket() as backend:
            configure_listener(backend, service, timeout=10)
            with Process([binary], cwd=root, log_path=log) as process:
                def connect():
                    return connect_when_ready(process, ingress, deadline=time.monotonic() + 10,
                                              failure=lambda: AssertionError("WaterWall exited before pairing"),
                                              timeout=5)

                def check_service(conn, expected):
                    conn.settimeout(10)
                    assert exact(conn, len(expected)) == expected, "service received incorrect upload bytes"
                    assert conn.recv(1) == b"", "service received extra bytes or no EOF after the upload"

                pair_id = bytes(range(16))
                # Consecutive carrier accepts put the detached upload and later download on
                # different workers when workers=2. Observing EOF fences server upload retirement.
                with connect() as upload:
                    upload.sendall(b"\x7f" + pair_id + body)
                    upload.shutdown(socket.SHUT_WR)
                    assert upload.recv(1) == b"", "server did not retire the finished upload socket"

                if expiry:
                    deadline = time.monotonic() + 35
                    diagnostic = f"detached upload timed out with {len(body)} undelivered upload bytes"
                    while diagnostic not in log.read_text():
                        process.check_running("WaterWall exited while waiting for detached upload expiry")
                        assert time.monotonic() < deadline, "missing download did not expire the detached upload"
                        time.sleep(0.02)
                    # Reuse the ID after expiry. The service must receive the replacement body only.
                    with connect() as upload:
                        replacement = body[::-1]
                        upload.sendall(b"\x7f" + pair_id + replacement)
                        upload.shutdown(socket.SHUT_WR)
                        assert upload.recv(1) == b"", "expired ID retained an upload claim"
                else:
                    replacement = body

                with connect() as download:
                    download.sendall(b"\x80" + pair_id)
                    with backend.accept()[0] as conn:
                        check_service(conn, replacement)
                    assert download.recv(1) == b"", "download stayed live after service completion"

                if not expiry:
                    pair_id = bytes(reversed(pair_id))
                    with ExitStack() as sockets:
                        downloads = [sockets.enter_context(connect()) for _ in range(2)]
                        for download in downloads:
                            download.sendall(b"\x80" + pair_id)
                        # The duplicate claim's EOF establishes that one download Intro is
                        # already registered, independent of which socket the worker read first.
                        rejected, _, _ = select.select(downloads, [], [], 5)
                        assert len(rejected) == 1 and rejected[0].recv(1) == b"", "download claim was not exclusive"
                        download = next(candidate for candidate in downloads if candidate is not rejected[0])
                        upload = sockets.enter_context(connect())
                        upload.sendall(b"\x7f" + pair_id)
                        with backend.accept()[0] as conn:
                            upload.sendall(body)
                            upload.shutdown(socket.SHUT_WR)
                            check_service(conn, body)
                        assert download.recv(1) == b"", "download stayed live after delayed upload completion"

                process.send_signal(signal.SIGTERM)
                assert process.wait(timeout=10) == 128 + signal.SIGTERM


def run_delayed_upload(binary, enabled):
    host = "127.0.0.1"
    app_port, upload_port, download_port, server_port, service_port = range(27981, 27986)
    nodes = [
        {"name": "in", "type": "TcpListener", "next": "client",
         "settings": {"address": host, "port": app_port}},
        {"name": "client", "type": "HalfDuplexClient", "settings": {"upload": "upload", "download": "download"}},
        {"name": "remote", "type": "TcpListener", "next": "server",
         "settings": {"address": host, "port": server_port}},
        {"name": "server", "type": "HalfDuplexServer", "next": "service", "settings": {}},
    ]
    for name, port in (("upload", upload_port), ("download", download_port), ("service", service_port)):
        nodes.append({"name": name, "type": "TcpConnector",
                      "settings": {"address": host, "port": port, "nodelay": True, "fastopen": False}})

    with RunDirectory("waterwall-halfduplex-delayed-upload-") as root, ExitStack() as sockets:
        (root / "config.json").write_text(json.dumps({"name": "halfduplex", "nodes": nodes}))
        (root / "core.json").write_text(json.dumps(core_config(
            workers=2, ram_profile="minimal", splice=enabled, **{"try-enabling-bbr": False})))

        def listener(port):
            sock = sockets.enter_context(socket.socket())
            configure_listener(sock, (host, port), timeout=10)
            return sock

        def accept(sock):
            conn = sockets.enter_context(sock.accept()[0])
            conn.settimeout(10)
            return conn

        upload_listener, download_listener, backend = map(listener, (upload_port, download_port, service_port))
        with Process([binary], cwd=root, log_path=root / "stdout.log") as process:
            app = sockets.enter_context(connect_when_ready(
                process, (host, app_port), deadline=time.monotonic() + 10,
                failure=lambda: AssertionError("WaterWall exited before application Init"), timeout=10))
            app.sendall(b"A")
            client_upload, client_download = map(accept, (upload_listener, download_listener))
            server_upload, server_download = [
                sockets.enter_context(socket.create_connection((host, server_port), timeout=10)) for _ in range(2)
            ]
            # Forward the real intros and the first byte to establish the service before application EOF.
            server_download.sendall(exact(client_download, 17))
            server_upload.sendall(exact(client_upload, 18))
            service = accept(backend)
            assert exact(service, 1) == b"A"

            body = bytes(range(256)) * 256
            app.sendall(body)
            app.shutdown(socket.SHUT_WR)
            held = exact(client_upload, len(body))
            assert held == body and client_upload.recv(1) == b"", "client upload did not finish after its full body"
            # Upload has demonstrably closed on the client. Withhold its data and EOF from the
            # server. An early download close here can reach the server ahead of those bytes.
            assert not select.select([client_download], [], [], 0.25)[0], "client closed download ahead of upload"
            server_upload.sendall(held)
            server_upload.shutdown(socket.SHUT_WR)
            assert exact(service, len(body)) == body and service.recv(1) == b"", "delayed upload lost bytes or EOF"
            assert server_download.recv(1) == b"", "server download did not settle after the upload reached service"
            client_download.shutdown(socket.SHUT_WR)
            assert client_download.recv(1) == b"", "client download stayed open after remote completion"
            process.send_signal(signal.SIGTERM)
            assert process.wait(timeout=10) == 128 + signal.SIGTERM


def interrupted(signum, _frame):
    # Let an outer timeout unwind sockets, peer joins and the owned process.
    raise SystemExit(128 + signum)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("splice", choices=("true", "false"))
    parser.add_argument("close_mode", nargs="?", choices=("server-close", "upload-close", "upload-expiry", "delayed-upload"))
    parser.add_argument("--paths", choices=("shared", "separate", "same"), default="shared")
    parser.add_argument("--workers", type=int, choices=(1, 2), default=2)
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, interrupted)
    if args.close_mode == "delayed-upload":
        run_delayed_upload(str(Path(args.binary).resolve()), args.splice == "true")
        print("HalfDuplex delayed client upload passed")
        sys.exit(0)
    if args.close_mode in ("upload-close", "upload-expiry"):
        run_upload_close(str(Path(args.binary).resolve()), args.splice == "true", args.workers,
                         args.close_mode == "upload-expiry")
        print("HalfDuplex upload EOF and pairing passed")
        sys.exit(0)
    server_closes = args.close_mode == "server-close"
    run(str(Path(args.binary).resolve()), args.splice == "true", server_closes, args.paths)
    print("HalfDuplex TCP response-close passed" if server_closes else
          "HalfDuplex staged TCP splice roundtrip passed")
