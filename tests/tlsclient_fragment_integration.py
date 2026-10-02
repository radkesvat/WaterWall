#!/usr/bin/env python3
"""TlsClient private fragment helper with timed/no-wait/branch/TLS12/TLS13/shaped/Reality and
pending-shutdown variants. Two workers/local TLS peer; checks ClientHello cuts, ALPN, exact reverse
echo and shutdown143. Requires namespace isolation, SSL/local credentials. Record peeking is a
shared named TLS fixture. CTest: waterwall.tlsclient_fragment_branch,
waterwall.tlsclient_fragment_no_wait, waterwall.tlsclient_fragment_pending,
waterwall.tlsclient_fragment_reality, waterwall.tlsclient_fragment_shaped,
waterwall.tlsclient_fragment_timed, waterwall.tlsclient_fragment_tls12,
waterwall.tlsclient_fragment_tls13."""
import concurrent.futures
import json
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import os
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parent / "support" / "python")))
from wwtest.sockets import configure_listener
from wwtest.config import core_config
from wwtest.run_directory import RunDirectory
from wwtest.process import Process, close_on_error, install_termination_handler
from wwtest.fixtures.tls import inspect_client_hello

from wwtest.sockets import exact




def run(binary, mode):
    tests = Path(__file__).resolve().parent
    fragment = {"mode": "counter", "count": 1, "cuts": [[250, 2, 100], [300, 5, 100]]}
    if mode == "timed":
        fragment = {"mode": "timed", "duration-ms": 1000, "cuts": fragment["cuts"]}
    if mode == "no_wait":
        fragment["wait-for-est"] = False
    if mode == "pending":
        fragment["cuts"] = [[250, 60000, 100]]
    if mode in ("tls12", "tls13", "shaped", "reality"):
        fragment["tls-hello-fragment"] = True
    with RunDirectory("waterwall-tls-fragment-") as directory:
        root = Path(directory)
        if mode == "reality":
            config = json.loads((tests / "cases/reality_v2_roundtrip/config.json").read_text())
            for node in config["nodes"]:
                if node["type"] == "RealityClient":
                    node["settings"]["fragment"] = fragment
                if node["type"] == "TlsServer":
                    for key, name in (("cert-file", "server.crt"), ("key-file", "server.key")):
                        node["settings"][key] = str(tests / "cases/tls_roundtrip" / name)
            (root / "config.json").write_text(json.dumps(config))
            subprocess.run(["bash", str(tests / "run_waterwall_case.sh"), binary, str(root), "30"], check=True)
            return

        settings = {"sni": "tls.integration.test", "verify": False, "alpns": ["http/1.1"], "fragment": fragment}
        if mode == "shaped":
            settings["tls13-record-shaping"] = {
                "scope": {"first-application-records": 4},
                "outcomes": [{"probability": 100, "padding-bytes": 128,
                              "delay": {"probability": 100, "ms": 2}}],
            }
        nodes = [
            {"name": "in", "type": "TcpListener", "next": "tls",
             "settings": {"address": "127.0.0.1", "port": 28011, "nodelay": True}},
            {"name": "tls", "type": "TlsClient", "next": "out", "settings": settings},
            {"name": "out", "type": "TcpConnector",
             "settings": {"address": "127.0.0.1", "port": 28012, "nodelay": True, "fastopen": False}},
        ]
        if mode == "branch":
            nodes[0]["next"] = "route"
            nodes.extend([
                {"name": "route", "type": "Router", "next": "unused",
                 "settings": {"rules": [{"source-port": 28011, "target": "tls"}]}},
                {"name": "unused", "type": "TcpConnector", "settings": {"address": "127.0.0.1", "port": 9}},
            ])
        (root / "config.json").write_text(json.dumps({"name": "tls-fragment", "nodes": nodes}))
        (root / "core.json").write_text(json.dumps({
            "configs": ["config.json"],
            "log": core_config()["log"],
            "misc": {"workers": 2, "splice": True, "ram-profile": "minimal", "try-enabling-bbr": False},
        }))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(tests / "cases/tls_roundtrip/server.crt", tests / "cases/tls_roundtrip/server.key")
        context.minimum_version = context.maximum_version = (
            ssl.TLSVersion.TLSv1_2 if mode == "tls12" else ssl.TLSVersion.TLSv1_3)
        context.set_alpn_protocols(["http/1.1"])
        data = bytes(range(256)) * 1024
        with socket.socket() as backend, (root / "stdout.log").open("w+") as log:
            configure_listener(backend, ('127.0.0.1', 28012), timeout=15)
            future = None
            with Process([binary], cwd=root, log=log) as process:
                try:
                    deadline = time.monotonic() + 10
                    while True:
                        if process.poll() is not None or time.monotonic() >= deadline:
                            raise AssertionError("TLS fragment startup failed")
                        try:
                            client = socket.create_connection(("127.0.0.1", 28011), timeout=1)
                            break
                        except ConnectionRefusedError:
                            time.sleep(.02)
                    with client:
                        client.settimeout(15)
                        if mode == "pending":
                            client.sendall(b"plaintext held during TLS handshake")
                            with backend.accept()[0] as peer:
                                peer.settimeout(.2)
                                try:
                                    peer.recv(1)
                                except socket.timeout:
                                    pass
                                else:
                                    raise AssertionError("delayed initial fragment escaped")
                                process.send_signal(signal.SIGTERM)
                                assert process.wait(timeout=10) == 128 + signal.SIGTERM
                                peer.settimeout(3)
                                assert peer.recv(1) == b"", "pending TLS/helper line survived shutdown"
                            return

                        def echo():
                            with backend.accept()[0] as raw:
                                raw.settimeout(15)
                                if fragment.get("tls-hello-fragment"):
                                    hello = inspect_client_hello(raw, [250, 50])
                                    assert len(hello) > 300
                                with context.wrap_socket(raw, server_side=True) as peer:
                                    assert peer.selected_alpn_protocol() == "http/1.1"
                                    assert exact(peer, len(data)) == data
                                    peer.sendall(data[::-1])

                        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor, close_on_error(client):
                            future = executor.submit(echo)
                            client.sendall(data)
                            assert exact(client, len(data)) == data[::-1]
                            future.result(timeout=20)
                    process.send_signal(signal.SIGTERM)
                    assert process.wait(timeout=10) == 128 + signal.SIGTERM
                except BaseException:
                    if future is not None and future.done() and not future.cancelled():
                        peer_error = future.exception()
                        if peer_error is not None:
                            print(f"TLS fragment peer failed: {peer_error!r}", file=sys.stderr)
                    raise


if __name__ == "__main__":
    install_termination_handler()
    run(str(Path(sys.argv[1]).resolve()), sys.argv[2])
    print("TlsClient private fragment helper passed")
