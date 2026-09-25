#!/usr/bin/env python3
"""Private TLS fragment helper: loopback TLS, branch topology and pending shutdown."""
import concurrent.futures
import json
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
from trojanclient_splice_integration import exact


def run(binary, mode):
    tests = Path(__file__).resolve().parent
    fragment = {"mode": "counter", "count": 1, "cuts": [[250, 2, 100], [300, 5, 100]]}
    if mode == "timed":
        fragment = {"mode": "timed", "duration-ms": 1000, "cuts": fragment["cuts"]}
    if mode == "no_wait":
        fragment["wait-for-est"] = False
    if mode == "pending":
        fragment["cuts"] = [[250, 60000, 100]]
    with tempfile.TemporaryDirectory(prefix="waterwall-tls-fragment-") as directory:
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
            "log": {"path": "log/", **{name: {"loglevel": "DEBUG", "file": name + ".log", "console": True}
                                      for name in ("internal", "core", "network", "dns")}},
            "misc": {"workers": 2, "splice": True, "ram-profile": "minimal", "try-enabling-bbr": False},
        }))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(tests / "cases/tls_roundtrip/server.crt", tests / "cases/tls_roundtrip/server.key")
        context.minimum_version = context.maximum_version = (
            ssl.TLSVersion.TLSv1_2 if mode == "tls12" else ssl.TLSVersion.TLSv1_3)
        context.set_alpn_protocols(["http/1.1"])
        data = bytes(range(256)) * 1024
        with socket.socket() as backend, (root / "stdout.log").open("w+") as log:
            backend.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            backend.bind(("127.0.0.1", 28012))
            backend.listen()
            backend.settimeout(15)
            process = subprocess.Popen([binary], cwd=root, stdout=log, stderr=subprocess.STDOUT)
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
                            with context.wrap_socket(raw, server_side=True) as peer:
                                assert peer.selected_alpn_protocol() == "http/1.1"
                                assert exact(peer, len(data)) == data
                                peer.sendall(data[::-1])

                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                        future = executor.submit(echo)
                        client.sendall(data)
                        assert exact(client, len(data)) == data[::-1]
                        future.result(timeout=20)
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
    run(str(Path(sys.argv[1]).resolve()), sys.argv[2])
    print("TlsClient private fragment helper passed")
