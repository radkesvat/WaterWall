#!/usr/bin/env python3
"""HeaderClient TCP bytes against an external PROXY-aware peer, inside the namespace harness."""
import concurrent.futures
import json
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time


def receive_exact(sock, size):
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(min(65536, size - len(chunks)))
        if not chunk:
            raise AssertionError(f"EOF after {len(chunks)} of {size} bytes")
        chunks.extend(chunk)
    return bytes(chunks)


def run(binary, enabled):
    payload = bytes(range(256)) * 4096
    response = payload[::-1]
    with tempfile.TemporaryDirectory(prefix="waterwall-header-splice-") as directory:
        root = Path(directory)
        nodes = [
            {"name": "listen", "type": "TcpListener", "next": "header",
             "settings": {"address": "127.0.0.1", "port": 27941, "nodelay": True}},
            {"name": "header", "type": "HeaderClient", "next": "connect",
             "settings": {"data": "proxy-protocol-v1", "frontend-ipv4": "192.0.2.2"}},
            {"name": "connect", "type": "TcpConnector",
             "settings": {"address": "127.0.0.1", "port": 27942, "nodelay": True, "fastopen": False}},
        ]
        (root / "config.json").write_text(json.dumps({"name": "header-splice", "nodes": nodes}))
        (root / "core.json").write_text(json.dumps({
            "log": {"path": "log/", **{name: {"loglevel": "DEBUG", "file": name + ".log", "console": True}
                                      for name in ("internal", "core", "network", "dns")}},
            "configs": ["config.json"],
            "misc": {"workers": 1, "splice": enabled, "ram-profile": "minimal", "mtu": 1500,
                     "try-enabling-bbr": False},
        }))
        with socket.socket() as listener, (root / "stdout.log").open("w+") as log:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 27942))
            listener.listen()
            listener.settimeout(15)
            process = subprocess.Popen([binary], cwd=root, stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 10
                while True:
                    if process.poll() is not None:
                        raise AssertionError(f"WaterWall startup exited {process.returncode}")
                    try:
                        client = socket.create_connection(("127.0.0.1", 27941), timeout=1)
                        break
                    except ConnectionRefusedError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.02)
                with client:
                    client.settimeout(15)
                    source_port = client.getsockname()[1]

                    def peer():
                        with listener.accept()[0] as conn:
                            conn.settimeout(15)
                            expected = f"PROXY TCP4 127.0.0.1 192.0.2.2 {source_port} 27941\r\n".encode()
                            assert receive_exact(conn, len(expected)) == expected, "incorrect PROXY prefix"
                            assert receive_exact(conn, len(payload)) == payload, "upstream bytes differ"
                            conn.sendall(response)
                            # Keep the peer open until the client has consumed all response bytes.
                            assert conn.recv(1) == b"", "unexpected bytes after payload"

                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                        result = executor.submit(peer)
                        client.sendall(payload)
                        assert receive_exact(client, len(response)) == response, "downstream bytes differ"
                        client.shutdown(socket.SHUT_RDWR)
                        result.result(timeout=20)
                process.send_signal(signal.SIGTERM)
                assert process.wait(timeout=10) == 128 + signal.SIGTERM, "unclean WaterWall shutdown"
            except BaseException:
                log.flush()
                print((root / "stdout.log").read_text(), file=sys.stderr)
                raise
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    run(str(Path(sys.argv[1]).resolve()), sys.argv[2] == "true")
    print("HeaderClient bidirectional TCP integrity and orderly shutdown passed")
