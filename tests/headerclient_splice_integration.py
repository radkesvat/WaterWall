#!/usr/bin/env python3
"""HeaderClient emits exact PROXY TCP4 prefix before a 1MiB upload and reverse echo. One worker and
loopback socket peer, both splice settings, EOF and shutdown143; namespace only. The read cap65536
and raw timeout semantics are preserved; this case does not use strace. CTest:
waterwall.headerclient_tcp_splice_false, waterwall.headerclient_tcp_splice_true."""
import concurrent.futures
import json
from pathlib import Path
import signal
import socket
import sys
import os
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parent / "support" / "python")))
from wwtest.sockets import configure_listener, connect_when_ready
from wwtest.config import core_config
from wwtest.sockets import exact as read_exact
from wwtest.run_directory import RunDirectory
from wwtest.process import Process, close_on_error, install_termination_handler




def receive_exact(sock, size):
    return read_exact(sock, size, max_chunk=65536, timeout_context=False)


def run(binary, enabled):
    payload = bytes(range(256)) * 4096
    response = payload[::-1]
    with RunDirectory("waterwall-header-splice-") as directory:
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
            "log": core_config()["log"],
            "configs": ["config.json"],
            "misc": {"workers": 1, "splice": enabled, "ram-profile": "minimal", "mtu": 1500,
                     "try-enabling-bbr": False},
        }))
        with socket.socket() as listener, (root / "stdout.log").open("w+") as log:
            configure_listener(listener, ('127.0.0.1', 27942), timeout=15)
            with Process([binary], cwd=root, log=log) as process:
                deadline = time.monotonic() + 10
                client = connect_when_ready(process, ('127.0.0.1', 27941), deadline=deadline,
                    failure=lambda: AssertionError(f'WaterWall startup exited {process.returncode}'), timeout=1, pause=0.02)
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

                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor, close_on_error(client):
                        result = executor.submit(peer)
                        client.sendall(payload)
                        assert receive_exact(client, len(response)) == response, "downstream bytes differ"
                        client.shutdown(socket.SHUT_RDWR)
                        result.result(timeout=20)
                process.send_signal(signal.SIGTERM)
                assert process.wait(timeout=10) == 128 + signal.SIGTERM, "unclean WaterWall shutdown"


if __name__ == "__main__":
    install_termination_handler()
    run(str(Path(sys.argv[1]).resolve()), sys.argv[2] == "true")
    print("HeaderClient bidirectional TCP integrity and orderly shutdown passed")
