#!/usr/bin/env python3
"""A silent TCP user receives a destination greeting through both reverse nodes.
Server-only default/custom activation sizes, replenishment, exact application
bytes and ordinary/splice transport with one/two workers. CTest:
waterwall.reverse_activation_workers_{1,2}_splice_{true,false}. Namespace only.
"""
import json
import os
from pathlib import Path
import signal
import socketserver
import sys
import threading
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parent / "support" / "python")))
from wwtest.config import core_config
from wwtest.process import Process, install_termination_handler
from wwtest.run_directory import RunDirectory
from wwtest.sockets import connect_when_ready, exact

BANNER = b"SSH-2.0-WaterWall-test\r\n"


class Greeting(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        try:
            self.request.sendall(BANNER)
            while True:
                data = self.request.recv(65536)
                if not data:
                    return
                self.request.sendall(data)
        except (ConnectionError, TimeoutError):
            return


def run(binary, workers, splice):
    settings = {} if workers == 1 else {"activation-min-size": 513, "activation-max-size": 4097}
    nodes = [
        {"name": "peers", "type": "TcpListener", "next": "reverse-server",
         "settings": {"address": "127.0.0.1", "port": 27981}},
        {"name": "reverse-server", "type": "ReverseServer", "next": "server-bridge", "settings": settings},
        {"name": "server-bridge", "type": "Bridge", "settings": {"pair": "user-bridge"}},
        {"name": "users", "type": "TcpListener", "next": "user-bridge",
         "settings": {"address": "127.0.0.1", "port": 27982}},
        {"name": "user-bridge", "type": "Bridge", "settings": {"pair": "server-bridge"}},
        {"name": "client-bridge", "type": "Bridge", "next": "reverse-client", "settings": {"pair": "target-bridge"}},
        {"name": "reverse-client", "type": "ReverseClient", "next": "peer-connector",
         "settings": {"minimum-unused": 1}},
        {"name": "peer-connector", "type": "TcpConnector",
         "settings": {"address": "127.0.0.1", "port": 27981, "fastopen": False, "nodelay": True}},
        {"name": "target-bridge", "type": "Bridge", "next": "target-connector", "settings": {"pair": "client-bridge"}},
        {"name": "target-connector", "type": "TcpConnector",
         "settings": {"address": "127.0.0.1", "port": 27983, "fastopen": False, "nodelay": True}},
    ]
    with socketserver.ThreadingTCPServer(("127.0.0.1", 27983), Greeting) as backend:
        backend.daemon_threads = True
        thread = threading.Thread(target=backend.serve_forever, daemon=True)
        thread.start()
        try:
            with RunDirectory("waterwall-reverse-activation-") as directory:
                root = Path(directory)
                (root / "config.json").write_text(json.dumps({"name": "reverse-activation", "nodes": nodes}))
                core = core_config()
                core["configs"] = ["config.json"]
                core["misc"].update({"workers": workers, "splice": splice, "tcp-tune": False,
                                     "try-enabling-bbr": False, "ram-profile": "minimal"})
                (root / "core.json").write_text(json.dumps(core))
                with (root / "stdout.log").open("w+") as log:
                    with Process([binary], cwd=root, log=log) as process:
                        for _ in range(3):
                            with connect_when_ready(process, ("127.0.0.1", 27982),
                                                    deadline=time.monotonic() + 10, timeout=5,
                                                    failure=lambda: AssertionError("WaterWall exited before accepting user")) as user:
                                user.settimeout(10)
                                # No user send occurs before this receive.
                                assert exact(user, len(BANNER)) == BANNER, "activation leaked or greeting stalled"
                                data = bytes(range(256)) * 4096
                                user.sendall(data)
                                assert exact(user, len(data)) == data, "application stream changed after activation"
                        process.send_signal(signal.SIGTERM)
                        assert process.wait(timeout=10) == 128 + signal.SIGTERM, "reverse shutdown failed"
        finally:
            backend.shutdown()
            thread.join(timeout=5)


if __name__ == "__main__":
    install_termination_handler()
    run(str(Path(sys.argv[1]).resolve()), int(sys.argv[2]), sys.argv[3] == "true")
    print("Reverse activation and server-first stream passed")
