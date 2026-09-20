#!/usr/bin/env python3
"""Preserve mode may feed a local stack when the delivered packet is whole."""
import socket
import time
import subprocess
import json
import threading


def main():
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        result = subprocess.run(["ip", "-j", "addr", "show", "dev", "wwfrag0"], capture_output=True, text=True)
        if result.returncode == 0:
            interfaces = json.loads(result.stdout)
            if any("UP" in item["flags"] and any(a.get("local") == "10.253.80.1" for a in item.get("addr_info", [])) for item in interfaces):
                break
        time.sleep(0.02)
    else:
        raise AssertionError("TUN did not become ready")
    payload = bytes((i * 31 + 7) & 255 for i in range(256))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("127.0.0.1", 24371))
        server.settimeout(8)
        errors = []

        def echo():
            try:
                for _ in range(3):
                    data, peer = server.recvfrom(65535)
                    assert data == payload, "backend received a fragment or corrupted datagram"
                    server.sendto(data, peer)
            except Exception as exc:
                errors.append(exc)

        worker = threading.Thread(target=echo)
        worker.start()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(8)
                # Linux IP_MTU_DISCOVER / IP_PMTUDISC_DONT permits IPv4 fragmentation.
                client.setsockopt(socket.IPPROTO_IP, 10, 0)
                client.bind(("10.253.80.1", 0))
                client.connect(("10.253.80.2", 24370))
                for _ in range(3):
                    client.send(payload)
                    assert client.recv(65535) == payload, "whole-datagram roundtrip changed payload"
        finally:
            worker.join(timeout=9)
        assert not worker.is_alive(), "echo did not finish"
        if errors:
            raise errors[0]


if __name__ == "__main__":
    main()
