#!/usr/bin/env python3
"""Reassembled packets may traverse ordinary transforms to a packet sink."""
import socket
import time
import subprocess
import json


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
    # The old topology allowlist refused this transform/sink path at startup.
    # Exercise both ordinary traffic and a reassembled datagram through it.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        sender.setsockopt(socket.IPPROTO_IP, 10, 0)
        sender.bind(("10.253.80.1", 0))
        for size in (256, 8192):
            sender.sendto(bytes((i * 31 + 7) & 255 for i in range(size)), ("10.253.80.2", 24370))
    time.sleep(0.1)


if __name__ == "__main__":
    main()
