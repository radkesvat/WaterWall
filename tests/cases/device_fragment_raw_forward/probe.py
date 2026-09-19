#!/usr/bin/env python3
"""Compare TUN ingress fragments with real raw-socket loopback output bytes."""
import select
import socket
import json
import subprocess
import time


def main():
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        result = subprocess.run(["ip", "-j", "addr", "show", "dev", "wwfragraw0"], capture_output=True, text=True)
        if result.returncode == 0:
            interfaces = json.loads(result.stdout)
            if any("UP" in item["flags"] and any(a.get("local") == "10.253.81.1" for a in item.get("addr_info", [])) for item in interfaces):
                break
        time.sleep(0.02)
    else:
        raise AssertionError("TUN did not become ready")
    # Unmarked traffic enters TUN; the configured raw writer's mark selects local egress.
    subprocess.run(["ip", "route", "add", "local", "10.253.81.2/32", "dev", "lo", "table", "100"], check=True)
    subprocess.run(["ip", "rule", "add", "fwmark", "99", "lookup", "100", "priority", "100"], check=True)
    payload = bytes((i * 19 + 3) & 255 for i in range(8192))
    with socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0003)) as before, \
            socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0003)) as after, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        before.bind(("wwfragraw0", 0))
        after.bind(("lo", 0))
        receiver.bind(("0.0.0.0", 24372))
        sender.setsockopt(socket.IPPROTO_IP, 10, 0)
        sender.bind(("10.253.81.1", 0))
        sender.sendto(payload, ("10.253.81.2", 24372))
        observed = {before: {}, after: {}}
        delivered = False
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            ready, _, _ = select.select([before, after, receiver], [], [], 0.1)
            for sock in ready:
                if sock is receiver:
                    assert sock.recv(65535) == payload, "raw forwarding changed the UDP datagram"
                    delivered = True
                    continue
                packet, address = sock.recvfrom(65535)
                if len(packet) < 20 or packet[9] != 17 or packet[12:20] != socket.inet_aton("10.253.81.1") + socket.inet_aton("10.253.81.2"):
                    continue
                # Loopback supplies outgoing and incoming copies; retain each exact span once.
                fragment = int.from_bytes(packet[6:8], "big")
                assert fragment & 0x3fff, "raw output was normalized"
                observed[sock][fragment] = packet
            if delivered and len(observed[before]) >= 6 and observed[before] == observed[after]:
                return
        raise AssertionError(f"raw fragment bytes/boundaries differ: input={len(observed[before])}, output={len(observed[after])}, delivered={delivered}")


if __name__ == "__main__":
    main()
