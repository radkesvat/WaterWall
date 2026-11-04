#!/usr/bin/env python3
"""TUN injection accepts valid IPv4 packets larger than its transmit MTU."""
import json
import socket
import subprocess
import time


def wait_interface(name, address, mtu):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        result = subprocess.run(["ip", "-j", "addr", "show", "dev", name],
                                capture_output=True, text=True)
        if result.returncode == 0:
            for item in json.loads(result.stdout):
                if ("UP" in item["flags"] and item["mtu"] == mtu and
                        any(entry.get("local") == address for entry in item.get("addr_info", []))):
                    return
        time.sleep(0.02)
    raise AssertionError(f"TUN {name} did not become ready with MTU {mtu}")


def main():
    wait_interface("wwmtuin", "10.253.82.1", 1500)
    wait_interface("wwmtuout", "10.253.83.1", 1200)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        receiver.bind(("10.253.83.1", 0))
        receiver.settimeout(3)
        sender.bind(("10.253.82.1", 0))
        # Linux IP_MTU_DISCOVER / IP_PMTUDISC_DONT: large input is fragmented
        # by the kernel and reassembled by the first TunDevice before injection.
        sender.setsockopt(socket.IPPROTO_IP, 10, 0)
        for size in (1172, 1173, 1472, 65507, 1):
            expected = bytes((index * 31 + size) & 255 for index in range(size))
            sender.sendto(expected, ("10.253.82.2", receiver.getsockname()[1]))
            try:
                actual, peer = receiver.recvfrom(65535)
            except socket.timeout as error:
                raise AssertionError(f"TUN failed to inject a {size + 28}-byte IP packet") from error
            assert actual == expected, f"TUN changed a {size + 28}-byte IP packet"
            assert peer == ("10.253.83.2", sender.getsockname()[1]), "unexpected rewritten peer"
    print("TUN MTU 1200: delivered IP sizes 1200, 1201, 1500, 65535 and 29")


if __name__ == "__main__":
    main()
