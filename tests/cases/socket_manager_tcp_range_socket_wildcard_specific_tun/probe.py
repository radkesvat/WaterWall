#!/usr/bin/env python3
"""Privileged SocketManager wildcard/specific listener routing (single/range TCP or UDP) against
distinct marker backends. Real loopback/TUN destinations; exact selected markers and joined
peer-error accounting. Requires Linux root/TUN/network namespaces. Marker wake-up
connections/datagrams remain intentional. CTest:
waterwall.socket_manager_tcp_range_socket_wildcard_specific_tun."""

import pathlib
import sys
from pathlib import Path
import os

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parents[2] / "support" / "python")))


sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from wwtest.fixtures.socket_manager import MarkerServers, TcpMarkerServer, expect_tcp_marker


LISTEN_PORT = 65535
SPECIFIC_IP = "10.251.23.1"
SPECIFIC_MARKER = b"tcp-specific-range\n"
WILDCARD_MARKER = b"tcp-wildcard-range\n"


def main():
    specific = TcpMarkerServer("127.0.0.1", 23752, SPECIFIC_MARKER)
    wildcard = TcpMarkerServer("127.0.0.1", 23753, WILDCARD_MARKER)

    with MarkerServers(specific, wildcard):
        expect_tcp_marker(SPECIFIC_IP, LISTEN_PORT, SPECIFIC_MARKER)
        expect_tcp_marker("127.0.0.1", LISTEN_PORT, WILDCARD_MARKER)


if __name__ == "__main__":
    main()
