#!/usr/bin/env python3

import pathlib
import sys


sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from socket_manager_privileged_common import MarkerServers, UdpMarkerServer, expect_udp_marker


LISTEN_PORT = 43620
SPECIFIC_IP = "10.251.22.1"
SPECIFIC_MARKER = b"udp-specific-single\n"
WILDCARD_MARKER = b"udp-wildcard-single\n"


def main():
    specific = UdpMarkerServer("127.0.0.1", 43621, SPECIFIC_MARKER)
    wildcard = UdpMarkerServer("127.0.0.1", 43622, WILDCARD_MARKER)

    with MarkerServers(specific, wildcard):
        expect_udp_marker(SPECIFIC_IP, LISTEN_PORT, SPECIFIC_MARKER)
        expect_udp_marker("127.0.0.1", LISTEN_PORT, WILDCARD_MARKER)
        specific.assert_hit()
        wildcard.assert_hit()


if __name__ == "__main__":
    main()
