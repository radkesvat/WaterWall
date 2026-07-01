#!/usr/bin/env python3

import pathlib
import sys


sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from socket_manager_privileged_common import MarkerServers, TcpMarkerServer, expect_tcp_marker


LISTEN_PORT = 43610
SPECIFIC_IP = "10.251.21.1"
SPECIFIC_MARKER = b"tcp-specific-single\n"
WILDCARD_MARKER = b"tcp-wildcard-single\n"


def main():
    specific = TcpMarkerServer("127.0.0.1", 43611, SPECIFIC_MARKER)
    wildcard = TcpMarkerServer("127.0.0.1", 43612, WILDCARD_MARKER)

    with MarkerServers(specific, wildcard):
        expect_tcp_marker(SPECIFIC_IP, LISTEN_PORT, SPECIFIC_MARKER)
        expect_tcp_marker("127.0.0.1", LISTEN_PORT, WILDCARD_MARKER)
        specific.assert_hit()
        wildcard.assert_hit()


if __name__ == "__main__":
    main()
