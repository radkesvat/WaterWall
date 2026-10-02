"""Compatibility source path for wwtest.fixtures.socket_manager.
Not executable: callers own TUN/runtime setup; the named fixture owns marker
server startup, wake-up, joins and peer-error accounting.
"""
import sys
from pathlib import Path
import os
sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parents[1] / "support/python")))
from wwtest.fixtures.socket_manager import MarkerServers, TcpMarkerServer, UdpMarkerServer, expect_tcp_marker, expect_udp_marker
