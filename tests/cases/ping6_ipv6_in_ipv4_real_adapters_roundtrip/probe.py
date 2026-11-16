#!/usr/bin/env python3
"""Run the shared real-adapter fixture with the protocol-41 fixed IPv6 envelope.

The shared probe independently constructs/inspects IPv6, verifies ICMPv6 against
actual inner addresses, checks exact replies and 1451/1452 native boundaries.
RawSocket and TunDevice explicitly reassemble IPv4 fragments in the private
namespace. Outer IpOverrider rules restore the native addresses before TUN.
"""
import importlib.util
from pathlib import Path

source = Path(__file__).resolve().parents[1] / "ping6_direct_real_adapters_roundtrip" / "probe.py"
spec = importlib.util.spec_from_file_location("ping6_adapter_probe", source)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
probe.IPV6_IN_IPV4 = True
probe.CARRIER_PROTOCOL = 41
probe.NATIVE_MAX = 1451
probe.TUN_NAME = "wwping6nested0"
probe.PSEUDO_SOURCE = "fd00:1234::1"
probe.PSEUDO_DESTINATION = "fd00:1234::2"

if __name__ == "__main__":
    probe.main()
