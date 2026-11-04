# TUN write MTU

`TunDevice (MTU 1500) → IpOverrider → TunDevice (MTU 1200)` injects
incoming IPv4 UDP packets into the local OS. The address rewrite directs them
to a local UDP receiver without bypassing either device.

The probe verifies exact payloads for IP sizes 1200, 1201, 1500 and 65535, then
a small packet to confirm continued delivery. The first device reassembles
kernel-fragmented input; the second must accept the complete datagram independently
of its configured transmit MTU. Both nodes disable GSO; native writer fixtures
separately cover raw and virtio framing and packet-local size refusals.

CTest: `waterwall.tundevice_write_mtu`. Requires Linux TUN and the existing
privileged network-namespace harness. No public network access is used.
