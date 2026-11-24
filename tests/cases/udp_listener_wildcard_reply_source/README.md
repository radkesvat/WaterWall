# Wildcard UDP listener reply addresses

One client socket sends requests to `127.0.0.2` and `127.0.0.3` on the same wildcard listener port. The loopback backend waits for both requests, then replies to the second before the first. The probe checks each reply's sender IP, port and payload.

The IPv4 listener receives from an odd client port, which selects worker 1 and exercises the handoff to the listener socket on worker 0. The dual-stack listener receives the same IPv4 traffic from an even port on worker 0, followed by a native IPv6 exchange over `::1`.

A listener bound specifically to `127.0.0.1` shares the IPv4 port. A request to that address must reach its exact backend, while a directed broadcast must reach the wildcard backend. Both replies must use the local unicast address.

Run the namespace test `waterwall.udp_listener_wildcard_reply_source`.
