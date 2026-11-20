# SynReply

`SynReply` is a configurable internal node for the middle of a Layer 3 chain.
Place it where both neighbours use the chain-owned worker packet line.
It forwards each original packet unchanged. For each valid, unfragmented,
payload-free opening IPv4 TCP SYN received upstream, it forwards the original
first and then sends one SYN-ACK downstream while the worker's path is open.
Each qualifying retransmission gets its own reply. Downstream traffic,
including responses from a TCP listener, passes through unchanged.
If either endpoint is the unspecified address (`0.0.0.0`), the limited
broadcast address (`255.255.255.255`), or multicast (`224.0.0.0/4`), the
packet passes through without a reply.

Omit `settings` or use an empty object to source each reply from the original
SYN's destination address. Set `settings.reply-source-ip` to a single IPv4
literal to use that address for every reply. A configured `reply-source-ip`
must belong to the server running SynReply. The node rejects unspecified,
limited broadcast and multicast addresses for this setting at startup. In
both modes, the reply goes to the observed sender.

`settings.ttl` sets the IPv4 TTL of generated SYN-ACKs only. It accepts a
JSON integer from 1 to 255 and defaults to 64.

`settings.fake-checksum` accepts only the JSON booleans `true` and `false`.
The default, `false`, gives generated SYN-ACKs a valid TCP checksum. With
`true`, the generated TCP checksum is nonzero and incorrect. In both modes
the reply's IPv4 header checksum is valid and original packets pass unchanged.

Handing off the SYN-ACK completes the response. TCP connection state and later
handshake steps belong to the TCP endpoints.

The node is enabled by default with `INCLUDE_SYN_REPLY`.
