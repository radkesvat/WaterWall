# SOCKS ordinary and splice boundaries

SOCKS parser fixtures also use real private pipes and resident prefixes for mixed
handshake input, coalesced application tails, parser reentry, rejection, and FIFO
release. Ready TCP cases check that both directions retain the original splice
buffer. UDP cases verify complete ordinary decoding/framing and the read
preferences of application, control, relay and backend lines, including UDP-only
Init and mixed-service UDP ASSOCIATE selection. The
`socks5{client,server}_tcp_{auth,noauth}_splice_{true,false}` integration cases use
external socket peers, local-only client DNS, large post-negotiation transfers,
and positive pipe-to-TCP syscall evidence; disabled cases require no successful
splice calls.
The `socks5{client,server}_udp_ordinary_reads` cases exercise real UDP
associations, including empty datagrams, with splice enabled globally and require
that their TCP control and UDP sockets make no splice attempts.


Native fixtures: [socks5client_reply_input_test.c](socks5client_reply_input_test.c),
[socks5server_control_input_test.c](socks5server_control_input_test.c), and
[socks_est_flow_test.c](socks_est_flow_test.c). They also cover Init/Est reentry,
Pause-aware protocol backlog release, reply-before-body ordering and byte/entry refusal.
The [socket fixture](../../../socks5_splice_integration.py) documents its exact CTest variants.
