# Router splice coverage

`waterwall.router_splice_unit` exercises Router and SniffRouter with ordinary,
private-pipe and resident-prefix-plus-pipe input: split sniffing, exact initial
replay, opaque forwarding in both directions, metadata-only Init commitment,
complete oversized headers, and Finish during retained input or branch callbacks.
It also checks Router's internal DomainResolver capability. Run it in both
`linux-unit-debug` and `linux-unit-release`. The existing node-layer units cover
both routers' metadata and whole-chain eligibility, including an unselected
blocking branch, disabled splice and unsupported builds.

The native Linux `waterwall.{router_metadata,router_sniff,router_resolve,sniffrouter}_tcp_splice_{true,false}`
cases use external loopback socket peers through the namespace harness. They
verify target/default selection, exact setup replay, bidirectional opaque bytes
and orderly shutdown. `strace` requires successful pipe-to-socket transfers in
both directions when enabled and no successful splice calls when disabled.

Sources: [router_splice_test.c](router_splice_test.c), [router_sniffing_test.c](router_sniffing_test.c); socket fixture: [router_splice_integration.py](../../../router_splice_integration.py).
