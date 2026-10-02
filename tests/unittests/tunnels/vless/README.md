# VlessClient splice coverage

`waterwall.vlessclient_splice_unit` and `waterwall.vlessclient_no_splice_unit`
compile the actual node and range helpers with splice enabled/disabled. Run both
with `ctest --preset linux-unit-debug -R '^waterwall\.vlessclient_(splice|no_splice)_unit$'`
and repeat with `linux-unit-release`. Coverage includes early Est/request ordering,
pre-response sends, response splits/addons, opaque TCP identity, UDP length bounds,
mixed private pipes, fallback after partial movement, padding, reentrant pressure,
logical queue bounds, and exact-line cleanup. Syscall wrappers distinguish parser
metadata reads from receiver inspection; preserved pipe bodies must not be read.

`waterwall.vlessclient_{tcp,udp}_splice_{true,false}` uses
`vlessclient_splice_integration.py` through the network-namespace harness. A loopback
socket VLESS peer verifies exact requests, outbound progress before response,
response addons, server-first TCP, UDP boundaries, and shutdown with a live carrier.
`strace` is required: enabled cases require positive splice transfers and disabled
cases require ordinary operation. The real chain includes the internal resolver;
no VlessServer or TLS node masks capability. Existing VLESS roundtrips remain the
ordinary server-interoperability coverage. These tests make no throughput claim.

Source: [vlessclient_splice_test.c](vlessclient_splice_test.c); socket fixture: [vlessclient_splice_integration.py](../../../vlessclient_splice_integration.py).

Client flow-control cases cover ordinary combined first requests, timeout
configuration and cancellation, pre-Est input, UDP batches that finish through
Pause and exact retention limits. Socket cases check later TCP splice traffic
after the deliberately materialized first request, timer fallback and shutdown
while waiting. The client/server source comments give the native selections.
