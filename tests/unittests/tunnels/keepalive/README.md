# KeepAlive framing and watchdog

KeepAlive
fixtures check ordinary and pipe bodies, fixed-header-only reads, large frame
splitting, nested FIFO, ping/pong, Pause-aware timer production and callback-close
cleanup. Both sides also compile the actual framing and buffer sources with
`WW_HAVE_SPLICE=0`. The `framed_{constant,port,v1,v2,keepalive,keepalive_client,keepalive_server}_splice_{true,false}`
socket cases exercise HeaderServer modes and a TCP-connected KeepAlive pair,
checking exact bidirectional bytes, positive endpoint pipe-to-TCP transfers,
disabled splice and orderly shutdown. External KeepAlive peers send a complete
6 MiB frame in each decoding direction. Native cases cover the 6 MiB boundary,
32-bit length rejection, five-byte header fragments and a maximum frame
assembled from many real pipes with complete ordinary fallback.

The optional KeepAliveClient watchdog has native coverage for exact reply
deadlines, one outstanding ping, fragmented ordinary/pipe pongs, reentrant replies,
late and nonempty pongs, transport Est, overlapping Pause/Resume, pending-frame
cleanup on timeout, disabled behavior and strict settings validation. Separate
idle items verify that a timely pong cancels only its watchdog, waiting never
extends a reply deadline, and a tolerance shorter than the ping interval expires
independently of probes or Resume.
The orderly-shutdown fixture checks embedded allocation and zero initialization
for four worker slots, then exercises two client instances across two workers,
checking independent idle tables, exact-line removal, surviving-line pings and
callback-reference settlement. It covers reentrant closes of the current line
and an unvisited due sibling, lazy table timer failure, late Est after quiescence,
and owner-worker table destruction with line cleanup before or after quiescence.
The `framed_keepalive_client_{watchdog,timeout}_splice_{true,false}` socket
cases check large transfers and continued pings after timely replies, closure of
both TCP endpoints after a missing reply, and orderly shutdown.

See [keepalive_splice_test.c](keepalive_splice_test.c) for the native fixture and exact CTest variants.

HeaderServer framing is described beside [headerserver_est_ordering_test.c](../header/headerserver_est_ordering_test.c); the shared socket driver is [framed_splice_integration.py](../../../framed_splice_integration.py).
