# Trojan server socket coverage

The native Linux `trojanserver_{tcp,tcp_db,udp,fallback,fallback_http}_splice_{true,false}` cases use
real socket peers and the same namespace/strace pattern as the client cases.
They verify authenticated server-first TCP, multiple real UDP destinations and
empty datagrams, exact fallback replay, actual splice transfers and orderly
shutdown. The database variant verifies the inserted UserController and rejects a
second authenticated connection at its live connection limit. The server native
units additionally cover early backend replies,
association-wide pressure, authentication boundaries, budgets and pipe fallback;
the existing fallback lifetime fixture covers mixed final batches as well.
The `fallback_http` cases check local HTTP replies immediately followed by Finish
without Est, with zero and nonzero fallback delay. HttpProxyServer disables splice
for these chains even when requested; native tests cover the same callback order
with ordinary and real-pipe replies.

See [trojanserver_splice_test.c](trojanserver_splice_test.c) for the native fixture and exact CTest variants.

Client flow-control cases cover ordinary combined first requests, timeout
configuration and cancellation, pre-Est input, UDP batches that finish through
Pause and exact retention limits. Socket cases check later TCP splice traffic
after the deliberately materialized first request, timer fallback and shutdown
while waiting. The client/server source comments give the native selections.
