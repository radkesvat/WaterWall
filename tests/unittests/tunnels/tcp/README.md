# TCP adapter admission and close

The TCP adapter pause/close fixtures cover FIFO admission before reentrant Pause,
capacity refusal for empty buffers, and nested Resume/Finish during write completion.
Real socketpair writes verify retained allocation charge across partial progress, the
combined active/queued ceiling, FIFO suffix release and asynchronous write failure.
A resolver/connector composition covers DNS and literal payload admission before Est;
DNS completion and socket-connect timing are controlled while writes use real sockets.
Both adapters exercise bounded socket cleanup on normal Finish. The peer receives
queued bytes before EOF and can still send input that the detached socket discards
locally. Peer EOF, idle or absolute expiry, and worker stop release the descriptor.
The tests also cover ordinary disposal with normal linger disabled or the fallback
marker cleared, and refusal during quiescence, socket errors, peer EOF, or a pending
outbound connect.

`waterwall.tcplistener_paused_eof` and `waterwall.tcpconnector_paused_eof` run
the same fixtures with IPv4 loopback sockets in the network namespace harness.
The adapter sends 131,072 patterned bytes and finishes with reads paused and
outstanding writes. The peer checks the full body and EOF for normal linger and
for the confirmed fallback exception. Both cases discard a byte queued before
Finish and additional input sent after the peer receives EOF. The ordinary-close
controls check descriptor and idle-entry removal with and without unread input,
and confirm complete body and EOF when the receive queue is empty.

`waterwall.tcp_close_linger_settings_unit` exercises both TCP constructors, both
combined TCP/UDP constructors, and opposite values on the two endpoints of a
single chain.

```bash
ctest --test-dir build/linux-unit-tests -C Debug --output-on-failure --no-tests=error \
  -R '^waterwall\.(tcp(listener|connector)_(pause_close_unit|paused_eof)|tcp_close_linger_settings_unit)$'
```

See [tcp_adapter_pause_close_test.c](tcp_adapter_pause_close_test.c) for the native fixture and exact CTest variants.
