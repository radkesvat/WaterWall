# TCP adapter admission and close

The TCP adapter pause/close fixtures cover FIFO admission before reentrant Pause,
capacity refusal for empty buffers, and nested Resume/Finish during write completion.
Real socketpair writes verify retained allocation charge across partial progress, the
combined active/queued ceiling, FIFO suffix release and asynchronous write failure.
A resolver/connector composition covers DNS and literal payload admission before Est;
DNS completion and socket-connect timing are controlled while writes use real sockets.
Both adapters test bounded socket cleanup after a fallback peer write-shutdown
request. Queued bytes precede FIN, late input is discarded after line destruction,
and peer EOF or worker stop releases the socket. Traffic cannot extend the absolute
deadline. Quiescence refuses a new linger.

`waterwall.tcplistener_paused_eof` and `waterwall.tcpconnector_paused_eof` run
the same fixtures with IPv4 loopback sockets in the network namespace harness.
The app sends 131,072 patterned bytes and finishes with reads paused, an empty
WIO queue, and outstanding kernel writes. Ordinary Finish closes the descriptor
and removes the idle entry even with unread peer input. Linux can reset a socket
in that case. The peer checks the complete body and EOF for ordinary close with
no unread input and for the fallback exception with unread input.

```bash
ctest --test-dir build/linux-unit-tests -C Debug --output-on-failure --no-tests=error \
  -R '^waterwall\.tcp(listener|connector)_paused_eof$'
```

See [tcp_adapter_pause_close_test.c](tcp_adapter_pause_close_test.c) for the native fixture and exact CTest variants.
