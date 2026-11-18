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

See [tcp_adapter_pause_close_test.c](tcp_adapter_pause_close_test.c) for the native fixture and exact CTest variants.
