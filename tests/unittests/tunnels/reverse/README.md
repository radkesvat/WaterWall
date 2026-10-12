# ReverseServer splice coverage

`waterwall.reverseserver_splice_unit` covers split and invalid handshakes, ordinary
waiting storage in both directions, exact replay, unchanged paired buffers,
Pause/Resume mapping, reentrant close, incomplete-input cleanup and exact/overflow
waiting limits with real private-pipe input. Run it in both `linux-unit-debug`
and `linux-unit-release`, alongside `waterwall.reverseserver_large_wait_unit` and
`waterwall.worker_context_helpers_unit`; the latter already covers cross-worker splice
transfer and cancellation. Node-layer units check the internal PipeTunnel's shared
capability flags and disabled/unsupported/blocked-chain gating.

`waterwall.reverseserver_workers_{1,2}_splice_{true,false}` runs through the namespace
harness with external user and reverse socket peers. Consecutive accepts with two
workers exercise cross-worker pairing. The cases verify exact initial replay,
bidirectional bulk bytes, positive pipe-to-socket transfers when enabled, no
successful splice calls when disabled, and shutdown with a paused unpaired source
and unread socket input. Native units exercise retained application FIFOs directly.

Sources: [reverseserver_splice_test.c](reverseserver_splice_test.c), [reverseserver_large_wait_test.c](reverseserver_large_wait_test.c); socket fixture: [reverseserver_splice_integration.py](../../../reverseserver_splice_integration.py).

Reverse activation coverage checks silent-user pairing in both arrival orders,
strict server-only activation range validation, exactly one size-bearing prefix,
activation-only handoff through Pause at minimum/default/maximum sizes, application
backlog waiting for Resume, and FIFO/cleanup under reentrant Payload, Resume, Pause
and Finish during startup. Waiting sources pause after user Est or a complete
reverse handshake. Cases cover combined consumer holds, replay before source
Resume, and inclusive/overflow 2 MiB / 1,024-buffer limits while waiting or paired,
independently of pool profile. Empty application input consumes no entries.
The client owner suite
checks fragmented headers/padding, protocol size bounds, malformed and incomplete
prefix cleanup, pipe-backed prefix consumption with an untouched application
body, and FIFO/refusal during reentrant destination Init. Its initial body and
queued input share the 2 MiB / 1,024-buffer budget, including exact/overflow buffer
limits and oversized initial-body refusal.
It also covers activation before Est, an Est between prefix fragments, and late
or repeated Est without repeated protocol work or connection accounting changes.
Carrier Pause waits for destination Init, a newer Resume cancels it, and replay
preserves FIFO and cleanup through nested payload or Finish. Active repeated
Pause/Resume notifications map to the correct half without suppressing duplicates.

`waterwall.reverse_activation_workers_{1,2}_splice_{true,false}` uses both reverse
nodes and a loopback greeting server in the namespace harness. Users receive the
server banner before their first send, then exchange exact bulk data. Server-only
custom lengths exercise a range absent from the client config.
