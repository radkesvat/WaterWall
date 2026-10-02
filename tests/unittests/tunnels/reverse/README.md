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
successful splice calls when disabled, and shutdown with retained unpaired input.

Sources: [reverseserver_splice_test.c](reverseserver_splice_test.c), [reverseserver_large_wait_test.c](reverseserver_large_wait_test.c); socket fixture: [reverseserver_splice_integration.py](../../../reverseserver_splice_integration.py).
