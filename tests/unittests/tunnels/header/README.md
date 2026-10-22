# HeaderServer framing and Est ordering

The [native fixture](headerserver_est_ordering_test.c) checks real-pipe split
port/PROXY headers, TCP/UDP protocol markers, coalesced tails, nested initialization
input and opaque established forwarding. Protocol cases check that the destination
protocol is replaced before next Init while source and other destination metadata
survive, and reject invalid markers. It also checks repeated Est and Pause/Resume,
retirement after the initial FIFO drains, zeroed state and callback dispatch after
bypass. The previous mock owns the normal line; HeaderServer and
the next mock borrow it, with a held observation reference for post-Finish checks.
The source gives its exact CTest name and feature conditions.

The [HeaderClient component cases](../easy/easy_nodes_splice_header.c) exercise
source and destination protocol selectors with ordinary and splice payloads,
snapshotting before a next Init that rewrites the transport or reenters Payload,
strict invalid-context rejection, one-time insertion, bypass and Finish cleanup.

The [framed socket fixture](../../../framed_splice_integration.py) exercises
constant, port, PROXY v1/v2 and paired HeaderClient/HeaderServer protocol modes
through private network namespaces with real TCP peers, exact bidirectional bytes
and enabled/disabled splice evidence.
