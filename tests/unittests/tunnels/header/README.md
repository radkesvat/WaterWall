# HeaderServer framing and Est ordering

The [native fixture](headerserver_est_ordering_test.c) checks real-pipe split
port/PROXY headers, TCP/UDP protocol headers, coalesced tails, nested initialization
input and established forwarding. The one-byte protocol header publishes exact TCP
or UDP to the next Init and preserves the source and destination endpoint. Invalid
protocol bytes close the line. The line-mark case splits a 16-byte mark across two
deliveries, checks that the next Init sees the complete mark with TCP, and verifies
that only the trailing payload reaches the branch. The fixture also checks repeated
Est and Pause/Resume, retirement after the initial FIFO drains, zeroed state and
callback dispatch after bypass. The previous mock owns the normal line. HeaderServer
and the next mock borrow it, with a held reference for post-Finish observations.

The [HeaderClient component cases](../easy/easy_nodes_splice_header.c) exercise
source and destination protocol selection, inherited and configured marks,
missing or invalid marks, and one-time insertion with ordinary and splice
buffers. They check that callbacks from next Init can change the line metadata
without changing the header already selected for transmission.

The [framed socket fixture](../../../framed_splice_integration.py) exercises
constant, port, PROXY v1/v2 and paired HeaderClient/HeaderServer protocol modes
through private network namespaces with real TCP peers, exact bidirectional bytes
and enabled/disabled splice evidence.
