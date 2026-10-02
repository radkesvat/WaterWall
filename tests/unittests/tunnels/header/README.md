# HeaderServer framing and Est ordering

The [native fixture](headerserver_est_ordering_test.c) checks real-pipe split
port/PROXY headers, coalesced tails, nested initialization input and opaque
established forwarding. The previous mock owns the normal line; HeaderServer and
the next mock borrow it, with a held observation reference for post-Finish checks.
The source gives its exact CTest name and feature conditions.

The [framed socket fixture](../../../framed_splice_integration.py) exercises
constant, port, PROXY v1/v2 modes through private network namespaces with real
TCP peers, exact bidirectional bytes and enabled/disabled splice evidence.
