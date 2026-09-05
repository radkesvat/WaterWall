#!/usr/bin/env python3
"""Line-ownership source policy checker.

`lineDestroy()` may only be called by the component that created the exact
`line_t`, and an owner's `Finish` handler for a normal line may not return while
that line is still logically alive. Both rules are architectural: nothing in the
type system distinguishes a line a tunnel created from one merely passing
through it. This checker pins the parts of that contract that are decidable from
the source:

    every production lineCreate()/lineCreateForWorker() site is classified as a
      normal owner, a packet-line allocation, a cross-worker paired-line
      allocation, or an approved test-only allocation;
    a classification is only accepted where that kind of allocation is allowed
      (a packet line may only come from tunnelchainFinalize(), a paired line only
      from pipeTo());
    no area calls lineDestroy() unless it also creates lines, which is the
      "a borrowed-line tunnel never destroys" rule;
    every registered owner close path really does destroy its line;
    every registered packet-lifecycle anchoring Finish handler hard-aborts and
      never destroys the packet line, including dual-role handlers that also see
      a normal line;
    no Finish handler anywhere in tunnels/ absorbs its callback without a written
      reason, so a lost propagation or a lost owner close cannot look like a no-op;
    the local re-entrancy hardening the owner contract does not replace stays in
      place;
    the focused unit tests that prove the runtime postcondition keep their content
      and their ctest registration.

Runtime behaviour is not proved here - the tests named in REQUIRED_CONTRACT_TESTS
do that. This checker's job is to fail when a new creation site or lineDestroy()
site is added without classification, when a registered packet anchor loses its
abort, or when any Finish handler becomes an unexplained no-op.

Every site is identified by (relative source path, exact function name) and never
by a line number. Function bodies are extracted with the lexical C scanner from
tunnels_abort_policy_test.py, which blanks comments, string literals and
character literals before anything is counted, so a commented-out or quoted
lookalike can never satisfy an entry.

Usage:
    python3 tests/line_ownership_policy_test.py [--mutation-test|-m]
"""
import os
import re
import sys

# Importing the sibling checker must not leave a __pycache__ directory behind in
# the source tree when this runs from a build directory.
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tunnels_abort_policy_test import (  # noqa: E402
    ROOT,
    analyze,
    line_of,
)

# ---------------------------------------------------------------------------
# Classifications
# ---------------------------------------------------------------------------

# A normal per-connection or internal line. Its creator is the owner, and the
# owner's Finish handler must return with the line logically dead.
NORMAL_OWNER = "normal-owner"

# The persistent per-worker packet line. Owned by the chain, destroyed only by
# tunnelchainDestroy(), and explicitly excluded from the owner postcondition.
PACKET_LINE = "packet-line"

# The cross-worker partner line a pipe creates for the worker it hands off to.
PAIRED_LINE = "paired-line"

# A line a test fixture allocates by hand. Never part of the runtime contract.
TEST_ONLY = "test-only"

# Where each classification is allowed to appear. A normal owner may live
# anywhere in production; the other three are single-site by construction, which
# is what makes a mislabelled normal owner detectable.
PACKET_LINE_ALLOCATION = ("ww/net/chain.c", "tunnelchainFinalize")
PAIRED_LINE_ALLOCATION = ("ww/net/pipe_tunnel.c", "pipeTo")

# ---------------------------------------------------------------------------
# Manifest: every production line creation site
# ---------------------------------------------------------------------------
#
# Each entry is (relative path, exact function name, classification, role).
# The role is the exact line this call creates, not the node's general purpose:
# a tunnel routinely owns one role while borrowing another.

CREATION_SITES = [
    # ------------------------------------------------------------------
    # Core
    # ------------------------------------------------------------------
    ("ww/net/chain.c", "tunnelchainFinalize", PACKET_LINE,
     "one persistent packet line per worker for a chain with a layer-3 node"),
    ("ww/net/pipe_tunnel.c", "pipeTo", PAIRED_LINE,
     "the partner line on the target worker; the source line stays borrowed"),

    # ------------------------------------------------------------------
    # Endpoint adapters: accepted or per-peer flow lines
    # ------------------------------------------------------------------
    ("tunnels/TcpListener/common/helpers.c", "tcplistenerOnInboundConnected", NORMAL_OWNER,
     "one accepted TCP connection"),
    ("tunnels/UdpListener/common/helpers.c", "onUdpListenerFilteredPayloadReceived", NORMAL_OWNER,
     "one stateful UDP peer flow"),
    ("tunnels/UdpListener/common/dynamic_endpoint.c", "udplistenerOnDynamicEndpointRead", NORMAL_OWNER,
     "one dynamic UDP endpoint line"),
    ("tunnels/UdpStatelessSocket/common/helpers.c", "udpstatelesssocketHandleRecvFrom", NORMAL_OWNER,
     "one stateless UDP peer line"),

    # ------------------------------------------------------------------
    # Drivers and control lines
    # ------------------------------------------------------------------
    ("tunnels/TesterClient/instance/start.c", "testerclientStartWorker", NORMAL_OWNER,
     "one worker test line; packet mode borrows the chain's packet line instead"),
    ("tunnels/SpeedTestClient/instance/start.c", "speedtestclientStartStream", NORMAL_OWNER,
     "one speed-test stream line"),
    ("tunnels/AuthenticationClient/common/protocol.c", "authenticationclientOpenControlLine", NORMAL_OWNER,
     "the reconnectable control line, always on worker 0"),

    # ------------------------------------------------------------------
    # Packet-side bridges: normal lines created behind a packet line
    # ------------------------------------------------------------------
    ("tunnels/WireGuardDevice/common/helpers.c", "wireguarddeviceEnsureTransportLine", NORMAL_OWNER,
     "one transport line per worker; the packet line it also serves is borrowed"),
    ("tunnels/PacketsToConnection/common/tcp.c", "lwipThreadPtcTcpAccptCallback", NORMAL_OWNER,
     "one line per accepted lwIP TCP connection"),
    ("tunnels/PacketsToConnection/common/udp.c", "ptcUdpReceived", NORMAL_OWNER,
     "one line per lwIP UDP flow"),
    ("tunnels/PacketsToStream/common/helpers.c", "packetstostreamEnsureOutputLine", NORMAL_OWNER,
     "the recreated stream output line behind the packet line"),

    # ------------------------------------------------------------------
    # Mux, split, and candidate child lines
    # ------------------------------------------------------------------
    ("tunnels/MuxClient/common/helpers.c", "muxclientCreateParentLine", NORMAL_OWNER,
     "the mux parent/carrier line; child lines are borrowed"),
    ("tunnels/MuxServer/upstream/payload.c", "handleOpenFrame", NORMAL_OWNER,
     "one mux child line; the parent line is borrowed"),
    ("tunnels/ConnectionFisherClient/upstream/init.c", "connectionfisherclientTunnelUpStreamInit", NORMAL_OWNER,
     "the candidate child lines; the main line is borrowed"),
    ("tunnels/HalfDuplexClient/upstream/init.c", "halfduplexclientTunnelUpStreamInit", NORMAL_OWNER,
     "the upload and download transport lines; the main line is borrowed"),
    ("tunnels/HalfDuplexServer/upstream/payload.c", "createAndInitializeMainLine", NORMAL_OWNER,
     "the reconstructed main line; the upload/download lines are borrowed"),
    ("tunnels/ReverseClient/common/helpers.c", "reverseclientBeginConnectMessageReceived", NORMAL_OWNER,
     "the paired upstream and downstream lines"),
    ("tunnels/HttpClient/common/split.c", "httpclientSplitUpStreamInit", NORMAL_OWNER,
     "the upload and download transport lines; the main line is borrowed"),
    ("tunnels/HttpServer/common/split.c", "splitPair", NORMAL_OWNER,
     "the reconstructed main line; the upload/download lines are borrowed"),

    # ------------------------------------------------------------------
    # Protocol clients: internal carrier lines behind a borrowed app line
    # ------------------------------------------------------------------
    ("tunnels/Socks5Client/common/helpers.c", "createInternalLine", NORMAL_OWNER,
     "the internal UDP control/relay lines; the application line is borrowed"),
    ("tunnels/TrojanClient/common/helpers.c", "createInternalLine", NORMAL_OWNER,
     "the internal UDP carrier line; the application line is borrowed"),
    ("tunnels/VlessClient/common/helpers.c", "createInternalLine", NORMAL_OWNER,
     "the internal UDP carrier line; the application line is borrowed"),

    # ------------------------------------------------------------------
    # Protocol servers: UDP remote lines behind a borrowed client line
    # ------------------------------------------------------------------
    ("tunnels/Socks5Server/common/helpers.c", "socks5serverGetOrCreateUdpRemoteLine", NORMAL_OWNER,
     "one UDP remote line per destination; the client line is borrowed"),
    ("tunnels/TrojanServer/common/helpers.c", "trojanserverGetOrCreateUdpRemoteLine", NORMAL_OWNER,
     "one UDP remote line per destination; the client line is borrowed"),
    ("tunnels/VlessServer/common/helpers.c", "vlessserverGetOrCreateUdpRemoteLine", NORMAL_OWNER,
     "one UDP remote line per destination; the client line is borrowed"),

    # ------------------------------------------------------------------
    # Test fixtures
    # ------------------------------------------------------------------
    ("tests/unittests/reality_close_lifecycle_server.c", "serverFixtureMoveLineToOwnerPool", TEST_ONLY,
     "a fixture line re-created in the owning worker's pool"),
    ("tests/unittests/tunnel_line_failure_harness.h", "twfLinePoolCreateLine", TEST_ONLY,
     "the shared pool-backed fixture line the owner-postcondition cases need"),
    ("tests/unittests/udpconnector_socket_pool_test.c", "createFixtureNormalLine", TEST_ONLY,
     "the owner-controlled normal lines used by the UdpConnector pool fixture"),
    ("tests/unittests/udpconnector_socket_pool_test.c", "testCase6_WorkerAndConnectorPoolIsolation", TEST_ONLY,
     "the explicit worker-owned lines used to prove UdpConnector pool isolation"),
    ("tests/unittests/mux_tls_close_backpressure_fixture.c", "mxbCreateLine", TEST_ONLY,
     "the combined Mux/TLS parent and child lines used by real callback-composition fixtures"),
    ("tests/unittests/muxclient_capacity_dispatch_test.c", "caseWorkerDrainIsLocal", TEST_ONLY,
     "one inventoried MuxClient parent per exact worker for owner-drain isolation"),
    ("tests/unittests/muxserver_idle_lifecycle_test.c", "caseWorkerDrainIsLocal", TEST_ONLY,
     "one borrowed parent and one inventoried owned child per exact worker"),
    ("tests/unittests/muxserver_admission_concurrency_test.c", "WTHREAD_ROUTINE", TEST_ONLY,
     "one borrowed MuxServer parent fixture line created on each exact registered owner worker"),
    ("tests/unittests/speedtestclient_orderly_shutdown_test.c", "publishLine", TEST_ONLY,
     "the fixture lines published into SpeedTestClient's worker-owned inventory"),
    ("tests/unittests/worker_context_helpers_test.c",
     "testLineRefcountPublishesTeardownToFinalReleaser",
     TEST_ONLY,
     "the line whose final reference is released by a foreign thread"),
    ("tests/unittests/worker_context_helpers_test.c",
     "exerciseForeignFinalLineReleaseDuringDetach",
     TEST_ONLY,
     "the local, plain-thread, and lwIP-thread final-release fixture lines"),
    ("tests/unittests/worker_context_helpers_test.c",
     "testPipePublicationIsLinearizedWithPreStop",
     TEST_ONLY,
     "the borrowed source lines used across pipe publication, refusal, Finish, and drain cases"),
    ("tests/unittests/worker_context_helpers_test.c", "pipeMessageCaseSetup", TEST_ONLY,
     "the borrowed source line for queued pipe-message settlement cases"),
    ("tests/unittests/wireguarddevice_orderly_shutdown_test.c", "fixtureSetup", TEST_ONLY,
     "a stand-in for the chain's worker packet line, which tunnelchainFinalize() normally allocates"),
    ("tests/unittests/testerclient_orderly_shutdown_test.c",
     "caseSuccessfulDownstreamFinishClosesBeforeSweep",
     TEST_ONLY,
     "two worker-owned lines used to reproduce a completed-line Finish before the final sweep"),
    ("tests/unittests/halfduplexserver_reentrant_init_test.c", "transportOwnerDownstreamFinish", TEST_ONLY,
     "a replacement fixture line used to prove the finished transport allocation remains retained"),
    ("tests/unittests/halfduplexserver_reentrant_init_test.c", "createTransportLine", TEST_ONLY,
     "the borrowed upload and download transport fixture lines"),
    ("tests/unittests/halfduplexserver_reentrant_init_test.c", "protocolCreateTransport", TEST_ONLY,
     "the borrowed upload and download lines used by the protocol-framing fixture"),
    ("tests/unittests/halfduplexclient_framing_random_test.c", "initializePair", TEST_ONLY,
     "the main, upload, and download lines used by each client-framing fixture pair"),
    ("tests/unittests/line_task_scheduling_test.c", "createLine", TEST_ONLY,
     "the owner-local and cross-worker lines used by the scheduler contract matrix"),
    ("tests/unittests/connectiontopackets_schedule_rejection_test.c", "ctpFixtureSetup", TEST_ONLY,
     "the borrowed normal line used for foreign CTP scheduler-refusal settlement"),
    ("tests/unittests/packetstoconnection_schedule_rejection_test.c", "ptcFixtureSetup", TEST_ONLY,
     "the owned normal line used for foreign PTC scheduler-refusal settlement"),
]

# How many lines a site creates, where that is not one. Losing one of a pair is a
# real ownership change, so the count is pinned rather than inferred.
CREATION_COUNTS = {
    ("tests/unittests/muxserver_idle_lifecycle_test.c", "caseWorkerDrainIsLocal"): 2,
    ("tunnels/HalfDuplexClient/upstream/init.c", "halfduplexclientTunnelUpStreamInit"): 2,
    ("tunnels/ReverseClient/common/helpers.c", "reverseclientBeginConnectMessageReceived"): 2,
    ("tunnels/HttpClient/common/split.c", "httpclientSplitUpStreamInit"): 2,
    ("tests/unittests/worker_context_helpers_test.c", "exerciseForeignFinalLineReleaseDuringDetach"): 3,
    ("tests/unittests/worker_context_helpers_test.c", "testPipePublicationIsLinearizedWithPreStop"): 6,
    ("tests/unittests/halfduplexclient_framing_random_test.c", "initializePair"): 3,
    ("tests/unittests/line_task_scheduling_test.c", "createLine"): 2,
    ("tests/unittests/udpconnector_socket_pool_test.c", "testCase6_WorkerAndConnectorPoolIsolation"): 3,
}

# ---------------------------------------------------------------------------
# Manifest: owner close paths
# ---------------------------------------------------------------------------
#
# The function that carries the owner's lineDestroy() for a normal line. Some are
# the Finish handler itself, others the close helper it delegates to; either way
# this is the frame that must leave the line dead.

OWNER_CLOSE_SITES = [
    ("tunnels/TcpListener/downstream/fin.c", "tcplistenerTunnelDownStreamFinish",
     "accepted TCP line, closed by the neighbour's Finish"),
    ("tunnels/UdpListener/downstream/fin.c", "udplistenerTunnelDownStreamFinish",
     "stateful UDP peer line; missing idle inventory is a fatal structural violation, so the valid path destroys once"),
    ("tunnels/UdpStatelessSocket/common/helpers.c", "udpstatelesssocketCloseOwnedLineFromAdjacent",
     "stateless UDP peer line, from either adjacent Finish"),
    ("tunnels/TesterClient/common/helpers.c", "testerclientCloseCompletedOwnedLine",
     "the completed-verification branch of the tester's own line"),
    ("tunnels/TesterClient/common/helpers.c", "testerclientFailOwnedLine",
     "the terminal-verdict branch; a shutdown request does not close the line"),
    ("tunnels/SpeedTestClient/common/helpers.c", "speedtestclientFinishLine",
     "speed-test stream line, on completion or failure"),
    ("tunnels/AuthenticationClient/common/protocol.c", "authenticationclientCloseControlLine",
     "the control line, on transport failure and on explicit reconnect/stop"),
    ("tunnels/WireGuardDevice/common/helpers.c", "wireguarddeviceCloseTransportLine",
     "a per-worker transport line closed by the device itself"),
    ("tunnels/PacketsToConnection/common/helpers.c", "ptcCloseOwnedLine",
     "the shared close path for an lwIP-backed connection line"),
    ("tunnels/PacketsToStream/downstream/fin.c", "packetstostreamTunnelDownStreamFinish",
     "the recreated stream output line"),
    ("tunnels/MuxClient/common/helpers.c", "muxclientCloseIdleExhaustedParentLine",
     "an empty exhausted or worker-drained mux parent line"),
    ("tunnels/MuxClient/common/helpers.c", "muxclientHandleParentLoss",
     "the mux parent after child queues transfer during ordinary loss or are released during shutdown"),
    ("tunnels/MuxServer/common/helpers.c", "muxserverCloseShutdownChild",
     "an attached owned child closed silently during worker drain or shutdown-time Finish"),
    ("tunnels/MuxServer/common/helpers.c", "muxserverCloseChildKeepParent",
     "an attached mux child closed locally while its borrowed parent remains live"),
    ("tunnels/MuxServer/common/helpers.c", "muxserverFinalizeAttachedPeerClose",
     "an attached mux child after its ordered peer-Close queue drains"),
    ("tunnels/MuxServer/common/helpers.c", "muxserverFinalizeDetachedChild",
     "a detached mux child after its retained queue drains"),
    ("tunnels/MuxServer/common/helpers.c", "muxserverAbortDetachedChild",
     "a detached mux child aborted by local Finish, backlog bounds, or worker stop"),
    ("tunnels/ConnectionFisherClient/common/helpers.c", "connectionfisherclientCloseChildLineInternal",
     "a candidate child line, winner or loser"),
    ("tunnels/HalfDuplexClient/downstream/fin.c", "halfduplexclientTunnelDownStreamFinish",
     "an upload or download transport line"),
    ("tunnels/HalfDuplexServer/downstream/fin.c", "halfduplexserverTunnelDownStreamFinish",
     "the reconstructed main line"),
    ("tunnels/ReverseClient/common/helpers.c", "reverseclientClosePair",
     "the shared owner close path for paired upstream/downstream lines"),
    ("tunnels/HttpClient/common/split.c", "httpclientSplitDestroyCreatedLine",
     "an upload or download transport line the split created"),
    ("tunnels/HttpServer/common/split.c", "splitCloseMain",
     "the reconstructed main line the split created"),
    ("tunnels/Socks5Client/common/helpers.c", "socks5clientCloseOwnedLine",
     "an internal UDP control/relay line"),
    ("tunnels/TrojanClient/common/helpers.c", "trojanclientCloseOwnedLine",
     "an internal UDP carrier line"),
    ("tunnels/VlessClient/common/helpers.c", "vlessclientCloseOwnedLine",
     "an internal UDP carrier line"),
    ("tunnels/Socks5Server/common/helpers.c", "socks5serverCloseUdpRemoteLine",
     "a UDP remote line"),
    ("tunnels/TrojanServer/common/helpers.c", "trojanserverCloseUdpRemoteLineInternal",
     "a UDP remote line"),
    ("tunnels/VlessServer/common/helpers.c", "vlessserverCloseUdpRemoteLineInternal",
     "a UDP remote line"),
    ("ww/net/pipe_tunnel.c", "pipetunnelDefaultDownStreamFin",
     "the paired line the pipe created for this worker"),
]

# How many lines an owner close path destroys, where that is not one. A handler
# that closes a set of related lines has to keep closing all of them.
OWNER_DESTROY_COUNTS = {
    ("tunnels/UdpListener/downstream/fin.c", "udplistenerTunnelDownStreamFinish"): 2,
    ("tunnels/PacketsToStream/downstream/fin.c", "packetstostreamTunnelDownStreamFinish"): 2,
    ("tunnels/MuxClient/common/helpers.c", "muxclientHandleParentLoss"): 2,
    ("tunnels/MuxServer/common/helpers.c", "muxserverCloseChildKeepParent"): 2,
    ("tunnels/ReverseClient/common/helpers.c", "reverseclientClosePair"): 2,
}

# ---------------------------------------------------------------------------
# Manifest: fatal packet-lifecycle anchoring Finish handlers
# ---------------------------------------------------------------------------
#
# Each entry is an exact handler, or the shared adapter edge guard installed for
# that handler role, where a runtime Finish on the persistent packet line is a
# contract violation. Transparent middle handlers forward Finish, while
# intentional terminal absorbers are registered separately in
# SILENT_FINISH_ALLOWED. Entries are (path, function, diagnostic anchor,
# description). The anchor pins which abort is the packet-line one, so a handler
# cannot pass by aborting for an unrelated reason.
#
# A dual-role handler also serves a normal line it owns, so it may still contain
# a lineDestroy() - but only after the anchoring packet-line abort, never before
# it.

PACKET_LINE_FINISH = [
    ("ww/net/packet_tunnel.c", "packettunnelLifecycleAnchorUpstreamFinish",
     "unexpected upstream Finish on worker packet line", "shared packet-device lifecycle anchor"),
    ("ww/net/packet_tunnel.c", "packettunnelLifecycleAnchorDownstreamFinish",
     "unexpected downstream Finish on worker packet line", "shared packet-device lifecycle anchor"),
    ("tunnels/PacketsToConnection/upstream/fin.c", "ptcTunnelUpStreamFinish",
     "unexpected upstream Finish on the packet line", "the bridge's packet side"),
    ("tunnels/PacketsToStream/upstream/fin.c", "packetstostreamTunnelUpStreamFinish",
     "not supposed to receive upstream fin", "the bridge's packet side"),
    ("tunnels/StreamToPackets/downstream/fin.c", "streamtopacketsTunnelDownStreamFinish",
     "not supposed to receive downstream fin", "the bridge's packet side"),
    ("tunnels/PacketSplitStream/upstream/fin.c", "packetsplitstreamTunnelUpStreamFinish",
     "is not supposed to be called", "packet split, packet side only"),
    ("tunnels/PacketSplitStream/downstream/fin.c", "packetsplitstreamTunnelDownStreamFinish",
     "is not supposed to be called", "packet split, packet side only"),
    ("ww/net/adapter.c", "disabledRoutine",
     "Illegal call to routine on Adapter",
     "shared edge guard, including PacketSender upstream Finish where no prev exists"),
    ("tunnels/TesterServer/upstream/fin.c", "testerserverTunnelUpStreamFinish",
     "packet-mode received unexpected finish on worker packet line", "packet mode of the tester server"),
    ("tunnels/TesterServer/downstream/fin.c", "testerserverTunnelDownStreamFinish",
     "packet-mode received unexpected downstream finish on worker packet line",
     "packet mode of the tester server"),
    ("tunnels/TesterClient/downstream/fin.c", "testerclientTunnelDownStreamFinish",
     "packet-mode received unexpected finish on worker packet line",
     "dual role: packet mode aborts, the normal line is closed below"),
    ("tunnels/WireGuardDevice/common/helpers.c", "wireguarddeviceHandleTransportLineFinish",
     "unexpected Finish on worker packet line",
     "dual role: the packet line aborts, an owned transport line is closed below"),
]

# ---------------------------------------------------------------------------
# Manifest: Finish handlers allowed to absorb their callback in silence
# ---------------------------------------------------------------------------
#
# PACKET_LINE_FINISH names handlers one at a time, so it can only pin the ones
# somebody remembered to list. The check below is the complement: it walks every
# tunnels/*/{upstream,downstream}/fin.c and rejects a handler whose whole body is
# `discard` statements. Such a handler has four possible readings - the close was
# propagated, the state was released, a contract violation was reported, or
# absorbing it really is correct - and a bare body does not say which.
#
# Absorbing a Finish is legitimate exactly when the handler owns no per-line state
# and has no onward direction, so there is genuinely nothing to do. It is *not*
# license to swallow a Finish in an anchoring role where close is impossible, and
# it is never correct for a tunnel that created the line. Each entry states which
# terminal role it represents; the checker only guarantees somebody had to write
# it down.

SILENT_FINISH_ALLOWED = {
    ("tunnels/BlackHole/upstream/fin.c", "blackholeTunnelUpStreamFinish"):
        "a chain-end sink: borrows every line, owns no state, has no next node",
    ("tunnels/PacketReceiver/upstream/fin.c", "packetreceiverTunnelUpStreamFinish"):
        "a chain-end counter: owns no state, has no next node, and reports by timer and file",
    ("tunnels/PacketReceiver/downstream/fin.c", "packetreceiverTunnelDownStreamFinish"):
        "the same node placed at the head of a chain",
}

# ---------------------------------------------------------------------------
# Manifest: approved lineDestroy() sites outside a creating tunnel
# ---------------------------------------------------------------------------
#
# Everything else must live in an area that has a registered creation site. That
# is the machine-checkable form of "a tunnel that merely borrows a line never
# destroys it".

CORE_DESTROY_SITES = {
    "ww/net/line.h": "the lineDestroy() definition itself",
    "ww/net/chain.c": "tunnelchainDestroy(), the only packet-line destruction site",
}

# ---------------------------------------------------------------------------
# Manifest: local hardening the owner contract does not replace
# ---------------------------------------------------------------------------
#
# The owner postcondition is an architectural guarantee. It is not a reason to
# delete a tunnel's own state-survival check: a future ownership bug should stay
# a dropped frame, not a null-session crash. HttpClient and HttpServer own reusable
# nghttp2 sessions across a re-entrant payload callback, so their guards are pinned
# here by the function that must keep consulting them.

REENTRANT_STATE_GUARDS = [
    ("tunnels/HttpClient/common/transport.c", "httpclientLinestateIsActive",
     ("httpclientTransportCloseDirections",),
     "the failure-unwind path must not touch state destroyed by a re-entrant Finish"),
    ("tunnels/HttpClient/common/transport.c", "httpclientCanSendUpstream",
     ("sendBytesUp",
      "httpclientSendRawUp",
      "httpclientTransportSendHttp1ChunkedPayload",
      "sendNghttp2Outbound",
      "httpclientTransportSendHttp2DataFrame"),
     "multi-part output must stop when a re-entrant Finish closes the upstream destination"),
    ("tunnels/HttpServer/common/transport.c", "httpserverLinestateIsActive",
     ("httpserverTransportCloseDirections",),
     "the failure-unwind path must not touch state destroyed by a re-entrant Finish"),
    ("tunnels/HttpServer/common/transport.c", "httpserverCanSendDownstream",
     ("sendBytesDown",
      "httpserverSendRawDown",
      "httpserverTransportSendHttp1ChunkedPayload",
      "sendNghttp2Outbound",
      "httpserverTransportSendHttp2DataFrame"),
     "multi-part output must stop when a re-entrant Finish closes the downstream destination"),
]

# Calling a helper is insufficient if its predicate regresses to the old
# active-state-only check. These definitions pin the finished-side half of the
# contract that prevents payload after Finish.
DESTINATION_GUARD_CONTRACTS = [
    ("tunnels/HttpClient/common/transport.c", "httpclientCanSendUpstream",
     ((r"\bhttpclientLinestateIsActive\s*\(\s*ls\s*\)", "active line state"),
      (r"!\s*ls->next_finished\b", "unfinished upstream destination"))),
    ("tunnels/HttpServer/common/transport.c", "httpserverCanSendDownstream",
     ((r"\bhttpserverLinestateIsActive\s*\(\s*ls\s*\)", "active line state"),
      (r"!\s*ls->prev_finished\b", "unfinished downstream destination"))),
]

# ---------------------------------------------------------------------------
# Manifest: focused tests that prove the runtime postcondition
# ---------------------------------------------------------------------------
#
# The checker cannot observe lineIsAlive() after a callback returns. These tests
# can, so losing one silently would leave the postcondition unproved.
#
# A test file that is still on disk but no longer built proves nothing, so each
# entry also names the exact CMake text that puts it in front of ctest. Entries are
# (path, source markers, ctest registrations, description); a header has no
# registration of its own and is covered by the executables that include it.

UNIT_CMAKE = "tests/unittests/CMakeLists.txt"
SUITE_CMAKE = "tests/CMakeLists.txt"
ABORT_RUNTIME_CMAKE = "tests/unittests/tunnels_abort_runtime_test.cmake"

REQUIRED_CONTRACT_TESTS = [
    ("tests/unittests/tunnel_line_failure_harness.h",
     ("twfRunOwnerFinish",
      "twfRequireOwnedLineReclaimed",
      "twfLinePoolCreateLine"),
     (),
     "the reusable owned-line postcondition pattern"),
    ("tests/unittests/owned_line_finish_udpstatelesssocket_test.c",
     ("caseEndpointOwnerFinishKillsLine",
      "caseBorrowedLineFinishDoesNotDestroy",
      "twfRunOwnerFinish"),
     ((UNIT_CMAKE, "add_executable(owned_line_finish_udpstatelesssocket_test"),
      (UNIT_CMAKE, "waterwall.owned_line_finish_udpstatelesssocket_unit")),
     "a representative endpoint owner, owned and borrowed roles"),
    ("tests/unittests/owned_line_finish_muxserver_test.c",
     ("caseInternalOwnerFinishKillsChildOnly",
      "caseParentFinishKillsOwnedChildren",
      "caseNestedDestroyIsNotRepeated",
      "twfRunOwnerFinish"),
     ((UNIT_CMAKE, "add_executable(owned_line_finish_muxserver_test"),
      (UNIT_CMAKE, "waterwall.owned_line_finish_muxserver_unit")),
     "a representative internal owner: the owned child dies, the borrowed parent does not"),
    ("tests/unittests/testerclient_orderly_shutdown_test.c",
     ("caseTerminalDownstreamFinishClosesOwnedLine",
      "caseSuccessfulDownstreamFinishClosesBeforeSweep",
      "casePacketModeFinishAborts",
      "testerclientTunnelDownStreamFinish"),
     ((UNIT_CMAKE, '"TesterClient|testerclient_orderly_shutdown_test|testerclient|OFF"'),),
     "TesterClient's terminal Finish, normal mode and packet mode"),
    ("tests/unittests/wireguarddevice_orderly_shutdown_test.c",
     ("casePacketLineFinishAborts",
      "wireguarddeviceHandleTransportLineFinish"),
     ((UNIT_CMAKE, '"WireGuardDevice|wireguarddevice_orderly_shutdown_test|wireguarddevice|OFF"'),),
     "WireGuardDevice's dual-role Finish"),
    ("tests/unittests/tunnels_abort_runtime_test.c",
     ("casePacketLifecycleAnchorUpstreamFinish",
      "casePacketLifecycleAnchorDownstreamFinish",
      "packet_lifecycle_anchor_upstream_finish",
      "packet_lifecycle_anchor_downstream_finish"),
     ((ABORT_RUNTIME_CMAKE, "packet_lifecycle_anchor_upstream_finish"),
      (ABORT_RUNTIME_CMAKE, "packet_lifecycle_anchor_downstream_finish"),
      (ABORT_RUNTIME_CMAKE, "waterwall.tunnels_abort_runtime_unit")),
     "shared packet lifecycle anchors do not return from Finish"),
    ("tests/unittests/httpclient_reentrant_finish_test.c",
     ("caseFinishDuringFirstFinalChunkStopsRemainingOutput",
      "finishClientFromNextOnFirstPayload"),
     ((UNIT_CMAKE, "add_executable(httpclient_reentrant_finish_test"),
      (UNIT_CMAKE, "waterwall.httpclient_reentrant_finish_unit")),
     "HttpClient stops a multi-part final send after re-entrant downstream Finish"),
    ("tests/unittests/httpserver_reentrant_finish_test.c",
     ("caseFinishDuringFirstFinalChunkStopsRemainingOutput",
      "finishServerFromPrevOnFirstPayload"),
     ((UNIT_CMAKE, "add_executable(httpserver_reentrant_finish_test"),
      (UNIT_CMAKE, "waterwall.httpserver_reentrant_finish_unit")),
     "HttpServer stops a multi-part final send after re-entrant upstream Finish"),
    ("tests/unittests/halfduplexserver_reentrant_init_test.c",
     ("runRejectedPairingCase",
      "rejectMainLineInit",
      "transportOwnerDownstreamFinish"),
     ((UNIT_CMAKE, "add_executable(halfduplexserver_reentrant_init_test"),
      (UNIT_CMAKE, "waterwall.halfduplexserver_reentrant_init_unit")),
     "HalfDuplexServer retains both transports when main Init is rejected re-entrantly"),
    ("tests/unittests/packetsender_orderly_shutdown_test.c",
     ("caseDownstreamFinishCancelsPendingTimer",
      "caseReentrantFinishStopsReadyBatch",
      "packetsenderTunnelDownStreamFinish"),
     ((UNIT_CMAKE, '"PacketSender|packetsender_orderly_shutdown_test|packetsender|ON"'),),
     "PacketSender stops its worker producer after downstream Finish"),
    ("tests/unittests/tunnels_abort_runtime_test.c",
     ("caseTesterClientDisabledUpstreamFinish",
      "testerclient_disabled_upstream_finish"),
     ((ABORT_RUNTIME_CMAKE, "WATERWALL_ABORT_TEST_HAS_TESTERCLIENT"),
      (ABORT_RUNTIME_CMAKE, "testerclient_disabled_upstream_finish"),
      (ABORT_RUNTIME_CMAKE, "waterwall.tunnels_abort_runtime_unit")),
     "TesterClient's impossible upstream Finish exits through abortProgramNow(1) in Release"),
    ("tests/unittests/tunnels_abort_runtime_test.c",
     ("caseAdapterChainHeadFinish",
      "caseAdapterChainHeadPayload",
      "caseAdapterChainEndFinish",
      "caseAdapterChainEndPayload"),
     ((ABORT_RUNTIME_CMAKE, "adapter_chain_head_finish"),
      (ABORT_RUNTIME_CMAKE, "adapter_chain_head_payload"),
      (ABORT_RUNTIME_CMAKE, "adapter_chain_end_finish"),
      (ABORT_RUNTIME_CMAKE, "adapter_chain_end_payload"),
      (ABORT_RUNTIME_CMAKE, "waterwall.tunnels_abort_runtime_unit")),
     "shared adapter guards exit through abortProgramNow(1) for both edge directions in Release"),
    ("tests/line_ownership_policy_test.py",
     ("PACKET_LINE_FINISH",
      "SILENT_FINISH_ALLOWED",
      "REQUIRED_CONTRACT_TESTS"),
     ((SUITE_CMAKE, "waterwall.line_ownership_policy_test"),
      (SUITE_CMAKE, "--mutation-test")),
     "this checker, which is only worth anything while ctest runs it with mutations on"),
]

# Directories scanned for production creation and destruction sites.
PRODUCTION_ROOTS = ("ww", "tunnels", "core")
TEST_ROOTS = ("tests",)

SOURCE_SUFFIXES = (".c", ".h", ".cc")

# Roots and exclusions for the legacy naming policy check.
NAMING_SCAN_ROOTS = (
    "ww",
    "tunnels",
    "core",
    "tests",
    "WaterWall-Docs/docs",
    "WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current",
)
NAMING_EXCLUDED_PREFIXES = (
    "ww/vendor/",
    "tunnels/TlsClient/boringssl/",
    "tunnels/TlsClient/brotli/",
    "tests/line_ownership_policy_test.py",
)
NAMING_EXCLUDED_FILENAMES = (
    "LINE-REFERENCE-API-RENAME-IMPLEMENTATION-PLAN.md",
)
NAMING_SCAN_SUFFIXES = (".c", ".h", ".cc", ".cpp", ".py", ".md", ".mdx")

FORBIDDEN_LEGACY_NAMES = tuple(
    a + b
    for a, b in [
        ("line", "Lock"),
        ("line", "Unlock"),
        ("withLine", "Locked"),
        ("withLine", "LockedWithBuf"),
        ("line", "LockForce"),
        ("client_line_", "locked"),
    ]
)
_FORBIDDEN_LEGACY_NAMES_RE = re.compile(
    r"\b(" + "|".join(FORBIDDEN_LEGACY_NAMES) + r")\b"
)

# lineCreate() and lineDestroy() are defined in line.h; that file is the contract,
# not a call site.
CONTRACT_HEADER = "ww/net/line.h"

# ---------------------------------------------------------------------------
# Lexical helpers
# ---------------------------------------------------------------------------

_CREATE_RE = re.compile(r"\blineCreate(?:ForWorker)?\s*\(")
_DESTROY_RE = re.compile(r"\blineDestroy\s*\(")
_HARD_ABORT_RE = re.compile(r"\babortProgramNow\s*\(\s*1\s*\)\s*;")

# `discard x;` is the project's spelling of (void)x - a statement that does nothing
# but silence an unused-parameter warning.
_DISCARD_RE = re.compile(r"\bdiscard\s+[A-Za-z_][A-Za-z0-9_]*\s*;")

_FILE_CACHE = {}


def read_source(rel_path, source_overrides):
    if source_overrides and rel_path in source_overrides:
        return source_overrides[rel_path]
    if rel_path not in _FILE_CACHE:
        full_path = os.path.join(ROOT, rel_path)
        if not os.path.exists(full_path):
            return None
        # A handful of vendored sources are not UTF-8. They are scanned like any
        # other file, so decoding must never be what stops the check.
        with open(full_path, "r", encoding="utf-8", errors="replace") as handle:
            _FILE_CACHE[rel_path] = handle.read()
    return _FILE_CACHE[rel_path]


def walk_sources(roots):
    """Yield every scanned source path, relative to the repository root."""
    for root in roots:
        base = os.path.join(ROOT, root)
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames.sort()
            for name in sorted(filenames):
                if not name.endswith(SOURCE_SUFFIXES):
                    continue
                yield os.path.relpath(os.path.join(dirpath, name), ROOT).replace(os.sep, "/")


_NAMING_SOURCES = None


def walk_naming_sources():
    """Yield source, test, template, and doc paths checked for legacy names."""
    global _NAMING_SOURCES
    if _NAMING_SOURCES is not None:
        return _NAMING_SOURCES
    paths = []
    if os.path.exists(os.path.join(ROOT, "AGENTS.md")):
        paths.append("AGENTS.md")
    for root in NAMING_SCAN_ROOTS:
        base = os.path.join(ROOT, root)
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames.sort()
            for name in sorted(filenames):
                if name in NAMING_EXCLUDED_FILENAMES:
                    continue
                if not name.endswith(NAMING_SCAN_SUFFIXES):
                    continue
                rel_path = os.path.relpath(os.path.join(dirpath, name), ROOT).replace(os.sep, "/")
                if any(rel_path.startswith(prefix) for prefix in NAMING_EXCLUDED_PREFIXES):
                    continue
                paths.append(rel_path)
    _NAMING_SOURCES = tuple(paths)
    return _NAMING_SOURCES


def enclosing_function(definitions, offset):
    """Name of the innermost function whose body contains ``offset``."""
    best = None
    best_span = None
    for name, spans in definitions.items():
        for span in spans:
            if span[0] <= offset < span[1]:
                if best_span is None or (span[1] - span[0]) < (best_span[1] - best_span[0]):
                    best, best_span = name, span
    return best


def scan_calls(rel_path, content, pattern):
    """Yield (function name or None, source line) for each unmasked match."""
    masked, definitions = analyze(content)
    for match in pattern.finditer(masked):
        yield enclosing_function(definitions, match.start()), line_of(content, match.start())


def function_span(content, rel_path, function, label, errors):
    """The single body span of ``function``, or None after reporting."""
    _masked, definitions = analyze(content)
    spans = definitions.get(function, [])
    if not spans:
        errors.append("[%s] %s: no definition of %s()" % (label, rel_path, function))
        return None
    if len(spans) > 1:
        lines = [line_of(content, span[0]) for span in spans]
        errors.append(
            "[%s] %s: %s() is defined %d times (lines %s); an entry must name exactly one function"
            % (label, rel_path, function, len(spans), lines)
        )
        return None
    return spans[0]


def enclosing_block_end(masked, offset, limit):
    """Offset just past the closing brace of the block that contains ``offset``.

    A diagnostic and the abort it belongs to live in the same branch. Bounding the
    search that way is what stops an unrelated abort further down the same
    function from satisfying the entry.
    """
    depth = 0
    i = offset
    while i < limit:
        char = masked[i]
        if char == "{":
            depth += 1
        elif char == "}":
            if depth == 0:
                return i
            depth -= 1
        i += 1
    return limit


def area_of(rel_path):
    """The ownership area a file belongs to: one tunnel, or the file itself."""
    parts = rel_path.split("/")
    if parts[0] == "tunnels" and len(parts) > 1:
        return "tunnels/" + parts[1]
    return rel_path


# ---------------------------------------------------------------------------
# Policy verification
# ---------------------------------------------------------------------------

def verify_policy(source_overrides=None, classification_overrides=None):
    errors = []
    checked = {
        "creations": 0,
        "owners": 0,
        "packet_handlers": 0,
        "destroy_sites": 0,
        "guards": 0,
        "guard_contracts": 0,
        "finish_handlers": 0,
        "tests": 0,
        "registrations": 0,
        "naming_files": 0,
    }

    sites = {}
    for rel_path, function, classification, role in CREATION_SITES:
        key = (rel_path, function)
        if key in sites:
            errors.append("Duplicate creation-site entry for %s::%s" % (rel_path, function))
            continue
        if classification_overrides and key in classification_overrides:
            classification = classification_overrides[key]
        sites[key] = (classification, role)

    # --- 1. every creation site in the tree is classified -------------------

    creating_areas = set()
    found_counts = {}
    for rel_path in walk_sources(PRODUCTION_ROOTS + TEST_ROOTS):
        if rel_path == CONTRACT_HEADER:
            continue
        content = read_source(rel_path, source_overrides)
        if content is None or "lineCreate" not in content:
            continue
        for function, line in scan_calls(rel_path, content, _CREATE_RE):
            if function is None:
                errors.append(
                    "%s:%d: lineCreate() outside any function body; the checker cannot classify it"
                    % (rel_path, line)
                )
                continue
            key = (rel_path, function)
            checked["creations"] += 1
            if key not in sites:
                errors.append(
                    "%s:%d: unclassified line creation in %s(); add it to CREATION_SITES as one of %s"
                    % (rel_path, line, function,
                       "/".join((NORMAL_OWNER, PACKET_LINE, PAIRED_LINE, TEST_ONLY)))
                )
                continue
            found_counts[key] = found_counts.get(key, 0) + 1
            creating_areas.add(area_of(rel_path))

    seen_sites = set(found_counts)
    for key in sorted(sites):
        expected = CREATION_COUNTS.get(key, 1)
        found = found_counts.get(key, 0)
        if found == 0:
            errors.append(
                "%s: CREATION_SITES lists %s() but it creates no line; remove the stale entry"
                % (key[0], key[1])
            )
        elif found != expected:
            errors.append(
                "%s::%s creates %d line(s), expected %d; update the site or CREATION_COUNTS"
                % (key[0], key[1], found, expected)
            )

    for key in sorted(CREATION_COUNTS):
        if key not in sites:
            errors.append(
                "%s::%s has a CREATION_COUNTS entry but no CREATION_SITES entry" % (key[0], key[1])
            )

    # --- 2. a classification is only valid where it is allowed --------------

    for (rel_path, function), (classification, _role) in sorted(sites.items()):
        if (rel_path, function) not in seen_sites:
            continue
        if classification == PACKET_LINE and (rel_path, function) != PACKET_LINE_ALLOCATION:
            errors.append(
                "%s::%s is classified %s, but the only packet-line allocation is %s::%s"
                % (rel_path, function, PACKET_LINE, PACKET_LINE_ALLOCATION[0], PACKET_LINE_ALLOCATION[1])
            )
        if classification == PAIRED_LINE and (rel_path, function) != PAIRED_LINE_ALLOCATION:
            errors.append(
                "%s::%s is classified %s, but the only paired-line allocation is %s::%s"
                % (rel_path, function, PAIRED_LINE, PAIRED_LINE_ALLOCATION[0], PAIRED_LINE_ALLOCATION[1])
            )
        if classification == TEST_ONLY and not rel_path.startswith("tests/"):
            errors.append(
                "%s::%s is classified %s but is production code" % (rel_path, function, TEST_ONLY)
            )
        if classification == NORMAL_OWNER and rel_path.startswith("tests/"):
            errors.append(
                "%s::%s is test code and must be classified %s" % (rel_path, function, TEST_ONLY)
            )
        if classification == NORMAL_OWNER and (rel_path, function) in (
            PACKET_LINE_ALLOCATION, PAIRED_LINE_ALLOCATION
        ):
            errors.append(
                "%s::%s is the %s allocation and must not be classified %s"
                % (rel_path, function, PACKET_LINE if (rel_path, function) == PACKET_LINE_ALLOCATION
                   else PAIRED_LINE, NORMAL_OWNER)
            )
        if classification not in (NORMAL_OWNER, PACKET_LINE, PAIRED_LINE, TEST_ONLY):
            errors.append("%s::%s has unknown classification %r" % (rel_path, function, classification))

    # --- 3. only a creating area may destroy -------------------------------

    for rel_path in walk_sources(PRODUCTION_ROOTS):
        content = read_source(rel_path, source_overrides)
        if content is None or "lineDestroy" not in content:
            continue
        area = area_of(rel_path)
        for function, line in scan_calls(rel_path, content, _DESTROY_RE):
            checked["destroy_sites"] += 1
            if rel_path in CORE_DESTROY_SITES or area in creating_areas:
                continue
            errors.append(
                "%s:%d: %s() calls lineDestroy() but %s creates no line; only a line's creator may destroy it"
                % (rel_path, line, function or "<file scope>", area)
            )

    # --- 4. every registered owner close path really destroys --------------

    for rel_path, function, description in OWNER_CLOSE_SITES:
        content = read_source(rel_path, source_overrides)
        if content is None:
            errors.append("[owner] missing source file %s (%s)" % (rel_path, description))
            continue
        span = function_span(content, rel_path, function, "owner", errors)
        if span is None:
            continue
        checked["owners"] += 1
        masked = analyze(content)[0]
        expected = OWNER_DESTROY_COUNTS.get((rel_path, function), 1)
        found = len(_DESTROY_RE.findall(masked, span[0], span[1]))
        if found == 0:
            errors.append(
                "[owner] %s::%s (%s) no longer calls lineDestroy(); an owner Finish must leave its line dead"
                % (rel_path, function, description)
            )
        elif found != expected:
            errors.append(
                "[owner] %s::%s destroys %d line(s), expected %d (%s); update the site or OWNER_DESTROY_COUNTS"
                % (rel_path, function, found, expected, description)
            )

    # --- 5. registered packet anchors abort and never destroy first ----------

    for rel_path, function, anchor, description in PACKET_LINE_FINISH:
        content = read_source(rel_path, source_overrides)
        if content is None:
            errors.append("[packet] missing source file %s (%s)" % (rel_path, description))
            continue
        span = function_span(content, rel_path, function, "packet", errors)
        if span is None:
            continue
        checked["packet_handlers"] += 1

        # The anchor is a diagnostic string, so it is searched in the original
        # text; everything counted afterwards comes from the masked text.
        anchor_at = content.find(anchor, span[0], span[1])
        if anchor_at < 0:
            errors.append(
                "[packet] %s::%s lost its packet-line diagnostic %r" % (rel_path, function, anchor)
            )
            continue

        masked = analyze(content)[0]
        window_end = enclosing_block_end(masked, anchor_at, span[1])
        abort = _HARD_ABORT_RE.search(masked, anchor_at, window_end)
        if abort is None:
            errors.append(
                "[packet] %s::%s (%s) does not abortProgramNow(1) after its packet-line diagnostic; "
                "this anchoring handler must reject its impossible packet-line Finish"
                % (rel_path, function, description)
            )
            continue

        early = _DESTROY_RE.search(masked, span[0], abort.end())
        if early is not None:
            errors.append(
                "[packet] %s::%s calls lineDestroy() at line %d, before its packet-line abort; "
                "a packet line is never destroyed at runtime"
                % (rel_path, function, line_of(content, early.start()))
            )

    # --- 6. local re-entrancy hardening is not deleted ----------------------

    for rel_path, guard, functions, description in REENTRANT_STATE_GUARDS:
        content = read_source(rel_path, source_overrides)
        if content is None:
            errors.append("[guard] missing source file %s (%s)" % (rel_path, description))
            continue
        masked = analyze(content)[0]
        guard_re = re.compile(r"\b%s\s*\(" % re.escape(guard))
        for function in functions:
            span = function_span(content, rel_path, function, "guard", errors)
            if span is None:
                continue
            checked["guards"] += 1
            if not guard_re.search(masked, span[0], span[1]):
                errors.append(
                    "[guard] %s::%s no longer consults %s(); %s"
                    % (rel_path, function, guard, description)
                )

    for rel_path, guard, requirements in DESTINATION_GUARD_CONTRACTS:
        content = read_source(rel_path, source_overrides)
        if content is None:
            errors.append("[guard] missing source file %s for %s()" % (rel_path, guard))
            continue
        span = function_span(content, rel_path, guard, "guard", errors)
        if span is None:
            continue

        checked["guard_contracts"] += 1
        body = analyze(content)[0][span[0]:span[1]]
        for pattern, description in requirements:
            if re.search(pattern, body) is None:
                errors.append(
                    "[guard] %s::%s no longer requires %s"
                    % (rel_path, guard, description)
                )

    # --- 7. no Finish handler absorbs its callback in silence ---------------

    for rel_path in walk_sources(("tunnels",)):
        if not rel_path.endswith("/fin.c"):
            continue
        content = read_source(rel_path, source_overrides)
        if content is None:
            continue
        masked, definitions = analyze(content)
        for function in sorted(definitions):
            for span in definitions[function]:
                checked["finish_handlers"] += 1
                # Masking already blanked comments and literals, so what is left after
                # dropping the `discard` statements is the handler's actual work.
                body = _DISCARD_RE.sub("", masked[span[0] + 1:span[1] - 1])
                if body.strip():
                    continue
                if (rel_path, function) in SILENT_FINISH_ALLOWED:
                    continue
                errors.append(
                    "%s:%d: %s() does nothing but return; a Finish handler must propagate the close, "
                    "release what it owns, or report an anchoring packet-line contract violation - add it to "
                    "SILENT_FINISH_ALLOWED with a rationale if it owns no per-line state and has no "
                    "onward direction, so absorbing the close really is the whole job"
                    % (rel_path, line_of(content, span[0]), function)
                )

    for rel_path, function in sorted(SILENT_FINISH_ALLOWED):
        content = read_source(rel_path, source_overrides)
        if content is None or function not in analyze(content)[1]:
            errors.append(
                "[finish] SILENT_FINISH_ALLOWED lists %s::%s but it does not exist; remove the stale entry"
                % (rel_path, function)
            )

    # --- 8. the runtime postcondition tests stay registered -----------------

    for rel_path, markers, registrations, description in REQUIRED_CONTRACT_TESTS:
        content = read_source(rel_path, source_overrides)
        if content is None:
            errors.append(
                "[tests] missing %s (%s); the runtime postcondition would be unproved"
                % (rel_path, description)
            )
            continue
        checked["tests"] += 1
        for marker in markers:
            if marker not in content:
                errors.append(
                    "[tests] %s no longer contains %r (%s)" % (rel_path, marker, description)
                )

        # A test file nothing builds proves nothing, so the ctest wiring is pinned
        # in the same entry as the file it runs.
        for cmake_path, needle in registrations:
            cmake = read_source(cmake_path, source_overrides)
            if cmake is None:
                errors.append("[tests] missing %s, which registers %s" % (cmake_path, rel_path))
                continue
            checked["registrations"] += 1
            if needle not in cmake:
                errors.append(
                    "[tests] %s no longer contains %r, so %s is no longer run by ctest (%s)"
                    % (cmake_path, needle, rel_path, description)
                )

    # --- 9. legacy line-reference API identifiers are never reintroduced -----

    scan_files = source_overrides.keys() if source_overrides else walk_naming_sources()
    for rel_path in scan_files:
        content = read_source(rel_path, source_overrides)
        if content is None:
            continue
        checked["naming_files"] += 1
        for match in _FORBIDDEN_LEGACY_NAMES_RE.finditer(content):
            errors.append(
                "[naming] %s:%d: forbidden legacy line-reference identifier %r found; "
                "use reference-based naming (lineRef/lineUnref/lineCallWithRef/lineCallWithRefWithBuf/lineRefForce/client_line_ref_held)"
                % (rel_path, line_of(content, match.start()), match.group(0))
            )

    return errors, checked


# ---------------------------------------------------------------------------
# Mutation testing
# ---------------------------------------------------------------------------

def _span(content, function):
    return analyze(content)[1][function][0]


def mutate_drop_creation(content, function):
    """Remove a registered creator's allocation, leaving a stale manifest entry."""
    masked = analyze(content)[0]
    span = _span(content, function)
    match = _CREATE_RE.search(masked, span[0], span[1])
    if match is None:
        raise AssertionError("no lineCreate() in %s()" % function)
    return content[:match.start()] + "lineCreateRenamed(" + content[match.end():]


def mutate_add_unclassified_creation(content, function):
    """Add a creation site to a function nothing has classified."""
    span = _span(content, function)
    return content[:span[0] + 1] + "\n    discard lineCreate(NULL, 0);" + content[span[0] + 1:]


def mutate_drop_owner_destroy(content, function):
    masked = analyze(content)[0]
    span = _span(content, function)
    match = _DESTROY_RE.search(masked, span[0], span[1])
    if match is None:
        raise AssertionError("no lineDestroy() in %s()" % function)
    return content[:match.start()] + "lineUnref(" + content[match.end():]


def mutate_drop_packet_abort(content, function, anchor):
    """Remove the hard abort that follows a packet-line diagnostic."""
    masked = analyze(content)[0]
    span = _span(content, function)
    anchor_at = content.find(anchor, span[0], span[1])
    if anchor_at < 0:
        raise AssertionError("anchor %r not found in %s()" % (anchor, function))
    window_end = enclosing_block_end(masked, anchor_at, span[1])
    match = _HARD_ABORT_RE.search(masked, anchor_at, window_end)
    if match is None:
        raise AssertionError("no abort follows %r in %s()" % (anchor, function))
    return content[:match.start()] + content[match.end():]


def mutate_destroy_packet_line(content, function, anchor):
    """Convert a packet-line violation into a normal-line teardown."""
    span = _span(content, function)
    anchor_at = content.find(anchor, span[0], span[1])
    if anchor_at < 0:
        raise AssertionError("anchor %r not found in %s()" % (anchor, function))
    return content[:span[0] + 1] + "\n    lineDestroy(l);" + content[span[0] + 1:]


def mutate_drop_guard(content, function, guard):
    """Neutralize every use of one lifecycle guard inside a function."""
    masked = analyze(content)[0]
    span = _span(content, function)
    matches = list(re.compile(r"\b%s\s*\(" % re.escape(guard)).finditer(masked, span[0], span[1]))
    if not matches:
        raise AssertionError("guard %r not found in %s()" % (guard, function))
    for match in reversed(matches):
        content = content[:match.start()] + "alwaysActive(" + content[match.end():]
    return content


def mutate_drop_guard_requirement(content, function, pattern):
    """Remove one required predicate from a destination-send guard."""
    masked = analyze(content)[0]
    span = _span(content, function)
    match = re.search(pattern, masked[span[0]:span[1]])
    if match is None:
        raise AssertionError("guard requirement %r not found in %s()" % (pattern, function))
    start = span[0] + match.start()
    end = span[0] + match.end()
    return content[:start] + "true" + content[end:]


def mutate_drop_test_marker(content, marker):
    if marker not in content:
        raise AssertionError("marker %r not found" % marker)
    # Every occurrence: a case name appears at least at its definition and its
    # call in main(), and losing only one of those is not what this pins.
    return content.replace(marker, "removedMarker")


def mutate_drop_registration(content, needle):
    """Unbuild a required test by removing the CMake text that registers it."""
    if needle not in content:
        raise AssertionError("registration %r not found" % needle)
    return content.replace(needle, "removed_registration")


def mutate_silence_finish(content, function):
    """Replace a Finish handler's body with the discards that hide a swallowed close."""
    span = _span(content, function)
    return content[:span[0]] + "{\n    discard t;\n    discard l;\n}" + content[span[1]:]


class MutationRunner:
    def __init__(self):
        self.applied = 0
        self.escaped = []

    def expect_failure(self, label, source_overrides=None, classification_overrides=None):
        self.applied += 1
        errors, _checked = verify_policy(source_overrides, classification_overrides)
        if not errors:
            self.escaped.append(label)


def run_mutation_tests():
    print("Running mutation tests on the line-ownership checker...")
    runner = MutationRunner()

    # 1: removing a registered creator must be noticed as a stale entry.
    for rel_path, function, _classification, _role in CREATION_SITES:
        content = read_source(rel_path, None)
        runner.expect_failure(
            "%s::%s lost its allocation" % (rel_path, function),
            {rel_path: mutate_drop_creation(content, function)})

    # 2: a normal owner relabelled as a packet or paired allocation, and the two
    #    core allocations relabelled as normal owners.
    for rel_path, function, classification, _role in CREATION_SITES:
        if classification != NORMAL_OWNER:
            continue
        for wrong in (PACKET_LINE, PAIRED_LINE, TEST_ONLY):
            runner.expect_failure(
                "%s::%s relabelled %s" % (rel_path, function, wrong),
                None, {(rel_path, function): wrong})
    for key in (PACKET_LINE_ALLOCATION, PAIRED_LINE_ALLOCATION):
        runner.expect_failure(
            "%s::%s relabelled %s" % (key[0], key[1], NORMAL_OWNER),
            None, {key: NORMAL_OWNER})

    # 3: a new, unclassified creation site anywhere in production.
    for rel_path, function in (("tunnels/TcpConnector/upstream/init.c", "tcpconnectorTunnelUpStreamInit"),
                               ("ww/net/tunnel.c", "tunnelBind")):
        content = read_source(rel_path, None)
        if content is None:
            continue
        runner.expect_failure(
            "%s::%s gained an unclassified lineCreate()" % (rel_path, function),
            {rel_path: mutate_add_unclassified_creation(content, function)})

    # 4: a borrowing tunnel that starts destroying lines.
    for rel_path, function in (("tunnels/TcpConnector/upstream/fin.c", "tcpconnectorTunnelUpStreamFinish"),
                               ("tunnels/TlsClient/upstream/fin.c", "tlsclientTunnelUpStreamFinish")):
        content = read_source(rel_path, None)
        if content is None:
            continue
        span = _span(content, function)
        runner.expect_failure(
            "%s::%s gained a lineDestroy()" % (rel_path, function),
            {rel_path: content[:span[0] + 1] + "\n    lineDestroy(l);" + content[span[0] + 1:]})

    # 5: an owner close path that stops destroying its line.
    for rel_path, function, _description in OWNER_CLOSE_SITES:
        content = read_source(rel_path, None)
        runner.expect_failure(
            "%s::%s dropped its lineDestroy()" % (rel_path, function),
            {rel_path: mutate_drop_owner_destroy(content, function)})

    # 6: a registered packet anchor loses its abort or becomes a normal close.
    for rel_path, function, anchor, _description in PACKET_LINE_FINISH:
        content = read_source(rel_path, None)
        runner.expect_failure(
            "%s::%s dropped its packet-line abort" % (rel_path, function),
            {rel_path: mutate_drop_packet_abort(content, function, anchor)})
        runner.expect_failure(
            "%s::%s destroys the packet line" % (rel_path, function),
            {rel_path: mutate_destroy_packet_line(content, function, anchor)})

    # 7: local re-entrancy hardening deleted because "the owner contract covers it".
    for rel_path, guard, functions, _description in REENTRANT_STATE_GUARDS:
        content = read_source(rel_path, None)
        for function in functions:
            runner.expect_failure(
                "%s::%s dropped its %s() check" % (rel_path, function, guard),
                {rel_path: mutate_drop_guard(content, function, guard)})

    for rel_path, guard, requirements in DESTINATION_GUARD_CONTRACTS:
        content = read_source(rel_path, None)
        for pattern, description in requirements:
            runner.expect_failure(
                "%s::%s dropped %s" % (rel_path, guard, description),
                {rel_path: mutate_drop_guard_requirement(content, guard, pattern)})

    # 8: a Finish handler quietly reduced to "return", losing a propagation, an
    #    owner's close, or a packet-line abort with nobody having to say so.
    for rel_path, function in (("tunnels/TcpConnector/upstream/fin.c", "tcpconnectorTunnelUpStreamFinish"),
                               ("tunnels/TunDevice/upstream/fin.c", "tundeviceTunnelUpStreamFinish"),
                               ("tunnels/UdpListener/downstream/fin.c", "udplistenerTunnelDownStreamFinish")):
        content = read_source(rel_path, None)
        if content is None:
            continue
        runner.expect_failure(
            "%s::%s reduced to a bare return" % (rel_path, function),
            {rel_path: mutate_silence_finish(content, function)})

    # 9: a required contract test that loses its content, or its ctest wiring.
    for rel_path, markers, registrations, _description in REQUIRED_CONTRACT_TESTS:
        content = read_source(rel_path, None)
        if content is None:
            continue
        for marker in markers:
            runner.expect_failure(
                "%s lost %r" % (rel_path, marker),
                {rel_path: mutate_drop_test_marker(content, marker)})
        for cmake_path, needle in registrations:
            cmake = read_source(cmake_path, None)
            if cmake is None:
                continue
            runner.expect_failure(
                "%s lost the registration of %s" % (cmake_path, rel_path),
                {cmake_path: mutate_drop_registration(cmake, needle)})

    # 10: a forbidden legacy line-reference identifier reintroduced.
    for rel_path, forbidden_name in (
        ("ww/net/line.h", FORBIDDEN_LEGACY_NAMES[0]),
        ("AGENTS.md", FORBIDDEN_LEGACY_NAMES[2]),
    ):
        content = read_source(rel_path, None)
        if content is None:
            continue
        runner.expect_failure(
            "%s reintroduced %s" % (rel_path, forbidden_name),
            {rel_path: content + "\n/* " + forbidden_name + " */\n"})

    if runner.escaped:
        print("Mutation testing FAILED: %d mutation(s) were not detected:" % len(runner.escaped))
        for label in runner.escaped:
            print("  - %s" % label)
        return False

    print("  %d mutations applied, all detected." % runner.applied)
    return True


def main():
    errors, checked = verify_policy()

    if errors:
        print("Line Ownership Policy Check FAILED with %d error(s):" % len(errors))
        for error in errors:
            print("  - %s" % error)
        sys.exit(1)

    print("Line Ownership Policy Check PASSED: %d creation site(s) classified, %d owner close path(s), "
          "%d lineDestroy() site(s), %d packet-anchor Finish handler(s), %d Finish handler(s) scanned, "
          "%d re-entrancy guard(s), %d destination guard contract(s), %d contract test(s) with "
          "%d ctest registration(s), %d file(s) scanned for legacy naming."
          % (checked["creations"], checked["owners"], checked["destroy_sites"],
             checked["packet_handlers"], checked["finish_handlers"], checked["guards"],
             checked["guard_contracts"], checked["tests"], checked["registrations"],
             checked["naming_files"]))

    if "--mutation-test" in sys.argv or "-m" in sys.argv:
        if not run_mutation_tests():
            sys.exit(1)


if __name__ == "__main__":
    main()
