/*
 * The owned-line Finish postcondition, on an endpoint owner.
 *
 * UdpStatelessSocket creates one line per peer flow and registers it in a
 * worker-local idle table. That makes it the smallest complete example of the
 * contract: on a Finish for a line it owns it must detach the idle entry, drop
 * its line state and leave the line logically dead before returning - and on a
 * Finish for a line it does not own it must do none of those things.
 *
 * Both cases run the handler under an outer lineRef(), which is the frame the
 * contract exists for: it keeps the allocation readable past the owner's
 * lineDestroy() so lineIsAlive() can be checked at all.
 */
#include "UdpStatelessSocket/structure.h"

#include "tunnel_orderly_shutdown_harness.h"
#include "udp_splice_fixture.h"
#include "worker_registry_fixture.h"

extern node_t nodeUdpStatelessSocketGet(void);

static void caseHeadOnlyMetadata(void)
{
    node_t node = nodeUdpStatelessSocketGet();
    twfRequire((node.flags & kNodeFlagChainHead) != 0 && (node.flags & kNodeFlagChainEnd) == 0,
               "UdpStatelessSocket must advertise only the head role");
    twfRequire(! node.can_have_prev && node.can_have_next && node.layer_group_prev_node == kNodeLayerNone,
               "UdpStatelessSocket must reject a previous neighbor");
    memoryFree(node.type);
}

/*
 * Fake worker table for the stubbed GSTATE below. Without it the identity
 * predicates correctly report "not an event worker" and the checked
 * current-worker accessors reject this test.
 */
static test_worker_registry_t g_test_worker_registry;

enum
{
    kTestLargeBufferSize = 8192,
    kTestLinePoolItems   = 8,
    kTestIdleAgeMs       = 30000,
    kTestPeerHash        = 0x5151
};

typedef struct udpstateless_fixture_s
{
    twf_worker_env_t    env;
    twf_line_pool_t     lines;
    twf_trace_t         trace;
    tunnel_t           *prev;
    tunnel_t           *uss;
    tunnel_t           *next;
    line_t             *line;
    local_idle_table_t *idle_table;
    local_idle_table_t *idle_table_slots[1];
} udpstateless_fixture_t;

/*
 * The production expiry callback is static, and nothing in these cases may reach
 * an expiry at all: the line is closed long before its idle age.
 */
static void neverExpire(local_idle_item_t *item)
{
    discard item;
    twfRequire(false, "an idle item expired; these cases close their line first");
}

static void fixtureSetup(udpstateless_fixture_t *fixture, bool attach_idle_item)
{
    memoryZero(fixture, sizeof(*fixture));
    twfWorkerEnvSetup(&fixture->env, kTestLargeBufferSize, 0);

    // udpsockGetWorkerIdleTable() checks getWID() against getWorkersCount(), which
    // subtracts the lwIP pseudo-worker. One event-loop worker therefore has to be
    // published as two; only slot 0 is ever indexed.
    GSTATE.workers_count = 2;
    testWorkerRegistryInstall(&g_test_worker_registry);

    fixture->uss  = tunnelCreate(NULL, sizeof(udpstatelesssocket_tstate_t), sizeof(udpstatelesssocket_lstate_t));
    twfRequire(fixture->uss != NULL, "failed to create the UdpStatelessSocket tunnel");
    fixture->next = twfCreateNextTunnel(&fixture->trace);

    tunnelBind(fixture->uss, fixture->next);

    fixture->idle_table = localIdleTableCreate(fixture->env.loop);
    twfRequire(fixture->idle_table != NULL, "failed to create the test idle table");
    fixture->idle_table_slots[0] = fixture->idle_table;

    udpstatelesssocket_tstate_t *ts = tunnelGetState(fixture->uss);
    // The socket owns peer lines at the head; downstream Finish arrives from next.
    ts->is_chain_end       = false;
    ts->socket.idle_tables = fixture->idle_table_slots;

    // Real pooled lines: lineDestroy() returns a line to line->pools[wid], so the
    // postcondition cannot be driven with a bare allocation.
    twfLinePoolSetup(&fixture->lines, fixture->uss->lstate_size, kTestLinePoolItems);
    fixture->line = twfLinePoolCreateLine(&fixture->lines);

    udpstatelesssocket_lstate_t *ls = lineGetState(fixture->line, fixture->uss);
    sockaddr_u                   peer_addr;
    sockaddr_u                   local_addr;

    memoryZero(&peer_addr, sizeof(peer_addr));
    memoryZero(&local_addr, sizeof(local_addr));
    twfRequire(sockaddrSetIpAddressPort(&peer_addr, "127.0.0.1", 40000) == 0, "failed to build the test peer address");
    twfRequire(sockaddrSetIpAddressPort(&local_addr, "127.0.0.1", 50000) == 0,
               "failed to build the test local address");

    if (attach_idle_item)
    {
        local_idle_item_t *idle =
            localidletableCreateItem(fixture->idle_table, kTestPeerHash, ls, neverExpire, kTestIdleAgeMs);
        twfRequire(idle != NULL, "failed to register the test idle item");
        udpstatelesssocketLinestateInitialize(ls, fixture->line, fixture->uss, idle, &peer_addr, &local_addr);
    }
    else
    {
        // No idle handle is exactly how this tunnel recognizes a line it did not
        // create, so it cannot be built through LinestateInitialize().
        *ls = (udpstatelesssocket_lstate_t) {.tunnel      = fixture->uss,
                                             .line        = fixture->line,
                                             .idle_handle = NULL,
                                             .peer_addr   = peer_addr,
                                             .local_addr  = local_addr,
                                             .read_paused = false};
    }
}

static void fixtureTeardown(udpstateless_fixture_t *fixture)
{
    localidletableDestroy(fixture->idle_table);
    twfRequireNoLeakedBuffers();
    twfLinePoolTeardown(&fixture->lines);
    tunnelDestroy(fixture->next);
    tunnelDestroy(fixture->uss);
}

// ---------------------------------------------------------------------------
// An owned peer line is dead when the handler returns
// ---------------------------------------------------------------------------

static void caseEndpointOwnerFinishKillsLine(void)
{
    twfSetCase("udpstatelesssocket downstream Finish closes its owned peer line");

    udpstateless_fixture_t fixture;
    fixtureSetup(&fixture, true);

    twfRequire(localidletableGetIdleItemByHash(fixture.idle_table, kTestPeerHash) != NULL,
               "the fixture must start with the peer registered in the idle table");

    twfRunOwnerFinish(fixture.uss,
                      fixture.line,
                      udpstatelesssocketTunnelDownStreamFinish,
                      "udpstatelesssocketTunnelDownStreamFinish");

    // Logical death alone cancels no external producer, so the lookup entry has to
    // be gone independently.
    twfRequire(localidletableGetIdleItemByHash(fixture.idle_table, kTestPeerHash) == NULL,
               "the owner must detach its idle-table entry before destroying the line");

    // next finished us, so nothing may travel back that way. The head has no prev.
    twfRequireEqualU32(fixture.trace.next_finish, 0, "a received downstream Finish must not be reflected upstream");
    twfRequireEqualU32(fixture.trace.next_payload, 0, "a received downstream Finish must not answer upstream");
    twfRequireEqualU32(fixture.trace.prev_finish, 0, "the closing endpoint must not emit a second Finish");

    twfRequireOwnedLineReclaimed(fixture.line, "udpstatelesssocketTunnelDownStreamFinish");
    fixtureTeardown(&fixture);
}

// ---------------------------------------------------------------------------
// A line this tunnel does not own is left entirely alone
// ---------------------------------------------------------------------------

static void caseBorrowedLineFinishDoesNotDestroy(void)
{
    twfSetCase("udpstatelesssocket downstream Finish leaves a borrowed line alone");

    udpstateless_fixture_t fixture;
    fixtureSetup(&fixture, false);

    lineRef(fixture.line);
    udpstatelesssocketTunnelDownStreamFinish(fixture.uss, fixture.line);

    twfRequire(lineIsAlive(fixture.line), "a borrowed line must not be destroyed by a tunnel that did not create it");

    udpstatelesssocket_lstate_t *ls = lineGetState(fixture.line, fixture.uss);
    twfRequire(ls->line == fixture.line, "the borrowed line's state must be left to its real owner");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "a received downstream Finish must not be reflected upstream");

    // The reference the fixture holds plus the creator's, still outstanding.
    twfRequireEqualU32(twfLineRefCount(fixture.line), 2, "a borrowed line must keep its creator's reference");

    lineUnref(fixture.line);

    // Stand in for the real owner, so the line returns to the pool before teardown.
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
    lineDestroy(fixture.line);

    fixtureTeardown(&fixture);
}

#if WW_HAVE_SPLICE
static line_t  *splice_peer_line;
static unsigned owner_splice_calls, owner_close_calls;
static void     observeOwnerSplice(void)
{
    twfRequire(currentThreadIsEventWorkerWID(0), "adapter sent on a foreign worker");
    ++owner_splice_calls;
}
static void observeOwnerClose(wio_t *io)
{
    twfRequire(currentThreadIsEventWorkerWID(0), "adapter close callback ran on a foreign worker");
    twfRequire(wioIsClosed(io), "close callback preceded closed publication");
    ++owner_close_calls;
    udpstatelesssocketOnSocketClose(io);
}
static void recordSplicePeer(tunnel_t *t, line_t *line)
{
    discard t;
    splice_peer_line = line;
}
static void caseSpliceOwnerDispatch(bool cancel_drain)
{
    twfSetCase("stateless UDP local/foreign splice disposal, cancellation and socket retirement");
    tos_worker_env_t env;
    tosWorkerEnvSetup(&env, 2, 8192, 1024);
    env.pools[2]            = env.pools[0]; /* Chain padding also visits the fixture pseudo-worker. */
    node_t node             = nodeUdpStatelessSocketGet();
    node.hash_next          = 1;
    node.next               = (char *) "next";
    node.node_settings_json = cJSON_Parse("{\"listen-address\":\"127.0.0.1\",\"listen-port\":0}");
    tunnel_t *t             = udpstatelesssocketTunnelCreate(&node);
    twfRequire(t != NULL, "create stateless splice adapter");
    twf_trace_t trace = {0};
    tunnel_t   *next  = twfCreateNextTunnel(&trace);
    next->fnInitU     = recordSplicePeer;
    tunnelBind(t, next);
    tunnel_chain_t *chain      = tunnelchainCreate(2);
    chain->sum_line_state_size = t->lstate_size;
    tunnelchainFinalize(chain);
    t->chain = chain;
    udpstatelesssocketTunnelOnPrepair(t);
    udpstatelesssocket_tstate_t *ts = tunnelGetState(t);
    twfRequire(ts->socket.io != NULL, "stateless socket prepare");
    owner_splice_calls = owner_close_calls = 0;
    udp_test_splice_observer               = observeOwnerSplice;
    wioSetCallBackClose(ts->socket.io, observeOwnerClose);
    int        receiver = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_u peer;
    sockaddrSetIpAddressPort(&peer, "127.0.0.1", 0);
    twfRequire(bind(receiver, &peer.sa, SOCKADDR_LEN(&peer)) == 0 && nonBlocking(receiver) == 0, "stateless peer bind");
    socklen_t size = sizeof(peer);
    getsockname(receiver, &peer.sa, &size);
    for (wid_t wid = 0; wid < 2; ++wid)
    {
        discard tosSetCurrentWorker(wid);
        udpstatelesssocketDispatchToPeer(t, udpTestSplicePayload(env.pools[wid]), &peer);
        if (wid != 0)
            tosPumpWorker(&env, 0);
        char bytes[64];
        int  n = (int) recv(receiver, bytes, sizeof(bytes), 0);
        twfRequire(n == sizeof("pipe-backed datagram") && memcmp(bytes, "pipe-backed datagram", n) == 0,
                   "stateless splice payload changed");
        twfRequireNoLeakedBuffers();
    }
    /* Cancellation owns a detached buffer and must not borrow worker 1's pool. */
    udpstatelesssocketDispatchToPeer(t, udpTestSplicePayload(env.pools[1]), &peer);
    discard tosSetCurrentWorker(0);
    workerMessagesCleanupPending(&env.workers[0]);
    twfRequireNoLeakedBuffers();
    wioSetPeerAddr(ts->socket.io, &peer.sa, SOCKADDR_LEN(&peer));
    sbuf_t *ingress = bufferpoolGetSmallBuffer(env.pools[0]);
    sbufSetLength(ingress, 0);
    udpstatelesssocketOnRecvFrom(ts->socket.io, ingress);
    twfRequire(splice_peer_line != NULL, "stateless ingress did not create owned peer");
    lineRef(splice_peer_line);
    discard tosSetCurrentWorker(1);
    udpstatelesssocketDispatchToPeer(t, udpTestSplicePayload(env.pools[1]), &peer);
    udpstatelesssocketDispatchToPeer(t, udpTestSplicePayload(env.pools[1]), &peer);
    udp_test_short_splice = true;
    if (cancel_drain)
    {
        discard tosSetCurrentWorker(0);
        udpstatelesssocketDispatchToPeer(t, udpTestSplicePayload(env.pools[0]), &peer);
        workerMessagesCleanupPending(&env.workers[0]);
        udpstatelesssocket_lstate_t *ls       = lineGetState(splice_peer_line, t);
        uint64_t                     deadline = localidletableTestGetDeadline(ls->idle_handle);
        udpstatelesssocketTunnelWritePayload(t, splice_peer_line, udpTestSplicePayload(env.pools[0]));
        twfRequire(localidletableTestGetDeadline(ls->idle_handle) == deadline,
                   "retired stateless traffic refreshed idle deadline");
        localidletableTestSetNowMS(ts->socket.idle_tables[0], deadline + 1);
        localidletableTestRunExpiry(ts->socket.idle_tables[0]);
        socketmanagerDrainUdpSocketForWorker(&ts->socket, 0);
    }
    else
        tosPumpWorker(&env, 0);
    tosPumpWorker(&env, 1);
    discard tosSetCurrentWorker(0);
    twfRequire(ts->socket.io == NULL && udpsockIsRetired(&ts->socket), "retirement retained stateless WIO");
    twfRequire(owner_splice_calls == 3 && owner_close_calls == 1, "owner send/close count mismatch");
    udp_test_splice_observer = NULL;
    twfRequire(! lineIsAlive(splice_peer_line) && trace.next_finish == 1, "retirement retained owned peer line");
    lineUnref(splice_peer_line);
    splice_peer_line = NULL;
    char byte;
    twfRequire(recv(receiver, &byte, 1, 0) < 0 && errno == EAGAIN, "retirement leaked prefix or queued suffix");
    udpstatelesssocketDispatchToPeer(t, udpTestSplicePayload(env.pools[0]), &peer);
    twfRequireNoLeakedBuffers();
    tosRequireNoProcessApiCall();
    close(receiver);
    tunnelchainDestroy(chain);
    tunnelDestroy(next);
    udpstatelesssocketTunnelDestroy(t, wwLifecycleStartupRollback());
    cJSON_Delete(node.node_settings_json);
    memoryFree(node.type);
    tosWorkerEnvTeardown(&env);
}
#endif

int main(void)
{
#if WW_HAVE_SPLICE
    caseSpliceOwnerDispatch(false);
    caseSpliceOwnerDispatch(true);
#endif
    caseHeadOnlyMetadata();
    caseEndpointOwnerFinishKillsLine();
    caseBorrowedLineFinishDoesNotDestroy();

    printf("owned_line_finish_udpstatelesssocket_test: all cases passed\n");
    return 0;
}
