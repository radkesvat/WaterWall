/*
 * Covers: owned line finish udpstatelesssocket; the explicit inputs, callbacks and expected results
 * below define this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: caseHeadOnlyMetadata, caseEndpointOwnerFinishKillsLine, caseBorrowedLineFinishDoesNotDestroy,
 * caseSpliceOwnerDispatch, casePendingDnsBounds, caseProtectedDnsProvider.
 * Pending DNS checks cover count/byte/allocation admission, synchronous completion,
 * submission refusal, timeout, shutdown and completion after borrowed-line death.
 * Limit diagnostics cover WARN context, independent reasons, exact-boundary silence
 * and suppression counts without waiting for a reporting window.
 * Checks: Assertion labels include: UdpStatelessSocket must advertise only the head role;
 * UdpStatelessSocket must reject a previous neighbor; an idle item expired; these cases close their line
 * first; the owner must detach its idle-table entry before destroying the line
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.owned_line_finish_udpstatelesssocket_unit
 */
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

#include "fixtures/failure/tunnel_orderly_shutdown_harness.h"
#include "fixtures/protocols/udp_splice_fixture.h"
#include "fixtures/worker_registry_fixture.h"
#include "loggers/dns_logger.h"

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
    udpstatelesssocket_dns_pending_t dns_pending;
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

    // Publish the fixture's one ordinary event worker.
    GSTATE.workers_count = 1;
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
    ts->socket.idle_tables = fixture->idle_table_slots;
    ts->dns_pending        = &fixture->dns_pending;
    bufferbudgetInit(&fixture->dns_pending.budget,
                     (buffer_budget_cost_t) {kUdpStatelessSocketDnsPendingBytes, kUdpStatelessSocketDnsPendingCharge});

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
    twfRequire(fixture->dns_pending.requests == 0 && fixture->dns_pending.budget.used.bytes == 0 &&
                   fixture->dns_pending.budget.used.charge == 0,
               "pending DNS retention survived fixture cleanup");
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
static line_t        *splice_peer_line;
static buffer_pool_t *owner_send_pool;
static unsigned       owner_send_calls, owner_close_calls;
static void           observeOwnerSend(buffer_pool_t *pool)
{
    twfRequire(currentThreadOwnsWorker(0), "adapter sent on a foreign worker");
    twfRequire(pool == owner_send_pool, "adapter borrowed a pool other than its socket owner's");
    ++owner_send_calls;
}
static void observeOwnerClose(wio_t *io)
{
    twfRequire(currentThreadOwnsWorker(0), "adapter close callback ran on a foreign worker");
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
    testSpliceInventoryInitialize(0);
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
    owner_send_calls = owner_close_calls = 0;
    owner_send_pool                      = env.pools[0];
    udp_test_send_observer               = observeOwnerSend;
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
    udp_test_retire_send = true;
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
    twfRequire(owner_send_calls == 3 && owner_close_calls == 1, "owner send/close count mismatch");
    udp_test_send_observer = NULL;
    owner_send_pool        = NULL;
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

static void caseDisabledDnsDropsBorrowedDatagram(void)
{
    twfSetCase("stateless disabled DNS drops unresolved borrowed datagrams without callbacks");
    udpstateless_fixture_t fixture;
    fixtureSetup(&fixture, false);
    udpstatelesssocket_tstate_t *state = tunnelGetState(fixture.uss);
    state->dns_policy                  = (dns_policy_t) {.supplied = true, .resolve = false};
    atomic_init(&state->socket.retired, false);
    address_context_t *destination = lineGetDestinationAddressContext(fixture.line);
    addresscontextDomainSetByString(destination, "disabled.example");
    addresscontextSetPort(destination, 53);
    addresscontextSetOnlyProtocol(destination, IP_PROTO_UDP);
    const uint32_t refs = twfLineRefCount(fixture.line);
    sbuf_t        *buf  = bufferpoolGetSmallBuffer(fixture.env.pool);
    sbufSetLength(buf, 1);
    udpstatelesssocketTunnelWritePayload(fixture.uss, fixture.line, buf);
    twfRequire(lineIsAlive(fixture.line) && twfLineRefCount(fixture.line) == refs,
               "disabled DNS destroyed a borrowed line or retained a DNS reference");
    twfRequire(fixture.trace.next_finish == 0 && fixture.trace.prev_finish == 0,
               "disabled DNS emitted Finish for a borrowed datagram");
    udpstatelesssocket_lstate_t *ls = lineGetState(fixture.line, fixture.uss);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
    lineDestroy(fixture.line);
    fixtureTeardown(&fixture);
}

#if defined(OS_LINUX)
static tunnel_t *protected_dns_provider;
static unsigned  protected_dns_queries, native_dns_queries;
static bool      protected_dns_answer = true;
typedef struct pending_dns_callback_s
{
    dns_resolve_cb cb;
    void          *userdata;
} pending_dns_callback_t;

static pending_dns_callback_t pending_dns_callbacks[kUdpStatelessSocketDnsPendingRequests + 1];
static bool                   native_dns_deferred, native_dns_synchronous;

static void completeNativeDns(size_t slot, int status)
{
    pending_dns_callback_t pending = pending_dns_callbacks[slot];
    twfRequire(pending.cb != NULL, "DNS fixture completed an empty callback slot");
    pending_dns_callbacks[slot] = (pending_dns_callback_t) {0};
    sockaddr_u peer;
    twfRequire(sockaddrSetIpAddressPort(&peer, "127.0.0.42", 53) == 0, "DNS fixture address failed");
    dns_resolved_addr_t resolved = {.family = AF_INET, .addrlen = sizeof(peer.sin)};
    memoryCopy(&resolved.addr, &peer, sizeof(peer.sin));
    pending.cb(pending.userdata,
               status,
               ares_strerror(status),
               status == ARES_SUCCESS ? &resolved : NULL,
               status == ARES_SUCCESS ? 1 : 0);
}

int __wrap_workerResolveDomainServiceAsync(wid_t wid, const char *domain, const char *service, int socktype,
                                           dns_resolve_cb cb, void *userdata);
int __wrap_workerResolveDomainServiceAsync(wid_t wid, const char *domain, const char *service, int socktype,
                                           dns_resolve_cb cb, void *userdata)
{
    discard wid;
    discard domain;
    discard service;
    discard socktype;
    ++native_dns_queries;
    if (native_dns_deferred || native_dns_synchronous)
    {
        for (size_t slot = 0; slot < ARRAY_SIZE(pending_dns_callbacks); ++slot)
        {
            if (pending_dns_callbacks[slot].cb != NULL)
                continue;
            pending_dns_callbacks[slot] = (pending_dns_callback_t) {cb, userdata};
            if (native_dns_synchronous)
                completeNativeDns(slot, ARES_SUCCESS);
            return ARES_SUCCESS;
        }
        twfRequire(false, "DNS fixture exceeded its callback capacity");
    }
    return ARES_ENOTINITIALIZED;
}

int __wrap_workerResolveDomainServiceFamilyAsync(wid_t wid, const char *domain, const char *service, int socktype,
                                                 int family, dns_resolve_cb cb, void *userdata);
int __wrap_workerResolveDomainServiceFamilyAsync(wid_t wid, const char *domain, const char *service, int socktype,
                                                 int family, dns_resolve_cb cb, void *userdata)
{
    twfRequire(family == AF_INET, "stateless only-ipv4 submitted another query family");
    return __wrap_workerResolveDomainServiceAsync(wid, domain, service, socktype, cb, userdata);
}

static void submitPendingDnsDatagram(udpstateless_fixture_t *fixture, line_t *line, size_t length, size_t capacity)
{
    static unsigned next_domain;
    char            domain[64];
    snprintf(domain, sizeof(domain), "pending-%u.test", ++next_domain);
    address_context_t *destination = lineGetDestinationAddressContext(line);
    addresscontextDomainSetByString(destination, domain);
    addresscontextSetPort(destination, 53);
    addresscontextSetOnlyProtocol(destination, IP_PROTO_UDP);
    sbuf_t *buf = bufferpoolGetBestFit(fixture->env.pool, capacity, 0);
    sbufSetLength(buf, length);
    udpstatelesssocketTunnelWritePayload(fixture->uss, line, buf);
}

static void completeAllNativeDns(int status)
{
    for (size_t slot = 0; slot < ARRAY_SIZE(pending_dns_callbacks); ++slot)
        if (pending_dns_callbacks[slot].cb != NULL)
            completeNativeDns(slot, status);
}

static void requirePendingDnsEmpty(udpstateless_fixture_t *fixture, uint32_t refs)
{
    twfRequire(fixture->dns_pending.requests == 0 && fixture->dns_pending.budget.used.bytes == 0 &&
                   fixture->dns_pending.budget.used.charge == 0 && twfLineRefCount(fixture->line) == refs,
               "DNS settlement retained request count, bytes, charge or line references");
    twfRequireNoLeakedBuffers();
}

static unsigned dns_limit_log_count;
static char     dns_limit_log[1024];

static void captureDnsLimitLog(int level, const char *data, int length)
{
    if (strstr(data, "UdpStatelessSocket: DNS pending limit exceeded") == NULL)
        return;
    twfRequire(level == LOG_LEVEL_WARN, "UDP DNS admission refusal must log WARN");
    ++dns_limit_log_count;
    const size_t copied = min((size_t) length, sizeof(dns_limit_log) - 1);
    memoryCopy(dns_limit_log, data, copied);
    dns_limit_log[copied] = '\0';
}

static void casePendingDnsBounds(void)
{
    twfSetCase("stateless pending DNS bounds count, payload and allocation across borrowed lines");
    udpstateless_fixture_t fixture;
    fixtureSetup(&fixture, false);
    node_t socket_node = {.name = (char *) "stateless-limit-test"};
    fixture.uss->node  = &socket_node;
    const bool own_log = getDnsLogger() == NULL;
    logger_t  *logger  = own_log ? createDnsLogger(NULL, false) : getDnsLogger();
    twfRequire(logger != NULL, "DNS limit logger setup failed");
    logger_handler previous_handler = getDnsLoggerHandle();
    loggerSetHandler(logger, captureDnsLimitLog);
    dns_limit_log_count                = 0;
    udpstatelesssocket_tstate_t *state = tunnelGetState(fixture.uss);
    state->dns_policy                  = (dns_policy_t) {.resolve = true, .strategy = kDsOnlyIpV4};
    state->dns_strategy_override       = true;
    atomic_init(&state->socket.retired, false);
    twfRequire(mutexTryInit(&state->dns_cache_mutex), "DNS cache mutex setup failed");
    node_t provider_node = {.type = (char *) "DomainResolver"};
    node_t factory       = nodeDomainResolverGet();
    state->dns_provider  = factory.createHandle(&provider_node);
    memoryFree(factory.type);
    twfRequire(state->dns_provider != NULL, "native DNS provider setup failed");
    const uint32_t refs    = twfLineRefCount(fixture.line);
    native_dns_queries     = 0;
    native_dns_deferred    = true;
    native_dns_synchronous = false;
    for (unsigned i = 0; i < kUdpStatelessSocketDnsPendingRequests; ++i)
        submitPendingDnsDatagram(&fixture, fixture.line, 0, 0);
    twfRequire(fixture.dns_pending.requests == kUdpStatelessSocketDnsPendingRequests &&
                   native_dns_queries == kUdpStatelessSocketDnsPendingRequests,
               "empty datagrams did not fill the request-count allowance");
    twfRequire(dns_limit_log_count == 0, "accepted request boundary emitted a DNS limit warning");
    line_t *other = twfLinePoolCreateLine(&fixture.lines);
    submitPendingDnsDatagram(&fixture, other, 1, 1);
    twfRequire(lineIsAlive(other) && twfLineRefCount(other) == 1 &&
                   native_dns_queries == kUdpStatelessSocketDnsPendingRequests,
               "another borrowed line bypassed the worker request cap or was closed");
    twfRequire(dns_limit_log_count == 1 && strstr(dns_limit_log, "node=stateless-limit-test worker=0") != NULL &&
                   strstr(dns_limit_log, "destination=pending-") != NULL && strstr(dns_limit_log, ".test:53") != NULL &&
                   strstr(dns_limit_log, "reason=pending-requests used=256 incoming=1 limit=256") != NULL &&
                   strstr(dns_limit_log, "action=dropping-datagram suppressed=0") != NULL,
               "request refusal warning lost node, worker, destination, limit or action context");
    submitPendingDnsDatagram(&fixture, fixture.line, 1, 1);
    twfRequire(dns_limit_log_count == 1 && fixture.dns_pending.request_limit_log.pending == 1,
               "repeated request refusal was not suppressed across borrowed lines");
    fixture.dns_pending.request_limit_log.window_started_ms = getTimeOfDayMS() - 5000;
    submitPendingDnsDatagram(&fixture, other, 1, 1);
    twfRequire(dns_limit_log_count == 2 && strstr(dns_limit_log, "suppressed=1") != NULL,
               "next request warning omitted the suppressed refusal count");
    completeNativeDns(0, ARES_ETIMEOUT);
    submitPendingDnsDatagram(&fixture, other, 1, 1);
    twfRequire(fixture.dns_pending.requests == kUdpStatelessSocketDnsPendingRequests && twfLineRefCount(other) == 2,
               "timeout did not restore one request slot for another line");
    lineRef(other);
    lineDestroy(other);
    completeNativeDns(0, ARES_SUCCESS);
    twfRequire(! lineIsAlive(other) && twfLineRefCount(other) == 1,
               "dead-line DNS completion leaked its retained reference");
    lineUnref(other);
    completeAllNativeDns(ARES_ECANCELLED);
    requirePendingDnsEmpty(&fixture, refs);

    // Valid maximum UDP datagrams fit until the logical-byte allowance is exact.
    for (size_t left = kUdpStatelessSocketDnsPendingBytes; left != 0;)
    {
        size_t length = min(left, (size_t) 65507);
        submitPendingDnsDatagram(&fixture, fixture.line, length, length);
        left -= length;
    }
    twfRequire(fixture.dns_pending.budget.used.bytes == kUdpStatelessSocketDnsPendingBytes,
               "pending DNS failed admission at the logical-byte boundary");
    twfRequire(dns_limit_log_count == 2, "accepted payload boundary emitted a DNS limit warning");
    unsigned submitted = native_dns_queries;
    submitPendingDnsDatagram(&fixture, fixture.line, 1, 1);
    twfRequire(native_dns_queries == submitted && lineIsAlive(fixture.line),
               "logical-byte overflow submitted DNS or closed its borrowed line");
    twfRequire(dns_limit_log_count == 3 &&
                   strstr(dns_limit_log, "reason=pending-payload-bytes used=2097152 incoming=1 limit=2097152") !=
                       NULL &&
                   strstr(dns_limit_log, "suppressed=0") != NULL,
               "payload refusal was hidden by another reason or omitted byte usage");
    completeAllNativeDns(ARES_ETIMEOUT);
    requirePendingDnsEmpty(&fixture, refs);

    // A tiny datagram can retain a large allocation; bytes alone cannot bound it.
    const size_t exact_capacity = kUdpStatelessSocketDnsPendingCharge - sizeof(sbuf_t) - kSbufAllocationAlignment;
    submitPendingDnsDatagram(&fixture, fixture.line, 1, exact_capacity);
    twfRequire(fixture.dns_pending.requests == 1 &&
                   fixture.dns_pending.budget.used.charge == kUdpStatelessSocketDnsPendingCharge,
               "pending DNS failed admission at the allocation-charge boundary");
    twfRequire(dns_limit_log_count == 3, "accepted charge boundary emitted a DNS limit warning");
    submitted = native_dns_queries;
    submitPendingDnsDatagram(&fixture, fixture.line, 0, 0);
    twfRequire(native_dns_queries == submitted, "empty datagram escaped the allocation-charge cap");
    twfRequire(dns_limit_log_count == 4 &&
                   strstr(dns_limit_log, "reason=pending-buffer-charge used=4194304 incoming=") != NULL &&
                   strstr(dns_limit_log, "limit=4194304") != NULL && strstr(dns_limit_log, "suppressed=0") != NULL,
               "charge refusal was hidden by another reason or omitted allocation usage");
    completeAllNativeDns(ARES_ECANCELLED);
    requirePendingDnsEmpty(&fixture, refs);
    submitPendingDnsDatagram(&fixture, fixture.line, 1, kUdpStatelessSocketDnsPendingCharge);
    twfRequire(native_dns_queries == submitted, "one oversized allocation bypassed the DNS retention cap");
    requirePendingDnsEmpty(&fixture, refs);

    native_dns_deferred = false;
    submitPendingDnsDatagram(&fixture, fixture.line, 1, 1);
    requirePendingDnsEmpty(&fixture, refs);
    native_dns_synchronous = true;
    submitPendingDnsDatagram(&fixture, fixture.line, 1, 1);
    requirePendingDnsEmpty(&fixture, refs);
    native_dns_synchronous = false;
    twfRequire(fixture.trace.next_finish == 0 && fixture.trace.prev_finish == 0,
               "DNS admission or settlement emitted Finish on a borrowed line");
    udpstatelesssocketLinestateDestroy(lineGetState(fixture.line, fixture.uss));
    lineDestroy(fixture.line);
    udpstatelesssocketDnsCacheClear(state);
    mutexDestroy(&state->dns_cache_mutex);
    tunnelOwnedChildDestroy(state->dns_provider);
    fixtureTeardown(&fixture);
    loggerSetHandler(logger, previous_handler);
    if (own_log)
        dnsloggerDestroy();
}

static void protectedDnsInit(tunnel_t *egress, line_t *line)
{
    discard            egress;
    address_context_t *destination = lineGetDestinationAddressContext(line);
    twfRequire(addresscontextIsResolverDns(destination) && addresscontextDestinationIsPinned(destination) &&
                   destination->port == 5353 && destination->proto_udp &&
                   ntohl(destination->ip_address.u_addr.ip4.addr) == 0x7f000035U,
               "stateless DNS did not reach the selected numeric server and UDP egress");
    addresscontextSetDestinationPinned(destination, false);
    tunnelDownStreamEst(protected_dns_provider, line);
}

static void protectedDnsFinish(tunnel_t *egress, line_t *line)
{
    discard egress;
    discard line;
}

static void protectedDnsPayload(tunnel_t *egress, line_t *line, sbuf_t *query)
{
    discard egress;
    ++protected_dns_queries;
    if (! protected_dns_answer)
    {
        lineReuseBuffer(line, query);
        return;
    }
    const uint8_t *wire = sbufGetRawPtr(query);
    size_t         end  = 12;
    while (end < sbufGetLength(query) && wire[end] != 0)
        end += (size_t) wire[end] + 1;
    end += 5;
    twfRequire(end <= sbufGetLength(query), "malformed DNS fixture question");
    const bool ipv4  = wire[end - 4] == 0 && wire[end - 3] == 1;
    sbuf_t    *reply = bufferpoolGetBestFit(lineGetBufferPool(line), end + (ipv4 ? 16 : 0), 0);
    sbufSetLength(reply, end + (ipv4 ? 16 : 0));
    uint8_t *answer = sbufGetMutablePtr(reply);
    memoryCopy(answer, wire, end);
    answer[2] = 0x81;
    answer[3] = 0x80;
    answer[6] = 0;
    answer[7] = ipv4 ? 1 : 0;
    answer[8] = answer[9] = answer[10] = answer[11] = 0;
    if (ipv4)
    {
        const uint8_t record[] = {0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 42};
        memoryCopy(answer + end, record, sizeof(record));
    }
    lineReuseBuffer(line, query);
    tunnelDownStreamPayload(protected_dns_provider, line, reply);
}

static void caseProtectedDnsProvider(void)
{
    twfSetCase("stateless DNS submits through its policy provider and snapshots mutable destinations");
    udpstateless_fixture_t fixture;
    fixtureSetup(&fixture, false);
    twfRequire(ares_library_init(ARES_LIB_INIT_ALL) == ARES_SUCCESS, "c-ares initialization failed");
    asyncdnsOptionsSetDefaults(&GSTATE.dns_options);
    GSTATE.dns_options.lookups = (char *) "b";
    cJSON *settings            = cJSON_Parse("{\"mode\":\"chain\",\"strategy\":\"only-ipv4\","
                                             "\"servers\":[\"127.0.0.53:5353\"]}");
    node_t provider_node       = {
              .name = (char *) "stateless-provider", .type = (char *) "DomainResolver", .node_settings_json = settings};
    node_t factory         = nodeDomainResolverGet();
    protected_dns_provider = factory.createHandle(&provider_node);
    memoryFree(factory.type);
    twfRequire(protected_dns_provider != NULL, "failed to construct stateless DNS provider");
    node_t    egress_node         = {.type = (char *) "FixtureDnsEgress"};
    tunnel_t *egress              = tunnelCreate(&egress_node, 0, 0);
    egress->fnInitU               = protectedDnsInit;
    egress->fnFinU                = protectedDnsFinish;
    egress->fnPayloadU            = protectedDnsPayload;
    tunnel_chain_t *chain         = tunnelchainCreate(1);
    protected_dns_provider->chain = chain;
    twfRequire(domainresolverTunnelAttachEmbedded(protected_dns_provider, fixture.uss, egress),
               "failed to select stateless DNS fixture egress");
    udpstatelesssocket_lstate_t *borrowed = lineGetState(fixture.line, fixture.uss);
    memoryZeroAligned32(borrowed, tunnelGetCorrectAlignedLineStateSize(sizeof(*borrowed)));
    lineDestroy(fixture.line);
    twfLinePoolTeardown(&fixture.lines);
    fixture.uss->lstate_offset = protected_dns_provider->lstate_size;
    twfLinePoolSetup(
        &fixture.lines, protected_dns_provider->lstate_size + fixture.uss->lstate_size, kTestLinePoolItems);
    chain->line_pools[0]               = fixture.lines.pools[0];
    fixture.line                       = twfLinePoolCreateLine(&fixture.lines);
    udpstatelesssocket_tstate_t *state = tunnelGetState(fixture.uss);
    state->dns_policy                  = (dns_policy_t) {.resolve = true, .supplied = true, .strategy = kDsOnlyIpV4};
    state->dns_strategy_override       = true;
    state->dns_provider                = protected_dns_provider;
    atomic_init(&state->socket.retired, false);
    twfRequire(mutexTryInit(&state->dns_cache_mutex), "DNS cache mutex setup failed");
    protected_dns_queries = native_dns_queries = 0;
    protected_dns_answer                       = true;
    address_context_t *destination             = lineGetDestinationAddressContext(fixture.line);
    addresscontextDomainSetByString(destination, "stateless-policy.test");
    addresscontextSetPort(destination, 20453);
    const uint32_t refs = twfLineRefCount(fixture.line);
    sbuf_t        *buf  = bufferpoolGetSmallBuffer(fixture.env.pool);
    sbufSetLength(buf, 1);
    udpstatelesssocketTunnelWritePayload(fixture.uss, fixture.line, buf);
    addresscontextReset(destination);
    addresscontextDomainSetByString(destination, "new-context.test");
    addresscontextSetPort(destination, 20454);
    sockaddr_u cached;
    for (unsigned i = 0;
         i < 20 && ! udpstatelesssocketDnsCacheLookup(state, "stateless-policy.test", 20453, kDsOnlyIpV4, &cached);
         ++i)
        twfRequire(wloopProcessEvents(fixture.env.loop, 5) >= 0, "DNS event dispatch failed");
    twfRequire(protected_dns_queries > 0 && native_dns_queries == 0, "stateless DNS bypassed the selected provider");
    twfRequire(udpstatelesssocketDnsCacheLookup(state, "stateless-policy.test", 20453, kDsOnlyIpV4, &cached) &&
                   ntohl(cached.sin.sin_addr.s_addr) == 0x7f00002aU && ntohs(cached.sin.sin_port) == 20453,
               "mutable context changed the retained DNS destination or cache key");
    twfRequire(twfLineRefCount(fixture.line) == refs, "completed stateless DNS request retained a line reference");
    protected_dns_answer = false;
    buf                  = bufferpoolGetSmallBuffer(fixture.env.pool);
    sbufSetLength(buf, 1);
    udpstatelesssocketTunnelWritePayload(fixture.uss, fixture.line, buf);
    protected_dns_provider->onWorkerQuiesce(protected_dns_provider, 0, wwLifecycleStartupRollback());
    protected_dns_provider->onWorkerStop(protected_dns_provider, 0, wwLifecycleStartupRollback());
    twfRequire(twfLineRefCount(fixture.line) == refs && native_dns_queries == 0,
               "shutdown DNS completion leaked a request or fell back to native");
    lineDestroy(fixture.line);
    udpstatelesssocketDnsCacheClear(state);
    mutexDestroy(&state->dns_cache_mutex);
    tunnelOwnedChildDestroy(protected_dns_provider);
    protected_dns_provider = NULL;
    cJSON_Delete(settings);
    chain->line_pools[0] = NULL;
    tunnelchainDestroy(chain);
    tunnelDestroy(egress);
    ares_library_cleanup();
    fixtureTeardown(&fixture);
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
    caseDisabledDnsDropsBorrowedDatagram();
#if defined(OS_LINUX)
    casePendingDnsBounds();
    caseProtectedDnsProvider();
#endif

    printf("owned_line_finish_udpstatelesssocket_test: all cases passed\n");
    return 0;
}
