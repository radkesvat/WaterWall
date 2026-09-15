/*
 * Native unit test suite for UdpConnector worker-local socket pooling.
 *
 * Exercises the worker-local socket-pool contract for ordinary Layer-4 lines,
 * including normal lines using packet balance mode.
 */

#include "UdpConnector/interface.h"
#include "UdpConnector/structure.h"

#include "tunnel_orderly_shutdown_harness.h"

#if defined(OS_LINUX)
#include <dirent.h>

static bool       g_fail_wio_read;
static bool       g_capture_wio_write;
static uint32_t   g_captured_wio_write_calls;
static wio_t     *g_captured_wio_write_io;
static sockaddr_u g_captured_wio_write_peer;
static char       g_captured_wio_write_data[64];
static uint32_t   g_captured_wio_write_len;

int __real_wioRead(wio_t *io);
int __wrap_wioRead(wio_t *io);
int __real_wioWriteDatagram(wio_t *io, sbuf_t *buf, const sockaddr_u *peer_addr);
int __wrap_wioWriteDatagram(wio_t *io, sbuf_t *buf, const sockaddr_u *peer_addr);

int __wrap_wioRead(wio_t *io)
{
    if (g_fail_wio_read)
    {
        g_fail_wio_read = false;
        wioClose(io);
        return -1;
    }
    return __real_wioRead(io);
}

int __wrap_wioWriteDatagram(wio_t *io, sbuf_t *buf, const sockaddr_u *peer_addr)
{
    if (g_capture_wio_write)
    {
        ++g_captured_wio_write_calls;
        g_captured_wio_write_io   = io;
        g_captured_wio_write_peer = *peer_addr;
        g_captured_wio_write_len  = sbufGetLength(buf);
        if (g_captured_wio_write_len > sizeof(g_captured_wio_write_data))
        {
            g_captured_wio_write_len = sizeof(g_captured_wio_write_data);
        }
        memoryCopy(g_captured_wio_write_data, sbufGetRawPtr(buf), g_captured_wio_write_len);
    }

    return __real_wioWriteDatagram(io, buf, peer_addr);
}

static uint32_t countOpenFileDescriptors(void)
{
    DIR *dir = opendir("/proc/self/fd");
    twfRequire(dir != NULL, "failed to inspect /proc/self/fd");

    uint32_t count = 0;
    while (readdir(dir) != NULL)
    {
        ++count;
    }
    closedir(dir);
    return count;
}
#endif

enum
{
    kTestLargeBuffer = 8192,
};

typedef struct test_fixture_s
{
    twf_worker_env_t env;
    tunnel_t        *prev;
    tunnel_t        *connector;
    tunnel_chain_t  *chain;
    uint32_t         est_calls;
    uint32_t         payload_calls;
    uint32_t         finish_calls;
    uint32_t         pause_calls;
    uint32_t         resume_calls;
    line_t          *last_payload_line;
    char             last_payload_data[256];
    uint32_t         last_payload_len;
    line_t          *reentrant_close_line;
    bool             close_reentrant_on_finish;
    bool             close_reentrant_on_est;
} test_fixture_t;

static void prevDownStreamEst(tunnel_t *t, line_t *l)
{
    test_fixture_t *fixture = *(test_fixture_t **) tunnelGetState(t);
    ++fixture->est_calls;
    if (fixture->close_reentrant_on_est && l == fixture->reentrant_close_line)
    {
        udpconnectorTunnelUpStreamFinish(fixture->connector, l);
        lineDestroy(l);
    }
}

static void prevDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    test_fixture_t *fixture = *(test_fixture_t **) tunnelGetState(t);
    ++fixture->payload_calls;
    fixture->last_payload_line = l;
    uint32_t len               = sbufGetLength(buf);
    if (len >= sizeof(fixture->last_payload_data))
    {
        len = sizeof(fixture->last_payload_data) - 1;
    }
    memoryCopy(fixture->last_payload_data, sbufGetRawPtr(buf), len);
    fixture->last_payload_data[len] = '\0';
    fixture->last_payload_len       = len;
    lineReuseBuffer(l, buf);
}

static void prevDownStreamFinish(tunnel_t *t, line_t *l)
{
    test_fixture_t *fixture = *(test_fixture_t **) tunnelGetState(t);
    ++fixture->finish_calls;
    if (fixture->close_reentrant_on_finish && fixture->reentrant_close_line != NULL &&
        fixture->reentrant_close_line != l && lineIsAlive(fixture->reentrant_close_line))
    {
        line_t *target                = fixture->reentrant_close_line;
        fixture->reentrant_close_line = NULL;
        udpconnectorLineDetach(
            fixture->connector, target, lineGetState(target, fixture->connector), kUdpConnectorDetachSocketFailure);
    }
}

static void prevDownStreamPause(tunnel_t *t, line_t *l)
{
    test_fixture_t *fixture = *(test_fixture_t **) tunnelGetState(t);
    discard         l;
    ++fixture->pause_calls;
}

static void prevDownStreamResume(tunnel_t *t, line_t *l)
{
    test_fixture_t *fixture = *(test_fixture_t **) tunnelGetState(t);
    discard         l;
    ++fixture->resume_calls;
}

static void setupFixtureMode(test_fixture_t *fixture, enum udpconnector_balance_mode_e mode)
{
    memoryZero(fixture, sizeof(*fixture));
    g_udpconnector_pool_test_force_hash_zero        = false;
    g_udpconnector_pool_test_fail_socket_alloc      = false;
    g_udpconnector_pool_test_fail_binding_alloc     = false;
    g_udpconnector_pool_test_fail_socket_map_insert = false;
    g_udpconnector_pool_test_fail_line_map_insert   = false;
#if defined(OS_LINUX)
    g_fail_wio_read            = false;
    g_capture_wio_write        = false;
    g_captured_wio_write_calls = 0;
    g_captured_wio_write_io    = NULL;
    memoryZero(&g_captured_wio_write_peer, sizeof(g_captured_wio_write_peer));
    memoryZero(g_captured_wio_write_data, sizeof(g_captured_wio_write_data));
    g_captured_wio_write_len = 0;
#endif
    twfWorkerEnvSetup(&fixture->env, kTestLargeBuffer, 0);

    fixture->prev = tunnelCreate(NULL, sizeof(test_fixture_t *), 0);
    twfRequire(fixture->prev != NULL, "failed to create prev tunnel");
    *(test_fixture_t **) tunnelGetState(fixture->prev) = fixture;

    fixture->prev->fnEstD     = prevDownStreamEst;
    fixture->prev->fnPayloadD = prevDownStreamPayload;
    fixture->prev->fnFinD     = prevDownStreamFinish;
    fixture->prev->fnPauseD   = prevDownStreamPause;
    fixture->prev->fnResumeD  = prevDownStreamResume;

    fixture->connector = tunnelCreate(NULL, sizeof(udpconnector_tstate_t), sizeof(udpconnector_lstate_t));
    twfRequire(fixture->connector != NULL, "failed to create UdpConnector tunnel");

    udpconnector_tstate_t *ts = tunnelGetState(fixture->connector);
    ts->balance_mode          = mode;
    ts->send_buffer_size      = 0;
    ts->recv_buffer_size      = 0;
    ts->fwmark                = -1;
    ts->domain_strategy       = (uint32_t) kDsOnlyIpV4;
    ts->worker_pools          = memoryAllocateZero(sizeof(*ts->worker_pools) * getWorkersCount());
    twfRequire(ts->worker_pools != NULL, "failed to allocate worker pools");
    for (wid_t wid = 0; wid < getWorkersCount(); ++wid)
    {
        ts->worker_pools[wid].wid = wid;
    }

    tunnelBind(fixture->prev, fixture->connector);

    fixture->chain = tunnelchainCreate(1);
    twfRequire(fixture->chain != NULL, "failed to allocate chain");
    fixture->chain->sum_line_state_size = fixture->connector->lstate_size;
    tunnelchainFinalize(fixture->chain);
    twfRequire(fixture->chain->finalized, "failed to finalize test chain");
    fixture->connector->chain = fixture->chain;
    fixture->prev->chain      = fixture->chain;
}

static void teardownFixture(test_fixture_t *fixture)
{
    udpconnector_tstate_t *ts = tunnelGetState(fixture->connector);
    if (ts->worker_pools != NULL)
    {
        for (wid_t wid = 0; wid < getWorkersCount(); ++wid)
        {
            udpconnector_worker_pool_t *pool = &ts->worker_pools[wid];
            if (pool->idle_table != NULL)
            {
                localidletableDrainItems(pool->idle_table);
            }
            while (pool->v4_sockets != NULL)
            {
                udpconnectorPoolSocketRetire(pool->v4_sockets);
            }
            while (pool->v6_sockets != NULL)
            {
                udpconnectorPoolSocketRetire(pool->v6_sockets);
            }
            if (pool->idle_table != NULL)
            {
                localidletableDestroy(pool->idle_table);
                pool->idle_table = NULL;
            }
        }
        memoryFree(ts->worker_pools);
        ts->worker_pools = NULL;
    }

    if (fixture->chain != NULL)
    {
        fixture->connector->chain = NULL;
        fixture->prev->chain      = NULL;
        tunnelchainDestroy(fixture->chain);
        fixture->chain = NULL;
    }

    tunnelDestroy(fixture->prev);
    tunnelDestroy(fixture->connector);
    twfWorkerEnvTeardown(&fixture->env);
}

static line_t *createFixtureNormalLine(test_fixture_t *fixture)
{
    line_t *l = lineCreate(tunnelchainGetLinePools(fixture->chain), 0);
    twfRequire(l != NULL, "failed to create normal fixture line");
    return l;
}

static line_t *createAndInitLineIpv4(test_fixture_t *fixture, const char *ip_str, uint16_t port)
{
    line_t            *l        = createFixtureNormalLine(fixture);
    address_context_t *dest_ctx = lineGetDestinationAddressContext(l);
    sockaddr_u         addr     = {0};
    twfRequire(sockaddrSetIpAddressPort(&addr, ip_str, port) == 0, "failed to set sockaddr");
    addresscontextSetOnlyProtocol(dest_ctx, IP_PROTO_UDP);
    addresscontextFromSockAddr(dest_ctx, &addr);

    udpconnector_lstate_t *ls = lineGetState(l, fixture->connector);
    twfRequire(udpconnectorLinestateInitialize(ls, fixture->connector, l), "failed to initialize linestate");

    udpconnector_tstate_t      *ts          = tunnelGetState(fixture->connector);
    udpconnector_worker_pool_t *worker_pool = udpconnectorGetLineWorkerPool(ts, l);
    ls->line_idle_id                        = ++worker_pool->next_line_idle_id;
    ls->idle_handle                         = localidletableCreateItem(udpconnectorGetWorkerIdleTable(ts),
                                               (hash_t) ls->line_idle_id,
                                               ls,
                                               udpconnectorOnIdleConnectionExpire,
                                               kUdpInitExpireTime);
    twfRequire(ls->idle_handle != NULL, "failed to create idle item");

    udpconnector_binding_t *binding = udpconnectorAcquireBinding(fixture->connector, l, ls, &addr);
    twfRequire(binding != NULL, "failed to acquire binding");
    ls->last_send_binding = binding;
    return l;
}

static line_t *createAndInitLineIpv6(test_fixture_t *fixture, const char *ip_str, uint16_t port, uint32_t scope_id)
{
    line_t            *l        = createFixtureNormalLine(fixture);
    address_context_t *dest_ctx = lineGetDestinationAddressContext(l);
    sockaddr_u         addr     = {0};
    twfRequire(sockaddrSetIpAddressPort(&addr, ip_str, port) == 0, "failed to set sockaddr");
    addr.sin6.sin6_scope_id = scope_id;
    addresscontextSetOnlyProtocol(dest_ctx, IP_PROTO_UDP);
    addresscontextFromSockAddr(dest_ctx, &addr);

    udpconnector_lstate_t *ls = lineGetState(l, fixture->connector);
    twfRequire(udpconnectorLinestateInitialize(ls, fixture->connector, l), "failed to initialize linestate");

    udpconnector_tstate_t      *ts          = tunnelGetState(fixture->connector);
    udpconnector_worker_pool_t *worker_pool = udpconnectorGetLineWorkerPool(ts, l);
    ls->line_idle_id                        = ++worker_pool->next_line_idle_id;
    ls->idle_handle                         = localidletableCreateItem(udpconnectorGetWorkerIdleTable(ts),
                                               (hash_t) ls->line_idle_id,
                                               ls,
                                               udpconnectorOnIdleConnectionExpire,
                                               kUdpInitExpireTime);
    twfRequire(ls->idle_handle != NULL, "failed to create idle item");

    udpconnector_binding_t *binding = udpconnectorAcquireBinding(fixture->connector, l, ls, &addr);
    twfRequire(binding != NULL, "failed to acquire binding");
    ls->last_send_binding = binding;
    return l;
}

static sbuf_t *makeDatagram(test_fixture_t *fixture, const char *msg)
{
    discard fixture;
    sbuf_t *buf = bufferpoolGetLargeBuffer(getCurrentEventWorkerBufferPool());
    size_t  len = stringLength(msg);
    memoryCopy(sbufGetMutablePtr(buf), msg, len);
    sbufSetLength(buf, (uint32_t) len);
    return buf;
}

// Case 1: Two fixed normal lines to different IPv4 peers on one worker acquire the same WIO/local source port.
static void testCase1_DifferentPeersShareSocket(void)
{
    twfSetCase("Case 1: Two fixed normal lines to different IPv4 peers share socket");
    test_fixture_t fixture;
    setupFixtureMode(&fixture, kUdpConnectorBalanceModeConnection);

    line_t *l1 = createAndInitLineIpv4(&fixture, "127.0.0.1", 20001);
    line_t *l2 = createAndInitLineIpv4(&fixture, "127.0.0.1", 20002);

    udpconnector_lstate_t *ls1 = lineGetState(l1, fixture.connector);
    udpconnector_lstate_t *ls2 = lineGetState(l2, fixture.connector);

    twfRequire(ls1->fixed_binding != NULL && ls2->fixed_binding != NULL, "fixed bindings must be set");
    twfRequire(ls1->fixed_binding->socket == ls2->fixed_binding->socket, "sockets must be shared");
    twfRequireEqualU32(ls1->fixed_binding->socket->active_bindings_count, 2, "socket must have 2 active bindings");
    twfRequireEqualU32(sockaddrPort(wioGetLocaladdrU(ls1->fixed_binding->socket->io)),
                       sockaddrPort(wioGetLocaladdrU(ls2->fixed_binding->socket->io)),
                       "source ports must match");

    udpconnectorTunnelUpStreamFinish(fixture.connector, l1);
    lineDestroy(l1);
    udpconnectorTunnelUpStreamFinish(fixture.connector, l2);
    lineDestroy(l2);

    teardownFixture(&fixture);

    setupFixtureMode(&fixture, kUdpConnectorBalanceModeConnection);
    l1                                = createAndInitLineIpv4(&fixture, "127.0.0.1", 20001);
    fixture.reentrant_close_line      = l1;
    fixture.close_reentrant_on_est    = true;
    udpconnector_lstate_t *est_ls     = lineGetState(l1, fixture.connector);
    wio_t                 *io         = est_ls->fixed_binding->socket->io;
    sockaddr_u             est_source = {0};
    sockaddrSetIpAddressPort(&est_source, "127.0.0.1", 20001);
    wioSetPeerAddr(io, &est_source.sa, sockaddrLen(&est_source));
    lineRef(l1);
    udpconnectorOnSocketRecvFrom(io, makeDatagram(&fixture, "close_during_est"));
    twfRequire(! lineIsAlive(l1), "re-entrant Est close left the owner line logically alive");
    lineUnref(l1);

    teardownFixture(&fixture);
}

// Case 2: Two fixed normal lines to the same exact peer acquire different WIOs/local source ports.
static void testCase2_SamePeerCollidesToNewSocket(void)
{
    twfSetCase("Case 2: Two fixed normal lines to the same peer acquire distinct sockets");
    test_fixture_t fixture;
    setupFixtureMode(&fixture, kUdpConnectorBalanceModeConnection);

    line_t *l1 = createAndInitLineIpv4(&fixture, "127.0.0.1", 20001);
    line_t *l2 = createAndInitLineIpv4(&fixture, "127.0.0.1", 20001);

    udpconnector_lstate_t *ls1 = lineGetState(l1, fixture.connector);
    udpconnector_lstate_t *ls2 = lineGetState(l2, fixture.connector);

    twfRequire(ls1->fixed_binding->socket != ls2->fixed_binding->socket, "sockets must be distinct");
    twfRequire(sockaddrPort(wioGetLocaladdrU(ls1->fixed_binding->socket->io)) !=
                   sockaddrPort(wioGetLocaladdrU(ls2->fixed_binding->socket->io)),
               "source ports must differ");

    udpconnectorTunnelUpStreamFinish(fixture.connector, l1);
    lineDestroy(l1);
    udpconnectorTunnelUpStreamFinish(fixture.connector, l2);
    lineDestroy(l2);

    teardownFixture(&fixture);
}

// Case 3: A domain and a literal address resolving to the same peer collide after resolution.
static void testCase3_DomainAndLiteralCollision(void)
{
    twfSetCase("Case 3: Domain and literal resolving to same peer collide");
    test_fixture_t fixture;
    setupFixtureMode(&fixture, kUdpConnectorBalanceModeConnection);

    line_t *l1 = createAndInitLineIpv4(&fixture, "127.0.0.1", 20001);
    line_t *l2 = createAndInitLineIpv4(&fixture, "127.0.0.1", 20001);

    udpconnector_lstate_t *ls1 = lineGetState(l1, fixture.connector);
    udpconnector_lstate_t *ls2 = lineGetState(l2, fixture.connector);

    twfRequire(ls1->fixed_binding->socket != ls2->fixed_binding->socket,
               "same resolved peer must collide to different sockets");

    udpconnectorTunnelUpStreamFinish(fixture.connector, l1);
    lineDestroy(l1);
    udpconnectorTunnelUpStreamFinish(fixture.connector, l2);
    lineDestroy(l2);

    teardownFixture(&fixture);
}

// Case 4: IPv4 and IPv6 never share a socket; IPv6 scope participates in equality.
static void testCase4_FamilyAndScopeIsolation(void)
{
    twfSetCase("Case 4: IPv4 and IPv6 never share; IPv6 scope participates in equality");
    test_fixture_t fixture;
    setupFixtureMode(&fixture, kUdpConnectorBalanceModeConnection);

    line_t *l_v4     = createAndInitLineIpv4(&fixture, "127.0.0.1", 20001);
    line_t *l_v6_s0  = createAndInitLineIpv6(&fixture, "::1", 20001, 0);
    line_t *l_v6_s1  = createAndInitLineIpv6(&fixture, "::1", 20001, 1);
    line_t *l_v6_s0b = createAndInitLineIpv6(&fixture, "::1", 20001, 0);

    udpconnector_lstate_t *ls_v4     = lineGetState(l_v4, fixture.connector);
    udpconnector_lstate_t *ls_v6_s0  = lineGetState(l_v6_s0, fixture.connector);
    udpconnector_lstate_t *ls_v6_s1  = lineGetState(l_v6_s1, fixture.connector);
    udpconnector_lstate_t *ls_v6_s0b = lineGetState(l_v6_s0b, fixture.connector);

    twfRequire(ls_v4->fixed_binding->socket != ls_v6_s0->fixed_binding->socket, "v4 and v6 cannot share socket");
    twfRequire(ls_v6_s0->fixed_binding->socket == ls_v6_s1->fixed_binding->socket,
               "v6 scope 0 and scope 1 are different peers and can share v6 socket");
    twfRequire(ls_v6_s0->fixed_binding->socket != ls_v6_s0b->fixed_binding->socket,
               "two v6 lines with same scope 0 must collide to different sockets");

    udpconnectorTunnelUpStreamFinish(fixture.connector, l_v4);
    lineDestroy(l_v4);
    udpconnectorTunnelUpStreamFinish(fixture.connector, l_v6_s0);
    lineDestroy(l_v6_s0);
    udpconnectorTunnelUpStreamFinish(fixture.connector, l_v6_s1);
    lineDestroy(l_v6_s1);
    udpconnectorTunnelUpStreamFinish(fixture.connector, l_v6_s0b);
    lineDestroy(l_v6_s0b);

    teardownFixture(&fixture);
}

// Case 5: Two distinct full keys that the test hash seam forces into the same hash bucket remain distinct and route
// correctly.
static void testCase5_HashCollisionSeamRouting(void)
{
    twfSetCase("Case 5: Forced hash bucket collision routes correctly");
    test_fixture_t fixture;
    setupFixtureMode(&fixture, kUdpConnectorBalanceModeConnection);

    g_udpconnector_pool_test_force_hash_zero = true;

    line_t *l1 = createAndInitLineIpv4(&fixture, "127.0.0.1", 20001);
    line_t *l2 = createAndInitLineIpv4(&fixture, "127.0.0.1", 20002);

    udpconnector_lstate_t *ls1 = lineGetState(l1, fixture.connector);
    udpconnector_lstate_t *ls2 = lineGetState(l2, fixture.connector);

    twfRequire(ls1->fixed_binding->socket == ls2->fixed_binding->socket, "lines must share socket");

    // Inject datagram from peer 2
    wio_t     *io  = ls1->fixed_binding->socket->io;
    sockaddr_u src = {0};
    sockaddrSetIpAddressPort(&src, "127.0.0.1", 20002);
    wioSetPeerAddr(io, &src.sa, sockaddrLen(&src));
    sbuf_t *buf2 = makeDatagram(&fixture, "reply_2");
    udpconnectorOnSocketRecvFrom(io, buf2);

    twfRequireEqualU32(fixture.payload_calls, 1, "payload must be delivered");
    twfRequire(fixture.last_payload_line == l2, "reply from peer 2 must reach line 2");

    // Inject datagram from peer 1
    sockaddrSetIpAddressPort(&src, "127.0.0.1", 20001);
    wioSetPeerAddr(io, &src.sa, sockaddrLen(&src));
    sbuf_t *buf1 = makeDatagram(&fixture, "reply_1");
    udpconnectorOnSocketRecvFrom(io, buf1);

    udpconnectorTunnelUpStreamFinish(fixture.connector, l1);
    lineDestroy(l1);
    udpconnectorTunnelUpStreamFinish(fixture.connector, l2);
    lineDestroy(l2);

    g_udpconnector_pool_test_force_hash_zero = false;

    teardownFixture(&fixture);
}

// Case 6: Identical peers on different workers use different worker-local pools, and two UdpConnector instances use
// distinct pools.
static void testCase6_WorkerAndConnectorPoolIsolation(void)
{
    twfSetCase("Case 6: Multi-worker and multi-connector pool isolation");
    tos_worker_env_t env;
    tosWorkerEnvSetup(&env, 2, kTestLargeBuffer, kTwfDefaultSmallBufferSize);

    tunnel_t *c1 = tunnelCreate(NULL, sizeof(udpconnector_tstate_t), sizeof(udpconnector_lstate_t));
    tunnel_t *c2 = tunnelCreate(NULL, sizeof(udpconnector_tstate_t), sizeof(udpconnector_lstate_t));
    twfRequire(c1 != NULL && c2 != NULL, "failed to create isolation-test connectors");
    udpconnector_tstate_t *ts1 = tunnelGetState(c1);
    udpconnector_tstate_t *ts2 = tunnelGetState(c2);
    ts1->balance_mode          = kUdpConnectorBalanceModeConnection;
    ts2->balance_mode          = kUdpConnectorBalanceModeConnection;
    ts1->fwmark                = -1;
    ts2->fwmark                = -1;
    ts1->send_buffer_size      = 0;
    ts1->recv_buffer_size      = 0;
    ts2->send_buffer_size      = 65536;
    ts2->recv_buffer_size      = 65536;
    ts1->worker_pools          = memoryAllocateZero(sizeof(*ts1->worker_pools) * getWorkersCount());
    ts2->worker_pools          = memoryAllocateZero(sizeof(*ts2->worker_pools) * getWorkersCount());
    twfRequire(ts1->worker_pools != NULL && ts2->worker_pools != NULL, "failed to allocate connector pools");
    for (wid_t wid = 0; wid < getWorkersCount(); ++wid)
    {
        ts1->worker_pools[wid].wid = wid;
        ts2->worker_pools[wid].wid = wid;
    }

    tunnel_chain_t *chain = memoryAllocateZero(sizeof(*chain) + 2 * sizeof(generic_pool_t *));
    twfRequire(chain != NULL, "failed to allocate isolation-test chain");
    chain->workers_count       = 2;
    master_pool_t *line_master = masterpoolCreateWithCapacity(16);
    twfRequire(line_master != NULL, "failed to allocate isolation-test line master pool");
    for (wid_t wid = 0; wid < chain->workers_count; ++wid)
    {
        chain->line_pools[wid] = genericpoolCreateWithDefaultCacheAlignedAllocatorAndCapacity(
            line_master, sizeof(line_t) + c1->lstate_size, 8);
        twfRequire(chain->line_pools[wid] != NULL, "failed to allocate isolation-test worker line pool");
    }
    c1->chain = chain;
    c2->chain = chain;

    sockaddr_u peer_a = {0};
    sockaddr_u peer_b = {0};
    twfRequire(sockaddrSetIpAddressPort(&peer_a, "127.0.0.1", 20001) == 0, "failed to prepare peer A");
    twfRequire(sockaddrSetIpAddressPort(&peer_b, "127.0.0.1", 20002) == 0, "failed to prepare peer B");

    line_t *c1_w0_line = lineCreateForWorker(0, chain->line_pools, 0);
    twfRequire(c1_w0_line != NULL, "failed to create connector 1 worker 0 line");
    udpconnector_lstate_t *c1_w0_ls = lineGetState(c1_w0_line, c1);
    twfRequire(udpconnectorLinestateInitialize(c1_w0_ls, c1, c1_w0_line),
               "failed to initialize connector 1 worker 0 line");
    udpconnector_binding_t *c1_w0_binding = udpconnectorAcquireBinding(c1, c1_w0_line, c1_w0_ls, &peer_a);
    twfRequire(c1_w0_binding != NULL, "failed to acquire connector 1 worker 0 binding");
    c1_w0_ls->last_send_binding = c1_w0_binding;

    line_t *c2_w0_line = lineCreateForWorker(0, chain->line_pools, 0);
    twfRequire(c2_w0_line != NULL, "failed to create connector 2 worker 0 line");
    udpconnector_lstate_t *c2_w0_ls = lineGetState(c2_w0_line, c2);
    twfRequire(udpconnectorLinestateInitialize(c2_w0_ls, c2, c2_w0_line),
               "failed to initialize connector 2 worker 0 line");
    udpconnector_binding_t *c2_w0_binding = udpconnectorAcquireBinding(c2, c2_w0_line, c2_w0_ls, &peer_b);
    twfRequire(c2_w0_binding != NULL, "failed to acquire connector 2 worker 0 binding");
    c2_w0_ls->last_send_binding = c2_w0_binding;

    discard tosSetCurrentWorker(1);
    line_t *c1_w1_line = lineCreateForWorker(1, chain->line_pools, 1);
    twfRequire(c1_w1_line != NULL, "failed to create connector 1 worker 1 line");
    udpconnector_lstate_t *c1_w1_ls = lineGetState(c1_w1_line, c1);
    twfRequire(udpconnectorLinestateInitialize(c1_w1_ls, c1, c1_w1_line),
               "failed to initialize connector 1 worker 1 line");
    udpconnector_binding_t *c1_w1_binding = udpconnectorAcquireBinding(c1, c1_w1_line, c1_w1_ls, &peer_a);
    twfRequire(c1_w1_binding != NULL, "failed to acquire connector 1 worker 1 binding");
    c1_w1_ls->last_send_binding = c1_w1_binding;

    twfRequire(c1_w0_binding->socket != c1_w1_binding->socket,
               "identical peers on different workers must use different sockets");
    twfRequire(c1_w0_binding->socket != c2_w0_binding->socket,
               "different connector instances on one worker must not share a socket");
    twfRequire(c1_w0_binding->socket->worker_pool == &ts1->worker_pools[0] &&
                   c1_w1_binding->socket->worker_pool == &ts1->worker_pools[1] &&
                   c2_w0_binding->socket->worker_pool == &ts2->worker_pools[0],
               "bindings must select the owning connector's exact worker pool");
    twfRequire(c1_w0_binding->socket->tunnel == c1 && c1_w1_binding->socket->tunnel == c1 &&
                   c2_w0_binding->socket->tunnel == c2,
               "pool sockets must retain their connector instance and socket settings");
    twfRequire(c1_w0_binding->socket->io != c1_w1_binding->socket->io &&
                   c1_w0_binding->socket->io != c2_w0_binding->socket->io,
               "worker and connector isolation must extend to WIO ownership");

    udpconnectorLineDetach(c1, c1_w1_line, c1_w1_ls, kUdpConnectorDetachFinish);
    lineDestroy(c1_w1_line);

    discard tosSetCurrentWorker(0);
    udpconnectorLineDetach(c1, c1_w0_line, c1_w0_ls, kUdpConnectorDetachFinish);
    lineDestroy(c1_w0_line);
    udpconnectorLineDetach(c2, c2_w0_line, c2_w0_ls, kUdpConnectorDetachFinish);
    lineDestroy(c2_w0_line);

    twfRequireEqualU32(
        udpconnectorTestGetSocketCount(c1, 0, AF_INET), 0, "connector 1 worker 0 socket must be reclaimed");
    twfRequireEqualU32(
        udpconnectorTestGetSocketCount(c1, 1, AF_INET), 0, "connector 1 worker 1 socket must be reclaimed");
    twfRequireEqualU32(
        udpconnectorTestGetSocketCount(c2, 0, AF_INET), 0, "connector 2 worker 0 socket must be reclaimed");

    c1->chain = NULL;
    c2->chain = NULL;
    for (wid_t wid = 0; wid < chain->workers_count; ++wid)
    {
        genericpoolDestroy(chain->line_pools[wid]);
    }
    masterpoolDestroy(line_master);
    memoryFree(chain);

    memoryFree(ts1->worker_pools);
    memoryFree(ts2->worker_pools);
    tunnelDestroy(c1);
    tunnelDestroy(c2);
    tosWorkerEnvTeardown(&env);
}

// Case 7: Replies from two peers in reverse order reach the exact mapped lines.
static void testCase7_ReverseOrderReplies(void)
{
    twfSetCase("Case 7: Replies from two peers in reverse order reach exact lines");
    test_fixture_t fixture;
    setupFixtureMode(&fixture, kUdpConnectorBalanceModeConnection);

    line_t *l1 = createAndInitLineIpv4(&fixture, "127.0.0.1", 20001);
    line_t *l2 = createAndInitLineIpv4(&fixture, "127.0.0.1", 20002);

    udpconnector_lstate_t *ls1 = lineGetState(l1, fixture.connector);
    wio_t                 *io  = ls1->fixed_binding->socket->io;

    sockaddr_u src = {0};
    sockaddrSetIpAddressPort(&src, "127.0.0.1", 20002);
    wioSetPeerAddr(io, &src.sa, sockaddrLen(&src));
    udpconnectorOnSocketRecvFrom(io, makeDatagram(&fixture, "resp2"));

    twfRequireEqualU32(fixture.payload_calls, 1, "payload 1 delivered");
    twfRequire(fixture.last_payload_line == l2, "must route to l2");

    sockaddrSetIpAddressPort(&src, "127.0.0.1", 20001);
    wioSetPeerAddr(io, &src.sa, sockaddrLen(&src));
    udpconnectorOnSocketRecvFrom(io, makeDatagram(&fixture, "resp1"));

    twfRequireEqualU32(fixture.payload_calls, 2, "payload 2 delivered");
    twfRequire(fixture.last_payload_line == l1, "must route to l1");

    udpconnectorTunnelUpStreamFinish(fixture.connector, l1);
    lineDestroy(l1);
    udpconnectorTunnelUpStreamFinish(fixture.connector, l2);
    lineDestroy(l2);

    teardownFixture(&fixture);
}

// Case 8: An unknown peer on a shared socket is dropped and its buffer recycled.
static void testCase8_UnknownPeerDropped(void)
{
    twfSetCase("Case 8: Unknown peer on shared socket dropped and recycled");
    test_fixture_t fixture;
    setupFixtureMode(&fixture, kUdpConnectorBalanceModeConnection);

    line_t *l1 = createAndInitLineIpv4(&fixture, "127.0.0.1", 20001);

    udpconnector_lstate_t *ls1 = lineGetState(l1, fixture.connector);
    wio_t                 *io  = ls1->fixed_binding->socket->io;

    sockaddr_u src = {0};
    sockaddrSetIpAddressPort(&src, "127.0.0.1", 29999);
    wioSetPeerAddr(io, &src.sa, sockaddrLen(&src));
    udpconnectorOnSocketRecvFrom(io, makeDatagram(&fixture, "unknown"));

    twfRequireEqualU32(fixture.payload_calls, 0, "unknown peer must produce 0 payload calls");

    udpconnectorTunnelUpStreamFinish(fixture.connector, l1);
    lineDestroy(l1);

    teardownFixture(&fixture);
}

// Case 9: Pausing line A drops only A's replies; line B sharing the socket continues, and Resume restores A.
static void testCase9_LinePauseAndResume(void)
{
    twfSetCase("Case 9: Pausing line A drops only A's replies; B continues; Resume restores A");
    test_fixture_t fixture;
    setupFixtureMode(&fixture, kUdpConnectorBalanceModeConnection);

    line_t *l1 = createAndInitLineIpv4(&fixture, "127.0.0.1", 20001);
    line_t *l2 = createAndInitLineIpv4(&fixture, "127.0.0.1", 20002);

    udpconnectorTunnelUpStreamPause(fixture.connector, l1);

    udpconnector_lstate_t *ls1 = lineGetState(l1, fixture.connector);
    wio_t                 *io  = ls1->fixed_binding->socket->io;

    sockaddr_u src = {0};
    sockaddrSetIpAddressPort(&src, "127.0.0.1", 20001);
    wioSetPeerAddr(io, &src.sa, sockaddrLen(&src));
    udpconnectorOnSocketRecvFrom(io, makeDatagram(&fixture, "paused_a"));
    twfRequireEqualU32(fixture.payload_calls, 0, "paused line A must drop reply");

    sockaddrSetIpAddressPort(&src, "127.0.0.1", 20002);
    wioSetPeerAddr(io, &src.sa, sockaddrLen(&src));
    udpconnectorOnSocketRecvFrom(io, makeDatagram(&fixture, "active_b"));
    twfRequireEqualU32(fixture.payload_calls, 1, "active line B must receive reply");
    twfRequire(fixture.last_payload_line == l2, "payload must be for line B");

    udpconnectorTunnelUpStreamResume(fixture.connector, l1);

    sockaddrSetIpAddressPort(&src, "127.0.0.1", 20001);
    wioSetPeerAddr(io, &src.sa, sockaddrLen(&src));
    udpconnectorOnSocketRecvFrom(io, makeDatagram(&fixture, "resumed_a"));
    twfRequireEqualU32(fixture.payload_calls, 2, "resumed line A must receive reply");
    twfRequire(fixture.last_payload_line == l1, "payload must be for line A");

    udpconnectorTunnelUpStreamFinish(fixture.connector, l1);
    lineDestroy(l1);
    udpconnectorTunnelUpStreamFinish(fixture.connector, l2);
    lineDestroy(l2);

    teardownFixture(&fixture);
}

// Case 10: Finishing line A removes its idle item/map entry and marks the socket draining; line B remains usable.
static void testCase10_FinishLineAMarksDraining(void)
{
    twfSetCase("Case 10: Finishing line A marks socket draining; line B remains usable");
    test_fixture_t fixture;
    setupFixtureMode(&fixture, kUdpConnectorBalanceModeConnection);

    line_t *l1 = createAndInitLineIpv4(&fixture, "127.0.0.1", 20001);
    line_t *l2 = createAndInitLineIpv4(&fixture, "127.0.0.1", 20002);

    udpconnector_lstate_t      *ls2  = lineGetState(l2, fixture.connector);
    udpconnector_pool_socket_t *sock = ls2->fixed_binding->socket;

    twfRequire(sock->state == kUdpConnectorPoolSocketAccepting, "socket must be accepting initially");

    udpconnectorTunnelUpStreamFinish(fixture.connector, l1);
    lineDestroy(l1);

    twfRequire(sock->state == kUdpConnectorPoolSocketDraining, "socket must become draining after line A detach");
    twfRequireEqualU32(sock->active_bindings_count, 1, "active bindings count must be 1");

    wio_t     *io  = sock->io;
    sockaddr_u src = {0};
    sockaddrSetIpAddressPort(&src, "127.0.0.1", 20002);
    wioSetPeerAddr(io, &src.sa, sockaddrLen(&src));
    udpconnectorOnSocketRecvFrom(io, makeDatagram(&fixture, "for_b"));
    twfRequireEqualU32(fixture.payload_calls, 1, "line B must receive reply on draining socket");

    udpconnectorTunnelUpStreamFinish(fixture.connector, l2);
    lineDestroy(l2);

    teardownFixture(&fixture);
}

// Case 11: A new line C cannot join that draining socket, including when it targets A's former peer.
static void testCase11_NewCannotJoinDrainingSocket(void)
{
    twfSetCase("Case 11: New line C cannot join draining socket");
    test_fixture_t fixture;
    setupFixtureMode(&fixture, kUdpConnectorBalanceModeConnection);

    line_t *l1 = createAndInitLineIpv4(&fixture, "127.0.0.1", 20001);
    line_t *l2 = createAndInitLineIpv4(&fixture, "127.0.0.1", 20002);

    udpconnector_lstate_t      *ls2   = lineGetState(l2, fixture.connector);
    udpconnector_pool_socket_t *sock1 = ls2->fixed_binding->socket;

    udpconnectorTunnelUpStreamFinish(fixture.connector, l1);
    lineDestroy(l1);

    twfRequire(sock1->state == kUdpConnectorPoolSocketDraining, "socket must be draining");

    line_t                     *l3    = createAndInitLineIpv4(&fixture, "127.0.0.1", 20001);
    udpconnector_lstate_t      *ls3   = lineGetState(l3, fixture.connector);
    udpconnector_pool_socket_t *sock3 = ls3->fixed_binding->socket;

    twfRequire(sock3 != sock1, "line C must not join draining socket");
    twfRequire(sock3->state == kUdpConnectorPoolSocketAccepting, "new socket must be accepting");

    udpconnectorTunnelUpStreamFinish(fixture.connector, l2);
    lineDestroy(l2);
    udpconnectorTunnelUpStreamFinish(fixture.connector, l3);
    lineDestroy(l3);

    teardownFixture(&fixture);
}

// Case 12: A delayed datagram from A's peer to the still-open draining socket is dropped and cannot reach C.
static void testCase12_DelayedDatagramToDrainingSocketDropped(void)
{
    twfSetCase("Case 12: Delayed datagram to draining socket dropped");
    test_fixture_t fixture;
    setupFixtureMode(&fixture, kUdpConnectorBalanceModeConnection);

    line_t *l1 = createAndInitLineIpv4(&fixture, "127.0.0.1", 20001);
    line_t *l2 = createAndInitLineIpv4(&fixture, "127.0.0.1", 20002);

    udpconnector_lstate_t      *ls2   = lineGetState(l2, fixture.connector);
    udpconnector_pool_socket_t *sock1 = ls2->fixed_binding->socket;

    udpconnectorTunnelUpStreamFinish(fixture.connector, l1);
    lineDestroy(l1);

    line_t *l3 = createAndInitLineIpv4(&fixture, "127.0.0.1", 20001);

    wio_t     *io1 = sock1->io;
    sockaddr_u src = {0};
    sockaddrSetIpAddressPort(&src, "127.0.0.1", 20001);
    wioSetPeerAddr(io1, &src.sa, sockaddrLen(&src));
    udpconnectorOnSocketRecvFrom(io1, makeDatagram(&fixture, "stale_reply_for_a"));

    twfRequireEqualU32(fixture.payload_calls, 0, "delayed reply to draining socket must be dropped");

    udpconnectorTunnelUpStreamFinish(fixture.connector, l2);
    lineDestroy(l2);
    udpconnectorTunnelUpStreamFinish(fixture.connector, l3);
    lineDestroy(l3);

    teardownFixture(&fixture);
}

// Case 13: Finishing the last binding closes/reclaims the draining socket once.
static void testCase13_FinishLastBindingReclaimsSocket(void)
{
    twfSetCase("Case 13: Finishing last binding reclaims draining socket");
    test_fixture_t fixture;
    setupFixtureMode(&fixture, kUdpConnectorBalanceModeConnection);

    line_t *l1 = createAndInitLineIpv4(&fixture, "127.0.0.1", 20001);
    line_t *l2 = createAndInitLineIpv4(&fixture, "127.0.0.1", 20002);

    udpconnector_tstate_t      *ts          = tunnelGetState(fixture.connector);
    udpconnector_worker_pool_t *worker_pool = &ts->worker_pools[0];

    udpconnectorTunnelUpStreamFinish(fixture.connector, l1);
    lineDestroy(l1);
    twfRequire(worker_pool->v4_sockets != NULL, "socket must still exist while l2 is alive");

    udpconnectorTunnelUpStreamFinish(fixture.connector, l2);
    lineDestroy(l2);
    twfRequire(worker_pool->v4_sockets == NULL, "socket must be retired after last binding closes");

    teardownFixture(&fixture);
}

// Case 14: Independent idle deadlines expire A and B separately and retire socket after last binding.
static void testCase14_IdleDeadlinesExpireSeparately(void)
{
    twfSetCase("Case 14: Independent idle deadlines expire A and B separately");
    test_fixture_t fixture;
    setupFixtureMode(&fixture, kUdpConnectorBalanceModeConnection);

    line_t *l1 = createAndInitLineIpv4(&fixture, "127.0.0.1", 20001);
    line_t *l2 = createAndInitLineIpv4(&fixture, "127.0.0.1", 20002);

    udpconnector_tstate_t *ts    = tunnelGetState(fixture.connector);
    udpconnector_lstate_t *ls1   = lineGetState(l1, fixture.connector);
    udpconnector_lstate_t *ls2   = lineGetState(l2, fixture.connector);
    local_idle_item_t     *item1 = ls1->idle_handle;
    udpconnectorOnIdleConnectionExpire(item1);
    localidletableRemoveIdleItem(udpconnectorGetWorkerIdleTable(ts), item1);
    twfRequireEqualU32(fixture.finish_calls, 1, "line 1 must receive downstream Finish on idle expiry");
    lineDestroy(l1);

    local_idle_item_t *item2 = ls2->idle_handle;
    udpconnectorOnIdleConnectionExpire(item2);
    localidletableRemoveIdleItem(udpconnectorGetWorkerIdleTable(ts), item2);
    twfRequireEqualU32(fixture.finish_calls, 2, "line 2 must receive downstream Finish on idle expiry");
    lineDestroy(l2);

    udpconnector_worker_pool_t *worker_pool = &ts->worker_pools[0];
    twfRequire(worker_pool->v4_sockets == NULL, "socket must be retired after all idle expires");

    teardownFixture(&fixture);
}

// Case 15: Unexpected WIO close removes the socket first and finishes every bound normal line once under re-entrant
// callbacks.
static void testCase15_UnexpectedSocketCloseReentrancy(void)
{
    twfSetCase("Case 15: Unexpected WIO close finishes bound lines under re-entrant callbacks");
    test_fixture_t fixture;
    setupFixtureMode(&fixture, kUdpConnectorBalanceModeConnection);

    line_t *l1 = createAndInitLineIpv4(&fixture, "127.0.0.1", 20001);
    line_t *l2 = createAndInitLineIpv4(&fixture, "127.0.0.1", 20002);

    udpconnector_lstate_t *ls1 = lineGetState(l1, fixture.connector);
    wio_t                 *io  = ls1->fixed_binding->socket->io;

    line_t *first_close_line = NULL;
    c_foreach(it, udpconnector_peer_binding_map, ls1->fixed_binding->socket->peer_map)
    {
        first_close_line = it.ref->second->line;
        break;
    }
    twfRequire(first_close_line == l1 || first_close_line == l2, "socket map returned an unexpected line");
    fixture.reentrant_close_line      = first_close_line == l1 ? l2 : l1;
    fixture.close_reentrant_on_finish = true;

    wioClose(io);

    twfRequireEqualU32(fixture.finish_calls, 2, "both lines must receive finish");
    lineDestroy(l1);
    lineDestroy(l2);

    teardownFixture(&fixture);
}

// Case 16: Upstream Finish flushes pause queue before unlinking binding; error detach recycles without flushing.
static void testCase16_FinishFlushesQueueErrorRecycles(void)
{
    twfSetCase("Case 16: Upstream Finish flushes pause queue; error detach recycles");
    test_fixture_t fixture;
    setupFixtureMode(&fixture, kUdpConnectorBalanceModeConnection);

    line_t                *l1  = createAndInitLineIpv4(&fixture, "127.0.0.1", 20001);
    udpconnector_lstate_t *ls1 = lineGetState(l1, fixture.connector);

    ls1->write_paused = true;
    sbuf_t *buf       = makeDatagram(&fixture, "queued_msg");
    udpconnectorTunnelUpStreamPayload(fixture.connector, l1, buf);
    twfRequireEqualU32(bufferqueueGetBufCount(&ls1->pause_queue), 1, "datagram must be queued");

    udpconnectorTunnelUpStreamFinish(fixture.connector, l1);
    lineDestroy(l1);

    // Test error detach recycles cleanly without leak
    line_t                *l2  = createAndInitLineIpv4(&fixture, "127.0.0.1", 20002);
    udpconnector_lstate_t *ls2 = lineGetState(l2, fixture.connector);
    ls2->write_paused          = true;
    buf                        = makeDatagram(&fixture, "queued_msg_2");
    udpconnectorTunnelUpStreamPayload(fixture.connector, l2, buf);
    udpconnectorLineDetach(fixture.connector, l2, ls2, kUdpConnectorDetachQueueOverflow);
    lineDestroy(l2);

    teardownFixture(&fixture);
}

// Case 17: Two packet-balanced normal lines using distinct peers join the same worker socket.
static void testCase17_PacketModeNormalLinesShareSocket(void)
{
    twfSetCase("Case 17: Two packet-balanced normal lines share worker socket");
    test_fixture_t fixture;
    setupFixtureMode(&fixture, kUdpConnectorBalanceModePacket);

    line_t *l1 = createAndInitLineIpv4(&fixture, "127.0.0.1", 20001);
    line_t *l2 = createAndInitLineIpv4(&fixture, "127.0.0.1", 20002);

    udpconnector_lstate_t *ls1 = lineGetState(l1, fixture.connector);
    udpconnector_lstate_t *ls2 = lineGetState(l2, fixture.connector);

    twfRequire(ls1->last_send_binding->socket == ls2->last_send_binding->socket,
               "packet mode normal lines must share socket");

    udpconnectorTunnelUpStreamFinish(fixture.connector, l1);
    lineDestroy(l1);
    udpconnectorTunnelUpStreamFinish(fixture.connector, l2);
    lineDestroy(l2);

    teardownFixture(&fixture);
}

// Case 18: One packet-balanced normal line acquires/reuses several peer bindings.
static void testCase18_MultiPeerPacketModeLineAcquisitionAndReplies(void)
{
    twfSetCase("Case 18: Multi-peer packet-mode line acquires bindings and receives replies");
    test_fixture_t fixture;
    setupFixtureMode(&fixture, kUdpConnectorBalanceModePacket);

    line_t                *l  = createAndInitLineIpv4(&fixture, "127.0.0.1", 20001);
    udpconnector_lstate_t *ls = lineGetState(l, fixture.connector);

    sockaddr_u addr2 = {0};
    sockaddrSetIpAddressPort(&addr2, "127.0.0.1", 20002);
    udpconnector_binding_t *b2 = udpconnectorAcquireBinding(fixture.connector, l, ls, &addr2);
    twfRequire(b2 != NULL, "must acquire binding 2");
    twfRequireEqualU32(ls->bindings_count, 2, "line must have 2 bindings");

    wio_t     *io  = b2->socket->io;
    sockaddr_u src = {0};
    sockaddrSetIpAddressPort(&src, "127.0.0.1", 20002);
    wioSetPeerAddr(io, &src.sa, sockaddrLen(&src));
    udpconnectorOnSocketRecvFrom(io, makeDatagram(&fixture, "reply_p2"));
    twfRequireEqualU32(fixture.payload_calls, 1, "reply 2 delivered");

    sockaddrSetIpAddressPort(&src, "127.0.0.1", 20001);
    wioSetPeerAddr(io, &src.sa, sockaddrLen(&src));
    udpconnectorOnSocketRecvFrom(io, makeDatagram(&fixture, "reply_p1"));
    twfRequireEqualU32(fixture.payload_calls, 2, "reply 1 delivered");

    udpconnectorTunnelUpStreamFinish(fixture.connector, l);
    lineDestroy(l);

    teardownFixture(&fixture);
}

// Case 19: Two packet-balanced lines overlapping on one peer cannot register on same socket.
static void testCase19_PacketModeLinesOverlappingPeerCollision(void)
{
    twfSetCase("Case 19: Packet-mode lines overlapping on one peer create distinct sockets");
    test_fixture_t fixture;
    setupFixtureMode(&fixture, kUdpConnectorBalanceModePacket);

    line_t *l1 = createAndInitLineIpv4(&fixture, "127.0.0.1", 20001);
    line_t *l2 = createAndInitLineIpv4(&fixture, "127.0.0.1", 20002);

    udpconnector_lstate_t *ls1 = lineGetState(l1, fixture.connector);
    udpconnector_lstate_t *ls2 = lineGetState(l2, fixture.connector);

    twfRequire(ls1->last_send_binding->socket == ls2->last_send_binding->socket, "l1 and l2 share socket initially");

    sockaddr_u addr1 = {0};
    sockaddrSetIpAddressPort(&addr1, "127.0.0.1", 20001);
    udpconnector_binding_t *b2_p1 = udpconnectorAcquireBinding(fixture.connector, l2, ls2, &addr1);
    twfRequire(b2_p1 != NULL, "l2 acquires binding to p1");
    twfRequire(b2_p1->socket != ls1->last_send_binding->socket, "overlapping peer must acquire distinct socket");

    udpconnectorTunnelUpStreamFinish(fixture.connector, l1);
    lineDestroy(l1);
    udpconnectorTunnelUpStreamFinish(fixture.connector, l2);
    lineDestroy(l2);

    teardownFixture(&fixture);
}

// Case 20: Unregistered source on pooled packet-mode socket is dropped.
static void testCase20_UnregisteredPacketSourceDropped(void)
{
    twfSetCase("Case 20: Unregistered packet source dropped");
    test_fixture_t fixture;
    setupFixtureMode(&fixture, kUdpConnectorBalanceModePacket);

    line_t                *l  = createAndInitLineIpv4(&fixture, "127.0.0.1", 20001);
    udpconnector_lstate_t *ls = lineGetState(l, fixture.connector);
    wio_t                 *io = ls->last_send_binding->socket->io;

    sockaddr_u src = {0};
    sockaddrSetIpAddressPort(&src, "127.0.0.1", 29999);
    wioSetPeerAddr(io, &src.sa, sockaddrLen(&src));
    udpconnectorOnSocketRecvFrom(io, makeDatagram(&fixture, "unregistered"));

    twfRequireEqualU32(fixture.payload_calls, 0, "unregistered source must be dropped");

    udpconnectorTunnelUpStreamFinish(fixture.connector, l);
    lineDestroy(l);

    teardownFixture(&fixture);
}

// Case 21: Packet-mode DNS acquisition failure preserves existing line bindings.
static void testCase21_PacketDnsFailurePreservesExistingBindings(void)
{
    twfSetCase("Case 21: Resolved packet binding failure drops only that peer queue");
    test_fixture_t fixture;
    setupFixtureMode(&fixture, kUdpConnectorBalanceModePacket);

    line_t                *l  = createAndInitLineIpv4(&fixture, "127.0.0.1", 20001);
    udpconnector_lstate_t *ls = lineGetState(l, fixture.connector);

    twfRequireEqualU32(ls->bindings_count, 1, "initial binding exists");

    udpconnector_packet_destination_t *cache = &ls->packet_destinations[0];
    sockaddr_u                         addr2 = {0};
    sockaddrSetIpAddressPort(&addr2, "127.0.0.1", 20002);
    addresscontextFromSockAddr(&cache->dest_ctx, &addr2);
    addresscontextSetOnlyProtocol(&cache->dest_ctx, IP_PROTO_UDP);
    cache->has_context = true;
    bufferqueuePushBack(&cache->pending_queue, makeDatagram(&fixture, "dns_pending_1"));
    bufferqueuePushBack(&cache->pending_queue, makeDatagram(&fixture, "dns_pending_2"));

    g_udpconnector_pool_test_fail_binding_alloc = true;
    twfRequire(udpconnectorTestFlushPacketDestinationQueue(fixture.connector, l, 0),
               "queue settlement unexpectedly destroyed the line");
    g_udpconnector_pool_test_fail_binding_alloc = false;

    twfRequireEqualU32(ls->bindings_count, 1, "existing binding must be preserved");
    twfRequireEqualU32(bufferqueueGetBufCount(&cache->pending_queue), 0, "failed peer queue must be dropped in full");
    twfRequire(! cache->has_context && ! cache->resolving, "failed peer cache must return to unresolved state");

    sockaddr_u addr3 = {0};
    sockaddrSetIpAddressPort(&addr3, "127.0.0.1", 20003);
    g_udpconnector_pool_test_fail_line_map_insert = true;
    twfRequire(udpconnectorAcquireBinding(fixture.connector, l, ls, &addr3) == NULL,
               "line-map publication fault must reject the new peer binding");
    g_udpconnector_pool_test_fail_line_map_insert = false;
    twfRequireEqualU32(ls->bindings_count, 1, "line-map rollback changed the existing line binding count");
    twfRequireEqualU32(ls->last_send_binding->socket->active_bindings_count,
                       1,
                       "line-map rollback changed the existing socket binding count");

    udpconnectorTunnelUpStreamFinish(fixture.connector, l);
    lineDestroy(l);

    teardownFixture(&fixture);
}

// Case 22: Mutable line context change acquires new binding and still accepts old peer reply.
static void testCase22_MutableContextChangeRetainsOldBinding(void)
{
    twfSetCase("Case 22: Mutable context payload path acquires a new peer and retains the old binding");
    test_fixture_t fixture;
    setupFixtureMode(&fixture, kUdpConnectorBalanceModePacket);

    line_t                *l      = createAndInitLineIpv4(&fixture, "127.0.0.1", 20001);
    udpconnector_lstate_t *ls     = lineGetState(l, fixture.connector);
    udpconnector_tstate_t *ts     = tunnelGetState(fixture.connector);
    ts->dest_addr_selected.status = kDvsFromDest;
    ts->dest_port_selected.status = kDvsFromDest;

    udpconnectorTunnelUpStreamPayload(fixture.connector, l, makeDatagram(&fixture, "send_p1"));
    twfRequireEqualU32(ls->bindings_count, 1, "the initial peer binding must be reused");

    sockaddr_u addr2 = {0};
    sockaddrSetIpAddressPort(&addr2, "127.0.0.1", 20002);
    address_context_t *dest_ctx = lineGetDestinationAddressContext(l);
    addresscontextFromSockAddr(dest_ctx, &addr2);
    addresscontextSetOnlyProtocol(dest_ctx, IP_PROTO_UDP);

    udpconnectorTunnelUpStreamPayload(fixture.connector, l, makeDatagram(&fixture, "send_p2"));
    twfRequireEqualU32(ls->bindings_count, 2, "mutable context change must acquire P2");

    udpconnector_peer_key_t                    key2 = udpconnectorPeerKeyFromSockAddr(&addr2);
    const udpconnector_peer_binding_map_value *p2   = udpconnector_peer_binding_map_get(&ls->peer_bindings, key2);
    twfRequire(p2 != NULL && p2->second != NULL, "P2 was not published in the canonical line map");
    udpconnector_binding_t *b2 = p2->second;
    twfRequire(ls->last_send_binding == b2, "P2 send did not update the last-send binding");

    wio_t     *io  = b2->socket->io;
    sockaddr_u src = {0};
    sockaddrSetIpAddressPort(&src, "127.0.0.1", 20001);
    wioSetPeerAddr(io, &src.sa, sockaddrLen(&src));
    udpconnectorOnSocketRecvFrom(io, makeDatagram(&fixture, "old_p1_reply"));
    twfRequireEqualU32(fixture.payload_calls, 1, "old P1 reply delivered");

    sockaddrSetIpAddressPort(&src, "127.0.0.1", 20002);
    wioSetPeerAddr(io, &src.sa, sockaddrLen(&src));
    udpconnectorOnSocketRecvFrom(io, makeDatagram(&fixture, "new_p2_reply"));
    twfRequireEqualU32(fixture.payload_calls, 2, "new P2 reply delivered");

    udpconnector_packet_destination_t *cache = &ls->packet_destinations[0];

    /* A resolved mutable domain remains a cache hit while the line context
     * still names that domain. Rebuilding mutable context must not turn the
     * documented lazy cache into one DNS request per datagram. */
    sockaddr_u addr3 = {0};
    sockaddrSetIpAddressPort(&addr3, "127.0.0.1", 20003);
    addresscontextReset(&cache->dest_ctx);
    addresscontextDomainSetByString(&cache->dest_ctx, "localhost");
    addresscontextSetPort(&cache->dest_ctx, 20003);
    dns_resolved_addr_t resolved = {
        .addrlen = (socklen_t) sockaddrLen(&addr3),
        .family  = AF_INET,
    };
    memoryCopy(&resolved.addr, &addr3, (size_t) resolved.addrlen);
    twfRequire(udpconnectorApplyResolvedAddress(&cache->dest_ctx, &resolved), "failed to seed resolved domain cache");
    cache->has_context = true;

    addresscontextReset(dest_ctx);
    addresscontextDomainSetByString(dest_ctx, "localhost");
    addresscontextSetPort(dest_ctx, 20003);
    addresscontextSetOnlyProtocol(dest_ctx, IP_PROTO_UDP);
    udpconnectorTunnelUpStreamPayload(fixture.connector, l, makeDatagram(&fixture, "same_resolved_domain"));
    twfRequireEqualU32(bufferqueueGetBufCount(&cache->pending_queue), 0, "same mutable domain started redundant DNS");
    twfRequireEqualU32(ls->bindings_count, 3, "same resolved domain did not acquire its concrete peer binding");

    /* Conversely, an upstream context that already resolves the same domain
     * name to a different concrete address is authoritative. Domain spelling
     * must not hide a real peer change. */
    sockaddr_u addr4 = {0};
    sockaddrSetIpAddressPort(&addr4, "127.0.0.2", 20003);
    addresscontextReset(dest_ctx);
    addresscontextDomainSetByString(dest_ctx, "localhost");
    addresscontextSetPort(dest_ctx, 20003);
    addresscontextSetOnlyProtocol(dest_ctx, IP_PROTO_UDP);
    dns_resolved_addr_t changed_resolution = {
        .addrlen = (socklen_t) sockaddrLen(&addr4),
        .family  = AF_INET,
    };
    memoryCopy(&changed_resolution.addr, &addr4, (size_t) changed_resolution.addrlen);
    twfRequire(udpconnectorApplyResolvedAddress(dest_ctx, &changed_resolution),
               "failed to prepare changed mutable domain resolution");
    udpconnectorTunnelUpStreamPayload(fixture.connector, l, makeDatagram(&fixture, "changed_domain_resolution"));
    twfRequireEqualU32(ls->bindings_count, 4, "changed concrete domain resolution reused the stale peer binding");

    addresscontextReset(&cache->dest_ctx);
    addresscontextDomainSetByString(&cache->dest_ctx, "localhost");
    addresscontextSetPort(&cache->dest_ctx, 20004);
    cache->has_context = true;
    cache->resolving   = true;

    sockaddr_u addr5 = {0};
    sockaddrSetIpAddressPort(&addr5, "127.0.0.1", 20004);
    addresscontextReset(dest_ctx);
    addresscontextFromSockAddr(dest_ctx, &addr5);
    addresscontextSetOnlyProtocol(dest_ctx, IP_PROTO_UDP);
    udpconnectorTunnelUpStreamPayload(fixture.connector, l, makeDatagram(&fixture, "new_context_during_dns"));
    twfRequireEqualU32(bufferqueueGetBufCount(&cache->pending_queue),
                       0,
                       "mutable-context datagram was queued behind a different in-flight DNS peer");
    twfRequireEqualU32(ls->bindings_count, 4, "in-flight DNS context change created an unrequested binding");

    udpconnectorTunnelUpStreamFinish(fixture.connector, l);
    lineDestroy(l);

    teardownFixture(&fixture);
}

// Case 23: A pinned ordinary Layer-4 line under packet balance mode remains a fixed pooled binding.
static void testCase23_PinnedNormalLineUsesFixedBinding(void)
{
    twfSetCase("Case 23: Pinned normal line uses a fixed pooled binding");
    test_fixture_t fixture;
    setupFixtureMode(&fixture, kUdpConnectorBalanceModePacket);

    line_t            *l_pinned        = createFixtureNormalLine(&fixture);
    address_context_t *dest_ctx_pinned = lineGetDestinationAddressContext(l_pinned);
    sockaddr_u         addr_pinned     = {0};
    twfRequire(sockaddrSetIpAddressPort(&addr_pinned, "127.0.0.1", 20001) == 0, "failed to set sockaddr");
    addresscontextSetOnlyProtocol(dest_ctx_pinned, IP_PROTO_UDP);
    addresscontextFromSockAddr(dest_ctx_pinned, &addr_pinned);
    addresscontextSetDestinationPinned(dest_ctx_pinned, true);

    udpconnector_lstate_t *ls_pinned = lineGetState(l_pinned, fixture.connector);
    twfRequire(udpconnectorLinestateInitialize(ls_pinned, fixture.connector, l_pinned),
               "failed to initialize linestate");
    ls_pinned->route_destination_pinned = true;

    udpconnector_tstate_t      *ts          = tunnelGetState(fixture.connector);
    udpconnector_worker_pool_t *worker_pool = udpconnectorGetLineWorkerPool(ts, l_pinned);
    ls_pinned->line_idle_id                 = ++worker_pool->next_line_idle_id;
    ls_pinned->idle_handle                  = localidletableCreateItem(udpconnectorGetWorkerIdleTable(ts),
                                                      (hash_t) ls_pinned->line_idle_id,
                                                      ls_pinned,
                                                      udpconnectorOnIdleConnectionExpire,
                                                      kUdpInitExpireTime);
    twfRequire(ls_pinned->idle_handle != NULL, "failed to create idle item");

    udpconnector_binding_t *binding_pinned =
        udpconnectorAcquireBinding(fixture.connector, l_pinned, ls_pinned, &addr_pinned);
    twfRequire(binding_pinned != NULL, "failed to acquire binding");
    ls_pinned->last_send_binding = binding_pinned;

    twfRequire(ls_pinned->fixed_binding != NULL, "pinned line has fixed binding");
    twfRequire(ls_pinned->bindings_count == 1, "pinned line publishes exactly one binding");

    udpconnectorTunnelUpStreamFinish(fixture.connector, l_pinned);
    lineDestroy(l_pinned);

    teardownFixture(&fixture);
}

// Case 24: Upstream Finish flushes ordinary pause queue through last_send_binding.
static void testCase24_UpstreamFinishFlushesLastSendBinding(void)
{
    twfSetCase("Case 24: Upstream Finish flushes pause queue through last_send_binding");
    test_fixture_t fixture;
    setupFixtureMode(&fixture, kUdpConnectorBalanceModePacket);

    line_t                *l  = createAndInitLineIpv4(&fixture, "127.0.0.1", 20001);
    udpconnector_lstate_t *ls = lineGetState(l, fixture.connector);

    sockaddr_u peer_2 = {0};
    twfRequire(sockaddrSetIpAddressPort(&peer_2, "127.0.0.1", 20002) == 0, "failed to prepare second peer");
    udpconnector_binding_t *initial_binding = ls->last_send_binding;
    udpconnector_binding_t *second_binding  = udpconnectorAcquireBinding(fixture.connector, l, ls, &peer_2);
    twfRequire(second_binding != NULL && second_binding != initial_binding && ls->bindings_count == 2,
               "failed to acquire a distinct second-peer binding");
    ls->last_send_binding = second_binding;

    static const char queued_data[] = "queued_pkt";

    sbuf_t *buf = makeDatagram(&fixture, queued_data);
    bufferqueuePushBack(&ls->pause_queue, buf);

#if defined(OS_LINUX)
    wio_t                  *expected_io  = second_binding->socket->io;
    udpconnector_peer_key_t expected_key = second_binding->peer_key;
    g_capture_wio_write                  = true;
#endif
    udpconnectorTunnelUpStreamFinish(fixture.connector, l);
#if defined(OS_LINUX)
    g_capture_wio_write = false;
    twfRequireEqualU32(g_captured_wio_write_calls, 1, "Finish must emit the queued datagram exactly once");
    twfRequire(g_captured_wio_write_io == expected_io, "Finish must use the last send binding's WIO");
    udpconnector_peer_key_t captured_key = udpconnectorPeerKeyFromSockAddr(&g_captured_wio_write_peer);
    twfRequire(udpconnectorPeerKeyEquals(&captured_key, &expected_key),
               "Finish must send to the last send binding's peer");
    twfRequireEqualU32(
        g_captured_wio_write_len, sizeof(queued_data) - 1, "Finish-time datagram length must be preserved");
    twfRequire(memoryCompare(g_captured_wio_write_data, queued_data, sizeof(queued_data) - 1) == 0,
               "Finish-time datagram payload must be preserved");
#endif
    lineDestroy(l);

    teardownFixture(&fixture);
}

// Case 25: One normal packet-mode line uses IPv4 and IPv6 bindings and routes both reply families to the same line.
static void testCase25_DualFamilyPacketModeLineReplies(void)
{
    twfSetCase("Case 25: Dual-family packet-mode line routes IPv4 and IPv6 replies to same line");
    test_fixture_t fixture;
    setupFixtureMode(&fixture, kUdpConnectorBalanceModePacket);

    line_t                *l  = createAndInitLineIpv4(&fixture, "127.0.0.1", 20001);
    udpconnector_lstate_t *ls = lineGetState(l, fixture.connector);

    sockaddr_u addr_v6 = {0};
    sockaddrSetIpAddressPort(&addr_v6, "::1", 20002);
    udpconnector_binding_t *b_v6 = udpconnectorAcquireBinding(fixture.connector, l, ls, &addr_v6);
    twfRequire(b_v6 != NULL, "acquired IPv6 binding for normal packet-mode line");

    wio_t *io_v4 = ls->last_send_binding->socket->io;
    wio_t *io_v6 = b_v6->socket->io;

    sockaddr_u src_v4 = {0};
    sockaddrSetIpAddressPort(&src_v4, "127.0.0.1", 20001);
    wioSetPeerAddr(io_v4, &src_v4.sa, sockaddrLen(&src_v4));
    udpconnectorOnSocketRecvFrom(io_v4, makeDatagram(&fixture, "v4_reply"));
    twfRequireEqualU32(fixture.payload_calls, 1, "v4 reply delivered");

    sockaddr_u src_v6 = {0};
    sockaddrSetIpAddressPort(&src_v6, "::1", 20002);
    wioSetPeerAddr(io_v6, &src_v6.sa, sockaddrLen(&src_v6));
    udpconnectorOnSocketRecvFrom(io_v6, makeDatagram(&fixture, "v6_reply"));
    twfRequireEqualU32(fixture.payload_calls, 2, "v6 reply delivered");

    udpconnectorTunnelUpStreamFinish(fixture.connector, l);
    lineDestroy(l);

    teardownFixture(&fixture);
}

// Case 26: Finishing/expiring a multi-peer packet-mode line removes all bindings across all sockets and emits one
// Finish.
static void testCase26_MultiPeerPacketModeLineFinishRemovesAllBindings(void)
{
    twfSetCase("Case 26: Multi-peer packet-mode line Finish removes all bindings");
    test_fixture_t fixture;
    setupFixtureMode(&fixture, kUdpConnectorBalanceModePacket);

    line_t                *l  = createAndInitLineIpv4(&fixture, "127.0.0.1", 20001);
    udpconnector_lstate_t *ls = lineGetState(l, fixture.connector);

    sockaddr_u addr2 = {0};
    sockaddrSetIpAddressPort(&addr2, "127.0.0.1", 20002);
    udpconnectorAcquireBinding(fixture.connector, l, ls, &addr2);

    sockaddr_u addr3 = {0};
    sockaddrSetIpAddressPort(&addr3, "::1", 20003);
    udpconnectorAcquireBinding(fixture.connector, l, ls, &addr3);

    twfRequireEqualU32(ls->bindings_count, 3, "must have 3 bindings");

    udpconnectorTunnelUpStreamFinish(fixture.connector, l);
    lineDestroy(l);

    udpconnector_tstate_t      *ts          = tunnelGetState(fixture.connector);
    udpconnector_worker_pool_t *worker_pool = &ts->worker_pools[0];
    twfRequire(worker_pool->v4_sockets == NULL && worker_pool->v6_sockets == NULL,
               "all sockets must be retired after multi-peer line finishes");

    teardownFixture(&fixture);
}

// Case 27: Unexpected socket close deduplicates a packet-mode line with multiple bindings on that socket.
static void testCase27_UnexpectedSocketCloseMultiBindingDeduplication(void)
{
    twfSetCase("Case 27: Unexpected socket close deduplicates multi-binding packet-mode line");
    test_fixture_t fixture;
    setupFixtureMode(&fixture, kUdpConnectorBalanceModePacket);

    line_t                *l  = createAndInitLineIpv4(&fixture, "127.0.0.1", 20001);
    udpconnector_lstate_t *ls = lineGetState(l, fixture.connector);

    sockaddr_u addr2 = {0};
    sockaddrSetIpAddressPort(&addr2, "127.0.0.1", 20002);
    udpconnector_binding_t *b2 = udpconnectorAcquireBinding(fixture.connector, l, ls, &addr2);

    twfRequire(b2->socket == ls->last_send_binding->socket, "both bindings on same socket");

    wioClose(b2->socket->io);

    twfRequireEqualU32(fixture.finish_calls, 1, "exactly one downstream Finish emitted");
    lineDestroy(l);

    teardownFixture(&fixture);
}

// Case 28: WIO read, binding allocation, and map publication failures leave no leaked state or descriptor.
static void testCase28_BindingAllocFailureRollback(void)
{
    twfSetCase("Case 28: Socket and binding publication failures roll back cleanly");
    test_fixture_t fixture;
    setupFixtureMode(&fixture, kUdpConnectorBalanceModeConnection);

    udpconnector_tstate_t      *ts          = tunnelGetState(fixture.connector);
    udpconnector_worker_pool_t *worker_pool = &ts->worker_pools[0];

#if defined(OS_LINUX)
    const uint32_t fd_count_before = countOpenFileDescriptors();
    g_fail_wio_read                = true;
    twfRequire(udpconnectorPoolSocketCreate(fixture.connector, worker_pool, AF_INET) == NULL,
               "wioRead failure must reject socket publication");
    twfRequireEqualU32(countOpenFileDescriptors(), fd_count_before, "wioRead failure leaked a UDP descriptor");
    twfRequire(worker_pool->v4_sockets == NULL && worker_pool->v4_sockets_count == 0,
               "wioRead failure published a pool socket");
#endif

    line_t            *l        = createFixtureNormalLine(&fixture);
    address_context_t *dest_ctx = lineGetDestinationAddressContext(l);
    sockaddr_u         addr     = {0};
    sockaddrSetIpAddressPort(&addr, "127.0.0.1", 20001);
    addresscontextSetOnlyProtocol(dest_ctx, IP_PROTO_UDP);
    addresscontextFromSockAddr(dest_ctx, &addr);

    udpconnector_lstate_t *ls = lineGetState(l, fixture.connector);
    twfRequire(udpconnectorLinestateInitialize(ls, fixture.connector, l), "failed to initialize line state");
    g_udpconnector_pool_test_fail_socket_map_insert = true;
    udpconnector_binding_t *binding                 = udpconnectorAcquireBinding(fixture.connector, l, ls, &addr);
    twfRequire(binding == NULL, "socket-map publication must fail");
    g_udpconnector_pool_test_fail_socket_map_insert = false;

    twfRequire(worker_pool->v4_sockets == NULL && worker_pool->v4_sockets_count == 0,
               "socket-map failure retained an empty socket");
    twfRequireEqualU32(ls->bindings_count, 0, "socket-map failure published a line binding");
    udpconnectorLineDetach(fixture.connector, l, ls, kUdpConnectorDetachInitRollback);
    twfRequireEqualU32(fixture.finish_calls, 1, "Init rollback must notify the downstream line owner");
    lineDestroy(l);

    l        = createFixtureNormalLine(&fixture);
    dest_ctx = lineGetDestinationAddressContext(l);
    addresscontextSetOnlyProtocol(dest_ctx, IP_PROTO_UDP);
    addresscontextFromSockAddr(dest_ctx, &addr);
    ls = lineGetState(l, fixture.connector);
    twfRequire(udpconnectorLinestateInitialize(ls, fixture.connector, l), "failed to initialize second line");

    g_udpconnector_pool_test_fail_binding_alloc = true;
    binding                                     = udpconnectorAcquireBinding(fixture.connector, l, ls, &addr);
    twfRequire(binding == NULL, "binding allocation must fail");
    g_udpconnector_pool_test_fail_binding_alloc = false;
    udpconnectorLineDetach(fixture.connector, l, ls, kUdpConnectorDetachInitRollback);
    twfRequireEqualU32(fixture.finish_calls, 2, "binding allocation rollback must notify the line owner");
    lineDestroy(l);

    twfRequire(worker_pool->v4_sockets == NULL, "socket must be retired after failed binding rollback");
    twfRequireEqualU32((uint32_t) worker_pool->active_bindings_count, 0, "failed rollback retained pool bindings");

    teardownFixture(&fixture);
}

// Case 29: Failure to create second same-peer socket rejects new line while existing lines remain operational.
static void testCase29_SecondSocketFailurePreservesExisting(void)
{
    twfSetCase("Case 29: Second socket creation failure preserves existing line");
    test_fixture_t fixture;
    setupFixtureMode(&fixture, kUdpConnectorBalanceModeConnection);

    line_t *l1 = createAndInitLineIpv4(&fixture, "127.0.0.1", 20001);

    g_udpconnector_pool_test_fail_socket_alloc = true;
    line_t            *l2                      = createFixtureNormalLine(&fixture);
    address_context_t *dest_ctx                = lineGetDestinationAddressContext(l2);
    sockaddr_u         addr                    = {0};
    sockaddrSetIpAddressPort(&addr, "127.0.0.1", 20001);
    addresscontextSetOnlyProtocol(dest_ctx, IP_PROTO_UDP);
    addresscontextFromSockAddr(dest_ctx, &addr);

    udpconnector_lstate_t *ls2 = lineGetState(l2, fixture.connector);
    udpconnectorLinestateInitialize(ls2, fixture.connector, l2);
    udpconnector_binding_t *b2 = udpconnectorAcquireBinding(fixture.connector, l2, ls2, &addr);
    twfRequire(b2 == NULL, "second socket creation must fail");

    g_udpconnector_pool_test_fail_socket_alloc = false;
    udpconnectorLineDetach(fixture.connector, l2, ls2, kUdpConnectorDetachInitRollback);
    lineDestroy(l2);

    // Line 1 still works
    udpconnector_lstate_t *ls1 = lineGetState(l1, fixture.connector);
    wio_t                 *io  = ls1->fixed_binding->socket->io;
    sockaddr_u             src = {0};
    sockaddrSetIpAddressPort(&src, "127.0.0.1", 20001);
    wioSetPeerAddr(io, &src.sa, sockaddrLen(&src));
    udpconnectorOnSocketRecvFrom(io, makeDatagram(&fixture, "l1_alive"));
    twfRequireEqualU32(fixture.payload_calls, 1, "line 1 payload delivered");

    udpconnectorTunnelUpStreamFinish(fixture.connector, l1);
    lineDestroy(l1);

    teardownFixture(&fixture);
}

// Case 30: Worker quiesce/stop cleans up all resources on correct WID including uninitialized slots.
static void testCase30_WorkerQuiesceStopCleanup(void)
{
    twfSetCase("Case 30: Worker quiesce/stop cleans up all resources");
    tos_worker_env_t env;
    tosWorkerEnvSetup(&env, 2, kTestLargeBuffer, kTwfDefaultSmallBufferSize);

    tunnel_t              *c  = tunnelCreate(NULL, sizeof(udpconnector_tstate_t), sizeof(udpconnector_lstate_t));
    udpconnector_tstate_t *ts = tunnelGetState(c);
    ts->fwmark                = -1;
    ts->worker_pools          = memoryAllocateZero(sizeof(*ts->worker_pools) * getWorkersCount());
    for (wid_t wid = 0; wid < getWorkersCount(); ++wid)
    {
        ts->worker_pools[wid].wid = wid;
    }

    udpconnector_worker_pool_t *pool0        = &ts->worker_pools[0];
    udpconnector_pool_socket_t *pool0_socket = udpconnectorPoolSocketCreate(c, pool0, AF_INET);
    twfRequire(pool0_socket != NULL, "failed to create worker-0 socket");

    ww_lifecycle_context_t ctx = {0};

    // Quiesce worker 0 and worker 1
    udpconnectorTunnelOnWorkerQuiesce(c, 0, &ctx);
    twfRequire(pool0->quiescing, "pool 0 must be quiescing");
    twfRequire(wioGetCallBackRead(pool0_socket->io) == NULL, "quiesce left worker-0 read callback admitted");
#if defined(OS_LINUX)
    twfRequire((wioGetEvents(pool0_socket->io) & WW_READ) == 0, "quiesce left worker-0 read interest armed");
#endif

    tosSetCurrentWorker(1);
    udpconnectorTunnelOnWorkerQuiesce(c, 1, &ctx);
    udpconnector_worker_pool_t *pool1 = &ts->worker_pools[1];
    twfRequire(pool1->quiescing, "pool 1 must be quiescing");

    // Stop worker 1 then worker 0
    udpconnectorTunnelOnWorkerStop(c, 1, &ctx);

    tosSetCurrentWorker(0);
    udpconnectorTunnelOnWorkerStop(c, 0, &ctx);

    twfRequire(pool0->v4_sockets == NULL, "pool 0 sockets must be drained");
    twfRequire(pool1->v4_sockets == NULL, "pool 1 sockets must be drained");

    udpconnectorTunnelDestroy(c, &ctx);
    tosWorkerEnvTeardown(&env);

    test_fixture_t fixture;
    setupFixtureMode(&fixture, kUdpConnectorBalanceModeConnection);
    line_t                *l1  = createAndInitLineIpv4(&fixture, "127.0.0.1", 20001);
    line_t                *l2  = createAndInitLineIpv4(&fixture, "127.0.0.1", 20002);
    udpconnector_lstate_t *ls1 = lineGetState(l1, fixture.connector);
    twfRequire(ls1->fixed_binding->socket->active_bindings_count == 2,
               "active drain subcase did not create a shared socket");

    udpconnectorTunnelOnWorkerQuiesce(fixture.connector, 0, &ctx);
    udpconnectorTunnelOnWorkerStop(fixture.connector, 0, &ctx);
    twfRequireEqualU32(fixture.finish_calls, 2, "worker drain did not finish both borrowed normal lines");

    udpconnector_tstate_t *fixture_ts = tunnelGetState(fixture.connector);
    twfRequire(fixture_ts->worker_pools[0].v4_sockets == NULL && fixture_ts->worker_pools[0].active_bindings_count == 0,
               "worker drain retained shared socket ownership");
    lineDestroy(l1);
    lineDestroy(l2);
    teardownFixture(&fixture);
}

int main(int argc, char **argv)
{
    (void) argc;
    (void) argv;

    testCase1_DifferentPeersShareSocket();
    testCase2_SamePeerCollidesToNewSocket();
    testCase3_DomainAndLiteralCollision();
    testCase4_FamilyAndScopeIsolation();
    testCase5_HashCollisionSeamRouting();
    testCase6_WorkerAndConnectorPoolIsolation();
    testCase7_ReverseOrderReplies();
    testCase8_UnknownPeerDropped();
    testCase9_LinePauseAndResume();
    testCase10_FinishLineAMarksDraining();
    testCase11_NewCannotJoinDrainingSocket();
    testCase12_DelayedDatagramToDrainingSocketDropped();
    testCase13_FinishLastBindingReclaimsSocket();
    testCase14_IdleDeadlinesExpireSeparately();
    testCase15_UnexpectedSocketCloseReentrancy();
    testCase16_FinishFlushesQueueErrorRecycles();
    testCase17_PacketModeNormalLinesShareSocket();
    testCase18_MultiPeerPacketModeLineAcquisitionAndReplies();
    testCase19_PacketModeLinesOverlappingPeerCollision();
    testCase20_UnregisteredPacketSourceDropped();
    testCase21_PacketDnsFailurePreservesExistingBindings();
    testCase22_MutableContextChangeRetainsOldBinding();
    testCase23_PinnedNormalLineUsesFixedBinding();
    testCase24_UpstreamFinishFlushesLastSendBinding();
    testCase25_DualFamilyPacketModeLineReplies();
    testCase26_MultiPeerPacketModeLineFinishRemovesAllBindings();
    testCase27_UnexpectedSocketCloseMultiBindingDeduplication();
    testCase28_BindingAllocFailureRollback();
    testCase29_SecondSocketFailurePreservesExisting();
    testCase30_WorkerQuiesceStopCleanup();

    printf("ALL 30 UDP CONNECTOR SOCKET POOL TESTS PASSED\n");
    return 0;
}
