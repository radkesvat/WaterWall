#include "Socks5Server/internal.h"
#include "tunnel_line_failure_harness.h"

static bool             measuring;
static unsigned         allocations, fail_nth, failures, inits;
static tunnel_t        *server, *prev, *next;
static tunnel_chain_t  *chain;
static twf_worker_env_t env;
static line_t          *client;

void       *__real_memoryAllocate(size_t size);
void       *__real_memoryCalloc(size_t n, size_t size);
void       *__real_memoryReAllocate(void *p, size_t size);
void       *__wrap_memoryAllocate(size_t size);
void       *__wrap_memoryCalloc(size_t n, size_t size);
void       *__wrap_memoryReAllocate(void *p, size_t size);
static bool refuse(void)
{
    if (measuring)
        ++allocations;
    if (fail_nth && --fail_nth == 0)
    {
        ++failures;
        return true;
    }
    return false;
}
void *__wrap_memoryAllocate(size_t size)
{
    return refuse() ? NULL : __real_memoryAllocate(size);
}
void *__wrap_memoryCalloc(size_t n, size_t size)
{
    return refuse() ? NULL : __real_memoryCalloc(n, size);
}
void *__wrap_memoryReAllocate(void *p, size_t size)
{
    return refuse() ? NULL : __real_memoryReAllocate(p, size);
}
static void noop(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
}
static void ownerFinish(tunnel_t *t, line_t *l)
{
    discard t;
    lineDestroy(l);
}
static void initNext(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    ++inits;
}
static void payload(tunnel_t *t, line_t *l, sbuf_t *b)
{
    discard t;
    lineReuseBuffer(l, b);
}
static bool lineInfo(tunnel_t *t, const line_t *l, udplistener_dynamic_line_info_t *out)
{
    discard t;
    discard l;
    *out = (udplistener_dynamic_line_info_t) {.is_dynamic       = true,
                                              .expected_wid     = 0,
                                              .generation       = 1,
                                              .handle           = {.owner_wid = 0, .generation = 1},
                                              .bound_local_port = 1080};
    return true;
}
static void setup(socks5server_line_kind_t kind)
{
    twfWorkerEnvSetup(&env, 8192, 300);
    server = tunnelCreate(NULL, sizeof(socks5server_tstate_t), sizeof(socks5server_lstate_t));
    prev   = tunnelCreate(NULL, 0, 0);
    next   = tunnelCreate(NULL, 0, 0);
    tunnelBind(prev, server);
    tunnelBind(server, next);
    prev->fnFinD     = ownerFinish;
    prev->fnPayloadD = payload;
    prev->fnPauseD = prev->fnResumeD = prev->fnEstD = noop;
    next->fnInitU                                   = initNext;
    next->fnPayloadU                                = payload;
    next->fnFinU = next->fnPauseU = next->fnResumeU = noop;
    chain                                           = tunnelchainCreate(1);
    chain->sum_line_state_size                      = server->lstate_size;
    tunnelchainFinalize(chain);
    server->chain = chain;
    client        = lineCreate(tunnelchainGetLinePools(chain), 0);
    lineRef(client);
    socks5serverLinestateInitialize(lineGetState(client, server), server, client, kind);
    inits = failures = 0;
}
static void teardown(void)
{
    fail_nth  = 0;
    measuring = false;
    if (lineIsAlive(client))
    {
        socks5serverTunnelUpStreamFinish(server, client);
        lineDestroy(client);
    }
    twfRequire(twfLineRefCount(client) == 1, "client reference leak");
    lineUnref(client);
    socks5server_tstate_t *ts = tunnelGetState(server);
    if (ts->worker_associations)
    {
        socks5server_assoc_map_t_drop(ts->worker_associations);
        memoryFree(ts->worker_associations);
    }
    tunnelchainDestroy(chain);
    tunnelDestroy(server);
    tunnelDestroy(prev);
    tunnelDestroy(next);
    twfWorkerEnvTeardown(&env);
}
static void roles(bool measure_only)
{
    for (unsigned kind = 0; kind <= kSocks5ServerLineKindRejected; ++kind)
    {
        twfSetCase("role backing allocations and empty destruction");
        setup((socks5server_line_kind_t) kind);
        socks5server_lstate_t *ls = lineGetState(client, server);
        socks5serverLinestateDestroy(ls);
        allocations = 0;
        measuring   = true;
        socks5serverLinestateInitialize(ls, server, client, (socks5server_line_kind_t) kind);
        measuring = false;
        printf("role %u: %u optional allocations (base line allocated before measurement)\n", kind, allocations);
        if (! measure_only)
            twfRequire(allocations == (kind == kSocks5ServerLineKindControlTcp ? 1U : 0U),
                       "unused role reserved backing storage");
        /* Bare role fixtures have no neighbouring ownership to Finish. */
        socks5serverLinestateDestroy(ls);
        lineDestroy(client);
        teardown();
    }
}
static void queueFailure(void)
{
    twfSetCase("first ordering queue allocation failure");
    setup(kSocks5ServerLineKindControlTcp);
    socks5server_lstate_t *ls = lineGetState(client, server);
    ls->phase                 = kSocks5ServerPhaseConnectWaitEst;
    ls->next_initialized      = true;
    ls->next_initializing     = true;
    sbuf_t *b                 = bufferpoolGetSmallBuffer(env.pool);
    sbufSetLength(b, 1);
    fail_nth = 1;
    socks5serverTunnelUpStreamPayload(server, client, b);
    twfRequire(failures == 1 && ! lineIsAlive(client), "first queue refusal did not close and settle the flow");
    teardown();
}
static void mapFailure(unsigned allocation)
{
    twfSetCase("first remote registry allocation failure");
    setup(kSocks5ServerLineKindUdpClient);
    socks5server_tstate_t *ts = tunnelGetState(server);
    ts->workers_count         = 1;
    ts->worker_associations   = memoryAllocateZero(sizeof(*ts->worker_associations));
    ts->dynamic_provider      = (udplistener_dynamic_provider_t) {.instance = prev, .get_line_info = lineInfo};
    socks5server_lstate_t *ls = lineGetState(client, server);
    ls->dynamic_handle        = (udplistener_dynamic_endpoint_handle_t) {.owner_wid = 0, .generation = 1};
    lineGetRoutingContext(client)->local_listener_port = 1080;
    socks5server_assoc_entry_t entry                   = {
                          .generation = 1, .owner_wid = 0, .dynamic_handle = ls->dynamic_handle, .assigned_port = 1080, .active = true};
    twfRequire(socks5server_assoc_map_t_insert(ts->worker_associations, 1, entry).inserted,
               "fixture association insert");
    const uint8_t datagram[] = {0, 0, 0, 1, 127, 0, 0, 1, 0, 80, 'X'};
    for (unsigned attempt = 0; attempt < 2; ++attempt)
    {
        sbuf_t *b = bufferpoolGetSmallBuffer(env.pool);
        sbufSetLength(b, sizeof(datagram));
        memoryCopy(sbufGetMutablePtr(b), datagram, sizeof(datagram));
        fail_nth = attempt == 0 ? allocation : 0;
        socks5serverTunnelUpStreamPayload(server, client, b);
        twfRequire(lineIsAlive(client), "map refusal destroyed borrowed client");
        twfRequire(inits == attempt && socks5server_remote_map_t_size(&ls->udp_remote_lines) == attempt,
                   "failed insertion published an unregistered remote");
        twfRequire(twfLineRefCount(client) == 2 + attempt, "failed insertion leaked parent reference");
    }
    twfRequire(failures == 1, "map allocation failure was not exercised");
    teardown();
}
int main(int argc, char **argv)
{
    bool           measure_only = argc > 1 && stringCompare(argv[1], "measure") == 0;
    const uint32_t profiles[]   = {kRamProfileS1Memory,
                                   kRamProfileS2Memory,
                                   kRamProfileM1Memory,
                                   kRamProfileM2Memory,
                                   kRamProfileL1Memory,
                                   kRamProfileL2Memory};
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        GSTATE.ram_profile = profiles[i];
        roles(measure_only);
    }
    if (! measure_only)
    {
        queueFailure();
        mapFailure(1);
        mapFailure(2);
        mapFailure(3);
    }
    return 0;
}
