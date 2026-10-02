/*
 * Covers: socks5client resources; the explicit inputs, callbacks and expected results below define this
 * suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Checks: Assertion labels include: unused client role reserved storage; queue failure leaked ownership or
 * left flow alive
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.socks5client_resources_unit
 */
#include "Socks5Client/internal.h"
#include "fixtures/failure/tunnel_line_failure_harness.h"

static bool     measuring;
static unsigned allocations, fail_nth, failures;
void           *__real_memoryAllocate(size_t size);
void           *__real_memoryReAllocate(void *p, size_t size);
void           *__wrap_memoryAllocate(size_t size);
void           *__wrap_memoryReAllocate(void *p, size_t size);
static bool     refuse(void)
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
int main(int argc, char **argv)
{
    bool           measure_only = argc > 1 && stringCompare(argv[1], "measure") == 0;
    const uint32_t profiles[]   = {kRamProfileS1Memory,
                                   kRamProfileS2Memory,
                                   kRamProfileM1Memory,
                                   kRamProfileM2Memory,
                                   kRamProfileL1Memory,
                                   kRamProfileL2Memory};
    for (size_t profile = 0; profile < sizeof(profiles) / sizeof(profiles[0]); ++profile)
    {
        twfSetCase("client role allocations and empty destruction");
        GSTATE.ram_profile = profiles[profile];
        twf_worker_env_t env;
        twfWorkerEnvSetup(&env, 8192, 300);
        tunnel_t *client = tunnelCreate(NULL, sizeof(socks5client_tstate_t), sizeof(socks5client_lstate_t));
        tunnel_t *prev = tunnelCreate(NULL, 0, 0), *next = tunnelCreate(NULL, 0, 0);
        tunnelBind(prev, client);
        tunnelBind(client, next);
        prev->fnFinD = ownerFinish;
        next->fnFinU = noop;
        twf_line_pool_t lines;
        twfLinePoolSetup(&lines, client->lstate_size, 1);
        for (unsigned kind = 0; kind <= kSocks5ClientLineKindUdpRelay; ++kind)
        {
            line_t                *l  = twfLinePoolCreateLine(&lines);
            socks5client_lstate_t *ls = lineGetState(l, client);
            allocations               = 0;
            measuring                 = true;
            socks5clientLinestateInitialize(ls, client, l, (socks5client_line_kind_t) kind);
            measuring = false;
            printf("profile %u role %u: %u optional allocations (base line excluded)\n",
                   profiles[profile],
                   kind,
                   allocations);
            if (! measure_only)
                twfRequire(
                    allocations ==
                        ((kind == kSocks5ClientLineKindDirect || kind == kSocks5ClientLineKindUdpControl) ? 1U : 0U),
                    "unused client role reserved storage");
            socks5clientLinestateDestroy(ls);
            lineDestroy(l);
        }
        if (! measure_only)
        {
            for (unsigned downstream = 0; downstream < 2; ++downstream)
            {
                twfSetCase("first client ordering-queue allocation failure");
                line_t *l = twfLinePoolCreateLine(&lines);
                lineRef(l);
                socks5client_lstate_t *ls = lineGetState(l, client);
                socks5clientLinestateInitialize(ls, client, l, kSocks5ClientLineKindDirect);
                ls->phase          = kSocks5ClientPhaseWaitCommand;
                ls->input_draining = true;
                sbuf_t *b          = bufferpoolGetSmallBuffer(env.pool);
                sbufSetLength(b, 1);
                failures = 0;
                fail_nth = 1;
                if (downstream)
                    socks5clientTunnelDownStreamPayload(client, l, b);
                else
                    socks5clientTunnelUpStreamPayload(client, l, b);
                twfRequire(failures == 1 && ! lineIsAlive(l) && twfLineRefCount(l) == 1,
                           "queue failure leaked ownership or left flow alive");
                lineUnref(l);
            }
        }
        twfLinePoolTeardown(&lines);
        tunnelDestroy(client);
        tunnelDestroy(prev);
        tunnelDestroy(next);
        twfWorkerEnvTeardown(&env);
    }
    return 0;
}
