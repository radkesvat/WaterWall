/*
 * Covers: socks5client resources; the explicit inputs, callbacks and expected results below define this
 * suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Checks: Assertion labels include: unused client role reserved storage; queue failure leaked ownership or
 * left flow alive; configured domain lengths preserve the 255-byte boundary without truncation
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.socks5client_resources_unit
 */
#include "Socks5Client/interface.h"
#include "Socks5Client/internal.h"
#include "fixtures/failure/tunnel_line_failure_harness.h"

static bool     measuring;
static unsigned allocations;
void           *__real_memoryAllocate(size_t size);
void           *__real_memoryReAllocate(void *p, size_t size);
void           *__wrap_memoryAllocate(size_t size);
void           *__wrap_memoryReAllocate(void *p, size_t size);
static void     countAllocation(void)
{
    if (measuring)
        ++allocations;
}

void *__wrap_memoryAllocate(size_t size)
{
    countAllocation();
    return __real_memoryAllocate(size);
}
void *__wrap_memoryReAllocate(void *p, size_t size)
{
    countAllocation();
    return __real_memoryReAllocate(p, size);
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

static void targetAddressLengths(void)
{
    const size_t lengths[] = {0, 255, 256, 257};
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i)
    {
        char domain[258];
        memorySet(domain, 'd', lengths[i]);
        domain[lengths[i]]      = '\0';
        node_t node             = nodeSocks5ClientGet();
        node.node_settings_json = cJSON_CreateObject();
        cJSON_AddStringToObject(node.node_settings_json, "target-address", domain);
        cJSON_AddNumberToObject(node.node_settings_json, "port", 80);
        tunnel_t *client = socks5clientTunnelCreate(&node);
        twfRequire((client != NULL) == (lengths[i] == 255), "constructor accepted an invalid domain length");
        if (client != NULL)
        {
            const socks5client_tstate_t *ts = tunnelGetState(client);
            twfRequire(addresscontextIsDomain(&ts->target_addr) && ts->target_addr.domain_len == 255 &&
                           stringLength(ts->target_addr.domain) == 255 &&
                           memoryEqual(ts->target_addr.domain, domain, 255),
                       "constructor truncated the maximum-length domain");
            socks5clientTunnelDestroy(client, wwLifecycleStartupRollback());
        }
        cJSON_Delete(node.node_settings_json);
        memoryFree(node.type);
    }
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
        GSTATE.ram_profile = profiles[profile];
        twf_worker_env_t env;
        twfWorkerEnvSetup(&env, 8192, 300);
        if (profile == 0 && ! measure_only)
            TEST_RUN_CASE(targetAddressLengths);
        twfSetCase("client role allocations and empty destruction");
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
                twfSetCase("client ordering-queue byte limit");
                line_t *l = twfLinePoolCreateLine(&lines);
                lineRef(l);
                socks5client_lstate_t *ls = lineGetState(l, client);
                socks5clientLinestateInitialize(ls, client, l, kSocks5ClientLineKindDirect);
                ls->phase          = kSocks5ClientPhaseWaitCommand;
                ls->input_draining = true;
                uint32_t limit     = downstream ? kSocks5ClientMaxPendingDownBytes : kSocks5ClientMaxPendingUpBytes;
                sbuf_t  *b         = bufferpoolGetBestFit(env.pool, limit + 1U, 0);
                sbufSetLength(b, limit + 1U);
                if (downstream)
                    socks5clientTunnelDownStreamPayload(client, l, b);
                else
                    socks5clientTunnelUpStreamPayload(client, l, b);
                twfRequire(! lineIsAlive(l) && twfLineRefCount(l) == 1,
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
