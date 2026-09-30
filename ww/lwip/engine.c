/* Establish MSVC compatibility types before lwIP can define fallback types. */
#include "wdef.h"

#include "engine_internal.h"
#include "pool_cache_internal.h"
#include "port_registry.h"
#include "shared_pools.h"

#include "lwip/init.h"
#include "lwip/ip.h"
#include "lwip/mem.h"
#include "lwip/memp.h"
#include "lwip/netif.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/stats.h"
#include "lwip/sys.h"
#include "lwip/timeouts.h"
#include "lwip/udp.h"
#include "netif/ppp/magic.h"
#include "netif/ppp/ppp_impl.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

/* sys.h intentionally hides this declaration for NO_SYS, but our protected
 * allocators and Windows clock still require exclusive process bootstrap. */
void sys_init(void);
void wwLwipPortCleanup(void);

struct ww_lwip_engine_s
{
    uint8_t              owner;
    struct wloop_s      *loop;
    unsigned             depth;
    bool                 dispatching;
    bool                 releasing;
    bool                 quiesced;
    ww_lwip_wake_fn      wake;
    void                *wake_argument;
    struct stats_        stats;
    void                *modules[kWwLwipStateCount];
    struct sys_timeo     timeouts[MEMP_NUM_SYS_TIMEOUT];
    bool                 timeout_used[MEMP_NUM_SYS_TIMEOUT];
    ww_lwip_pool_cache_t pool_cache;
};

static WW_LWIP_THREAD_LOCAL ww_lwip_engine_t *current_engine;
static struct stats_                          shared_stats;
static size_t                                 module_offsets[kWwLwipStateCount];
static size_t                                 control_size;
static bool                                   shared_initialized;
static unsigned                               live_engines;

static const struct
{
    size_t (*size)(void);
    void (*init)(void *);
} modules[] = {
#define WW_LWIP_MODULE(name) {wwLwipStateSize_##name, wwLwipStateInit_##name},
#include "engine_modules.inc"
#undef WW_LWIP_MODULE
};

static size_t alignedSize(size_t size)
{
    const size_t alignment = _Alignof(ww_max_align_t);
    return (size + alignment - 1) / alignment * alignment;
}

struct stats_ *wwLwipEngineStats(void)
{
    return current_engine != NULL ? &current_engine->stats : &shared_stats;
}

struct stats_ *wwLwipSharedStats(void)
{
    return &shared_stats;
}

void wwLwipEngineSharedInit(void)
{
    LWIP_ASSERT("exclusive shared bootstrap", ! shared_initialized && current_engine == NULL);
    sys_init();
    wwLwipPortsInitialize();
    control_size = alignedSize(sizeof(ww_lwip_engine_t));
    for (unsigned i = 0; i < kWwLwipState_tcp_lists; ++i)
    {
        module_offsets[i] = control_size;
        control_size += alignedSize(modules[i].size());
    }
    module_offsets[kWwLwipState_tcp_lists] = control_size;
    control_size += alignedSize(NUM_TCP_PCB_LISTS * sizeof(struct tcp_pcb **));
    stats_init();
    mem_init();
    memp_init();
    ppp_init();
    shared_initialized = true;
}

void wwLwipEngineSharedCleanup(void)
{
    LWIP_ASSERT("shared cleanup outside stack execution", current_engine == NULL);
    LWIP_ASSERT("IPv4 reassembly fully released", wwLwipReassemblyUsage(4) == 0);
    LWIP_ASSERT("IPv6 reassembly fully released", wwLwipReassemblyUsage(6) == 0);
    LWIP_ASSERT("all engines destroyed before shared finalization", live_engines == 0);
    for (unsigned i = 0; i < MEMP_MAX; ++i)
    {
        LWIP_ASSERT("shared pool fully returned", memp_pools[i]->stats->used == 0);
    }
    wwLwipPortCleanup();
    wwLwipPortsFinalize();
    shared_initialized = false;
}

size_t wwLwipEngineControlSize(void)
{
    return control_size;
}

ww_lwip_engine_t *wwLwipEngineCurrent(void)
{
    return current_engine;
}

ww_lwip_pool_cache_t *wwLwipEnginePoolCache(void)
{
    assert(current_engine == NULL || wwLwipEngineOwnerIsCurrent(current_engine->owner, current_engine->loop));
    return current_engine != NULL ? &current_engine->pool_cache : NULL;
}

bool wwLwipEngineIsReleasing(void)
{
    wwLwipEngineAssertCurrent();
    return current_engine->releasing;
}

void wwLwipEngineAssertCurrent(void)
{
    if (current_engine == NULL || ! wwLwipEngineOwnerIsCurrent(current_engine->owner, current_engine->loop))
    {
        LWIP_PLATFORM_ASSERT("lwIP engine requires its owner event worker");
    }
}

void wwLwipEngineAssertOwner(const void *owner)
{
    wwLwipEngineAssertCurrent();
    if (owner != current_engine)
    {
        LWIP_PLATFORM_ASSERT("foreign lwIP protocol object");
    }
}

void *wwLwipModuleState(enum ww_lwip_state_module module)
{
    if (current_engine == NULL)
    {
        LWIP_PLATFORM_ASSERT("lwIP module access requires an active engine scope");
    }
    if ((unsigned) module >= kWwLwipStateCount)
    {
        LWIP_PLATFORM_ASSERT("valid protocol state module");
    }
    /* Enter validates the immutable owner and saved loop before selecting this
     * private TLS pointer; paired Leave only restores the enclosing scope.
     * Worker identity cannot change inside that scope. Keep the full boundary
     * checks without repeating them for every protocol field in Release. */
    assert(wwLwipEngineOwnerIsCurrent(current_engine->owner, current_engine->loop));
    return current_engine->modules[module];
}

bool wwLwipEngineEnter(ww_lwip_engine_t *engine, ww_lwip_engine_t **previous)
{
    if (! wwLwipEngineOwnerIsCurrent(engine->owner, engine->loop))
    {
        return false;
    }
    *previous      = current_engine;
    current_engine = engine;
    ++engine->depth;
    return true;
}

static void engineLeave(ww_lwip_engine_t *engine, ww_lwip_engine_t *previous, bool notify)
{
    LWIP_ASSERT("balanced engine scope", current_engine == engine && engine->depth != 0);
    --engine->depth;
    current_engine = previous;
    if (notify && engine->depth == 0 && ! engine->releasing && ! engine->quiesced && engine->wake != NULL)
        engine->wake(engine, engine->wake_argument);
}

void wwLwipEngineLeave(ww_lwip_engine_t *engine, ww_lwip_engine_t *previous)
{
    engineLeave(engine, previous, true);
}

uint32_t wwLwipEngineNextTimeout(ww_lwip_engine_t *engine)
{
    ww_lwip_engine_t *previous;
    if (! wwLwipEngineEnter(engine, &previous))
        return SYS_TIMEOUTS_SLEEPTIME_INFINITE;
    uint32_t delay = engine->quiesced ? SYS_TIMEOUTS_SLEEPTIME_INFINITE : sys_timeouts_sleeptime();
    if (! engine->quiesced)
    {
        for (struct netif *netif = netif_list; netif != NULL; netif = netif->next)
        {
            if (netif->loop_first != NULL)
                delay = 0;
        }
    }
    engineLeave(engine, previous, false);
    return delay;
}

void wwLwipEngineSetWake(ww_lwip_engine_t *engine, ww_lwip_wake_fn wake, void *argument)
{
    LWIP_ASSERT("wake owner", wwLwipEngineOwnerIsCurrent(engine->owner, engine->loop));
    LWIP_ASSERT("no rearm after quiescence", wake == NULL || ! engine->quiesced);
    engine->wake          = wake;
    engine->wake_argument = argument;
}

void wwLwipEngineQuiesce(ww_lwip_engine_t *engine)
{
    LWIP_ASSERT("quiesce on idle owner", wwLwipEngineOwnerIsCurrent(engine->owner, engine->loop) && engine->depth == 0);
    engine->quiesced      = true;
    engine->wake          = NULL;
    engine->wake_argument = NULL;
}

ww_lwip_engine_t *wwLwipEngineCreate(uint8_t owner, struct wloop_s *loop)
{
    if (! shared_initialized || ! wwLwipEngineOwnerIsCurrent(owner, loop))
    {
        return NULL;
    }
    ww_lwip_engine_t *engine = calloc(1, control_size);
    if (engine == NULL)
    {
        return NULL;
    }
    engine->owner = owner;
    engine->loop  = loop;
    wwLwipPoolCacheInitialize(&engine->pool_cache);
    memcpy(engine->stats.memp, shared_stats.memp, sizeof(engine->stats.memp));
    for (unsigned i = 0; i < kWwLwipStateCount; ++i)
    {
        engine->modules[i] = (unsigned char *) engine + module_offsets[i];
        if (i < kWwLwipState_tcp_lists)
        {
            modules[i].init(engine->modules[i]);
        }
    }
    ww_lwip_engine_t *previous;
    const bool        entered = wwLwipEngineEnter(engine, &previous);
    LWIP_ASSERT("new engine owner", entered);
    (void) entered;
    lwip_init();
    magic_init();
    wwLwipEngineLeave(engine, previous);
    SYS_ARCH_LOCKED(++live_engines);
    return engine;
}

void *wwLwipTimeoutAlloc(void)
{
    wwLwipEngineAssertCurrent();
    for (unsigned i = 0; i < MEMP_NUM_SYS_TIMEOUT; ++i)
    {
        if (! current_engine->timeout_used[i])
        {
            current_engine->timeout_used[i] = true;
            return &current_engine->timeouts[i];
        }
    }
    return NULL;
}

void wwLwipTimeoutFree(void *timeout)
{
    wwLwipEngineAssertCurrent();
    for (unsigned i = 0; i < MEMP_NUM_SYS_TIMEOUT; ++i)
    {
        if (timeout == &current_engine->timeouts[i])
        {
            LWIP_ASSERT("live timeout", current_engine->timeout_used[i]);
            current_engine->timeout_used[i] = false;
            return;
        }
    }
    LWIP_PLATFORM_ASSERT("foreign engine timeout");
}

bool wwLwipEngineOwnsNetif(const struct netif *netif)
{
    wwLwipEngineAssertCurrent();
    return netif->ww_engine == current_engine;
}

int wwLwipEngineInput(ww_lwip_engine_t *engine, struct pbuf *packet, struct netif *netif)
{
    ww_lwip_engine_t *previous;
    if (! wwLwipEngineEnter(engine, &previous))
    {
        return ERR_ARG;
    }
    if (engine->quiesced || engine->dispatching || ! wwLwipEngineOwnsNetif(netif))
    {
        wwLwipEngineLeave(engine, previous);
        return ERR_ARG;
    }
    engine->dispatching = true;
    const err_t result  = ip_input(packet, netif);
    engine->dispatching = false;
    wwLwipEngineLeave(engine, previous);
    return result;
}

void wwLwipEngineCheckTimeouts(ww_lwip_engine_t *engine)
{
    ww_lwip_engine_t *previous;
    if (! wwLwipEngineEnter(engine, &previous))
    {
        return;
    }
    if (! engine->quiesced && ! engine->dispatching)
    {
        engine->dispatching = true;
        sys_check_timeouts();
        netif_poll_all();
        engine->dispatching = false;
    }
    wwLwipEngineLeave(engine, previous);
}

void wwLwipEngineDestroy(ww_lwip_engine_t *engine)
{
    ww_lwip_engine_t *previous;
    const bool        entered = wwLwipEngineEnter(engine, &previous);
    LWIP_ASSERT("destroy on owner outside dispatch", entered && ! engine->dispatching && engine->depth == 1);
    (void) entered;
    engine->releasing = true;
    wwLwipReassemblyCleanup4();
    wwLwipReassemblyCleanup6();
    wwLwipLowpanCleanup();
    while (tcp_active_pcbs != NULL || tcp_tw_pcbs != NULL || tcp_bound_pcbs != NULL)
    {
        struct tcp_pcb *pcb =
            tcp_active_pcbs != NULL ? tcp_active_pcbs : (tcp_tw_pcbs != NULL ? tcp_tw_pcbs : tcp_bound_pcbs);
        if (pcb->refused_data != NULL)
        {
            pbuf_free(pcb->refused_data);
            pcb->refused_data = NULL;
        }
        tcp_abandon(pcb, 0);
    }
    while (tcp_listen_pcbs.pcbs != NULL)
    {
        const err_t result = tcp_close(tcp_listen_pcbs.pcbs);
        LWIP_ASSERT("listener cleanup", result == ERR_OK);
        (void) result;
    }
    for (struct netif *netif = netif_list; netif != NULL; netif = netif->next)
        wwLwipNetifProtocolCleanup(netif);
    while (udp_pcbs != NULL)
    {
        udp_remove(udp_pcbs);
    }
    while (netif_list != NULL)
    {
        netif_remove(netif_list);
    }
    wwLwipEngineLeave(engine, previous);
    wwLwipPoolCacheDestroy(&engine->pool_cache);
    free(engine);
    SYS_ARCH_LOCKED(--live_engines);
}
