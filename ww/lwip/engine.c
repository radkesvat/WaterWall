/* Establish MSVC compatibility types before lwIP can define fallback types. */
#include "wdef.h"

#include "engine_internal.h"
#include "packet_batch.h"
#include "pool_cache_internal.h"
#include "port_registry.h"
#include "shared_pools.h"
#include "wmem.h"

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
    uint8_t                    owner;
    struct wloop_s            *loop;
    unsigned                   depth;
    bool                       dispatching;
    bool                       releasing;
    bool                       quiesced;
    bool                       ack_batch;
    struct tcp_pcb            *ack_pending;
    struct tcp_pcb            *receive_members;
    uint32_t                   receive_budget;
    uint32_t                   receive_connections;
    uint32_t                   receive_share;
    bool                       receive_rebalance;
    packet_batch_participant_t receive_batch;
    ww_lwip_wake_fn            wake;
    void                      *wake_argument;
    struct stats_              stats;
    void                      *modules[kWwLwipStateCount];
    struct sys_timeo           timeouts[MEMP_NUM_SYS_TIMEOUT];
    bool                       timeout_used[MEMP_NUM_SYS_TIMEOUT];
    ww_lwip_pool_cache_t       pool_cache;
};

static WW_LWIP_THREAD_LOCAL ww_lwip_engine_t *current_engine;
static struct stats_                          shared_stats;
static size_t                                 module_offsets[kWwLwipStateCount];
static size_t                                 control_size;
static bool                                   shared_initialized;
static unsigned                               live_engines;
static uint32_t                               default_receive_budget = WW_LWIP_DEFAULT_RECEIVE_BUDGET;

static void engineFlushAcks(ww_lwip_engine_t *engine);

void wwLwipEngineSetDefaultReceiveBudget(uint32_t budget)
{
    assert(! shared_initialized && current_engine == NULL && live_engines == 0);
    assert(budget == 0 || (budget >= WW_LWIP_MIN_RECEIVE_WINDOW && budget <= 1024U * 1024U * 1024U));
    default_receive_budget = budget;
}

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
    if (engine->depth == 1 && engine->receive_rebalance && ! engine->ack_batch && ! engine->dispatching &&
        ! engine->quiesced && ! engine->releasing)
        engineFlushAcks(engine);
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
    assert(! engine->ack_batch && engine->ack_pending == NULL);
    engine->quiesced      = true;
    engine->wake          = NULL;
    engine->wake_argument = NULL;
}

void wwLwipEngineBeginAckBatch(ww_lwip_engine_t *engine)
{
    assert(engine != NULL);
    if (! wwLwipEngineOwnerIsCurrent(engine->owner, engine->loop))
        LWIP_PLATFORM_ASSERT("ACK batch requires its owner event worker");
    assert(engine->depth == 0 && ! engine->dispatching && ! engine->quiesced);
    assert(! engine->ack_batch && engine->ack_pending == NULL);
    engine->ack_batch = true;
}

static void engineReceiveBatchBegin(void *context)
{
    wwLwipEngineBeginAckBatch(context);
}

static void engineReceiveBatchEnd(void *context)
{
    wwLwipEngineEndAckBatch(context);
}

bool wwLwipEngineJoinReceiveBatch(ww_lwip_engine_t *engine)
{
    assert(engine != NULL && wwLwipEngineOwnerIsCurrent(engine->owner, engine->loop));
    return packetBatchJoin(&engine->receive_batch);
}

void wwLwipEngineCancelAck(struct tcp_pcb *pcb)
{
    assert(current_engine != NULL && pcb->ww_engine == current_engine);
    if (pcb->ww_ack_previous != NULL)
    {
        *pcb->ww_ack_previous = pcb->ww_ack_next;
        if (pcb->ww_ack_next != NULL)
            pcb->ww_ack_next->ww_ack_previous = pcb->ww_ack_previous;
        pcb->ww_ack_previous = NULL;
        pcb->ww_ack_next     = NULL;
    }
}

static void engineUpdateReceiveShare(ww_lwip_engine_t *engine)
{
    const uint32_t previous = engine->receive_share;
    engine->receive_share =
        engine->receive_connections == 0
            ? TCP_WND
            : LWIP_MIN(TCP_WND,
                       LWIP_MAX(WW_LWIP_MIN_RECEIVE_WINDOW, engine->receive_budget / engine->receive_connections));
    /* Joining never enlarges a share. Retiring members at either clamp also
     * leaves every advertised target unchanged, so no member scan is needed. */
    if (engine->receive_connections == 0)
        engine->receive_rebalance = false;
    else if (engine->receive_share > previous)
        engine->receive_rebalance = true;
}

uint32_t wwLwipTcpReceiveWindow(struct tcp_pcb *pcb)
{
    assert(current_engine != NULL && pcb->ww_engine == current_engine && pcb->state != LISTEN);
    if (current_engine->receive_budget == 0 || pcb->state == CLOSED || pcb->state == TIME_WAIT)
        return pcb->rcv_wnd;
    if (pcb->ww_receive_previous == NULL)
    {
        pcb->ww_receive_next     = current_engine->receive_members;
        pcb->ww_receive_previous = &current_engine->receive_members;
        if (pcb->ww_receive_next != NULL)
            pcb->ww_receive_next->ww_receive_previous = &pcb->ww_receive_next;
        current_engine->receive_members = pcb;
        ++current_engine->receive_connections;
        engineUpdateReceiveShare(current_engine);
    }
    assert(current_engine->receive_connections > 0 && pcb->rcv_wnd <= TCP_WND_MAX(pcb));
    const uint32_t share = LWIP_MIN((uint32_t) TCP_WND_MAX(pcb), current_engine->receive_share);
    const uint32_t held  = TCP_WND_MAX(pcb) - pcb->rcv_wnd;
    if (share < TCP_WND_MAX(pcb) && ! pcb->ww_receive_limited)
    {
        pcb->ww_receive_limited = 1;
        /* Earlier unbounded output may have advanced the speculative edge
         * before failing. Start from the successful wire promise once; later
         * output commits its logical edge to avoid cumulative scale rounding. */
        pcb->rcv_ann_right_edge = pcb->ww_rcv_advertised_valid ? pcb->ww_rcv_advertised_edge : pcb->rcv_nxt;
    }
    return held < share ? LWIP_MIN((uint32_t) pcb->rcv_wnd, share - held) : 0;
}

void wwLwipTcpPrepareReceiveWindow(struct tcp_pcb *pcb)
{
    if (! pcb->ww_receive_limited)
        discard wwLwipTcpReceiveWindow(pcb);
    if (pcb->ww_receive_limited)
        tcp_update_rcv_ann_wnd(pcb);
}

void wwLwipEngineForgetReceive(struct tcp_pcb *pcb)
{
    assert(current_engine != NULL && pcb->ww_engine == current_engine);
    if (pcb->ww_receive_previous != NULL)
    {
        *pcb->ww_receive_previous = pcb->ww_receive_next;
        if (pcb->ww_receive_next != NULL)
            pcb->ww_receive_next->ww_receive_previous = pcb->ww_receive_previous;
        pcb->ww_receive_previous = NULL;
        pcb->ww_receive_next     = NULL;
        assert(current_engine->receive_connections > 0);
        --current_engine->receive_connections;
        engineUpdateReceiveShare(current_engine);
    }
}

static void engineQueueAck(struct tcp_pcb *pcb)
{
    if (pcb->ww_ack_previous == NULL)
    {
        pcb->ww_ack_next     = current_engine->ack_pending;
        pcb->ww_ack_previous = &current_engine->ack_pending;
        if (pcb->ww_ack_next != NULL)
            pcb->ww_ack_next->ww_ack_previous = &pcb->ww_ack_next;
        current_engine->ack_pending = pcb;
    }
}

static void engineRebalanceReceiveWindows(ww_lwip_engine_t *engine)
{
    engine->receive_rebalance = false;
    /* Recalculation cannot call a neighbour or free a PCB. Collect ACK intent
     * first; the existing pop-before-output queue handles callback retirement. */
    for (struct tcp_pcb *pcb = engine->receive_members; pcb != NULL; pcb = pcb->ww_receive_next)
    {
        if (pcb->state == ESTABLISHED && pcb->ww_rcv_advertised_valid &&
            TCP_SEQ_LEQ(pcb->ww_rcv_advertised_edge, pcb->rcv_nxt))
        {
            tcp_update_rcv_ann_wnd(pcb);
            if (RCV_WND_SCALE(pcb, pcb->rcv_ann_wnd) != 0)
            {
                tcp_ack_now(pcb);
                engineQueueAck(pcb);
            }
        }
    }
}

static void engineFlushAcks(ww_lwip_engine_t *engine)
{
    assert(current_engine == engine && ! engine->ack_batch && ! engine->dispatching);
    engine->dispatching = true;
    do
    {
        if (engine->receive_rebalance)
            engineRebalanceReceiveWindows(engine);
        while (engine->ack_pending != NULL)
        {
            struct tcp_pcb *pcb = engine->ack_pending;
            wwLwipEngineCancelAck(pcb);
            if ((pcb->flags & (TF_ACK_DELAY | TF_ACK_NOW)) != 0)
            {
                tcp_ack_now(pcb);
                tcp_output(pcb);
            }
        }
    } while (engine->receive_rebalance);
    engine->dispatching = false;
}

int wwLwipEngineDeferAck(struct tcp_pcb *pcb)
{
    assert(current_engine != NULL && pcb->ww_engine == current_engine);
    if (! current_engine->ack_batch || pcb->state != ESTABLISHED ||
        (pcb->flags & (TF_ACK_NOW | TF_INFR | TF_RTO | TF_RXCLOSED | TF_FIN)) != 0 ||
        RCV_WND_SCALE(pcb, pcb->rcv_ann_wnd) == 0)
        return 0;
#if TCP_QUEUE_OOSEQ
    if (pcb->ooseq != NULL)
        return 0;
#endif
#if LWIP_TCP_SACK_OUT
    if (LWIP_TCP_SACK_VALID(pcb, 0))
        return 0;
#endif
    engineQueueAck(pcb);
    tcp_set_flags(pcb, TF_ACK_DELAY);
    return 1;
}

void wwLwipEngineEndAckBatch(ww_lwip_engine_t *engine)
{
    assert(engine != NULL && engine->ack_batch && engine->depth == 0 && ! engine->dispatching);
    ww_lwip_engine_t *previous;
    if (! wwLwipEngineEnter(engine, &previous))
        LWIP_PLATFORM_ASSERT("ACK batch requires its owner event worker");
    engine->ack_batch = false;
    engineFlushAcks(engine);
    wwLwipEngineLeave(engine, previous);
}

ww_lwip_engine_t *wwLwipEngineCreate(uint8_t owner, struct wloop_s *loop)
{
    if (! shared_initialized || ! wwLwipEngineOwnerIsCurrent(owner, loop))
    {
        return NULL;
    }
    ww_lwip_engine_t *engine = memoryAllocateZero(control_size);
    engine->owner            = owner;
    engine->loop             = loop;
    engine->receive_budget   = default_receive_budget;
    engine->receive_share    = TCP_WND;
    engine->receive_batch    = (packet_batch_participant_t) {
           .begin = engineReceiveBatchBegin, .end = engineReceiveBatchEnd, .context = engine};
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
    assert(engine->receive_batch.batch == NULL);
    ww_lwip_engine_t *previous;
    const bool        entered = wwLwipEngineEnter(engine, &previous);
    LWIP_ASSERT("destroy on owner outside dispatch", entered && ! engine->dispatching && engine->depth == 1);
    assert(! engine->ack_batch && engine->ack_pending == NULL);
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
    LWIP_ASSERT("receive-window membership fully released",
                engine->receive_members == NULL && engine->receive_connections == 0);
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
    memoryFree(engine);
    SYS_ARCH_LOCKED(--live_engines);
}
