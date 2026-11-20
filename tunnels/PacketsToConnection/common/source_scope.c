#include "loggers/network_logger.h"
#include "structure.h"

uint64_t ptcPacketSourceEpoch(tunnel_t *t, const sbuf_t *buf, bool reverse)
{
    ptc_tstate_t *state = tunnelGetState(t);
    if (state->source_epoch == NULL)
        return 0;
    const uint8_t *bytes = sbufGetRawPtr(buf);
    if (UNLIKELY(sbufGetLength(buf) < 20 || (bytes[0] >> 4U) != 4))
        return 0;
    ip_addr_t  source;
    ip4_addr_t address;
    memoryCopy(&address.addr, bytes + (reverse ? 16 : 12), sizeof(address.addr));
    ipAddrCopyFromIp4(source, address);
    return state->source_epoch(state->source_epoch_context, &source);
}

bool ptcPacketEpochValid(tunnel_t *t, const sbuf_t *buf, bool reverse, uint64_t epoch)
{
    ptc_tstate_t *state = tunnelGetState(t);
    return state->source_epoch == NULL || (epoch != 0 && ptcPacketSourceEpoch(t, buf, reverse) == epoch);
}

void ptcTaggedPacketInput(tunnel_t *t, line_t *line, sbuf_t *buf, uint64_t epoch)
{
    if (UNLIKELY(! ptcPacketEpochValid(t, buf, false, epoch)))
    {
        lineReuseBuffer(line, buf);
        return;
    }
    ptcTunnelUpStreamPayloadAfterAffinity(t, line, buf);
}

void ptcSetSourceEpochProvider(tunnel_t *t, void *context, ptc_source_epoch_fn provider)
{
    ptc_tstate_t *state = tunnelGetState(t);
    assert(state->routes_v4 == NULL && provider != NULL && state->source_epoch == NULL);
    state->source_epoch_context = context;
    state->source_epoch         = provider;
    packetAffinitySetTaggedContinuation(state->input_affinity, ptcTaggedPacketInput);
}

uint64_t ptcLineSourceEpoch(tunnel_t *t, line_t *line)
{
    assert(lineIsOnCurrentWorker(line));
    ptc_lstate_t *state = lineGetState(line, t);
    return state->source_epoch;
}
bool ptcLineIsDatagram(tunnel_t *t, line_t *line)
{
    assert(lineIsOnCurrentWorker(line));
    ptc_lstate_t *state = lineGetState(line, t);
    return state->kind == kPtcLineKindUdp;
}

static bool matches(const ip_addr_t *source, const ip_addr_t *network, const ip_addr_t *mask)
{
    return IP_IS_V4(source) && IP_IS_V4(network) && ip4AddrNetcmp(ip_2_ip4(source), ip_2_ip4(network), ip_2_ip4(mask));
}

typedef struct retire_s
{
    tunnel_t              *tunnel;
    ip_addr_t              network, mask;
    wid_t                  coordinator;
    ptc_retire_complete_fn callback;
    void                  *context;
    atomic_uint            remaining;
    atomic_bool            failed;
} retire_t;

static void complete(void *worker, void *arg1, void *arg2, void *arg3)
{
    discard   worker;
    discard   arg2;
    discard   arg3;
    retire_t *retire = arg1;
    retire->callback(retire->context, ! atomicLoad(&retire->failed));
    memoryFree(retire);
}
static void completeCanceled(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard   arg2;
    discard   arg3;
    discard   reason;
    retire_t *retire = arg1;
    retire->callback(retire->context, false);
    memoryFree(retire);
}
static void acknowledge(retire_t *retire, bool success)
{
    if (! success)
        atomicStore(&retire->failed, true);
    if (atomicSub(&retire->remaining, 1) != 1)
        return;
    if (atomicLoad(&retire->failed))
    {
        /* Cancellation only settles ownership and notifies; it never posts work. */
        retire->callback(retire->context, false);
        memoryFree(retire);
        return;
    }
    const worker_message_submit_result_e result =
        sendWorkerMessageForceQueueWithCleanup(retire->coordinator, complete, completeCanceled, retire, NULL, NULL);
    assert(result != kWorkerMessageSubmitRejectedCallerRetains);
    discard result;
}
static void canceled(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard arg2;
    discard arg3;
    discard reason;
    acknowledge(arg1, false);
}

static void retireWorker(void *worker, void *arg1, void *arg2, void *arg3)
{
    discard       arg2;
    discard       arg3;
    retire_t     *retire = arg1;
    tunnel_t     *t      = retire->tunnel;
    ptc_tstate_t *state  = tunnelGetState(t);
    const wid_t   wid    = ((worker_t *) worker)->wid;
    if (state->owned_lines != NULL)
    {
        for (;;)
        {
            line_t *found = NULL;
            for (line_t *line = state->owned_lines[wid]; line != NULL;)
            {
                ptc_lstate_t *ls = lineGetState(line, t);
                if (matches(&lineGetSourceAddressContext(line)->ip_address, &retire->network, &retire->mask))
                {
                    found = line;
                    break;
                }
                line = ls->owned_next;
            }
            if (found == NULL)
                break;
            ptcCloseLineForStop(t, found);
        }
    }
    interface_route_context_t *route = state->routes_v4 != NULL ? state->routes_v4[wid] : NULL;
    if (route != NULL)
    {
        ww_lwip_engine_t *previous;
        const bool        entered = wwLwipEngineEnter(route->engine, &previous);
        assert(entered);
        discard entered;
        ptcTcpDrainRetireSourceRange(route, &retire->network, &retire->mask);
        struct tcp_pcb **lists[] = {&tcp_active_pcbs, &tcp_tw_pcbs};
        for (size_t i = 0; i < sizeof(lists) / sizeof(lists[0]); ++i)
        {
            struct tcp_pcb *pcb = *lists[i];
            while (pcb != NULL)
            {
                struct tcp_pcb *next = pcb->next;
                if (pcb->pretend_netif_idx == netif_get_index(&route->netif) &&
                    pcb->pretend_netif_generation == route->netif.ww_generation &&
                    matches(&pcb->remote_ip, &retire->network, &retire->mask))
                    tcp_abort(pcb);
                pcb = next;
            }
        }
        struct udp_pcb *pcb = udp_pcbs;
        while (pcb != NULL)
        {
            struct udp_pcb *next = pcb->next;
            if (pcb != route->udp_pcb && pcb->pretend_netif_idx == netif_get_index(&route->netif) &&
                pcb->pretend_netif_generation == route->netif.ww_generation &&
                matches(&pcb->remote_ip, &retire->network, &retire->mask))
            {
                udp_recv(pcb, NULL, NULL);
                udp_remove(pcb);
            }
            pcb = next;
        }
        wwLwipEngineLeave(route->engine, previous);
    }
    acknowledge(retire, true);
}

void ptcRetireSourceRange(tunnel_t *t, const ip_addr_t *network, const ip_addr_t *mask, wid_t coordinator,
                          ptc_retire_complete_fn callback, void *context)
{
    assert(network != NULL && mask != NULL && callback != NULL && currentThreadOwnsWorker(coordinator));
    retire_t *retire       = memoryAllocate(sizeof(*retire));
    *retire                = (retire_t) {.tunnel      = t,
                                         .network     = *network,
                                         .mask        = *mask,
                                         .coordinator = coordinator,
                                         .callback    = callback,
                                         .context     = context};
    const unsigned workers = getWorkersCount();
    atomic_init(&retire->remaining, workers + 1U);
    atomic_init(&retire->failed, false);
    for (unsigned i = 0; i < workers; ++i)
    {
        const worker_message_submit_result_e result =
            sendWorkerMessageForceQueueWithCleanup((wid_t) i, retireWorker, canceled, retire, NULL, NULL);
        assert(result != kWorkerMessageSubmitRejectedCallerRetains);
        discard result;
    }
    acknowledge(retire, true);
}
