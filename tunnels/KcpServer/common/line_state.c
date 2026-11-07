#include "structure.h"

#include "loggers/network_logger.h"

void kcpserverLinestateDestroy(kcpserver_lstate_t *ls)
{
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}

void kcpserverCarrierRetain(kcpserver_carrier_t *carrier)
{
    assert(carrier != NULL && carrier->refs > 0 && carrier->refs < UINT32_MAX);
    ++carrier->refs;
}

void kcpserverCarrierRelease(kcpserver_carrier_t *carrier)
{
    assert(carrier != NULL && carrier->refs > 0);
    if (--carrier->refs == 0)
    {
        assert(! carrier->active && carrier->sessions == NULL && carrier->pending_timer == NULL);
        lineUnref(carrier->line);
        memoryFree(carrier);
    }
}

static void pendingExpired(wtimer_t *timer)
{
    kcpserver_carrier_t *carrier = weventGetUserdata(timer);
    assert(carrier != NULL && carrier->active && carrier->pending_timer == timer);
    kcpserverCarrierRetain(carrier);
    uint64_t now = wloopNowMonotonicMS(weventGetLoop(timer));
    if (now < carrier->pending_deadline)
    {
        uint32_t delay = (uint32_t) min(carrier->pending_deadline - now, (uint64_t) UINT32_MAX);
        if (! wtimerReset(timer, max(1U, delay)))
        {
            kcpserverCarrierClose(carrier, true);
        }
    }
    else
    {
        carrier->pending       = false;
        carrier->pending_timer = NULL;
        weventSetUserData(timer, NULL);
        wtimerDelete(timer);
        if (carrier->sessions == NULL)
        {
            kcpserverCarrierClose(carrier, true);
        }
    }
    kcpserverCarrierRelease(carrier);
}

bool kcpserverArmPending(kcpserver_carrier_t *carrier, uint64_t deadline)
{
    uint64_t now              = wloopNowMonotonicMS(getWorkerLoop(lineGetWID(carrier->line)));
    uint32_t delay            = (uint32_t) min(deadline > now ? deadline - now : 1, (uint64_t) UINT32_MAX);
    carrier->pending_deadline = deadline;
    if (carrier->pending_timer != NULL)
    {
        return wtimerReset(carrier->pending_timer, max(1U, delay));
    }
    carrier->pending_timer =
        wtimerAdd(getWorkerLoop(lineGetWID(carrier->line)), pendingExpired, max(1U, delay), INFINITE);
    if (carrier->pending_timer == NULL)
    {
        return false;
    }
    weventSetUserData(carrier->pending_timer, carrier);
    return true;
}

bool kcpserverLinestateInitialize(kcpserver_lstate_t *ls, line_t *l, tunnel_t *t)
{
    kcpserver_tstate_t *ts = tunnelGetState(t);
    kcpserverLinestateDestroy(ls);
    assert(lineIsOnCurrentWorker(l) && lineGetWID(l) < ts->workers_count);
    if (atomicLoadRelaxed(&ts->stopping) || ts->workers[lineGetWID(l)].quiescing)
    {
        return false;
    }
    kcpserver_carrier_t *carrier = memoryAllocateZero(sizeof(*carrier));
    carrier->tunnel              = t;
    carrier->line                = l;
    carrier->pool                = lineGetBufferPool(l);
    carrier->wid                 = lineGetWID(l);
    carrier->refs                = 1;
    carrier->active              = true;
    lineRef(l);
    bufferqueueInitEmpty(&carrier->input);
    bufferbudgetInit(&carrier->input_budget,
                     (buffer_budget_cost_t) {.bytes = 2U * 1024U * 1024U, .charge = 8U * 1024U * 1024U});
    bool attached = bufferqueueTryAttachBudget(&carrier->input, &carrier->input_budget);
    assert(attached);
    discard  attached;
    uint64_t now = wloopNowMonotonicMS(getWorkerLoop(lineGetWID(l)));
    if (! kcpserverArmPending(carrier, touDeadline(now, ts->no_recv_timeout_ms)))
    {
        carrier->active = false;
        bufferqueueDestroy(&carrier->input);
        kcpserverCarrierRelease(carrier);
        return false;
    }
    kcpserver_worker_t *worker = &ts->workers[lineGetWID(l)];
    carrier->next              = worker->carriers;
    if (carrier->next != NULL)
    {
        carrier->next->prev = carrier;
    }
    worker->carriers = carrier;
    *ls              = (kcpserver_lstate_t) {.kind = kKcpServerCarrier, .carrier = carrier};
    addresscontextSetOnlyProtocol(lineGetSourceAddressContext(l), IP_PROTO_UDP);
    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(l), IP_PROTO_UDP);
    return true;
}
