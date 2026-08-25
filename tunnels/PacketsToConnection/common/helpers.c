#include "structure.h"

#include "loggers/network_logger.h"

bool ptcNextGateEnter(tunnel_t *t)
{
    ptc_tstate_t *state = tunnelGetState(t);

    if (UNLIKELY(ptcTunnelIsStopping(t) || ! quiescenceGateEnter(&state->next_gate)))
    {
        return false;
    }
    if (UNLIKELY(ptcTunnelIsStopping(t)))
    {
        quiescenceGateLeave(&state->next_gate);
        return false;
    }
    return true;
}

void ptcNextGateLeave(tunnel_t *t)
{
    ptc_tstate_t *state = tunnelGetState(t);
    quiescenceGateLeave(&state->next_gate);
}

bool ptcTunnelIsStopping(tunnel_t *t)
{
    ptc_tstate_t *state = tunnelGetState(t);
    return atomicLoadRelaxed(&state->stopping);
}

void ptcDetachTcpPcbLocked(ptc_lstate_t *ls)
{
    struct tcp_pcb *pcb = ls->tcp_pcb;

    if (pcb == NULL)
    {
        return;
    }

    tcp_arg(pcb, NULL);
    tcp_recv(pcb, NULL);
    tcp_sent(pcb, NULL);
    tcp_poll(pcb, NULL, 0);
    tcp_err(pcb, NULL);
    ls->write_poll_armed     = false;
    ls->write_retry_queued   = false;
    ls->refused_retry_queued = false;
    ls->tcp_pcb              = NULL;
}

void ptcDetachUdpFlowLocked(ptc_lstate_t *ls)
{
    interface_route_context_t *route_ctx = ls->route_ctx;

    if (route_ctx == NULL)
    {
        ls->udp_pcb = NULL;
        return;
    }

    ptc_udp_flow_map_t_iter it = ptc_udp_flow_map_t_find(&route_ctx->udp_flows, ls->udp_flow_key);
    if (it.ref != ptc_udp_flow_map_t_end(&route_ctx->udp_flows).ref && it.ref->second == ls->line)
    {
        ptc_udp_flow_map_t_erase_at(&route_ctx->udp_flows, it);
    }

    if (ls->udp_pcb != NULL)
    {
        if (route_ctx->udp_pcb == ls->udp_pcb)
        {
            route_ctx->udp_pcb = NULL;
        }
        udp_recv(ls->udp_pcb, NULL, NULL);
        udp_remove(ls->udp_pcb);
    }

    ls->route_ctx = NULL;
    ls->udp_pcb   = NULL;
}

void ptcOwnedLineRegister(ptc_lstate_t *ls)
{
    ptc_tstate_t *state = tunnelGetState(ls->tunnel);
    const wid_t   wid   = lineGetWID(ls->line);

    if (UNLIKELY(state->owned_lines == NULL || wid >= state->owned_worker_count || ls->owned_registered))
    {
        LOGF("PacketsToConnection: invalid owned-line registration state");
        abortProgramNow(1);
    }

    mutexLock(&state->owned_lines_lock);
    line_t *head   = state->owned_lines[wid];
    ls->owned_prev = NULL;
    ls->owned_next = head;
    if (head != NULL)
    {
        ptc_lstate_t *head_state = lineGetState(head, ls->tunnel);
        head_state->owned_prev   = ls->line;
    }
    state->owned_lines[wid] = ls->line;
    ls->owned_registered    = true;
    mutexUnlock(&state->owned_lines_lock);
}

void ptcOwnedLineUnregister(ptc_lstate_t *ls)
{
    if (UNLIKELY(! ls->owned_registered))
    {
        LOGF("PacketsToConnection: attempted to unregister a line absent from the owned-line registry");
        abortProgramNow(1);
    }

    ptc_tstate_t *state = tunnelGetState(ls->tunnel);
    const wid_t   wid   = lineGetWID(ls->line);

    if (UNLIKELY(state->owned_lines == NULL || wid >= state->owned_worker_count))
    {
        LOGF("PacketsToConnection: invalid owned-line registry state during unregister");
        abortProgramNow(1);
    }

    mutexLock(&state->owned_lines_lock);
    if (ls->owned_prev != NULL)
    {
        ptc_lstate_t *previous = lineGetState(ls->owned_prev, ls->tunnel);
        previous->owned_next   = ls->owned_next;
    }
    else
    {
        assert(state->owned_lines[wid] == ls->line);
        state->owned_lines[wid] = ls->owned_next;
    }
    if (ls->owned_next != NULL)
    {
        ptc_lstate_t *next = lineGetState(ls->owned_next, ls->tunnel);
        next->owned_prev   = ls->owned_prev;
    }
    ls->owned_prev       = NULL;
    ls->owned_next       = NULL;
    ls->owned_registered = false;
    mutexUnlock(&state->owned_lines_lock);
}

/* Called with lwIP's core lock held after both callback gates are closed. */
void ptcDetachOwnedLinePcbsLocked(tunnel_t *t)
{
    ptc_tstate_t *state = tunnelGetState(t);

    if (state->owned_lines == NULL)
    {
        return;
    }

    mutexLock(&state->owned_lines_lock);
    for (uint32_t wid = 0; wid < state->owned_worker_count; ++wid)
    {
        for (line_t *line = state->owned_lines[wid]; line != NULL;)
        {
            ptc_lstate_t *ls = lineGetState(line, t);
            line             = ls->owned_next;

            if (ls->kind == kPtcLineKindTcp && ls->tcp_pcb != NULL)
            {
                struct tcp_pcb *pcb = ls->tcp_pcb;
                ptcDetachTcpPcbLocked(ls);
                tcp_abort(pcb);
            }
            else if (ls->kind == kPtcLineKindUdp)
            {
                ptcDetachUdpFlowLocked(ls);
            }
        }
    }
    mutexUnlock(&state->owned_lines_lock);
}

/*
 * The acknowledgement queue and the pause queue are two views of the same
 * ordered payloads. Every record whose buffer is still unwritten sits in a
 * contiguous suffix of `ack_queue`, in exactly the order `pause_queue` holds
 * those buffers - a payload only becomes "paused" after every earlier one
 * already is. So the record owning the front paused buffer is at this index, and
 * no search is needed. The previous linear association made both admission and
 * teardown quadratic in the number of retained payloads.
 */
static size_t ptcFrontPauseAckIndex(const ptc_lstate_t *ls)
{
    const size_t records = (size_t) sbuf_ack_queue_t_size(&ls->ack_queue);
    const size_t paused  = bufferqueueGetBufCount((buffer_queue_t *) (uintptr_t) &ls->pause_queue);

    assert(paused <= records);
    return records - paused;
}

sbuf_ack_t *ptcPauseAckRecordAt(ptc_lstate_t *ls, size_t index)
{
    assert(index < (size_t) sbuf_ack_queue_t_size(&ls->ack_queue));
    return sbuf_ack_queue_t_at_mut(&ls->ack_queue, (isize_t) index);
}

size_t ptcFrontPauseAckIndexOf(const ptc_lstate_t *ls)
{
    return ptcFrontPauseAckIndex(ls);
}

bool ptcReserveWriteSlots(ptc_lstate_t *ls)
{
    /*
     * One acknowledgement record, plus the one pause slot the payload needs if
     * lwIP will not take all of it. Reserving both before any ownership moves is
     * what makes the write path transactional: after this succeeds, neither
     * insertion can fail, and before it succeeds nothing has been handed over.
     */
    if (! sbuf_ack_queue_t_reserve(&ls->ack_queue, sbuf_ack_queue_t_size(&ls->ack_queue) + 1))
    {
        return false;
    }
    return bufferqueueReserveExtra(&ls->pause_queue, 1);
}

void ptcAckQueuePushBack(ptc_lstate_t *ls, sbuf_t *buf, uint32_t total)
{
    /* ptcReserveWriteSlots() ran first, so this insertion cannot allocate. */
    sbuf_ack_t *record =
        sbuf_ack_queue_t_push_back(&ls->ack_queue, ((sbuf_ack_t) {.buf = buf, .written = 0, .total = total}));

    if (UNLIKELY(record == NULL))
    {
        LOGF("PacketsToConnection: acknowledgement record insertion failed after a successful reservation");
        abortProgramNow(1);
    }

    /*
     * The caller admitted these bytes against the limit before handing over
     * ownership, so the sum cannot pass a `uint32_t` here.
     */
    assert(ls->pending_bytes <= UINT32_MAX - total);
    ls->pending_bytes += total;
}

void ptcAckQueuePopFront(ptc_lstate_t *ls)
{
    const sbuf_ack_t *ack = sbuf_ack_queue_t_front(&ls->ack_queue);

    /*
     * Release must reconcile even if the invariant were broken: a counter that
     * ran low would otherwise wrap and make the next admission check accept an
     * unbounded backlog - exactly the failure the limit exists to prevent.
     */
    assert(ls->pending_bytes >= ack->total);
    ls->pending_bytes = (ls->pending_bytes >= ack->total) ? (ls->pending_bytes - ack->total) : 0;
    sbuf_ack_queue_t_pop_front(&ls->ack_queue);
}

bool ptcPendingBytesWouldOverflow(const ptc_tstate_t *ts, const ptc_lstate_t *ls, uint32_t len)
{
    if (UNLIKELY(ls->pending_bytes > ts->max_pending_bytes))
    {
        assert(false);
        return true;
    }
    return len > ts->max_pending_bytes - ls->pending_bytes;
}

bool ptcPendingEntriesExhausted(const ptc_tstate_t *ts, const ptc_lstate_t *ls)
{
    /*
     * A byte limit does not bound allocations: each retained payload owns a whole
     * pooled sbuf whatever its length, so one-byte callbacks reach the byte limit
     * only after retaining hundreds of thousands of buffers.
     */
    return (size_t) sbuf_ack_queue_t_size(&ls->ack_queue) >= (size_t) ts->max_pending_entries;
}

/*
 * A payload is paused only after its own record was just appended, so the record
 * that owns it is the last one - and appending to the back of `pause_queue`
 * keeps it the last element of the unwritten suffix too.
 */
void ptcPauseQueuePushBack(ptc_lstate_t *ls, sbuf_t *buf)
{
    /* Reserved by ptcReserveWriteSlots(), so this cannot allocate. */
    if (UNLIKELY(! bufferqueueTryPushBack(&ls->pause_queue, &buf)))
    {
        LOGF("PacketsToConnection: pause insertion failed after a successful reservation");
        abortProgramNow(1);
    }

    assert(ptcFrontPauseAckIndex(ls) + bufferqueueGetBufCount(&ls->pause_queue) ==
           (size_t) sbuf_ack_queue_t_size(&ls->ack_queue));
    sbuf_ack_queue_t_back_mut(&ls->ack_queue)->buf = buf;
}

/* Reinsertion of a buffer this queue just yielded; the slot is still free. */
void ptcPauseQueuePushFront(ptc_lstate_t *ls, sbuf_t *buf)
{
    if (UNLIKELY(! bufferqueueTryPushFront(&ls->pause_queue, &buf)))
    {
        LOGF("PacketsToConnection: pause reinsertion failed on a slot it had just released");
        abortProgramNow(1);
    }

    ptcPauseAckRecordAt(ls, ptcFrontPauseAckIndex(ls))->buf = buf;
}

bool ptcRequiredControlRefusedLocked(ptc_lstate_t *ls, const char *operation)
{
    tunnel_t     *t       = ls->tunnel;
    ptc_tstate_t *state   = tunnelGetState(t);
    bool          aborted = false;

    /* The caller already owns lwIP's core lock. Stop the exact producer before
     * publishing the allocation-free owner-worker reconciliation. */
    if (ls->kind == kPtcLineKindTcp)
    {
        struct tcp_pcb *pcb = ls->tcp_pcb;
        ptcDetachTcpPcbLocked(ls);
        if (pcb != NULL)
        {
            tcp_abort(pcb);
            aborted = true;
        }
    }
    else if (ls->kind == kPtcLineKindUdp)
    {
        ptcDetachUdpFlowLocked(ls);
    }

    mutexLock(&state->owned_lines_lock);
    ls->terminal_required = true;
    mutexUnlock(&state->owned_lines_lock);

    LOGE("PacketsToConnection: required owner control '%s' was refused; flow detached", operation);
    if (! requestProgramShutdown(1))
    {
        abortProgramNow(1);
    }
    return aborted;
}

ptc_flush_result_t ptcFlushWriteQueue(ptc_lstate_t *ls)
{
    struct tcp_pcb *tpcb      = ls->tcp_pcb;
    bool            wrote_any = false;

    if (tpcb == NULL)
    {
        return kPtcFlushTerminal;
    }

    while (bufferqueueGetBufCount(&ls->pause_queue) > 0)
    {
        /* Read before the pop: the pop is what shifts the suffix by one. */
        sbuf_ack_t *ack       = ptcPauseAckRecordAt(ls, ptcFrontPauseAckIndexOf(ls));
        sbuf_t     *buf       = bufferqueuePopFront(&ls->pause_queue);
        uint32_t    buf_len   = sbufGetLength(buf);
        uint16_t    available = tcp_sndbuf(tpcb);

        assert(ack->buf == buf);

        if (available == 0)
        {
            ls->write_paused = true;
            ptcPauseQueuePushFront(ls, buf);
            break;
        }

        uint16_t write_len = (uint16_t) min((uint32_t) available, buf_len);
        err_t    err       = tcp_write(tpcb, sbufGetMutablePtr(buf), write_len, TCP_WRITE_FLAG_COPY);

        if (err == ERR_MEM)
        {
            ls->write_paused = true;
            ptcPauseQueuePushFront(ls, buf);
            break;
        }
        if (err != ERR_OK)
        {
            ptcPauseQueuePushFront(ls, buf);
            tcp_poll(tpcb, NULL, 0);
            ls->write_poll_armed = false;
            return kPtcFlushTerminal;
        }

        wrote_any = true;

        if (write_len == buf_len)
        {
            /*
             * TCP_WRITE_FLAG_COPY means lwIP owns its own copy of every byte, so
             * holding this allocation until the peer acknowledges them buys
             * nothing. The record stays to carry the unacknowledged byte count;
             * only the storage goes back now.
             */
            ack->buf = NULL;
            lineReuseBuffer(ls->line, buf);
            continue;
        }

        sbufShiftRight(buf, write_len);
        ls->write_paused = true;
        ptcPauseQueuePushFront(ls, buf);
        break;
    }

    if (wrote_any)
    {
        tcp_output(tpcb);
    }

    if (bufferqueueGetBufCount(&ls->pause_queue) == 0)
    {
        ls->write_paused = false;
        if (ls->write_poll_armed)
        {
            tcp_poll(tpcb, NULL, 0);
            ls->write_poll_armed = false;
        }
        return kPtcFlushComplete;
    }

    if (! ls->write_poll_armed)
    {
        tcp_poll(tpcb, ptcTcpPollCallback, kPtcWritePollInterval);
        ls->write_poll_armed = true;
    }
    return kPtcFlushRetryable;
}

err_t ptcTcpSendCompleteCallback(void *arg, struct tcp_pcb *tpcb, u16_t len)
{
    // No owner-worker guard is needed here: tcp_sent only fires from ACK processing in
    // tcp_input(), which for this pcb always runs on the owning packet worker. So the
    // owner-pool ops below (lineReuseBuffer / lineScheduleTask) never run cross-worker.
    ptc_lstate_t *ls = arg;

    if (ls == NULL || ls->kind != kPtcLineKindTcp || ls->tcp_pcb != tpcb)
    {
        return ERR_OK;
    }

    while (len > 0 && ! sbuf_ack_queue_t_is_empty(&ls->ack_queue))
    {
        sbuf_ack_t *ack = sbuf_ack_queue_t_front_mut(&ls->ack_queue);

        /* A corrupt record must not turn the sent callback into an infinite loop. */
        assert(ack->written <= ack->total);
        if (UNLIKELY(ack->written > ack->total))
        {
            break;
        }

        const uint32_t remaining = ack->total - ack->written;
        const uint16_t cost      = (uint16_t) min(remaining, (uint32_t) len);

        if (UNLIKELY(cost == 0))
        {
            /* Completed records are normally removed by the write that completed them. */
            assert(remaining != 0);
            break;
        }

        ack->written += cost;
        len -= cost;

        if (ack->written == ack->total)
        {
            /*
             * A record can only be fully acknowledged once every one of its bytes
             * reached lwIP, and the flush releases the allocation at that moment -
             * so a completed record never still owns a buffer. The branch stays as
             * a Release-safe backstop rather than a leak.
             */
            assert(ack->buf == NULL);
            if (UNLIKELY(ack->buf != NULL))
            {
                lineReuseBuffer(ls->line, ack->buf);
            }
            ptcAckQueuePopFront(ls);
        }
    }

    if (ls->write_paused)
    {
        const ptc_flush_result_t result = ptcFlushWriteQueue(ls);
        if (result == kPtcFlushTerminal)
        {
            struct tcp_pcb *pcb = ls->tcp_pcb;
            ptcDetachTcpPcbLocked(ls);
            if (pcb != NULL)
            {
                tcp_abort(pcb);
            }
            if (lineIsAlive(ls->line) && ! lineScheduleTask(ls->line, ptcCloseLineTask, ls->tunnel))
            {
                discard ptcRequiredControlRefusedLocked(ls, "terminal-write close");
            }
            return ERR_ABRT;
        }
        if (! ls->write_paused && lineIsAlive(ls->line))
        {
            if (! lineScheduleTask(ls->line, ptcResumeUpstreamTask, ls->tunnel))
            {
                if (ptcRequiredControlRefusedLocked(ls, "write Resume"))
                {
                    return ERR_ABRT;
                }
            }
        }
    }

    return ERR_OK;
}

err_t ptcTcpPollCallback(void *arg, struct tcp_pcb *tpcb)
{
    ptc_lstate_t *ls = arg;

    if (ls == NULL || ls->tcp_pcb != tpcb || ls->kind != kPtcLineKindTcp)
    {
        return ERR_OK;
    }
    if (ls->write_retry_queued)
    {
        return ERR_OK;
    }

    ls->write_retry_queued = true;
    WW_WORKER_MESSAGE_BENCHMARK_RECORD_CONTINUATION(kWorkerMessageBenchmarkContinuationBridgeRetryOrDelivery);
    if (! lineIsAlive(ls->line) || ! lineScheduleTask(ls->line, ptcWriteRetryTask, ls->tunnel))
    {
        ls->write_retry_queued = false;
        tcp_poll(tpcb, NULL, 0);
        ls->write_poll_armed = false;
        if (ptcRequiredControlRefusedLocked(ls, "TCP write retry"))
        {
            return ERR_ABRT;
        }
    }
    return ERR_OK;
}

static void ptcUdpIdleTimerCallback(wtimer_t *timer)
{
    ptc_lstate_t *ls = weventGetUserdata(timer);
    assert(ls != NULL && ls->udp_idle_timer == timer);

    line_t   *l = ls->line;
    tunnel_t *t = ls->tunnel;
    assert(l != NULL && t != NULL && lineIsAlive(l));

    ls->udp_idle_timer = NULL;

    if (ptcNextGateEnter(t))
    {
        ptcCloseLineFromNetwork(t, l);
        ptcNextGateLeave(t);
    }
    else
    {
        ptcCloseLineForStop(t, l);
    }
    lineUnref(l);
}

bool ptcArmUdpIdleOnOwnerThread(ptc_lstate_t *ls)
{
    if (ls->kind != kPtcLineKindUdp)
    {
        return true;
    }

    ptc_tstate_t *ts = tunnelGetState(ls->tunnel);
    if (ls->udp_idle_timer != NULL)
    {
        wtimerReset(ls->udp_idle_timer, ts->udp_idle_timeout_ms);
        return true;
    }

    ls->udp_idle_timer = wtimerAdd(getCurrentEventWorkerLoop(), ptcUdpIdleTimerCallback, ts->udp_idle_timeout_ms, 1);
    if (ls->udp_idle_timer == NULL)
    {
        return false;
    }
    weventSetUserData(ls->udp_idle_timer, ls);
    lineRef(ls->line);
    return true;
}

void ptcCancelUdpIdleTimer(ptc_lstate_t *ls)
{
    if (ls->udp_idle_timer == NULL)
    {
        return;
    }
    weventSetUserData(ls->udp_idle_timer, NULL);
    wtimerDelete(ls->udp_idle_timer);
    ls->udp_idle_timer = NULL;
    lineUnref(ls->line);
}

bool ptcEnsureNextInit(tunnel_t *t, line_t *l, ptc_lstate_t *ls)
{
    if (ls->next_init_sent)
    {
        return true;
    }

    ls->next_init_sent = true;
    return lineCallWithRef(l, tunnelNextUpStreamInit, t);
}

void ptcOpenLineTask(tunnel_t *t, line_t *l)
{
    if (! ptcNextGateEnter(t))
    {
        ptcCloseLineForStop(t, l);
        return;
    }

    ptc_lstate_t *ls = lineGetState(l, t);

    if (! ptcEnsureNextInit(t, l, ls))
    {
        ptcNextGateLeave(t);
        return;
    }

    ls = lineGetState(l, t);
    if (ls->kind == kPtcLineKindUdp && ! ptcArmUdpIdleOnOwnerThread(ls))
    {
        ptcCloseLineFromNetwork(t, l);
    }
    ptcNextGateLeave(t);
}

void ptcDeliverPayloadTask(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    buffer_pool_t *pool = lineGetBufferPool(l);

    if (! ptcNextGateEnter(t))
    {
        bufferpoolReuseBuffer(pool, buf);
        ptcCloseLineForStop(t, l);
        return;
    }

    ptc_lstate_t *ls       = lineGetState(l, t);
    uint32_t      tcp_read = sbufGetLength(buf);

    if (! ptcEnsureNextInit(t, l, ls))
    {
        bufferpoolReuseBuffer(pool, buf);
        ptcNextGateLeave(t);
        return;
    }

    ls = lineGetState(l, t);

    if (ls->kind == kPtcLineKindUdp)
    {
        if (! ptcArmUdpIdleOnOwnerThread(ls))
        {
            bufferpoolReuseBuffer(pool, buf);
            ptcCloseLineFromNetwork(t, l);
            ptcNextGateLeave(t);
            return;
        }
        if (ls->read_paused)
        {
            lineReuseBuffer(l, buf);
            ptcNextGateLeave(t);
            return;
        }
    }

    if (! lineCallWithRefWithBuf(l, tunnelNextUpStreamPayload, t, buf))
    {
        ptcNextGateLeave(t);
        return;
    }

    ls = lineGetState(l, t);

    if (ls->kind == kPtcLineKindTcp)
    {
        if (ls->read_paused)
        {
            LOCK_TCPIP_CORE();
            const bool accumulated = ptcPausedReadAccumulateLocked(ls, tcp_read);
            UNLOCK_TCPIP_CORE();
            ptcNextGateLeave(t);
            discard accumulated;
            return;
        }

        LOCK_TCPIP_CORE();
        discard ptcReturnReceiveCreditLocked(ls, tcp_read);
        UNLOCK_TCPIP_CORE();
    }
    ptcNextGateLeave(t);
}

static void ptcCloseOwnedLine(tunnel_t *t, line_t *l, bool graceful_tcp, bool finish_next)
{
    if (! lineIsAlive(l))
    {
        return;
    }

    lineRef(l);

    ptc_lstate_t *ls = lineGetState(l, t);

    LOCK_TCPIP_CORE();
    if (ls->kind == kPtcLineKindTcp && ls->tcp_pcb != NULL)
    {
        bool                               drain_aborted = false;
        const ptc_tcp_drain_adopt_result_t adopted =
            graceful_tcp ? ptcTcpDrainAdoptLocked(t, ls, &drain_aborted) : kPtcTcpDrainFailed;
        discard drain_aborted;

        if (adopted != kPtcTcpDrainAdopted)
        {
            struct tcp_pcb *pcb = ls->tcp_pcb;
            ptcDetachTcpPcbLocked(ls);
            if (pcb != NULL)
            {
                tcp_abort(pcb);
            }
        }
    }
    else if (ls->kind == kPtcLineKindUdp)
    {
        ptcDetachUdpFlowLocked(ls);
    }
    UNLOCK_TCPIP_CORE();

    const bool send_finish = finish_next && ls->next_init_sent;
    ptcLinestateDestroy(ls);

    if (send_finish)
    {
        tunnelNextUpStreamFinish(t, l);
    }

    if (lineIsAlive(l))
    {
        lineDestroy(l);
    }

    lineUnref(l);
}

void ptcCloseLineFromNetwork(tunnel_t *t, line_t *l)
{
    ptcCloseOwnedLine(t, l, true, true);
}

void ptcCloseLineFromDownstream(tunnel_t *t, line_t *l)
{
    /* next sent Finish, so this close must never reflect a callback to next. */
    ptcCloseOwnedLine(t, l, true, false);
}

void ptcCloseLineOverPendingLimit(tunnel_t *t, line_t *l)
{
    /*
     * next is still open and produced the excess, so it gets exactly one
     * Finish. The PCB is reset instead of drained - see the header note.
     */
    ptcCloseOwnedLine(t, l, false, true);
}

void ptcCloseLineTask(tunnel_t *t, line_t *l)
{
    if (! ptcNextGateEnter(t))
    {
        ptcCloseLineForStop(t, l);
        return;
    }
    ptcCloseLineFromNetwork(t, l);
    ptcNextGateLeave(t);
}

void ptcResumeUpstreamTask(tunnel_t *t, line_t *l)
{
    if (! ptcNextGateEnter(t))
    {
        ptcCloseLineForStop(t, l);
        return;
    }
    discard lineCallWithRef(l, tunnelNextUpStreamResume, t);
    ptcNextGateLeave(t);
}

void ptcWriteRetryTask(tunnel_t *t, line_t *l)
{
    ptc_lstate_t      *ls;
    ptc_flush_result_t result = kPtcFlushTerminal;

    if (! lineIsAlive(l))
    {
        return;
    }

    ls = lineGetState(l, t);
    LOCK_TCPIP_CORE();
    ls->write_retry_queued = false;
    if (ls->tcp_pcb != NULL)
    {
        result = ptcFlushWriteQueue(ls);
        if (result == kPtcFlushTerminal)
        {
            struct tcp_pcb *pcb = ls->tcp_pcb;
            ptcDetachTcpPcbLocked(ls);
            tcp_abort(pcb);
        }
    }
    UNLOCK_TCPIP_CORE();

    if (result == kPtcFlushTerminal)
    {
        ptcCloseLineTask(t, l);
        return;
    }
    if (result == kPtcFlushComplete)
    {
        ptcResumeUpstreamTask(t, l);
    }
}

void ptcRefusedDataRetryTask(tunnel_t *t, line_t *l)
{
    if (! lineIsAlive(l))
    {
        return;
    }

    ptc_lstate_t *ls = lineGetState(l, t);
    LOCK_TCPIP_CORE();
    ls->refused_retry_queued = false;
    if (ls->kind == kPtcLineKindTcp && ls->tcp_pcb != NULL && ! ptcTunnelIsStopping(t))
    {
        discard tcp_process_refused_data(ls->tcp_pcb);
    }
    UNLOCK_TCPIP_CORE();
}

void ptcCloseLineForStop(tunnel_t *t, line_t *l)
{
    /*
     * PTC owns this normal line. Quiesce has already blocked ordinary next
     * callbacks, but chain hooks drain PTC before its next tunnel. An Init that
     * completed therefore still needs exactly one teardown Finish before the
     * owned line becomes dead and the next tunnel's line state is reclaimed.
     */
    ptcCloseOwnedLine(t, l, false, true);
}

void ptcDrainOwnedLinesOnCurrentWorker(tunnel_t *t, wid_t wid)
{
    ptc_tstate_t *state = tunnelGetState(t);

    assert(currentThreadIsEventWorkerWID(wid));
    if (state->owned_lines == NULL || wid >= state->owned_worker_count)
    {
        return;
    }

    for (;;)
    {
        mutexLock(&state->owned_lines_lock);
        line_t *line = state->owned_lines[wid];
        if (line != NULL)
        {
            lineRef(line);
        }
        mutexUnlock(&state->owned_lines_lock);

        if (line == NULL)
        {
            return;
        }

        ptcCloseLineForStop(t, line);
        lineUnref(line);
    }
}

void ptcDrainTerminalLinesOnCurrentWorker(tunnel_t *t, wid_t wid)
{
    ptc_tstate_t *state = tunnelGetState(t);

    assert(currentThreadIsEventWorkerWID(wid));
    if (state->owned_lines == NULL || wid >= state->owned_worker_count)
    {
        return;
    }

    for (;;)
    {
        line_t *terminal = NULL;

        mutexLock(&state->owned_lines_lock);
        for (line_t *line = state->owned_lines[wid]; line != NULL;)
        {
            ptc_lstate_t *ls = lineGetState(line, t);
            if (ls->terminal_required)
            {
                ls->terminal_required = false;
                lineRef(line);
                terminal = line;
                break;
            }
            line = ls->owned_next;
        }
        mutexUnlock(&state->owned_lines_lock);

        if (terminal == NULL)
        {
            return;
        }

        /* The producer PCB/map was already detached under the core lock. The
         * owner now performs line-state teardown, directionally legal Finish
         * (only if Init was sent), and the owner-only lineDestroy(). */
        ptcCloseLineForStop(t, terminal);
        lineUnref(terminal);
    }
}
