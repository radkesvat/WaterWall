#include "structure.h"

#include "loggers/network_logger.h"

/*
 * The acknowledgement queue and the pause queue are two views of the same
 * ordered payloads. Every record whose buffer is still unwritten sits in a
 * contiguous suffix of `ack_queue`, in exactly the order `pause_queue` holds
 * those buffers - a payload only becomes "paused" after every earlier one
 * already is. So the record owning the front paused buffer is at this index, and
 * no search is needed. The previous linear association made both admission and
 * teardown quadratic in the number of retained payloads.
 */
size_t ptcFrontPauseAckIndexOf(const ptc_lstate_t *ls)
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

void ptcReserveWriteSlots(ptc_lstate_t *ls)
{
    /* Admission caps both queues at kPtcMaxPendingEntries before reserving.
     * Reserve outside assertions so Release builds perform the growth too. */
    const bool ack_reserved   = sbuf_ack_queue_t_reserve(&ls->ack_queue, sbuf_ack_queue_t_size(&ls->ack_queue) + 1);
    const bool pause_reserved = bufferqueueReserveExtra(&ls->pause_queue, 1);
    assert(ack_reserved && pause_reserved);
    discard ack_reserved;
    discard pause_reserved;
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

    /* A record owns a charged payload total. Underflow means ownership or
     * accounting corruption, so Release must not silently enlarge admission. */
    if (UNLIKELY(ls->pending_bytes < ack->total))
    {
        LOGF("PacketsToConnection: acknowledgement total exceeds pending byte charge");
        abortProgramNow(1);
    }
    ls->pending_bytes -= ack->total;
    sbuf_ack_queue_t_pop_front(&ls->ack_queue);
}

bool ptcPendingBytesWouldOverflow(const ptc_tstate_t *ts, const ptc_lstate_t *ls, uint32_t len)
{
    // Fixed headroom covers bytes delivered before Pause can take effect.
    const uint64_t maximum = (uint64_t) ts->max_pending_bytes + kPtcPendingDeliveryHeadroom;
    return ls->pending_bytes > maximum || len > maximum - ls->pending_bytes;
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

    assert(ptcFrontPauseAckIndexOf(ls) + bufferqueueGetBufCount(&ls->pause_queue) ==
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

    ptcPauseAckRecordAt(ls, ptcFrontPauseAckIndexOf(ls))->buf = buf;
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
        ptcPauseQueuePushFront(ls, buf);
        /* A 16-bit tcp_write() may leave a suffix while the scaled send
         * buffer still has capacity. Keep this record at the FIFO head and
         * continue until capacity or allocation actually refuses progress. */
    }

    if (wrote_any)
    {
        tcp_output(tpcb);
    }

    const ptc_tstate_t *state = tunnelGetState(ls->tunnel);
    if (bufferqueueGetBufCount(&ls->pause_queue) == 0 && ls->pending_bytes <= state->max_pending_bytes)
    {
        ls->write_paused = false;
        if (ls->write_poll_armed)
        {
            tcp_poll(tpcb, NULL, 0);
            ls->write_poll_armed = false;
        }
        return kPtcFlushComplete;
    }

    // An empty write queue may still have a large charged ACK record. Keep
    // production paused until the configured budget can admit the next delivery.
    ls->write_paused = true;
    if (! ls->write_poll_armed)
    {
        tcp_poll(tpcb, ptcTcpPollCallback, kPtcWritePollInterval);
        ls->write_poll_armed = true;
    }
    return kPtcFlushRetryable;
}

err_t ptcTcpSendCompleteCallback(void *arg, struct tcp_pcb *tpcb, u16_t len)
{
    /* ACK processing runs in this PCB's owner engine. Buffer recycling and
     * deferred line delivery retain that same event-worker affinity. */
    ptc_lstate_t *ls = arg;

    if (ls == NULL || ls->kind != kPtcLineKindTcp || ls->tcp_pcb != tpcb)
    {
        return ERR_OK;
    }

    assert(currentThreadOwnsWorker(lineGetWID(ls->line)));
    assert(wwLwipEngineCurrent() == ls->engine);

    while (len > 0 && ! sbuf_ack_queue_t_is_empty(&ls->ack_queue))
    {
        sbuf_ack_t *ack = sbuf_ack_queue_t_front_mut(&ls->ack_queue);

        /* Every active record has unacknowledged bytes. Invalid progress
         * would strand its ownership and invalidate the pending-byte budget. */
        if (UNLIKELY(ack->written >= ack->total))
        {
            LOGF("PacketsToConnection: invalid acknowledgement record progress");
            abortProgramNow(1);
        }

        const uint32_t remaining = ack->total - ack->written;
        const uint16_t cost      = (uint16_t) min(remaining, (uint32_t) len);

        ack->written += cost;
        len -= cost;

        if (ack->written == ack->total)
        {
            /* Fully copied buffers were released by the write path. A live
             * buffer here still belongs to pause_queue and cannot be recycled. */
            if (UNLIKELY(ack->buf != NULL))
            {
                LOGF("PacketsToConnection: completed acknowledgement still owns a paused buffer");
                abortProgramNow(1);
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
            if (lineIsAlive(ls->line))
            {
                const line_task_submit_result_e submit_result =
                    lineScheduleTask(ls->line, ptcCloseLineTask, ls->tunnel, NULL);
                if (submit_result == kLineTaskSubmitRejectedSettled)
                {
                    discard ptcRequiredControlRefusedLocked(ls, "terminal-write close");
                }
                else
                {
                    assert(submit_result == kLineTaskSubmitAcceptedAsync);
                }
            }
            return ERR_ABRT;
        }
        if (! ls->write_paused && lineIsAlive(ls->line))
        {
            const line_task_submit_result_e submit_result =
                lineScheduleTask(ls->line, ptcResumeUpstreamTask, ls->tunnel, NULL);
            if (submit_result == kLineTaskSubmitRejectedSettled)
            {
                if (ptcRequiredControlRefusedLocked(ls, "write Resume"))
                {
                    return ERR_ABRT;
                }
            }
            else
            {
                assert(submit_result == kLineTaskSubmitAcceptedAsync);
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

    ls->write_retry_queued                  = true;
    line_task_submit_result_e submit_result = kLineTaskSubmitRejectedSettled;
    if (lineIsAlive(ls->line))
    {
        submit_result = lineScheduleTask(ls->line, ptcWriteRetryTask, ls->tunnel, NULL);
    }
    if (submit_result == kLineTaskSubmitRejectedSettled)
    {
        ls->write_retry_queued = false;
        tcp_poll(tpcb, NULL, 0);
        ls->write_poll_armed = false;
        if (ptcRequiredControlRefusedLocked(ls, "TCP write retry"))
        {
            return ERR_ABRT;
        }
    }
    else
    {
        assert(submit_result == kLineTaskSubmitAcceptedAsync);
    }
    return ERR_OK;
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
    ww_lwip_engine_t *previous;
    const bool        entered = wwLwipEngineEnter(ls->engine, &previous);
    assert(entered);
    discard entered;
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
    wwLwipEngineLeave(ls->engine, previous);

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
