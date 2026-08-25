#include "structure.h"

#include "loggers/network_logger.h"

#include "loggers/log_rate_limiter.h"

enum
{
    kPtcUdpMaxPayloadLen       = UINT16_MAX - IP_HLEN - UDP_HLEN,
    kPtcUdpDropLogIntervalMs   = 5U * 1000U,
    kPtcOverLimitLogIntervalMs = 5U * 1000U
};

static atomic_log_rate_limiter_t udp_oversize_log;
static atomic_log_rate_limiter_t udp_send_error_log;
static atomic_log_rate_limiter_t tcp_over_limit_log;

/* What the caller still owes after a core-locked write attempt. */
typedef enum ptc_write_outcome_e
{
    /* lwIP or the acknowledgement queue owns the buffer; nothing further. */
    kPtcWriteOwned = 0,
    /* The buffer went nowhere and must be recycled. */
    kPtcWriteReuse,
    /* The buffer is queued; next must be told to stop producing. */
    kPtcWritePause,
    /* The PCB was reset; the owned line must be closed toward the network. */
    kPtcWriteTerminal,
    /* Admission refused these bytes; recycle them, then shed the flow. */
    kPtcWriteOverLimit,
    /* No room could be reserved for this flow's bookkeeping; shed only it. */
    kPtcWriteNoMemory
} ptc_write_outcome_t;

static void ptcArmWritePollLocked(ptc_lstate_t *ls, struct tcp_pcb *tpcb)
{
    if (! ls->write_poll_armed)
    {
        tcp_poll(tpcb, ptcTcpPollCallback, kPtcWritePollInterval);
        ls->write_poll_armed = true;
    }
}

static ptc_write_outcome_t ptcQueueForRetryLocked(ptc_lstate_t *ls, struct tcp_pcb *tpcb, sbuf_t *buf)
{
    ls->write_paused = true;
    ptcPauseQueuePushBack(ls, buf);
    ptcArmWritePollLocked(ls, tpcb);
    return kPtcWritePause;
}

/*
 * Requires LOCK_TCPIP_CORE(). Admission runs before the acknowledgement record
 * exists, so a refusal leaves every queue exactly as it found them and the
 * caller still owns `buf`.
 */
static ptc_write_outcome_t ptcTcpWriteLocked(ptc_tstate_t *ts, ptc_lstate_t *ls, sbuf_t *buf, uint32_t buf_len)
{
    struct tcp_pcb *tpcb = ls->tcp_pcb;

    if (tpcb == NULL)
    {
        return kPtcWriteReuse;
    }

    if (UNLIKELY(ptcPendingBytesWouldOverflow(ts, ls, buf_len) || ptcPendingEntriesExhausted(ts, ls)))
    {
        return kPtcWriteOverLimit;
    }

    /*
     * Both the acknowledgement slot and the pause slot this payload may need are
     * reserved before anything is handed over, so from here on no insertion can
     * fail and there is no point at which the queues disagree about ownership.
     */
    if (UNLIKELY(! ptcReserveWriteSlots(ls)))
    {
        return kPtcWriteNoMemory;
    }

    const uint16_t available = tcp_sndbuf(tpcb);

    ptcAckQueuePushBack(ls, buf, buf_len);

    if (ls->write_paused || available == 0)
    {
        return ptcQueueForRetryLocked(ls, tpcb, buf);
    }

    const uint16_t write_len = (uint16_t) min((uint32_t) available, buf_len);
    const err_t    err       = tcp_write(tpcb, sbufGetMutablePtr(buf), write_len, TCP_WRITE_FLAG_COPY);

    if (err == ERR_MEM)
    {
        return ptcQueueForRetryLocked(ls, tpcb, buf);
    }

    if (err != ERR_OK)
    {
        /* The record already owns `buf`; line destruction releases it. */
        ptcDetachTcpPcbLocked(ls);
        tcp_abort(tpcb);
        return kPtcWriteTerminal;
    }

    tcp_output(tpcb);

    if (write_len != buf_len)
    {
        sbufShiftRight(buf, write_len);
        return ptcQueueForRetryLocked(ls, tpcb, buf);
    }

    /*
     * lwIP copied every byte, so the allocation is no longer needed - only the
     * record, which still owes the peer's acknowledgement. Releasing here is what
     * keeps a fast flow from holding one pooled buffer per unacknowledged write.
     */
    sbuf_ack_queue_t_back_mut(&ls->ack_queue)->buf = NULL;
    return kPtcWriteReuse;
}

/* Requires LOCK_TCPIP_CORE(). UDP retains nothing, so it needs no admission. */
static ptc_write_outcome_t ptcUdpSendLocked(ptc_lstate_t *ls, sbuf_t *buf, uint32_t buf_len)
{
    if (ls->udp_pcb == NULL)
    {
        return kPtcWriteReuse;
    }

    /* The size guard in the caller makes this narrowing explicit and lossless. */
    const u16_t  udp_len = (u16_t) buf_len;
    struct pbuf *p       = pbufAlloc(PBUF_TRANSPORT, udp_len, PBUF_POOL);

    if (p == NULL || pbuf_take(p, sbufGetMutablePtr(buf), udp_len) != ERR_OK)
    {
        if (p != NULL)
        {
            pbuf_free(p);
        }
        return kPtcWriteReuse;
    }

    const err_t err = udp_sendfrom(ls->udp_pcb, p, &ls->udp_local_addr, ls->udp_local_port);
    if (UNLIKELY(err != ERR_OK) && atomicLogRateLimiterShouldLog(&udp_send_error_log, kPtcUdpDropLogIntervalMs))
    {
        LOGW("PacketsToConnection: dropping a UDP payload after lwIP send error %d", err);
    }
    pbuf_free(p);
    return kPtcWriteReuse;
}

/* True when the caller has already disposed of `buf` and must return. */
static bool ptcRejectDownStreamPayload(tunnel_t *t, line_t *l, ptc_lstate_t *ls, sbuf_t *buf, uint32_t buf_len)
{
    if (ls->kind == kPtcLineKindTcp)
    {
        if (UNLIKELY(buf_len == 0))
        {
            lineReuseBuffer(l, buf);
            return true;
        }
        return false;
    }

    if (UNLIKELY(buf_len > kPtcUdpMaxPayloadLen))
    {
        if (atomicLogRateLimiterShouldLog(&udp_oversize_log, kPtcUdpDropLogIntervalMs))
        {
            LOGW("PacketsToConnection: dropping an oversized UDP payload (%u bytes, maximum %u)",
                 (unsigned int) buf_len,
                 (unsigned int) kPtcUdpMaxPayloadLen);
        }
        lineReuseBuffer(l, buf);
        return true;
    }

    if (! ptcArmUdpIdleOnOwnerThread(ls))
    {
        lineReuseBuffer(l, buf);
        ptcCloseLineFromNetwork(t, l);
        return true;
    }

    return false;
}

void ptcTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ptc_tstate_t *ts = tunnelGetState(t);
    ptc_lstate_t *ls = lineGetState(l, t);

    assert(lineIsAlive(l));

    const uint32_t buf_len = sbufGetLength(buf);

    if (ptcRejectDownStreamPayload(t, l, ls, buf, buf_len))
    {
        return;
    }

    LOCK_TCPIP_CORE();
    const ptc_write_outcome_t outcome =
        (ls->kind == kPtcLineKindTcp) ? ptcTcpWriteLocked(ts, ls, buf, buf_len) : ptcUdpSendLocked(ls, buf, buf_len);
    UNLOCK_TCPIP_CORE();

    if (outcome == kPtcWriteReuse || outcome == kPtcWriteOverLimit || outcome == kPtcWriteNoMemory)
    {
        lineReuseBuffer(l, buf);
    }

    if (outcome == kPtcWriteOverLimit || outcome == kPtcWriteNoMemory)
    {
        if (atomicLogRateLimiterShouldLog(&tcp_over_limit_log, kPtcOverLimitLogIntervalMs))
        {
            if (outcome == kPtcWriteOverLimit)
            {
                LOGW("PacketsToConnection: retained payload passed max-pending-bytes (%u) or %u entries, "
                     "closing the flow",
                     (unsigned int) ts->max_pending_bytes,
                     (unsigned int) ts->max_pending_entries);
            }
            else
            {
                // One flow's bookkeeping, not the process: every other flow keeps working.
                LOGW("PacketsToConnection: out of memory queueing a payload, closing the flow");
            }
        }
        ptcCloseLineOverPendingLimit(t, l);
        return;
    }

    if (outcome == kPtcWriteTerminal)
    {
        ptcCloseLineFromNetwork(t, l);
        return;
    }

    if (outcome == kPtcWritePause)
    {
        if (ptcNextGateEnter(t))
        {
            discard lineCallWithRef(l, tunnelNextUpStreamPause, t);
            ptcNextGateLeave(t);
        }
    }
}
