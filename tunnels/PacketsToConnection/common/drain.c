#include "structure.h"

#include "loggers/log_rate_limiter.h"
#include "loggers/network_logger.h"

/*
 * A post-line TCP closer.  The normal line may be destroyed as soon as Finish
 * returns, so this object owns only a PCB and a global-allocator copy of bytes
 * that tcp_write() had not yet accepted.  All access is under the lwIP core
 * lock, including callbacks from the timer thread.
 */

enum
{
    kPtcDrainLogIntervalMs = 5U * 1000U,
    kPtcDrainPollInterval  = 1
};

typedef enum ptc_closer_phase_e
{
    kPtcCloserDelivering = 0,
    kPtcCloserFinPending,
    kPtcCloserClosing
} ptc_closer_phase_t;

typedef enum ptc_drain_result_e
{
    kPtcDrainAlive = 0,
    kPtcDrainClosed,
    kPtcDrainAborted
} ptc_drain_result_t;

typedef enum ptc_pcb_close_state_e
{
    kPtcPcbFinPending = 0,
    kPtcPcbFinSent,
    kPtcPcbGracefulTerminal,
    kPtcPcbUnexpected
} ptc_pcb_close_state_t;

struct ptc_tcp_drain_s
{
    ptc_tcp_drain_t *next;
    ptc_tcp_drain_t *prev;
    tunnel_t        *tunnel;
    struct tcp_pcb  *pcb;
    uint64_t         deadline_ms;
    uint8_t         *bytes;
    uint32_t         len;
    uint32_t         written;
    uint8_t          phase;
    bool             peer_finished;
};

static atomic_log_rate_limiter_t g_ptc_drain_budget_log;
static atomic_log_rate_limiter_t g_ptc_drain_abort_log;
static atomic_log_rate_limiter_t g_ptc_drain_alloc_log;

static err_t ptcDrainRecvCallback(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err);
static err_t ptcDrainSentCallback(void *arg, struct tcp_pcb *pcb, u16_t len);
static err_t ptcDrainPollCallback(void *arg, struct tcp_pcb *pcb);
static void  ptcDrainErrorCallback(void *arg, err_t err);

static uint64_t ptcDrainNowMs(void)
{
    return (uint64_t) (getHRTimeUs() / 1000ULL);
}

err_t ptcTcpSendFinLocked(struct tcp_pcb *pcb)
{
    if (pcb->state != ESTABLISHED && pcb->state != CLOSE_WAIT && pcb->state != SYN_RCVD)
    {
        return ERR_CONN;
    }
    return tcp_shutdown(pcb, 0, 1);
}

static void ptcDrainUnlinkLocked(ptc_tstate_t *ts, ptc_tcp_drain_t *drain)
{
    if (drain->prev != NULL)
    {
        drain->prev->next = drain->next;
    }
    else
    {
        ts->drains = drain->next;
    }
    if (drain->next != NULL)
    {
        drain->next->prev = drain->prev;
    }
}

static void ptcDrainFreeLocked(ptc_tcp_drain_t *drain)
{
    ptc_tstate_t *ts = tunnelGetState(drain->tunnel);

    ptcDrainUnlinkLocked(ts, drain);
    ts->drain_bytes -= drain->len;
    --ts->drain_count;
    memoryFree(drain->bytes);
    memoryFree(drain);
}

static struct tcp_pcb *ptcDrainDetachPcbLocked(ptc_tcp_drain_t *drain)
{
    struct tcp_pcb *pcb = drain->pcb;

    if (pcb != NULL)
    {
        tcp_arg(pcb, NULL);
        tcp_recv(pcb, NULL);
        tcp_sent(pcb, NULL);
        tcp_poll(pcb, NULL, 0);
        tcp_err(pcb, NULL);
        pcb->connected = NULL;
        drain->pcb     = NULL;
    }
    return pcb;
}

static void ptcDrainInstallCallbacksLocked(ptc_tcp_drain_t *drain)
{
    tcp_arg(drain->pcb, drain);
    tcp_recv(drain->pcb, ptcDrainRecvCallback);
    tcp_sent(drain->pcb, ptcDrainSentCallback);
    tcp_poll(drain->pcb, ptcDrainPollCallback, kPtcDrainPollInterval);
    tcp_err(drain->pcb, ptcDrainErrorCallback);
    drain->pcb->connected = NULL;
}

static ptc_drain_result_t ptcDrainFinishLocked(ptc_tcp_drain_t *drain)
{
    discard ptcDrainDetachPcbLocked(drain);
    ptcDrainFreeLocked(drain);
    return kPtcDrainClosed;
}

static ptc_drain_result_t ptcDrainAbortLocked(ptc_tcp_drain_t *drain, const char *reason)
{
    if (atomicLogRateLimiterShouldLog(&g_ptc_drain_abort_log, kPtcDrainLogIntervalMs))
    {
        LOGW("PacketsToConnection: aborting a closing TCP flow (%s), %u byte(s) undelivered",
             reason,
             (unsigned int) (drain->len - drain->written));
    }

    struct tcp_pcb *pcb = ptcDrainDetachPcbLocked(drain);
    if (pcb != NULL)
    {
        tcp_abort(pcb);
    }
    ptcDrainFreeLocked(drain);
    return kPtcDrainAborted;
}

static ptc_pcb_close_state_t ptcDrainClassifyPcbLocked(const ptc_tcp_drain_t *drain)
{
    const struct tcp_pcb *pcb = drain->pcb;

    if (pcb->state == TIME_WAIT)
    {
        return kPtcPcbGracefulTerminal;
    }
    if ((pcb->flags & TF_CLOSEPEND) != 0)
    {
        return kPtcPcbFinPending;
    }
    if (pcb->state == FIN_WAIT_1 || pcb->state == FIN_WAIT_2 || pcb->state == CLOSING || pcb->state == LAST_ACK)
    {
        return kPtcPcbFinSent;
    }
    if (pcb->state == ESTABLISHED || pcb->state == CLOSE_WAIT || pcb->state == SYN_RCVD)
    {
        return kPtcPcbFinPending;
    }
    return kPtcPcbUnexpected;
}

static ptc_drain_result_t ptcDrainAdvanceLocked(ptc_tcp_drain_t *drain, uint64_t now_ms);

static ptc_drain_result_t ptcDrainEnterClosingLocked(ptc_tcp_drain_t *drain, uint64_t now_ms)
{
    drain->phase       = (uint8_t) kPtcCloserClosing;
    drain->deadline_ms = now_ms + (uint64_t) kPtcCloserPeerCloseTimeoutMs;
    return drain->peer_finished ? ptcDrainFinishLocked(drain) : kPtcDrainAlive;
}

static ptc_drain_result_t ptcDrainAdvanceDeliveringLocked(ptc_tcp_drain_t *drain, uint64_t now_ms)
{
    struct tcp_pcb *pcb       = drain->pcb;
    bool            wrote_any = false;

    if (UNLIKELY(now_ms >= drain->deadline_ms))
    {
        return ptcDrainAbortLocked(drain, "the delivery deadline expired");
    }

    while (drain->written < drain->len)
    {
        const uint16_t available = tcp_sndbuf(pcb);
        if (available == 0)
        {
            break;
        }

        const uint32_t remaining = drain->len - drain->written;
        const uint16_t amount    = (uint16_t) min((uint32_t) available, remaining);
        const err_t    result    = tcp_write(pcb, drain->bytes + drain->written, amount, TCP_WRITE_FLAG_COPY);

        if (result == ERR_MEM)
        {
            break;
        }
        if (result != ERR_OK)
        {
            return ptcDrainAbortLocked(drain, "lwIP refused the write");
        }
        drain->written += amount;
        wrote_any = true;
    }

    if (wrote_any)
    {
        tcp_output(pcb);
    }
    if (drain->written < drain->len)
    {
        return kPtcDrainAlive;
    }

    const err_t shutdown = ptcTcpSendFinLocked(pcb);
    if (shutdown != ERR_OK)
    {
        return ptcDrainAbortLocked(drain, "lwIP refused the shutdown");
    }

    const ptc_pcb_close_state_t state = ptcDrainClassifyPcbLocked(drain);
    if (state == kPtcPcbGracefulTerminal)
    {
        return ptcDrainFinishLocked(drain);
    }
    if (state == kPtcPcbFinPending)
    {
        drain->phase = (uint8_t) kPtcCloserFinPending;
        return kPtcDrainAlive;
    }
    if (state != kPtcPcbFinSent)
    {
        return ptcDrainAbortLocked(drain, "the PCB did not enter a FIN state");
    }
    return ptcDrainEnterClosingLocked(drain, now_ms);
}

static ptc_drain_result_t ptcDrainAdvanceLocked(ptc_tcp_drain_t *drain, uint64_t now_ms)
{
    if (drain->pcb == NULL)
    {
        ptcDrainFreeLocked(drain);
        return kPtcDrainClosed;
    }

    const ptc_pcb_close_state_t state = ptcDrainClassifyPcbLocked(drain);
    if (state == kPtcPcbGracefulTerminal)
    {
        return ptcDrainFinishLocked(drain);
    }

    if (drain->phase == (uint8_t) kPtcCloserClosing)
    {
        if (drain->peer_finished)
        {
            return ptcDrainFinishLocked(drain);
        }
        if (state != kPtcPcbFinSent)
        {
            return ptcDrainAbortLocked(drain, "the PCB left the active FIN states");
        }
        return now_ms >= drain->deadline_ms
                   ? ptcDrainAbortLocked(drain, "the peer never closed its half of the connection")
                   : kPtcDrainAlive;
    }

    if (drain->phase == (uint8_t) kPtcCloserFinPending)
    {
        if (state == kPtcPcbFinSent)
        {
            return ptcDrainEnterClosingLocked(drain, now_ms);
        }
        if (state == kPtcPcbUnexpected)
        {
            return ptcDrainAbortLocked(drain, "the PCB left the deferred-FIN states");
        }
        return now_ms >= drain->deadline_ms ? ptcDrainAbortLocked(drain, "the FIN allocation deadline expired")
                                            : kPtcDrainAlive;
    }

    return ptcDrainAdvanceDeliveringLocked(drain, now_ms);
}

static err_t ptcDrainSentCallback(void *arg, struct tcp_pcb *pcb, u16_t len)
{
    discard          len;
    ptc_tcp_drain_t *drain = arg;
    if (drain == NULL || drain->pcb != pcb)
    {
        return ERR_OK;
    }
    return ptcDrainAdvanceLocked(drain, ptcDrainNowMs()) == kPtcDrainAborted ? ERR_ABRT : ERR_OK;
}

static err_t ptcDrainPollCallback(void *arg, struct tcp_pcb *pcb)
{
    ptc_tcp_drain_t *drain = arg;
    if (drain == NULL || drain->pcb != pcb)
    {
        return ERR_OK;
    }
    return ptcDrainAdvanceLocked(drain, ptcDrainNowMs()) == kPtcDrainAborted ? ERR_ABRT : ERR_OK;
}

static err_t ptcDrainRecvCallback(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    ptc_tcp_drain_t *drain = arg;

    if (drain == NULL || drain->pcb != pcb)
    {
        if (p != NULL)
        {
            pbuf_free(p);
        }
        return ERR_OK;
    }
    if (err != ERR_OK)
    {
        if (p != NULL)
        {
            pbuf_free(p);
        }
        return ptcDrainAbortLocked(drain, "the peer reported a receive error") == kPtcDrainAborted ? ERR_ABRT : ERR_OK;
    }
    if (p == NULL)
    {
        drain->peer_finished = true;
        return ptcDrainAdvanceLocked(drain, ptcDrainNowMs()) == kPtcDrainAborted ? ERR_ABRT : ERR_OK;
    }

    const ptc_drain_result_t advanced = ptcDrainAdvanceLocked(drain, ptcDrainNowMs());
    if (advanced != kPtcDrainAlive)
    {
        pbuf_free(p);
        return advanced == kPtcDrainAborted ? ERR_ABRT : ERR_OK;
    }

    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
}

static void ptcDrainErrorCallback(void *arg, err_t err)
{
    ptc_tcp_drain_t *drain = arg;
    if (drain == NULL)
    {
        return;
    }
    LOGD("PacketsToConnection: closing TCP flow failed with error %d, %u byte(s) undelivered",
         (int) err,
         (unsigned int) (drain->len - drain->written));
    drain->pcb = NULL;
    ptcDrainFreeLocked(drain);
}

static uint8_t *ptcDrainTakeBytes(ptc_lstate_t *ls, uint32_t total)
{
    uint8_t *bytes = memoryAllocate(total);
    if (bytes == NULL)
    {
        return NULL;
    }

    uint32_t offset = 0;
    size_t   index  = ptcFrontPauseAckIndexOf(ls);

    while (bufferqueueGetBufCount(&ls->pause_queue) > 0)
    {
        sbuf_t        *buf = bufferqueuePopFront(&ls->pause_queue);
        const uint32_t len = sbufGetLength(buf);

        assert(offset + len <= total);
        memoryCopy(bytes + offset, sbufGetRawPtr(buf), len);
        offset += len;

        /*
         * The record stays, holding its `total` against `pending_bytes`; only
         * the buffer ownership moves. Adoption is always immediately followed by
         * ptcLinestateDestroy(), which drops every record and reconciles the
         * counter to zero in one place. Records and paused buffers are in the
         * same order, so this stays single-pass.
         */
        sbuf_ack_t *ack = ptcPauseAckRecordAt(ls, index);
        assert(ack->buf == buf);
        ack->buf = NULL;
        ++index;

        lineReuseBuffer(ls->line, buf);
    }
    assert(offset == total);
    return bytes;
}

ptc_tcp_drain_adopt_result_t ptcTcpDrainAdoptLocked(tunnel_t *t, ptc_lstate_t *ls, bool *out_aborted)
{
    ptc_tstate_t *ts = tunnelGetState(t);
    *out_aborted     = false;

    if (ls->tcp_pcb == NULL)
    {
        return kPtcTcpDrainNotNeeded;
    }

    const size_t queued = bufferqueueGetBufLen(&ls->pause_queue);
    if (queued > UINT32_MAX || ts->drain_bytes + queued > kPtcMaxDrainBytesTotal || ts->drain_count >= kPtcMaxDrains)
    {
        if (atomicLogRateLimiterShouldLog(&g_ptc_drain_budget_log, kPtcDrainLogIntervalMs))
        {
            LOGW("PacketsToConnection: resetting a closing flow because the bounded closer budget is full");
        }
        return kPtcTcpDrainFailed;
    }

    if (! ptcPausedReadAccumulateLocked(ls, 0) ||
        (ls->rx_uncredited > 0 && ! ptcReturnReceiveCreditLocked(ls, ls->rx_uncredited)))
    {
        return kPtcTcpDrainFailed;
    }
    ls->read_paused_len = 0;

    ptc_tcp_drain_t *drain = memoryAllocateZero(sizeof(*drain));
    if (drain == NULL)
    {
        if (atomicLogRateLimiterShouldLog(&g_ptc_drain_alloc_log, kPtcDrainLogIntervalMs))
        {
            LOGW("PacketsToConnection: out of memory for a closing TCP flow");
        }
        return kPtcTcpDrainFailed;
    }

    const uint32_t total = (uint32_t) queued;
    if (total > 0)
    {
        drain->bytes = ptcDrainTakeBytes(ls, total);
        if (drain->bytes == NULL)
        {
            memoryFree(drain);
            return kPtcTcpDrainFailed;
        }
    }

    drain->tunnel        = t;
    drain->pcb           = ls->tcp_pcb;
    drain->len           = total;
    drain->deadline_ms   = ptcDrainNowMs() + (uint64_t) kPtcDrainTimeoutMs;
    drain->peer_finished = drain->pcb->state == CLOSE_WAIT;

    drain->next = ts->drains;
    if (ts->drains != NULL)
    {
        ts->drains->prev = drain;
    }
    ts->drains = drain;
    ts->drain_bytes += total;
    ++ts->drain_count;

    tcp_output(ls->tcp_pcb);

    ptcDetachTcpPcbLocked(ls);
    ptcDrainInstallCallbacksLocked(drain);
    *out_aborted = ptcDrainAdvanceLocked(drain, ptcDrainNowMs()) == kPtcDrainAborted;
    return kPtcTcpDrainAdopted;
}

void ptcTcpDrainDestroyAllLocked(tunnel_t *t)
{
    ptc_tstate_t *ts = tunnelGetState(t);
    while (ts->drains != NULL)
    {
        ptc_tcp_drain_t *drain = ts->drains;
        struct tcp_pcb  *pcb   = ptcDrainDetachPcbLocked(drain);
        if (pcb != NULL)
        {
            tcp_abort(pcb);
        }
        ptcDrainFreeLocked(drain);
    }
}

uint32_t ptcTcpDrainCount(tunnel_t *t)
{
    ptc_tstate_t *ts = tunnelGetState(t);
    uint32_t      count;

    LOCK_TCPIP_CORE();
    count = ts->drain_count;
    UNLOCK_TCPIP_CORE();
    return count;
}
