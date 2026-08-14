#include "structure.h"

#include "loggers/network_logger.h"

#include "loggers/log_rate_limiter.h"

/*
 * Finishing a TCP flow that still owes the peer bytes.
 *
 * A borrowed line can be finished at any moment, including while the send window
 * is full or before the handshake has even completed. The bytes already sitting
 * in the line's pending queue were accepted by this node - the application was
 * told they were taken - so dropping them on Finish would be silent data loss on
 * an otherwise orderly close. tcp_close() preserves what lwIP already copied; it
 * cannot preserve what never reached lwIP.
 *
 * So the pcb and the remaining bytes move here, to an object the CTP instance
 * owns rather than the line. That ownership boundary is the whole point: the
 * line's owner may call lineDestroy() the instant its Finish handler returns, so
 * a drain must not retain a line_t, a ctp_lstate_t, or a worker-local pool
 * buffer. The bytes are copied into one global-allocator block on the way in.
 *
 * Everything here runs under LOCK_TCPIP_CORE(). The drain's callbacks are lwIP's
 * own, and two of them - sent and poll - can arrive on the lwIP timer thread
 * rather than on the worker the flow started on, which is the other reason
 * nothing worker-local may be reachable from this object.
 *
 * Nothing here ever calls a neighboring tunnel. The side that would have been
 * notified is the side that finished the line.
 */

enum
{
    kCtpDrainLogIntervalMs = 5U * 1000U,

    /*
     * tcp_poll() ticks in units of the 500 ms coarse timer. Twice a second is
     * often enough to retry a blocked write or a refused close without adding
     * meaningful work to the timer thread.
     */
    kCtpDrainPollInterval = 1
};

static atomic_log_rate_limiter_t g_drain_budget_log;
static atomic_log_rate_limiter_t g_drain_abort_log;
static atomic_log_rate_limiter_t g_drain_alloc_log;

struct ctp_tcp_drain_s
{
    ctp_tcp_drain_t *next;
    ctp_tcp_drain_t *prev;

    tunnel_t       *tunnel;
    struct tcp_pcb *pcb;

    /* Copies, so the registry entry can be found again without the line. */
    ctp_flow_key_t flow_key;
    uint64_t       generation;

    /*
     * Whichever deadline the current phase is under. Delivery and peer-close are
     * separate bounds, so entering the closing phase rearms this rather than
     * continuing to burn the delivery budget.
     */
    uint64_t deadline_ms;

    uint8_t *bytes;
    uint32_t len;
    uint32_t written; /* bytes tcp_write() has accepted so far */

    uint8_t phase;

    /* A SYN_SENT drain may queue bytes, but must not close before SYN-ACK. */
    bool established;

    /* The peer has stopped sending; its own FIN has arrived. */
    bool peer_finished;
};

/*
 * The closer has exactly three phases and only ever moves forward.
 *
 * The transition is irreversible on purpose. tcp_shutdown() can close the
 * sending half exactly once - lwIP returns ERR_CONN if it is asked again - and
 * the old fallback to tcp_close() for the states that follow was a defect: a
 * close sets TF_RXCLOSED, and tcp_input() resets a connection whose peer sends
 * legal data after that flag is set. A half-close is precisely the arrangement
 * where the peer is still entitled to send.
 */
typedef enum ctp_closer_phase_e
{
    /* Handing the remaining bytes to lwIP. The FIN has not been sent yet. */
    kCtpCloserDelivering = 0,

    /* lwIP accepted shutdown but could not allocate the FIN segment yet. */
    kCtpCloserFinPending,

    /* The pcb changed to a FIN state. Credit, peer EOF and the deadline remain. */
    kCtpCloserClosing
} ctp_closer_phase_t;

typedef enum ctp_drain_advance_result_e
{
    kCtpDrainAlive = 0,
    kCtpDrainClosed,
    kCtpDrainAborted
} ctp_drain_advance_result_t;

typedef enum ctp_drain_pcb_close_state_e
{
    kCtpDrainPcbFinPending = 0,
    kCtpDrainPcbFinSent,
    kCtpDrainPcbGracefulTerminal,
    kCtpDrainPcbUnexpected
} ctp_drain_pcb_close_state_t;

static err_t ctpDrainConnectedCallback(void *arg, struct tcp_pcb *tpcb, err_t err);
static err_t ctpDrainRecvCallback(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
static err_t ctpDrainSentCallback(void *arg, struct tcp_pcb *tpcb, u16_t len);
static err_t ctpDrainPollCallback(void *arg, struct tcp_pcb *tpcb);
static void  ctpDrainErrorCallback(void *arg, err_t err);

// ---------------------------------------------------------------------------
// list and lifetime
// ---------------------------------------------------------------------------

static void ctpDrainUnlinkLocked(ctp_tstate_t *ts, ctp_tcp_drain_t *drain)
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

    drain->next = NULL;
    drain->prev = NULL;
}

/*
 * Releases the drain's memory and its place in the instance list. The pcb is
 * handled by the caller, which is what decides whether this was a graceful
 * finish or an abort.
 */
static void ctpDrainFreeLocked(ctp_tstate_t *ts, ctp_tcp_drain_t *drain)
{
    ctpDrainUnlinkLocked(ts, drain);

    ts->drain_bytes -= drain->len;
    --ts->drain_count;
    memoryFree(drain->bytes);
    memoryFree(drain);
}

/*
 * Detaches lwIP from the drain so no further callback can reach it.
 *
 * Every finish path goes through here first, which is what makes the object safe
 * to free immediately afterwards even when the call that got us here came from
 * inside one of these callbacks.
 */
static struct tcp_pcb *ctpDrainDetachPcbLocked(ctp_tcp_drain_t *drain)
{
    struct tcp_pcb *pcb = drain->pcb;

    if (pcb == NULL)
    {
        return NULL;
    }

    tcp_arg(pcb, NULL);
    tcp_recv(pcb, NULL);
    tcp_sent(pcb, NULL);
    tcp_poll(pcb, NULL, 0);
    tcp_err(pcb, NULL);
    pcb->connected = NULL;
    drain->pcb     = NULL;
    return pcb;
}

static void ctpDrainInstallCallbacksLocked(ctp_tcp_drain_t *drain)
{
    struct tcp_pcb *pcb = drain->pcb;

    assert(pcb != NULL);
    tcp_arg(pcb, drain);
    tcp_recv(pcb, ctpDrainRecvCallback);
    tcp_sent(pcb, ctpDrainSentCallback);
    tcp_poll(pcb, ctpDrainPollCallback, kCtpDrainPollInterval);
    tcp_err(pcb, ctpDrainErrorCallback);
    pcb->connected = ctpDrainConnectedCallback;
}

/*
 * The drain is over. `graceful` says whether the peer got everything: it decides
 * both how the pcb goes away and whether the tuple keeps routing afterwards.
 */
static void ctpDrainRetireAndFreeLocked(ctp_tcp_drain_t *drain, bool graceful)
{
    tunnel_t            *t          = drain->tunnel;
    ctp_tstate_t        *ts         = tunnelGetState(t);
    const ctp_flow_key_t flow_key   = drain->flow_key;
    const uint64_t       generation = drain->generation;

    ctpFlowRetireDrainLocked(t, &flow_key, generation, graceful);
    ctpDrainFreeLocked(ts, drain);
}

/*
 * The FIN is out and the peer has stopped sending, so lwIP can finish the
 * connection on its own. Detaching first is what makes freeing the closer safe
 * even when this is reached from inside one of its callbacks; from here lwIP's
 * default receive handler credits and releases anything that still arrives.
 */
static ctp_drain_advance_result_t ctpDrainFinishClosedLocked(ctp_tcp_drain_t *drain)
{
    discard ctpDrainDetachPcbLocked(drain);
    ctpDrainRetireAndFreeLocked(drain, true);
    return kCtpDrainClosed;
}

static ctp_drain_advance_result_t ctpDrainAbortLocked(ctp_tcp_drain_t *drain, const char *why)
{
    if (atomicLogRateLimiterShouldLog(&g_drain_abort_log, kCtpDrainLogIntervalMs))
    {
        LOGW("ConnectionToPackets: aborting a closing TCP flow (%s), %u byte(s) undelivered",
             why,
             (unsigned int) (drain->len - drain->written));
    }

    struct tcp_pcb *pcb = ctpDrainDetachPcbLocked(drain);
    if (pcb != NULL)
    {
        tcp_abort(pcb);
    }
    ctpDrainRetireAndFreeLocked(drain, false);
    return kCtpDrainAborted;
}

// ---------------------------------------------------------------------------
// progress
// ---------------------------------------------------------------------------

/*
 * The second phase: the FIN is out and every byte is with lwIP.
 *
 * Deliberately does nothing to the pcb. Re-running the shutdown is what R6-01
 * called out - lwIP would refuse it and the old helper answered that refusal
 * with tcp_close(), setting TF_RXCLOSED and turning the peer's next legal byte
 * into a reset. All that is left is to notice the peer finishing, and to stop
 * waiting if it never does.
 */
static ctp_drain_advance_result_t ctpDrainAdvanceClosingLocked(ctp_tcp_drain_t *drain, uint64_t now_ms)
{
    if (drain->peer_finished)
    {
        return ctpDrainFinishClosedLocked(drain);
    }

    if (UNLIKELY(now_ms >= drain->deadline_ms))
    {
        /*
         * Handing it to lwIP here would be handing it to nobody: a TX-only
         * shutdown leaves TF_RXCLOSED clear, and tcp_slowtmr() only reaps
         * FIN_WAIT_2 when that flag is set. The pcb, its registry entry and its
         * netif index would outlive the process's interest in them. So the
         * closer removes it from every lwIP list itself, and the reset tells a
         * peer that stopped talking mid-exchange that the connection is gone.
         */
        return ctpDrainAbortLocked(drain, "the peer never closed its half of the connection");
    }

    return kCtpDrainAlive;
}

/*
 * Classifies the PCB itself instead of trusting the callback that last ran.
 * tcp_fasttmr() can queue a deferred FIN without an application callback, and
 * the peer can then move the PCB directly into TIME_WAIT before tcp_poll().
 */
static ctp_drain_pcb_close_state_t ctpDrainClassifyPcbCloseStateLocked(const ctp_tcp_drain_t *drain)
{
    const struct tcp_pcb *pcb = drain->pcb;

    if (pcb->state == TIME_WAIT)
    {
        return kCtpDrainPcbGracefulTerminal;
    }

    if ((pcb->flags & TF_CLOSEPEND) != 0)
    {
        return kCtpDrainPcbFinPending;
    }

    if (pcb->state == FIN_WAIT_1 || pcb->state == FIN_WAIT_2 || pcb->state == CLOSING || pcb->state == LAST_ACK)
    {
        return kCtpDrainPcbFinSent;
    }

    if (pcb->state == ESTABLISHED || pcb->state == CLOSE_WAIT || pcb->state == SYN_RCVD)
    {
        return kCtpDrainPcbFinPending;
    }

    return kCtpDrainPcbUnexpected;
}

static ctp_drain_advance_result_t ctpDrainEnterClosingLocked(ctp_tcp_drain_t *drain, uint64_t now_ms)
{
    drain->phase       = (uint8_t) kCtpCloserClosing;
    drain->deadline_ms = now_ms + (uint64_t) kCtpCloserPeerCloseTimeoutMs;

    if (drain->peer_finished)
    {
        return ctpDrainFinishClosedLocked(drain);
    }
    return kCtpDrainAlive;
}

static ctp_drain_advance_result_t ctpDrainAdvanceFinPendingLocked(ctp_tcp_drain_t *drain, uint64_t now_ms)
{
    const ctp_drain_pcb_close_state_t state = ctpDrainClassifyPcbCloseStateLocked(drain);

    if (state == kCtpDrainPcbGracefulTerminal)
    {
        return ctpDrainFinishClosedLocked(drain);
    }

    if (state == kCtpDrainPcbFinSent)
    {
        /* A transition completed by this timer tick wins at deadline equality. */
        return ctpDrainEnterClosingLocked(drain, now_ms);
    }

    if (state == kCtpDrainPcbUnexpected)
    {
        return ctpDrainAbortLocked(drain, "the PCB left the deferred-FIN states");
    }

    if (UNLIKELY(now_ms >= drain->deadline_ms))
    {
        return ctpDrainAbortLocked(drain, "the FIN allocation deadline expired");
    }
    return kCtpDrainAlive;
}

/*
 * Hands lwIP as much of the remainder as its send window will take, and sends
 * the FIN once it has taken all of it.
 */
static ctp_drain_advance_result_t ctpDrainAdvanceDeliveringLocked(ctp_tcp_drain_t *drain, uint64_t now_ms)
{
    struct tcp_pcb *pcb       = drain->pcb;
    bool            wrote_any = false;

    if (UNLIKELY(now_ms >= drain->deadline_ms))
    {
        // Bytes lwIP has never seen are about to be dropped, and only a reset
        // tells the peer the stream it received is incomplete.
        return ctpDrainAbortLocked(drain, "the delivery deadline expired");
    }

    while (drain->written < drain->len)
    {
        const uint16_t available = tcp_sndbuf(pcb);

        if (available == 0)
        {
            break;
        }

        const uint32_t remaining = drain->len - drain->written;
        const uint16_t write_len = (uint16_t) min((uint32_t) available, remaining);
        const err_t    written   = tcp_write(pcb, drain->bytes + drain->written, write_len, TCP_WRITE_FLAG_COPY);

        if (written == ERR_MEM)
        {
            // Out of segments or pool memory. tcp_sent/tcp_poll will bring us
            // back here once lwIP has room again.
            break;
        }

        if (written != ERR_OK)
        {
            // Anything else is terminal - a pcb that has left a writable state,
            // for instance - and retrying it would only burn the deadline.
            return ctpDrainAbortLocked(drain, "lwIP refused the write");
        }

        drain->written += write_len;
        wrote_any = true;
    }

    if (wrote_any)
    {
        tcp_output(pcb);
    }

    if (drain->written < drain->len)
    {
        return kCtpDrainAlive;
    }

    /* tcp_close() frees a SYN_SENT pcb immediately, including its queued data. */
    if (! drain->established)
    {
        return kCtpDrainAlive;
    }

    /*
     * Everything is with lwIP, so the FIN can go out.
     *
     * This is a TX-only shutdown rather than a close. tcp_close() would send RST
     * and free the pcb whenever this node had not returned all receive credit -
     * which is the ordinary state here, because credit is returned from an
     * owner-worker task and withheld outright while the previous tunnel is
     * paused - and the reset would take every unacknowledged outbound byte with
     * it. A shutdown carries no such rule.
     *
     * If no segment can carry the FIN, lwIP returns ERR_OK with TF_CLOSEPEND and
     * retries from its timer. That acceptance is not proof the FIN was sent;
     * the delivery deadline remains the hard bound until the pcb changes state.
     */
    const err_t shutdown = ctpTcpSendFinLocked(pcb);

    if (shutdown != ERR_OK)
    {
        return ctpDrainAbortLocked(drain, "lwIP refused the shutdown");
    }

    /*
     * The peer-close deadline starts only after the state transition rather than
     * inheriting what is left of the delivery budget: they bound different waits.
     */
    const ctp_drain_pcb_close_state_t close_state = ctpDrainClassifyPcbCloseStateLocked(drain);
    if (close_state == kCtpDrainPcbGracefulTerminal)
    {
        return ctpDrainFinishClosedLocked(drain);
    }
    if (close_state == kCtpDrainPcbFinPending)
    {
        drain->phase = (uint8_t) kCtpCloserFinPending;
        return kCtpDrainAlive;
    }
    if (close_state != kCtpDrainPcbFinSent)
    {
        return ctpDrainAbortLocked(drain, "the PCB did not enter a FIN state after shutdown");
    }

    /*
     * The exchange is not over yet. The peer still has to acknowledge the data
     * and the FIN, and it may keep sending in the other direction, so the closer
     * stays alive - crediting whatever arrives so its receive window cannot shut
     * - until the peer's own FIN or the deadline. Retiring now would hand the
     * tuple to an evictable tombstone while this node still owns the pcb.
     */
    return ctpDrainEnterClosingLocked(drain, now_ms);
}

/*
 * The result distinguishes a live closer, a successful close, and an abort. In
 * either terminal result the closer object is gone and callers must not touch it.
 */
static ctp_drain_advance_result_t ctpDrainAdvanceLocked(ctp_tcp_drain_t *drain, uint64_t now_ms)
{
    if (drain->pcb == NULL)
    {
        ctpDrainRetireAndFreeLocked(drain, false);
        return kCtpDrainClosed;
    }

    const ctp_drain_pcb_close_state_t close_state = ctpDrainClassifyPcbCloseStateLocked(drain);
    if (close_state == kCtpDrainPcbGracefulTerminal)
    {
        return ctpDrainFinishClosedLocked(drain);
    }

    if (drain->phase == (uint8_t) kCtpCloserClosing)
    {
        if (close_state != kCtpDrainPcbFinSent)
        {
            return ctpDrainAbortLocked(drain, "the PCB left the active FIN states");
        }
        return ctpDrainAdvanceClosingLocked(drain, now_ms);
    }

    if (drain->phase == (uint8_t) kCtpCloserFinPending)
    {
        return ctpDrainAdvanceFinPendingLocked(drain, now_ms);
    }

    return ctpDrainAdvanceDeliveringLocked(drain, now_ms);
}

// ---------------------------------------------------------------------------
// lwIP callbacks - drain-only, and never toward a neighbouring tunnel
// ---------------------------------------------------------------------------

static err_t ctpDrainSentCallback(void *arg, struct tcp_pcb *tpcb, u16_t len)
{
    discard len;

    ctp_tcp_drain_t *drain = arg;

    if (drain == NULL || drain->pcb != tpcb)
    {
        return ERR_OK;
    }

    return ctpDrainAdvanceLocked(drain, ctpNowMs()) == kCtpDrainAborted ? ERR_ABRT : ERR_OK;
}

static err_t ctpDrainPollCallback(void *arg, struct tcp_pcb *tpcb)
{
    ctp_tcp_drain_t *drain = arg;

    if (drain == NULL || drain->pcb != tpcb)
    {
        return ERR_OK;
    }

    return ctpDrainAdvanceLocked(drain, ctpNowMs()) == kCtpDrainAborted ? ERR_ABRT : ERR_OK;
}

static err_t ctpDrainConnectedCallback(void *arg, struct tcp_pcb *tpcb, err_t err)
{
    ctp_tcp_drain_t *drain = arg;

    if (drain == NULL || drain->pcb != tpcb)
    {
        return ERR_OK;
    }

    if (UNLIKELY(err != ERR_OK))
    {
        return ctpDrainAbortLocked(drain, "the active open failed") == kCtpDrainAborted ? ERR_ABRT : ERR_OK;
    }

    drain->established = true;
    return ctpDrainAdvanceLocked(drain, ctpNowMs()) == kCtpDrainAborted ? ERR_ABRT : ERR_OK;
}

/*
 * The peer is still sending. Nobody is listening any more - the line that would
 * have received it is gone - but the bytes still have to be acknowledged, or the
 * receive window closes and the peer stops reading our FIN.
 */
static err_t ctpDrainRecvCallback(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
    ctp_tcp_drain_t *drain = arg;

    if (drain == NULL || drain->pcb != tpcb)
    {
        if (p != NULL)
        {
            pbuf_free(p);
        }
        return ERR_OK;
    }

    if (UNLIKELY(err != ERR_OK))
    {
        if (p != NULL)
        {
            pbuf_free(p);
        }
        return ctpDrainAbortLocked(drain, "the peer reported a receive error") == kCtpDrainAborted ? ERR_ABRT : ERR_OK;
    }

    if (p == NULL)
    {
        drain->peer_finished = true;

        /*
         * A half-close does not stop the peer reading the bytes still owed, so
         * this only ends the closer once its own FIN is already out. Otherwise
         * the drain keeps writing and shuts down afterwards, from CLOSE_WAIT.
         */
        return ctpDrainAdvanceLocked(drain, ctpNowMs()) == kCtpDrainAborted ? ERR_ABRT : ERR_OK;
    }

    const ctp_drain_advance_result_t advanced = ctpDrainAdvanceLocked(drain, ctpNowMs());
    if (advanced != kCtpDrainAlive)
    {
        pbuf_free(p);
        return advanced == kCtpDrainAborted ? ERR_ABRT : ERR_OK;
    }

    /*
     * Nobody is listening any more - the line that would have received this is
     * gone - but the bytes still have to be credited. Without that the receive
     * window shuts, the peer stops reading, and the data and FIN this closer
     * exists to deliver never get acknowledged.
     */
    tcp_recved(tpcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
}

static void ctpDrainErrorCallback(void *arg, err_t err)
{
    ctp_tcp_drain_t *drain = arg;

    if (drain == NULL)
    {
        return;
    }

    LOGD("ConnectionToPackets: closing TCP flow failed with error %d, %u byte(s) undelivered",
         (int) err,
         (unsigned int) (drain->len - drain->written));

    // lwIP has already freed the pcb; touching it now would be a use-after-free.
    drain->pcb = NULL;
    ctpDrainRetireAndFreeLocked(drain, false);
}

// ---------------------------------------------------------------------------
// adoption
// ---------------------------------------------------------------------------

/*
 * Copies whatever the line still has queued into one contiguous block owned by
 * the global allocator.
 *
 * The queue's buffers belong to the line's worker pool and may not be held past
 * this call, let alone touched from the lwIP timer thread, so this copy is what
 * severs the drain from worker-local memory.
 */
static uint8_t *ctpDrainTakeBytes(ctp_lstate_t *ls, uint32_t total, wid_t wid)
{
    uint8_t *bytes = memoryAllocate(total);

    if (UNLIKELY(bytes == NULL))
    {
        return NULL;
    }

    uint32_t offset = 0;

    while (bufferqueueGetBufCount(&ls->pending_queue) > 0)
    {
        sbuf_t        *buf = bufferqueuePopFront(&ls->pending_queue);
        const uint32_t len = sbufGetLength(buf);

        assert(offset + len <= total);
        memoryCopy(bytes + offset, sbufGetRawPtr(buf), len);
        offset += len;

        bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
    }

    return bytes;
}

ctp_tcp_drain_adopt_result_t ctpTcpDrainAdoptLocked(tunnel_t *t, ctp_lstate_t *ls, bool *out_aborted)
{
    ctp_tstate_t *ts = tunnelGetState(t);

    *out_aborted = false;

    if (ls->tcp_pcb == NULL || ! ls->flow_registered)
    {
        return kCtpTcpDrainNotNeeded;
    }

    const size_t queued = bufferqueueGetBufLen(&ls->pending_queue);

    /*
     * A connected flow is adopted even with nothing queued. The FIN still has to
     * leave without resetting, the peer's acknowledgements of data lwIP has not
     * yet retransmitted still have to route back to this worker, and the peer may
     * still be sending in the other direction with nobody left to credit it -
     * none of which a bare close can arrange.
     */
    if (queued == 0 && ! ls->connected)
    {
        return kCtpTcpDrainNotNeeded;
    }

    // The per-line pending limit already keeps this well inside 32 bits; the
    // check is here so a future change to that limit cannot make it wrap.
    if (queued > (size_t) UINT32_MAX)
    {
        return kCtpTcpDrainFailed;
    }

    const uint32_t total = (uint32_t) queued;

    /*
     * Past either bound the flow is reset, whether or not anything is queued.
     *
     * The empty-queue case used to fall back to an untracked TX shutdown on the
     * grounds that it owed the peer nothing. It does: bytes already copied into
     * lwIP can still be unacknowledged, and nothing would ever come back to that
     * pcb - lwIP does not time out a write-only half-close - so the fallback
     * traded a visible reset for a pcb and a netif index held until the process
     * exits. A reset is the honest failure.
     */
    if (ts->drain_bytes + total > (uint32_t) kCtpMaxDrainBytesTotal || ts->drain_count >= (uint32_t) kCtpMaxDrains)
    {
        if (atomicLogRateLimiterShouldLog(&g_drain_budget_log, kCtpDrainLogIntervalMs))
        {
            LOGW("ConnectionToPackets: resetting a closing flow, the shared drain budget (%d bytes) or "
                 "closer count (%d) is full; %u queued byte(s) affected",
                 (int) kCtpMaxDrainBytesTotal,
                 (int) kCtpMaxDrains,
                 (unsigned int) total);
        }

        return kCtpTcpDrainFailed;
    }

    ctp_tcp_drain_t *drain = memoryAllocateZero(sizeof(*drain));

    if (UNLIKELY(drain == NULL))
    {
        if (atomicLogRateLimiterShouldLog(&g_drain_alloc_log, kCtpDrainLogIntervalMs))
        {
            LOGW("ConnectionToPackets: out of memory for a closing flow's drain, %u queued byte(s) affected",
                 (unsigned int) total);
        }
        return kCtpTcpDrainFailed;
    }

    if (total > 0)
    {
        drain->bytes = ctpDrainTakeBytes(ls, total, lineGetWID(ls->line));

        if (UNLIKELY(drain->bytes == NULL))
        {
            memoryFree(drain);
            if (atomicLogRateLimiterShouldLog(&g_drain_alloc_log, kCtpDrainLogIntervalMs))
            {
                LOGW("ConnectionToPackets: out of memory for a closing flow's %u queued byte(s)", (unsigned int) total);
            }
            return kCtpTcpDrainFailed;
        }
    }

    drain->tunnel      = t;
    drain->pcb         = ls->tcp_pcb;
    drain->flow_key    = ls->flow_key;
    drain->generation  = ls->generation;
    drain->len         = total;
    drain->deadline_ms = ctpNowMs() + (uint64_t) kCtpDrainTimeoutMs;
    drain->established = ls->connected;

    /*
     * CLOSE_WAIT means lwIP already delivered the peer's FIN - to the *line's*
     * receive callback, before this closer existed. Without carrying that over,
     * the closer would send its own FIN and then wait for an EOF that has
     * already happened and cannot arrive twice.
     */
    drain->peer_finished = (drain->pcb->state == CLOSE_WAIT);

    drain->next = ts->drains;
    if (ts->drains != NULL)
    {
        ts->drains->prev = drain;
    }
    ts->drains = drain;
    ts->drain_bytes += total;
    ++ts->drain_count;

    /*
     * The pcb changes hands here. Its callbacks are repointed at the drain in
     * the same core-locked section, so there is no window in which an lwIP
     * callback could still reach the line state that is about to be destroyed.
     */
    if (ls->rx_uncredited > 0)
    {
        ctpTcpReturnReceiveCreditLocked(ls, ls->rx_uncredited);
        tcp_output(ls->tcp_pcb);
    }
    ls->read_paused_len = 0;

    ctpFlowMarkDrainingLocked(t, ls);
    ls->tcp_pcb = NULL;

    ctpDrainInstallCallbacksLocked(drain);

    *out_aborted = ctpDrainAdvanceLocked(drain, ctpNowMs()) == kCtpDrainAborted;
    return kCtpTcpDrainAdopted;
}

// ---------------------------------------------------------------------------
// shutdown
// ---------------------------------------------------------------------------

/*
 * Called from Stop, after ctpFlowDropAllLocked() has already closed or aborted
 * every registered pcb - including the draining ones - and cleared their
 * callbacks. Only the memory is left to release.
 */
void ctpTcpDrainDestroyAllLocked(tunnel_t *t)
{
    ctp_tstate_t *ts = tunnelGetState(t);

    while (ts->drains != NULL)
    {
        ctp_tcp_drain_t *drain = ts->drains;

        // The pcb is gone or no longer ours; do not touch it.
        drain->pcb = NULL;
        ctpDrainFreeLocked(ts, drain);
    }

    ts->drain_bytes = 0;
    ts->drain_count = 0;
}

uint32_t ctpTcpDrainCount(tunnel_t *t)
{
    ctp_tstate_t *ts    = tunnelGetState(t);
    uint32_t      count = 0;

    LOCK_TCPIP_CORE();
    for (const ctp_tcp_drain_t *drain = ts->drains; drain != NULL; drain = drain->next)
    {
        ++count;
    }
    UNLOCK_TCPIP_CORE();

    return count;
}
