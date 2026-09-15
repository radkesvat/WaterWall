#include "structure.h"

#include "loggers/network_logger.h"

#include "loggers/log_rate_limiter.h"

static atomic_log_rate_limiter_t ctp_admission_log;

/*
 * Why this runs before the queue takes the buffer: comparing the queue length
 * after insertion means the over-limit bytes are already owned, and the close
 * path that follows would hand them to the graceful closer. Refusing first keeps
 * the limit an admission decision rather than a delivery decision.
 *
 * One read-sized allowance covers input already delivered before Pause can take
 * effect. The configured budget and entry limit remain bounded admission rules.
 *
 * Returns the name of the limit that refused the payload, or NULL to admit it.
 */
static const char *ctpRefusePendingPayload(const ctp_tstate_t *ts, ctp_lstate_t *ls, uint32_t len,
                                           uint32_t delivery_headroom)
{
    const size_t queued  = bufferqueueGetBufLen(&ls->pending_queue);
    const size_t entries = bufferqueueGetBufCount(&ls->pending_queue);
    const uint64_t maximum = (uint64_t) ts->max_pending_bytes + delivery_headroom;

    if (UNLIKELY(queued > maximum || (size_t) len > maximum - queued))
    {
        return "max-pending-bytes";
    }

    if (UNLIKELY(entries >= (size_t) kCtpMaxPendingEntries))
    {
        return "retained-entry limit";
    }

    return NULL;
}

void ctpTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    if (UNLIKELY(ctpLineIsPacketLine(t, l)))
    {
        LOGF("ConnectionToPackets: unexpected upstream Payload on the packet line");
        abortProgramNow(1);
        return;
    }

    ctp_tstate_t *ts = tunnelGetState(t);
    ctp_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->tunnel == NULL))
    {
        // A close path already released this flow; the bytes have nowhere to go.
        lineReuseBuffer(l, buf);
        return;
    }

    if (ls->kind == (uint8_t) kCtpLineKindUdp)
    {
        ctpUdpSendPayload(t, l, ls, buf);
        return;
    }

    if (UNLIKELY(sbufGetLength(buf) == 0))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    const char *refusal =
        ctpRefusePendingPayload(ts, ls, sbufGetLength(buf), bufferpoolGetLargeBufferSize(lineGetBufferPool(l)));

    if (UNLIKELY(refusal != NULL))
    {
        // The configured budget plus one delivery allowance is exhausted.
        // Refuse further input without passing it to the graceful closer.
        lineReuseBuffer(l, buf);
        if (atomicLogRateLimiterShouldLog(&ctp_admission_log, kCtpDropLogIntervalMs))
        {
            LOGW("ConnectionToPackets: unwritten payload passed the flow's %s (%u budget bytes + %u delivery bytes / "
                 "%u entries), "
                 "resetting the flow",
                 refusal,
                 (unsigned int) ts->max_pending_bytes,
                 (unsigned int) bufferpoolGetLargeBufferSize(lineGetBufferPool(l)),
                 (unsigned int) kCtpMaxPendingEntries);
        }
        ctpCloseLineTowardPrevWithoutDrain(t, l);
        return;
    }

    /*
     * Everything goes through the queue, including bytes that could be written
     * immediately. That is what keeps ordering trivially correct across the
     * pre-connect window, a full send window and a partial tcp_write().
     */
    if (UNLIKELY(! bufferqueueTryPushBack(&ls->pending_queue, &buf)))
    {
        // One flow's queue could not grow. Reset only that flow.
        lineReuseBuffer(l, buf);
        if (atomicLogRateLimiterShouldLog(&ctp_admission_log, kCtpDropLogIntervalMs))
        {
            LOGW("ConnectionToPackets: out of memory queueing a payload, resetting the flow");
        }
        ctpCloseLineTowardPrevWithoutDrain(t, l);
        return;
    }

    LOCK_TCPIP_CORE();
    const ctp_flush_result_t flushed = ctpFlushPendingLocked(ls);
    UNLOCK_TCPIP_CORE();
    ctpDrainTerminalLinesOnCurrentWorker(t, lineGetWID(l));

    if (UNLIKELY(flushed == kCtpFlushTerminal))
    {
        LOGD("ConnectionToPackets: lwIP refused this flow's payload for good, closing it");
        ctpCloseLineTowardPrev(t, l);
        return;
    }

    // May close the line through prev, so nothing may touch `ls` afterwards.
    ctpApplyWriteBackpressure(t, l);
}
