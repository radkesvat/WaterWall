#include "structure.h"

#include "loggers/network_logger.h"

void realityclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    realityclient_lstate_t *ls = lineGetState(l, t);

    if (ls->terminal_closing || ls->next_finished)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (ls->phase != kRealityClientPhaseRealityActive || ls->handoff_completion_in_progress ||
        ls->upstream_send_in_progress || ls->pending_active != NULL || bufferqueueGetEntryCount(&ls->pending_up) != 0)
    {
        if (UNLIKELY(! bufferqueueTryPushBack(&ls->pending_up, &buf)))
        {
            const buffer_budget_cost_t used            = bufferbudgetGetUsage(&ls->pending_budget);
            const buffer_budget_cost_t limits          = bufferbudgetGetLimits(&ls->pending_budget);
            const size_t               incoming_bytes  = sbufGetLength(buf);
            const size_t               incoming_charge = sbufGetQueueCharge(buf);
            LOGW("RealityClient: closing connection: pending plaintext %s "
                 "(retained_bytes=%zu, incoming_bytes=%zu, limit_bytes=%zu, retained_charge_bytes=%zu, "
                 "incoming_charge_bytes=%zu, limit_charge_bytes=%zu)",
                 incoming_bytes > limits.bytes - used.bytes      ? "byte budget exceeded"
                 : incoming_charge > limits.charge - used.charge ? "storage charge budget exceeded"
                                                                 : "queue admission failed",
                 used.bytes,
                 incoming_bytes,
                 limits.bytes,
                 used.charge,
                 incoming_charge,
                 limits.charge);
            lineReuseBuffer(l, buf);
            realityclientCloseLineBidirectional(t, l);
            return;
        }
        if (LIKELY(realityclientSetSourcePaused(t, l, true)))
        {
            discard realityclientFlushPendingUpstream(t, l);
        }
        return;
    }

    lineRef(l);
    ls->upstream_send_in_progress = true;
    if (LIKELY(realityclientEncryptAndSend(t, l, buf)))
    {
        ls = lineGetState(l, t);
        if (LIKELY(! ls->terminal_closing && ls->phase == kRealityClientPhaseRealityActive))
        {
            ls->upstream_send_in_progress = false;
            discard realityclientFlushPendingUpstream(t, l);
        }
    }
    lineUnref(l);
}
