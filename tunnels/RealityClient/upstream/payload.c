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
        ls->upstream_send_in_progress || ls->pending_active != NULL || bufferqueueGetBufCount(&ls->pending_up) != 0)
    {
        if (UNLIKELY(! bufferqueueTryPushBack(&ls->pending_up, &buf)))
        {
            lineReuseBuffer(l, buf);
            LOGW("RealityClient: pending plaintext limit or queue admission failure");
            realityclientCloseLineBidirectional(t, l);
            return;
        }
        ls->plaintext_producer_paused = true;
        if (LIKELY(realityclientUpdateSourcePressure(t, l)))
        {
            discard realityclientFlushPendingUpstream(t, l);
        }
        return;
    }

    lineRef(l);
    ls->upstream_send_in_progress = true;
    if (LIKELY(realityclientEncryptAndSend(t, l, buf) && lineIsAlive(l)))
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
