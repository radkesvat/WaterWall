#include "internal.h"

static bool vlessserverFallbackResult(tunnel_t *t, line_t *l, fallback_replay_result_e result)
{
    if (result == kFallbackReplayRefused)
        vlessserverCloseLineBidirectional(t, l);
    return result == kFallbackReplayOk;
}

static void vlessserverFallbackTask(tunnel_t *t, line_t *l)
{
    vlessserver_lstate_t *ls = lineGetState(l, t);
    if (ls->tunnel != t)
        return;
    discard vlessserverFallbackResult(t, l, fallbackReplayOnTask(&ls->fallback, t, l, vlessserverFallbackTask));
}

bool vlessserverSendFallbackPayload(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls, sbuf_t *buf)
{
    return vlessserverFallbackResult(t, l, fallbackReplaySubmit(&ls->fallback, t, l, buf, vlessserverFallbackTask));
}

bool vlessserverStartFallback(tunnel_t *t, line_t *l)
{
    vlessserver_tstate_t *ts = tunnelGetState(t);
    vlessserver_lstate_t *ls = lineGetState(l, t);
    if (ts->fallback_tunnel == NULL)
        goto failed;
    vlessserverRetainActiveHead(ls);
    if (ls->header_filled != 0)
    {
        buffer_pool_t *pool   = lineGetBufferPool(l);
        sbuf_t        *prefix = bufferpoolGetBestFit(pool, ls->header_filled, bufferpoolGetLargeBufferPadding(pool));
        sbufWrite(prefix, ls->header, ls->header_filled);
        sbufSetLength(prefix, ls->header_filled);
        if (! bufferqueueTryPushFront(&ls->pending_up, &prefix))
        {
            lineReuseBuffer(l, prefix);
            goto failed;
        }
    }
    if (ts->fallback_replay_config.delay_ms != 0)
    {
        /* Fallback selection precedes TCP budget attachment. The independent
         * response budget and authenticated TCP retention keep their policy. */
        bufferbudgetAssertEmpty(&ls->upstream_budget);
        bufferbudgetInit(&ls->upstream_budget,
                         (buffer_budget_cost_t) {kVlessServerMaxPendingBytes,
                                                 kVlessServerMaxFallbackCharge,
                                                 kVlessServerMaxPendingBuffers});
    }
    if (fallbackReplayBegin(&ls->fallback,
                            l,
                            ts->fallback_tunnel,
                            &ts->fallback_replay_config,
                            &ls->upstream_budget,
                            &ls->pending_up) != kFallbackReplayOk)
        goto failed;
    ls->input_bytes   = 0;
    ls->header_filled = 0;
    ls->phase         = kVlessServerPhaseFallback;
    lineMarkFallback(l);
    if (! lineCallWithRef(l, tunnelUpStreamInit, ts->fallback_tunnel))
        return false;
    ls = lineGetState(l, t);
    if (ls->tunnel != t)
        return false;
    /* Init has returned; a close during Pause replay must flush the transcript. */
    fallbackReplayMarkInitialized(&ls->fallback);
    if (ls->response_paused && ! lineCallWithRef(l, tunnelUpStreamPause, ts->fallback_tunnel))
        return false;
    if (ls->tunnel != t)
        return false;
    return vlessserverFallbackResult(t, l, fallbackReplayInitDone(&ls->fallback, t, l, vlessserverFallbackTask));
failed:
    vlessserverCloseLineBidirectional(t, l);
    return false;
}

void vlessserverCloseFallbackFromUpstream(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls, tunnel_t *fallback)
{
    discard t;
    lineRef(l);
    /* Close the node's returning callback direction before final reentrant replay. */
    ls->phase = kVlessServerPhaseClosing;
    bool send_finish;
    if (fallbackReplayCloseFromPrev(&ls->fallback, l, &send_finish) != kFallbackReplayGone)
    {
        vlessserverLinestateDestroy(ls);
        if (send_finish)
            tunnelUpStreamFin(fallback, l);
    }
    lineUnref(l);
}
