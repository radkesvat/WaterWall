#include "auth.h"
#include "internal.h"

static bool vmessserverFallbackResult(tunnel_t *t, line_t *l, fallback_replay_result_e result)
{
    if (result == kFallbackReplayRefused)
        vmessserverCloseLineBidirectional(t, l);
    return result == kFallbackReplayOk;
}

static void vmessserverFallbackTask(tunnel_t *t, line_t *l)
{
    vmessserver_lstate_t *ls = lineGetState(l, t);
    if (ls->tunnel != t)
        return;
    discard vmessserverFallbackResult(t, l, fallbackReplayOnTask(&ls->fallback, t, l, vmessserverFallbackTask));
}

bool vmessserverSendFallbackPayload(tunnel_t *t, line_t *l, vmessserver_lstate_t *ls, sbuf_t *buf)
{
    return vmessserverFallbackResult(t, l, fallbackReplaySubmit(&ls->fallback, t, l, buf, vmessserverFallbackTask));
}

bool vmessserverStartFallback(tunnel_t *t, line_t *l)
{
    vmessserver_tstate_t *ts = tunnelGetState(t);
    vmessserver_lstate_t *ls = lineGetState(l, t);
    if (ts->fallback_tunnel == NULL || ls->auth_recognized)
        goto failed;
    vmessserverAuthLineDetach(ls);
    vmessserverRetainActiveHead(ls);
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
    if (fallbackReplayBegin(&ls->fallback,
                            l,
                            ts->fallback_tunnel,
                            &ts->fallback_replay_config,
                            &ls->upstream_budget,
                            &ls->pending_up) != kFallbackReplayOk)
        goto failed;
    ls->input_bytes   = 0;
    ls->header_filled = 0;
    ls->phase         = kVmessServerPhaseFallback;
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
    return vmessserverFallbackResult(t, l, fallbackReplayInitDone(&ls->fallback, t, l, vmessserverFallbackTask));
failed:
    vmessserverCloseLineBidirectional(t, l);
    return false;
}

void vmessserverCloseFallbackFromUpstream(tunnel_t *t, line_t *l, vmessserver_lstate_t *ls, tunnel_t *fallback)
{
    discard t;
    lineRef(l);
    /* Close the node's returning callback direction before final reentrant replay. */
    ls->phase = kVmessServerPhaseClosing;
    bool send_finish;
    if (fallbackReplayCloseFromPrev(&ls->fallback, l, &send_finish) != kFallbackReplayGone)
    {
        vmessserverLinestateDestroy(ls);
        if (send_finish)
            tunnelUpStreamFin(fallback, l);
    }
    lineUnref(l);
}
