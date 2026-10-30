#include "internal.h"

static void trojanserverFallbackTask(tunnel_t *t, line_t *l);

static bool trojanserverFallbackResult(tunnel_t *t, line_t *l, fallback_replay_result_e result)
{
    if (result == kFallbackReplayRefused)
        trojanserverCloseLineBidirectional(t, l);
    return result == kFallbackReplayOk;
}

static void trojanserverFallbackTask(tunnel_t *t, line_t *l)
{
    trojanserver_lstate_t *ls = lineGetState(l, t);
    if (ls->tunnel != t)
        return;
    const bool owns_pump = ! ls->pumping;
    lineRef(l);
    if (owns_pump)
        ls->pumping = true;
    const bool ready =
        trojanserverFallbackResult(t, l, fallbackReplayOnTask(&ls->fallback, t, l, trojanserverFallbackTask));
    if (ready && owns_pump && lineIsAlive(l) && ls->line == l)
    {
        ls->pumping = false;
        trojanserverPump(t, l);
    }
    lineUnref(l);
}

fallback_replay_result_e trojanserverDrainFallbackPayload(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls,
                                                          bool *dispatched)
{
    return fallbackReplayDrainOne(&ls->fallback, t, l, trojanserverFallbackTask, dispatched);
}

bool trojanserverSendFallbackPayload(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls, sbuf_t *buf)
{
    /* Keep nested input behind the active branch callback. The existing pump
     * drains each nested zero-delay entry before this outer call returns. */
    const bool owns_pump = ! ls->pumping;
    lineRef(l);
    if (owns_pump)
        ls->pumping = true;
    bool ready =
        trojanserverFallbackResult(t, l, fallbackReplaySubmit(&ls->fallback, t, l, buf, trojanserverFallbackTask));
    if (ready && owns_pump && lineIsAlive(l) && ls->line == l)
    {
        ls->pumping = false;
        trojanserverPump(t, l);
        ready = lineIsAlive(l) && ls->line == l;
    }
    lineUnref(l);
    return ready;
}

void trojanserverCloseFallbackFromUpstream(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls, tunnel_t *fallback)
{
    lineRef(l);
    /* The previous owner can destroy this borrowed line on return. Close its
     * returning callback direction before the final reentrant Payload. */
    ls->phase = kTrojanServerPhaseClosing;
    bool send_finish;
    if (fallbackReplayCloseFromPrev(&ls->fallback, l, &send_finish) != kFallbackReplayGone)
    {
        trojanserverCloseUdpRemoteLines(t, ls);
        trojanserverLinestateDestroy(ls);
        if (send_finish)
            tunnelUpStreamFin(fallback, l);
    }
    lineUnref(l);
}

void trojanserverStartFallback(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls)
{
    trojanserver_tstate_t *ts = tunnelGetState(t);
    if (ts->fallback_tunnel == NULL || ls->input_bytes > kTrojanServerMaxPendingBytes)
        goto failed;
    trojanserverRetainActiveHead(ls);
    if (ls->header_filled != 0)
    {
        buffer_pool_t *pool   = lineGetBufferPool(l);
        sbuf_t        *prefix = bufferpoolGetBestFit(pool, ls->header_filled, bufferpoolGetLargeBufferPadding(pool));
        sbufWrite(prefix, ls->header, ls->header_filled);
        sbufSetLength(prefix, ls->header_filled);
        if (UNLIKELY(! bufferqueueTryPushFront(&ls->pending_up, &prefix)))
        {
            bufferpoolReuseBuffer(pool, prefix);
            goto failed;
        }
    }
    if (ts->fallback_replay_config.delay_ms != 0)
    {
        /* The parser has not attached the authenticated TCP output budget.
         * Reuse its empty storage for the selected delayed-fallback policy. */
        bufferbudgetAssertEmpty(&ls->output_budget);
        bufferbudgetInit(&ls->output_budget,
                         (buffer_budget_cost_t) {kTrojanServerMaxPendingBytes,
                                                 kTrojanServerMaxFallbackCharge,
                                                 kTrojanServerMaxQueuedBuffers});
    }
    if (fallbackReplayBegin(
            &ls->fallback, l, ts->fallback_tunnel, &ts->fallback_replay_config, &ls->output_budget, &ls->pending_up) !=
        kFallbackReplayOk)
        goto failed;
    ls->input_bytes = 0;
    trojanserverResetHeader(ls);
    ls->phase               = kTrojanServerPhaseFallback;
    ls->branch              = kTrojanServerBranchFallback;
    ls->next_initialized    = true;
    ls->branch_initializing = true;
    lineMarkFallback(l);
    if (! lineCallWithRef(l, tunnelUpStreamInit, ts->fallback_tunnel))
        return;
    if (ls->line != l)
        return;
    ls->branch_initializing = false;
    /* Init is complete even while replaying the remembered receiver Pause. */
    fallbackReplayMarkInitialized(&ls->fallback);
    if (ls->prev_paused && ! ls->next_pause_sent && ! lineCallWithRef(l, tunnelUpStreamPause, t))
        return;
    if (ls->line != l)
        return;
    discard trojanserverFallbackResult(t, l, fallbackReplayInitDone(&ls->fallback, t, l, trojanserverFallbackTask));
    return;
failed:
    trojanserverCloseLineBidirectional(t, l);
}

tunnel_t *trojanserverSelectedUpstream(tunnel_t *t, const trojanserver_lstate_t *ls)
{
    trojanserver_tstate_t *ts = tunnelGetState(t);

    if (ls->branch == kTrojanServerBranchFallback)
    {
        return ts->fallback_tunnel;
    }

    return NULL;
}
