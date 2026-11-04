#include "structure.h"

#include "loggers/network_logger.h"

bool httpclientCloseDrainAllowed(httpclient_lstate_t *ls)
{
    if (ls->close_drain_deadline_ms == 0 || getHRTimeUs() / 1000 < ls->close_drain_deadline_ms)
        return true;
    LOGW("HttpClient: HTTP/2 upload drain timed out");
    return false;
}

static void closeDrainTimeout(wtimer_t *timer)
{
    httpclient_lstate_t *ls = weventGetUserdata(timer);
    assert(ls->close_drain_timer == timer);
    ls->close_drain_timer = NULL;
    uint64_t now          = getHRTimeUs() / 1000;
    if (now < ls->close_drain_deadline_ms)
    {
        if (wtimerReset(timer, (uint32_t) (ls->close_drain_deadline_ms - now)))
        {
            ls->close_drain_timer = timer;
            return;
        }
    }
    else
        LOGW("HttpClient: HTTP/2 upload drain timed out");
    httpclientCarrierClose(ls->tunnel, ls->line, false);
}

void httpclientCancelCloseDrain(httpclient_lstate_t *ls)
{
    wtimer_t *timer             = ls->close_drain_timer;
    ls->close_drain_timer       = NULL;
    ls->close_drain_deadline_ms = 0;
    if (timer != NULL)
    {
        weventSetUserData(timer, NULL);
        wtimerDelete(timer);
    }
}

void httpclientApplicationFinish(tunnel_t *t, line_t *application)
{
    httpclient_lstate_t *app_ls  = lineGetState(application, t);
    line_t              *carrier = app_ls->carrier_line;
    httpclient_lstate_t *ls      = lineGetState(carrier, t);
    httpclient_tstate_t *ts      = tunnelGetState(t);
    lineRef(carrier);
    ls->application_line = NULL;
    ls->prev_finished    = true;
    httpclientLinestateDestroy(app_ls);

    if (atomicLoadRelaxed(&ts->stopping) || ! wloopNormalDispatchAllowed(getWorkerLoop(lineGetWID(carrier))))
    {
        httpclientCarrierClose(t, carrier, false);
        lineUnref(carrier);
        return;
    }
    assert(ts->close_drain_timeout_ms > 0);
    ls->close_drain_deadline_ms = getHRTimeUs() / 1000 + ts->close_drain_timeout_ms;
    ls->close_drain_timer =
        wtimerAdd(getWorkerLoop(lineGetWID(carrier)), closeDrainTimeout, ts->close_drain_timeout_ms, 1);
    if (ls->close_drain_timer == NULL)
        httpclientCarrierClose(t, carrier, false);
    else
    {
        weventSetUserData(ls->close_drain_timer, ls);
        /* The detached application no longer consumes responses. Release its
         * read hold so WINDOW_UPDATE can finish the accepted upload. */
        if (ls->application_read_paused)
        {
            ls->application_read_paused = false;
            tunnelNextUpStreamResume(t, carrier);
        }
        if (lineIsAlive(carrier))
            httpclientProgressClose(t, carrier, ls);
    }
    lineUnref(carrier);
}

void httpclientProgressClose(tunnel_t *t, line_t *l, httpclient_lstate_t *ls)
{
    if (ls->line_role != kHttpClientLineCarrier || ! ls->prev_finished || ls->startup_in_progress || ls->h2_sending ||
        ls->pending_up_draining || ls->receive.draining || ls->close_driving)
        return;
    lineRef(l);
    ls->close_driving = true;
    if (! httpclientCloseDrainAllowed(ls) || (ls->h2_stream_closed && ! ls->h2_end_stream_emitted))
        goto close;

    httpclient_tstate_t *ts = tunnelGetState(t);
    if (ls->runtime_proto == kHttpClientRuntimeUnknown || ls->runtime_proto == kHttpClientRuntimeWaitUpgrade ||
        ls->runtime_proto == kHttpClientRuntimeAfterUpgrade || (ts->websocket_enabled && ! ls->websocket_active))
        goto waiting;
    if (! httpclientTransportFlushPendingUp(t, l, ls))
        goto close;
    if (! lineIsAlive(l))
        goto done;

    if (! ls->fin_sent)
    {
        ls->fin_sent = true;
        if (ts->websocket_enabled && ! httpclientTransportSendWebSocketClose(t, l, ls))
            goto close;
        if (ls->runtime_proto == kHttpClientRuntimeHttp2)
        {
            if (! httpclientTransportSendHttp2DataFrame(t, l, ls, NULL, true))
                goto close;
        }
        else if (! ts->websocket_enabled && ! httpclientTransportSendHttp1FinalChunk(t, l))
            goto close;
    }
    if (! lineIsAlive(l))
        goto done;
    if (ls->runtime_proto == kHttpClientRuntimeHttp2 && ! ls->h2_end_stream_emitted)
        goto waiting;
    if (ls->runtime_proto == kHttpClientRuntimeHttp2)
        lineRequestCloseLinger(l, kLineCloseLingerProtocolDrain);
close:
    if (lineIsAlive(l))
        httpclientCarrierClose(t, l, false);
    goto done;
waiting:
    ls->close_driving = false;
done:
    lineUnref(l);
}
