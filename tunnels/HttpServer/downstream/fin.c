#include "structure.h"

#include "loggers/network_logger.h"

static void failAndCloseD(tunnel_t *t, line_t *l, httpserver_lstate_t *ls)
{
    if (! lineIsAlive(l))
    {
        httpserverLinestateDestroy(ls);
        return;
    }

    httpserverTransportClosePrevDirection(t, l, ls);
}

void httpserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    httpserver_lstate_t *ls = lineGetState(l, t);
    httpserver_tstate_t *ts = tunnelGetState(t);

    if (ls->split_role == kHttpServerSplitRoleMain)
    {
        httpserverSplitDownStreamFinish(t, l);
        return;
    }

    lineLock(l);

    ls->next_finished = true;

    if (! httpserverTransportFlushPendingDown(t, l, ls))
    {
        failAndCloseD(t, l, ls);
        lineUnlock(l);
        return;
    }

    if (ls->prev_finished)
    {
        // prev finished us re-entrantly (e.g. its write queue overflowed) while we were
        // flushing queued response data. It owns nothing here, but it has finished the
        // direction back toward us: we must not send any more bytes or a Finish toward it.
        httpserverLinestateDestroy(ls);
        lineUnlock(l);
        return;
    }

    if (ts->websocket_enabled && ls->websocket_active)
    {
        if (! httpserverTransportSendWebSocketClose(t, l, ls))
        {
            failAndCloseD(t, l, ls);
            lineUnlock(l);
            return;
        }

        if (ls->runtime_proto == kHttpServerRuntimeHttp2 && ! ls->fin_sent)
        {
            ls->fin_sent = true;
            if (! httpserverTransportSendHttp2DataFrame(t, l, ls, NULL, true))
            {
                failAndCloseD(t, l, ls);
                lineUnlock(l);
                return;
            }
        }
    }
    else if (ls->runtime_proto == kHttpServerRuntimeHttp1)
    {
        if (! ls->h1_response_headers_sent)
        {
            if (! httpserverTransportSendHttp1ResponseHeaders(t, l))
            {
                failAndCloseD(t, l, ls);
                lineUnlock(l);
                return;
            }
            ls->h1_response_headers_sent = true;
        }

        if (! ls->fin_sent)
        {
            ls->fin_sent = true;
            if (! httpserverTransportSendHttp1FinalChunk(t, l))
            {
                failAndCloseD(t, l, ls);
                lineUnlock(l);
                return;
            }
        }
    }
    else if (ls->runtime_proto == kHttpServerRuntimeHttp2)
    {
        if (! ls->h2_response_headers_sent)
        {
            if (! httpserverTransportSubmitHttp2ResponseHeaders(t, l, ls, true))
            {
                failAndCloseD(t, l, ls);
                lineUnlock(l);
                return;
            }
            ls->fin_sent = true;
        }
        else if (! ls->fin_sent)
        {
            ls->fin_sent = true;
            if (! httpserverTransportSendHttp2DataFrame(t, l, ls, NULL, true))
            {
                failAndCloseD(t, l, ls);
                lineUnlock(l);
                return;
            }
        }
    }

    // A final-byte send above can re-enter through an upstream Finish from prev (a middle
    // tunnel that keeps the line alive). In that case prev is already finished and must not
    // receive a reflected Finish; we still own the single state destruction here.
    bool prev_already_finished = ls->prev_finished;

    ls->prev_finished = true;
    httpserverLinestateDestroy(ls);
    if (! prev_already_finished)
    {
        tunnelPrevDownStreamFinish(t, l);
    }
    lineUnlock(l);
}
