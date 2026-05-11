#include "structure.h"

#include "loggers/network_logger.h"

static void failAndCloseD(tunnel_t *t, line_t *l, httpclient_lstate_t *ls)
{
    if (lineIsAlive(l))
    {
        httpclientTransportCloseBothDirections(t, l, ls);
    }
    else
    {
        httpclientLinestateDestroy(ls);
    }
}

void httpclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    httpclient_lstate_t *ls = lineGetState(l, t);
    httpclient_tstate_t *ts = tunnelGetState(t);

    if (ls->split_role == kHttpClientSplitRoleUpload || ls->split_role == kHttpClientSplitRoleDownload)
    {
        httpclientSplitDownStreamPayload(t, l, buf);
        return;
    }

    lineLock(l);

    if (ls->runtime_proto == kHttpClientRuntimeHttp2)
    {
        if (! httpclientTransportFeedHttp2Input(t, l, ls, buf))
        {
            failAndCloseD(t, l, ls);
            lineUnlock(l);
            return;
        }
        if (ls->response_complete && ! ls->prev_finished)
        {
            httpclientTransportCloseBothDirections(t, l, ls);
            lineUnlock(l);
            return;
        }

        if (ts->websocket_enabled && ls->websocket_active && ls->websocket_close_received)
        {
            httpclientTransportCloseBothDirections(t, l, ls);
            lineUnlock(l);
            return;
        }
        lineUnlock(l);
        return;
    }

    if (ls->runtime_proto == kHttpClientRuntimeUpgradedRaw)
    {
        if (ls->prev_finished)
        {
            lineReuseBuffer(l, buf);
            lineUnlock(l);
            return;
        }

        tunnelPrevDownStreamPayload(t, l, buf);
        lineUnlock(l);
        return;
    }

    if (ts->websocket_enabled && ls->websocket_active)
    {
        bufferstreamPush(&ls->in_stream, buf);
        if (! httpclientTransportDrainWebSocketDown(t, l, ls))
        {
            failAndCloseD(t, l, ls);
            lineUnlock(l);
            return;
        }
        if (ls->websocket_close_received)
        {
            httpclientTransportCloseBothDirections(t, l, ls);
            lineUnlock(l);
            return;
        }
        lineUnlock(l);
        return;
    }

    bufferstreamPush(&ls->in_stream, buf);

    if (! httpclientTransportHandleHttp1ResponseHeaderPhase(t, l, ls))
    {
        failAndCloseD(t, l, ls);
        lineUnlock(l);
        return;
    }

    if (! lineIsAlive(l))
    {
        httpclientLinestateDestroy(ls);
        lineUnlock(l);
        return;
    }

    if (ls->response_complete && ! ls->prev_finished)
    {
        httpclientTransportCloseBothDirections(t, l, ls);
        lineUnlock(l);
        return;
    }

    if (ls->runtime_proto == kHttpClientRuntimeHttp2)
    {
        while (! bufferstreamIsEmpty(&ls->in_stream))
        {
            sbuf_t *leftover = bufferstreamIdealRead(&ls->in_stream);
            if (! httpclientTransportFeedHttp2Input(t, l, ls, leftover))
            {
                failAndCloseD(t, l, ls);
                lineUnlock(l);
                return;
            }

            if (! lineIsAlive(l))
            {
                httpclientLinestateDestroy(ls);
                lineUnlock(l);
                return;
            }

            if (ls->response_complete && ! ls->prev_finished)
            {
                httpclientTransportCloseBothDirections(t, l, ls);
                lineUnlock(l);
                return;
            }
        }

        lineUnlock(l);
        return;
    }

    if (ls->runtime_proto == kHttpClientRuntimeHttp1 && ls->h1_headers_parsed)
    {
        if (! httpclientTransportDrainHttp1Body(t, l, ls))
        {
            failAndCloseD(t, l, ls);
            lineUnlock(l);
            return;
        }
    }

    if (! lineIsAlive(l))
    {
        httpclientLinestateDestroy(ls);
        lineUnlock(l);
        return;
    }

    if (ls->response_complete && ! ls->prev_finished)
    {
        httpclientTransportCloseBothDirections(t, l, ls);
        lineUnlock(l);
        return;
    }

    if (ts->websocket_enabled && ls->websocket_active && ls->websocket_close_received)
    {
        httpclientTransportCloseBothDirections(t, l, ls);
        lineUnlock(l);
        return;
    }

    lineUnlock(l);
}
