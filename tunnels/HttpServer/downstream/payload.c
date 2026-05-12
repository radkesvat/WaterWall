#include "structure.h"

#include "loggers/network_logger.h"

static void failAndCloseDownStream(tunnel_t *t, line_t *l, httpserver_lstate_t *ls)
{
    if (lineIsAlive(l))
    {
        httpserverTransportCloseBothDirections(t, l, ls);
    }
}

void httpserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    httpserver_lstate_t *ls = lineGetState(l, t);
    httpserver_tstate_t *ts = tunnelGetState(t);

    if (ls->split_role == kHttpServerSplitRoleMain)
    {
        httpserverSplitDownStreamPayload(t, l, buf);
        return;
    }

    lineLock(l);

    if (ls->runtime_proto == kHttpServerRuntimeUpgradedRaw)
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

    if (ts->websocket_enabled)
    {
        if (! ls->websocket_active)
        {
            bufferqueuePushBack(&ls->pending_down, buf);
            lineUnlock(l);
            return;
        }

        if (ls->runtime_proto == kHttpServerRuntimeHttp2 && ! ls->h2_response_headers_sent)
        {
            if (! httpserverTransportSubmitHttp2ResponseHeaders(t, l, ls, false))
            {
                lineReuseBuffer(l, buf);
                failAndCloseDownStream(t, l, ls);
                lineUnlock(l);
                return;
            }
        }

        if (! httpserverTransportSendWebSocketData(t, l, ls, buf, 0x2))
        {
            failAndCloseDownStream(t, l, ls);
            lineUnlock(l);
            return;
        }
        lineUnlock(l);
        return;
    }

    if (ls->runtime_proto == kHttpServerRuntimeHttp1)
    {
        if (! ls->h1_headers_parsed)
        {
            bufferqueuePushBack(&ls->pending_down, buf);
            lineUnlock(l);
            return;
        }

        if (! ls->h1_response_headers_sent)
        {
            if (! httpserverTransportSendHttp1ResponseHeaders(t, l))
            {
                lineReuseBuffer(l, buf);
                failAndCloseDownStream(t, l, ls);
                lineUnlock(l);
                return;
            }
            ls->h1_response_headers_sent = true;
        }

        if (! httpserverTransportSendHttp1ChunkedPayload(t, l, buf))
        {
            failAndCloseDownStream(t, l, ls);
            lineUnlock(l);
            return;
        }
        lineUnlock(l);
        return;
    }

    if (ls->runtime_proto == kHttpServerRuntimeHttp2)
    {
        if (ls->h2_stream_id <= 0)
        {
            bufferqueuePushBack(&ls->pending_down, buf);
            lineUnlock(l);
            return;
        }

        if (! ls->h2_response_headers_sent)
        {
            if (! httpserverTransportSubmitHttp2ResponseHeaders(t, l, ls, false))
            {
                lineReuseBuffer(l, buf);
                failAndCloseDownStream(t, l, ls);
                lineUnlock(l);
                return;
            }
        }

        if (! httpserverTransportSendHttp2DataFrame(t, l, ls, buf, false))
        {
            failAndCloseDownStream(t, l, ls);
            lineUnlock(l);
            return;
        }
        lineUnlock(l);
        return;
    }

    bufferqueuePushBack(&ls->pending_down, buf);
    lineUnlock(l);
}
