#include "structure.h"

#include "loggers/network_logger.h"

static void failAndCloseU(tunnel_t *t, line_t *l, httpserver_lstate_t *ls)
{
    if (lineIsAlive(l))
    {
        httpserverTransportCloseBothDirections(t, l, ls);
    }
    else
    {
        httpserverLinestateDestroy(ls);
    }
}

void httpserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    httpserver_lstate_t *ls = lineGetState(l, t);
    httpserver_tstate_t *ts = tunnelGetState(t);

    if (ls->split_role == kHttpServerSplitRoleUnknown || ls->split_role == kHttpServerSplitRoleUpload ||
        ls->split_role == kHttpServerSplitRoleDownload)
    {
        httpserverSplitUpStreamPayload(t, l, buf);
        return;
    }

    lineLock(l);

    if (ts->verbose)
    {
        LOGD("HttpServer: upstream payload runtime=%d len=%u", ls->runtime_proto, sbufGetLength(buf));
    }

    if (ls->runtime_proto == kHttpServerRuntimeUpgradedRaw)
    {
        tunnelNextUpStreamPayload(t, l, buf);

        if (! lineIsAlive(l))
        {
            lineUnlock(l);
            return;
        }

        if (! httpserverTransportFlushPendingDown(t, l, ls))
        {
            if (! lineIsAlive(l))
            {
                lineUnlock(l);
                return;
            }

            failAndCloseU(t, l, ls);
            lineUnlock(l);
            return;
        }

        lineUnlock(l);
        return;
    }

    if (ls->runtime_proto == kHttpServerRuntimeHttp2)
    {
        if (! httpserverTransportFeedHttp2Input(t, l, ls, buf))
        {
            failAndCloseU(t, l, ls);
            lineUnlock(l);
            return;
        }
        else if (! httpserverTransportFlushPendingDown(t, l, ls))
        {
            failAndCloseU(t, l, ls);
            lineUnlock(l);
            return;
        }

        if (ts->websocket_enabled && ls->websocket_active &&
            (ls->websocket_close_received || ls->h2_request_finished))
        {
            httpserverTransportCloseBothDirections(t, l, ls);
            lineUnlock(l);
            return;
        }
        if (! lineIsAlive(l))
        {
            httpserverLinestateDestroy(ls);
            lineUnlock(l);
            return;
        }
        lineUnlock(l);
        return;
    }

    if (ts->websocket_enabled && ls->websocket_active)
    {
        bufferstreamPush(&ls->in_stream, buf);
        if (! httpserverTransportDrainWebSocketUp(t, l, ls))
        {
            failAndCloseU(t, l, ls);
            lineUnlock(l);
            return;
        }

        if (ls->websocket_close_received)
        {
            httpserverTransportCloseBothDirections(t, l, ls);
            lineUnlock(l);
            return;
        }

        if (! httpserverTransportFlushPendingDown(t, l, ls))
        {
            failAndCloseU(t, l, ls);
            lineUnlock(l);
            return;
        }

        lineUnlock(l);
        return;
    }

    bufferstreamPush(&ls->in_stream, buf);

    if (! httpserverTransportDetectRuntimeProtocol(t, l, ls))
    {
        failAndCloseU(t, l, ls);
        lineUnlock(l);
        return;
    }

    if (! lineIsAlive(l))
    {
        httpserverLinestateDestroy(ls);
        lineUnlock(l);
        return;
    }

    if (ls->runtime_proto == kHttpServerRuntimeHttp2)
    {
        while (! bufferstreamIsEmpty(&ls->in_stream))
        {
            sbuf_t *frame = bufferstreamIdealRead(&ls->in_stream);
            if (! httpserverTransportFeedHttp2Input(t, l, ls, frame))
            {
                failAndCloseU(t, l, ls);
                lineUnlock(l);
                return;
            }

            if (! lineIsAlive(l))
            {
                httpserverLinestateDestroy(ls);
                lineUnlock(l);
                return;
            }
        }

        if (! httpserverTransportFlushPendingDown(t, l, ls))
        {
            failAndCloseU(t, l, ls);
            lineUnlock(l);
            return;
        }
        lineUnlock(l);
        return;
    }

    if (! httpserverTransportHandleHttp1RequestHeaderPhase(t, l, ls))
    {
        if (! lineIsAlive(l))
        {
            lineUnlock(l);
            return;
        }

        failAndCloseU(t, l, ls);
        lineUnlock(l);
        return;
    }

    if (! lineIsAlive(l))
    {
        httpserverLinestateDestroy(ls);
        lineUnlock(l);
        return;
    }

    if (ls->runtime_proto == kHttpServerRuntimeHttp2)
    {
        while (! bufferstreamIsEmpty(&ls->in_stream))
        {
            sbuf_t *frame = bufferstreamIdealRead(&ls->in_stream);
            if (! httpserverTransportFeedHttp2Input(t, l, ls, frame))
            {
                failAndCloseU(t, l, ls);
                lineUnlock(l);
                return;
            }

            if (! lineIsAlive(l))
            {
                httpserverLinestateDestroy(ls);
                lineUnlock(l);
                return;
            }
        }

        if (! httpserverTransportFlushPendingDown(t, l, ls))
        {
            failAndCloseU(t, l, ls);
            lineUnlock(l);
            return;
        }
        lineUnlock(l);
        return;
    }

    if (ls->runtime_proto == kHttpServerRuntimeUpgradedRaw)
    {
        if (! httpserverTransportDrainRawUp(t, l, ls))
        {
            if (! lineIsAlive(l))
            {
                lineUnlock(l);
                return;
            }

            failAndCloseU(t, l, ls);
            lineUnlock(l);
            return;
        }

        if (! httpserverTransportFlushPendingDown(t, l, ls))
        {
            if (! lineIsAlive(l))
            {
                lineUnlock(l);
                return;
            }

            failAndCloseU(t, l, ls);
            lineUnlock(l);
            return;
        }

        lineUnlock(l);
        return;
    }

    if (ls->runtime_proto == kHttpServerRuntimeHttp1 && ls->h1_headers_parsed)
    {
        if (! httpserverTransportDrainHttp1RequestBody(t, l, ls))
        {
            failAndCloseU(t, l, ls);
            lineUnlock(l);
            return;
        }
    }

    if (! httpserverTransportFlushPendingDown(t, l, ls))
    {
        failAndCloseU(t, l, ls);
        lineUnlock(l);
        return;
    }

    if (! lineIsAlive(l))
    {
        httpserverLinestateDestroy(ls);
        lineUnlock(l);
        return;
    }

    if (ts->websocket_enabled && ls->websocket_active && ls->websocket_close_received)
    {
        httpserverTransportCloseBothDirections(t, l, ls);
        lineUnlock(l);
        return;
    }

    lineUnlock(l);
}
