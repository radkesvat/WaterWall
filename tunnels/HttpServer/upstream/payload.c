#include "structure.h"

#include "loggers/network_logger.h"

static void failAndCloseU(tunnel_t *t, line_t *l, httpserver_lstate_t *ls)
{
    if (lineIsAlive(l))
    {
        httpserverTransportCloseBothDirections(t, l, ls);
    }
}

static void processPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    httpserver_lstate_t *ls = lineGetState(l, t);
    httpserver_tstate_t *ts = tunnelGetState(t);

    if (ls->split_role == kHttpServerSplitRoleUnknown || ls->split_role == kHttpServerSplitRoleUpload ||
        ls->split_role == kHttpServerSplitRoleDownload)
    {
        httpserverSplitProcessUpStreamPayload(t, l, buf);
        return;
    }

    lineRef(l);

    if (ts->verbose)
    {
        LOGD("HttpServer: upstream payload runtime=%d len=%u", ls->runtime_proto, sbufGetLength(buf));
    }

    if (ls->runtime_proto == kHttpServerRuntimeUpgradedRaw)
    {
        httpserverTransportQueueUpgradePayload(t, l, buf, true);
        if (lineIsAlive(l) && ls->line != NULL && ! httpserverTransportFinishCustomUpgrade(t, l, ls))
            failAndCloseU(t, l, ls);
        lineUnref(l);
        return;
    }

    if (ls->runtime_proto == kHttpServerRuntimeHttp2)
    {
        if (! httpserverTransportFeedHttp2Input(t, l, ls, buf))
        {
            failAndCloseU(t, l, ls);
            lineUnref(l);
            return;
        }
        else if (! httpserverTransportFlushPendingDown(t, l, ls))
        {
            failAndCloseU(t, l, ls);
            lineUnref(l);
            return;
        }

        if (ts->websocket_enabled && ls->websocket_active &&
            (ls->websocket_close_received || ls->h2_request_finished))
        {
            httpserverTransportCloseBothDirections(t, l, ls);
            lineUnref(l);
            return;
        }
        if (! lineIsAlive(l))
        {
            lineUnref(l);
            return;
        }
        lineUnref(l);
        return;
    }

    if (ts->websocket_enabled && ls->websocket_active)
    {
        bufferstreamPush(&ls->in_stream, buf);
        if (! httpserverTransportDrainWebSocketUp(t, l, ls))
        {
            failAndCloseU(t, l, ls);
            lineUnref(l);
            return;
        }

        if (ls->websocket_close_received)
        {
            httpserverTransportCloseBothDirections(t, l, ls);
            lineUnref(l);
            return;
        }

        if (! httpserverTransportFlushPendingDown(t, l, ls))
        {
            failAndCloseU(t, l, ls);
            lineUnref(l);
            return;
        }

        lineUnref(l);
        return;
    }

    if (ls->runtime_proto == kHttpServerRuntimeHttp1 && ls->h1_request_finished)
    {
        if (ts->verbose && ! ls->h1_trailing_bytes_logged)
        {
            LOGD("HttpServer: ignoring bytes after the HTTP/1.1 request body");
            ls->h1_trailing_bytes_logged = true;
        }
        lineReuseBuffer(l, buf);
        lineUnref(l);
        return;
    }

    bufferstreamPush(&ls->in_stream, buf);

    if (! httpserverTransportDetectRuntimeProtocol(t, l, ls))
    {
        failAndCloseU(t, l, ls);
        lineUnref(l);
        return;
    }

    if (! lineIsAlive(l))
    {
        lineUnref(l);
        return;
    }

    if (ls->runtime_proto == kHttpServerRuntimeHttp2)
    {
        if (! bufferstreamIsEmpty(&ls->in_stream))
        {
            sbuf_t *frame = bufferstreamFullRead(&ls->in_stream);
            if (! httpserverTransportFeedHttp2Input(t, l, ls, frame))
            {
                failAndCloseU(t, l, ls);
                lineUnref(l);
                return;
            }

            if (! lineIsAlive(l))
            {
                lineUnref(l);
                return;
            }
        }

        if (! httpserverTransportFlushPendingDown(t, l, ls))
        {
            failAndCloseU(t, l, ls);
            lineUnref(l);
            return;
        }
        lineUnref(l);
        return;
    }

    if (! httpserverTransportHandleHttp1RequestHeaderPhase(t, l, ls))
    {
        if (! lineIsAlive(l))
        {
            lineUnref(l);
            return;
        }

        failAndCloseU(t, l, ls);
        lineUnref(l);
        return;
    }

    if (! lineIsAlive(l))
    {
        lineUnref(l);
        return;
    }

    if (! tunnelIsActiveForLine(t, l))
    {
        lineUnref(l);
        return;
    }

    if (ls->runtime_proto == kHttpServerRuntimeHttp2)
    {
        if (! bufferstreamIsEmpty(&ls->in_stream))
        {
            sbuf_t *frame = bufferstreamFullRead(&ls->in_stream);
            if (! httpserverTransportFeedHttp2Input(t, l, ls, frame))
            {
                failAndCloseU(t, l, ls);
                lineUnref(l);
                return;
            }

            if (! lineIsAlive(l))
            {
                lineUnref(l);
                return;
            }
        }

        if (! httpserverTransportFlushPendingDown(t, l, ls))
        {
            failAndCloseU(t, l, ls);
            lineUnref(l);
            return;
        }
        lineUnref(l);
        return;
    }

    if (ls->runtime_proto == kHttpServerRuntimeHttp1 && ls->h1_headers_parsed)
    {
        if (! httpserverTransportDrainHttp1RequestBody(t, l, ls))
        {
            failAndCloseU(t, l, ls);
            lineUnref(l);
            return;
        }
    }

    if (! httpserverTransportFlushPendingDown(t, l, ls))
    {
        failAndCloseU(t, l, ls);
        lineUnref(l);
        return;
    }

    if (! lineIsAlive(l))
    {
        lineUnref(l);
        return;
    }

    if (ts->websocket_enabled && ls->websocket_active && ls->websocket_close_received)
    {
        httpserverTransportCloseBothDirections(t, l, ls);
        lineUnref(l);
        return;
    }

    lineUnref(l);
}

static void rejectInput(tunnel_t *t, line_t *l, httpserver_lstate_t *ls)
{
    if (ls->split_role != kHttpServerSplitRoleNone)
        httpserverSplitRejectInput(t, l);
    else
        httpserverTransportCloseBothDirections(t, l, ls);
}

static bool drainReceivedInput(tunnel_t *t, line_t *l, httpserver_lstate_t *ls)
{
    sbuf_t *slice;
    while ((slice = httpReceiveNext(&ls->receive, lineGetBufferPool(l))) != NULL)
    {
        processPayload(t, l, slice);
        if (! lineIsAlive(l) || ls->line == NULL || ! tunnelIsActiveForLine(t, l))
        {
            return false;
        }
        size_t limit = kHttpReceiveStreamBytes;
        if (ls->split_role == kHttpServerSplitRoleUpload && ls->h1_headers_parsed && ls->split_main_line == NULL)
        {
            httpserver_tstate_t *ts = tunnelGetState(t);
            limit = ts->no_split_upload_buffering_limit ? UINT32_MAX : (size_t) httpserverSplitWaitingLimit(l);
        }
        if (! httpReceiveSettle(&ls->in_stream, limit))
        {
            LOGW("HttpServer: retained receive limit exceeded");
            rejectInput(t, l, ls);
            return false;
        }
    }
    if (ls->runtime_proto == kHttpServerRuntimeUpgradedRaw && ! httpserverTransportFinishCustomUpgrade(t, l, ls) &&
        lineIsAlive(l) && ls->line != NULL)
        rejectInput(t, l, ls);
    return lineIsAlive(l) && ls->line != NULL;
}

bool httpserverDrainSplitInput(tunnel_t *t, line_t *l)
{
    httpserver_lstate_t *ls = lineGetState(l, t);
    assert(ls->receive.draining);
    lineRef(l);
    bool ok = httpserverTransportDrainHttp1RequestBody(t, l, ls);
    if (ok && lineIsAlive(l) && ls->line != NULL)
    {
        /* Paired waiting input may have no queued slice to trigger settlement.
         * Bytes beyond this single request are already ignored by Payload. */
        if (ls->h1_request_finished)
            bufferstreamEmpty(&ls->in_stream);
        if (! httpReceiveSettle(&ls->in_stream, kHttpReceiveStreamBytes))
        {
            rejectInput(t, l, ls);
            ok = false;
        }
        else
            ok = drainReceivedInput(t, l, ls);
    }
    else
        ok = false;
    lineUnref(l);
    return ok;
}

void httpserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    httpserver_lstate_t *ls = lineGetState(l, t);
    lineRef(l);
    const http_receive_result_t admitted = httpReceiveAdmit(&ls->receive, lineGetBufferPool(l), buf);
    if (admitted == kHttpReceiveRejected)
    {
        lineReuseBuffer(l, buf);
        LOGW("HttpServer: nested receive limit exceeded");
        rejectInput(t, l, ls);
    }
    if (admitted != kHttpReceiveDrain)
    {
        lineUnref(l);
        return;
    }

    discard drainReceivedInput(t, l, ls);
    lineUnref(l);
}
