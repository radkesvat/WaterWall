#include "structure.h"

#include "loggers/network_logger.h"

static void failAndCloseD(tunnel_t *t, line_t *l, httpclient_lstate_t *ls)
{
    if (lineIsAlive(l))
    {
        httpclientTransportCloseBothDirections(t, l, ls);
    }
}

static void processPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    httpclient_lstate_t *ls = lineGetState(l, t);
    httpclient_tstate_t *ts = tunnelGetState(t);

    if (ls->split_role == kHttpClientSplitRoleUpload || ls->split_role == kHttpClientSplitRoleDownload)
    {
        httpclientSplitProcessDownStreamPayload(t, l, buf);
        return;
    }

    lineRef(l);

    if (ls->runtime_proto == kHttpClientRuntimeHttp1 && ls->response_complete)
    {
        if (ts->verbose && ! ls->h1_trailing_bytes_logged)
        {
            LOGD("HttpClient: ignoring bytes after the HTTP/1.1 response body");
            ls->h1_trailing_bytes_logged = true;
        }
        lineReuseBuffer(l, buf);
        lineUnref(l);
        return;
    }

    if (ls->runtime_proto == kHttpClientRuntimeHttp2)
    {
        if (! httpclientTransportFeedHttp2Input(t, l, ls, buf))
        {
            failAndCloseD(t, l, ls);
            lineUnref(l);
            return;
        }
        if (ts->websocket_enabled && ls->websocket_active && ls->websocket_close_received)
        {
            httpclientTransportCloseBothDirections(t, l, ls);
            lineUnref(l);
            return;
        }
        lineUnref(l);
        return;
    }

    if (ls->runtime_proto == kHttpClientRuntimeUpgradedRaw)
    {
        if (ls->prev_finished)
        {
            lineReuseBuffer(l, buf);
            lineUnref(l);
            return;
        }

        if (! httpclientTransportQueueRawInput(t, l, buf, false))
        {
            failAndCloseD(t, l, ls);
        }
        lineUnref(l);
        return;
    }

    if (ts->websocket_enabled && ls->websocket_active)
    {
        bufferstreamPush(&ls->in_stream, buf);
        if (! httpclientTransportDrainWebSocketDown(t, l, ls))
        {
            failAndCloseD(t, l, ls);
            lineUnref(l);
            return;
        }
        if (ls->websocket_close_received)
        {
            httpclientTransportCloseBothDirections(t, l, ls);
            lineUnref(l);
            return;
        }
        lineUnref(l);
        return;
    }

    bufferstreamPush(&ls->in_stream, buf);

    if (! httpclientTransportHandleHttp1ResponseHeaderPhase(t, l, ls))
    {
        failAndCloseD(t, l, ls);
        lineUnref(l);
        return;
    }

    if (! lineIsAlive(l) || ! tunnelIsActiveForLine(t, l))
    {
        lineUnref(l);
        return;
    }

    if (ls->runtime_proto == kHttpClientRuntimeHttp2)
    {
        if (! bufferstreamIsEmpty(&ls->in_stream))
        {
            sbuf_t *leftover = bufferstreamFullRead(&ls->in_stream);
            if (! httpclientTransportFeedHttp2Input(t, l, ls, leftover))
            {
                failAndCloseD(t, l, ls);
                lineUnref(l);
                return;
            }

            if (! lineIsAlive(l))
            {
                lineUnref(l);
                return;
            }
        }

        lineUnref(l);
        return;
    }

    if (ls->runtime_proto == kHttpClientRuntimeHttp1 && ls->h1_headers_parsed)
    {
        if (! httpclientTransportDrainHttp1Body(t, l, ls))
        {
            failAndCloseD(t, l, ls);
            lineUnref(l);
            return;
        }
    }

    if (! lineIsAlive(l))
    {
        lineUnref(l);
        return;
    }

    /*
     * response_complete is an HTTP framing boundary, not a Waterwall half-close.
     * Keep the line open until the transport delivers downstream Finish.
     */

    if (ts->websocket_enabled && ls->websocket_active && ls->websocket_close_received)
    {
        httpclientTransportCloseBothDirections(t, l, ls);
        lineUnref(l);
        return;
    }

    lineUnref(l);
}

static void rejectInput(tunnel_t *t, line_t *l, httpclient_lstate_t *ls)
{
    if (ls->split_role == kHttpClientSplitRoleUpload || ls->split_role == kHttpClientSplitRoleDownload)
        httpclientSplitRejectInput(t, l);
    else
        httpclientTransportCloseBothDirections(t, l, ls);
}

void httpclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    httpclient_lstate_t *ls = lineGetState(l, t);
    lineRef(l);
    const http_receive_result_t admitted = httpReceiveAdmit(&ls->receive, lineGetBufferPool(l), buf);
    if (admitted == kHttpReceiveRejected)
    {
        lineReuseBuffer(l, buf);
        LOGW("HttpClient: nested receive limit exceeded");
        rejectInput(t, l, ls);
    }
    if (admitted != kHttpReceiveDrain)
    {
        lineUnref(l);
        return;
    }

    sbuf_t *slice;
    while ((slice = httpReceiveNext(&ls->receive, lineGetBufferPool(l))) != NULL)
    {
        processPayload(t, l, slice);
        if (! lineIsAlive(l) || ls->line == NULL || ! tunnelIsActiveForLine(t, l))
        {
            lineUnref(l);
            return;
        }
        size_t limit = kHttpReceiveStreamBytes;
        if (! httpReceiveSettle(&ls->in_stream, limit))
        {
            LOGW("HttpClient: retained receive limit exceeded");
            rejectInput(t, l, ls);
            lineUnref(l);
            return;
        }
    }
    if (ls->runtime_proto == kHttpClientRuntimeUpgradedRaw && ! httpclientTransportFinishCustomUpgrade(t, l, ls) &&
        lineIsAlive(l) && ls->line != NULL)
        rejectInput(t, l, ls);
    lineUnref(l);
}
