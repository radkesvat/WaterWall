#include "structure.h"

#include "loggers/network_logger.h"

static void failAndCloseU(tunnel_t *t, line_t *l, httpclient_lstate_t *ls)
{
    if (lineIsAlive(l))
    {
        httpclientTransportCloseBothDirections(t, l, ls);
    }
}

void httpclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    httpclient_lstate_t *ls = lineGetState(l, t);
    httpclient_tstate_t *ts = tunnelGetState(t);

    if (ls->split_role == kHttpClientSplitRoleMain)
    {
        httpclientSplitUpStreamPayload(t, l, buf);
        return;
    }

    lineRef(l);

    /* Older readiness input stays ahead of input nested in its replay. HTTP/1
     * chunk and raw-upgrade serializers keep their stricter nested admission. */
    if (ls->runtime_proto != kHttpClientRuntimeUpgradedRaw && ! ls->h1_write_in_progress &&
        (ls->pending_up_draining || bufferqueueGetBufCount(&ls->pending_up) != 0))
    {
        if (! httpclientQueuePendingUp(l, ls, buf) || ! httpclientTransportFlushPendingUp(t, l, ls))
            failAndCloseU(t, l, ls);
        lineUnref(l);
        return;
    }

    if (ts->websocket_enabled)
    {
        if (! ls->websocket_active)
        {
            if (! httpclientQueuePendingUp(l, ls, buf))
                failAndCloseU(t, l, ls);
            lineUnref(l);
            return;
        }

        if (! httpclientTransportSendWebSocketData(t, l, ls, buf, 0x2))
        {
            failAndCloseU(t, l, ls);
            lineUnref(l);
            return;
        }

        lineUnref(l);
        return;
    }

    if (ls->runtime_proto == kHttpClientRuntimeHttp1)
    {
        if (! httpclientTransportSendHttp1ChunkedPayload(t, l, buf))
        {
            failAndCloseU(t, l, ls);
            lineUnref(l);
            return;
        }
        lineUnref(l);
        return;
    }

    if (ls->runtime_proto == kHttpClientRuntimeHttp2)
    {
        if (! httpclientTransportSendHttp2DataFrame(t, l, ls, buf, false))
        {
            failAndCloseU(t, l, ls);
            lineUnref(l);
            return;
        }
        lineUnref(l);
        return;
    }

    if (ls->runtime_proto == kHttpClientRuntimeUpgradedRaw)
    {
        if (! httpclientTransportQueueRawInput(t, l, buf, true))
        {
            failAndCloseU(t, l, ls);
        }
        lineUnref(l);
        return;
    }

    if (! httpclientQueuePendingUp(l, ls, buf))
        failAndCloseU(t, l, ls);
    lineUnref(l);
}
