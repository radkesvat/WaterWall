#include "structure.h"

#include "loggers/network_logger.h"

static void failAndCloseU(tunnel_t *t, line_t *l, httpclient_lstate_t *ls)
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

void httpclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    httpclient_lstate_t *ls = lineGetState(l, t);
    httpclient_tstate_t *ts = tunnelGetState(t);

    if (ls->split_role == kHttpClientSplitRoleMain)
    {
        httpclientSplitUpStreamPayload(t, l, buf);
        return;
    }

    lineLock(l);

    if (ts->websocket_enabled)
    {
        if (! ls->websocket_active)
        {
            bufferqueuePushBack(&ls->pending_up, buf);
            lineUnlock(l);
            return;
        }

        if (! httpclientTransportSendWebSocketData(t, l, ls, buf, 0x2))
        {
            failAndCloseU(t, l, ls);
            lineUnlock(l);
            return;
        }

        lineUnlock(l);
        return;
    }

    if (ls->runtime_proto == kHttpClientRuntimeHttp1)
    {
        if (! httpclientTransportSendHttp1ChunkedPayload(t, l, buf))
        {
            failAndCloseU(t, l, ls);
            lineUnlock(l);
            return;
        }
        lineUnlock(l);
        return;
    }

    if (ls->runtime_proto == kHttpClientRuntimeHttp2)
    {
        if (! httpclientTransportSendHttp2DataFrame(t, l, ls, buf, false))
        {
            failAndCloseU(t, l, ls);
            lineUnlock(l);
            return;
        }
        lineUnlock(l);
        return;
    }

    if (ls->runtime_proto == kHttpClientRuntimeUpgradedRaw)
    {
        tunnelNextUpStreamPayload(t, l, buf);
        lineUnlock(l);
        return;
    }

    if (ls->runtime_proto == kHttpClientRuntimeWaitUpgrade)
    {
        bufferqueuePushBack(&ls->pending_up, buf);
        lineUnlock(l);
        return;
    }

    bufferqueuePushBack(&ls->pending_up, buf);
    lineUnlock(l);
}
