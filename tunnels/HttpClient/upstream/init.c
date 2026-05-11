#include "structure.h"

#include "loggers/network_logger.h"

static void closeOrDestroyLine(tunnel_t *t, line_t *l, httpclient_lstate_t *ls)
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

void httpclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    if (httpclientSplitIsEnabled(t))
    {
        httpclientSplitUpStreamInit(t, l);
        return;
    }

    httpclient_tstate_t *ts = tunnelGetState(t);
    httpclient_lstate_t *ls = lineGetState(l, t);

    httpclientLinestateInitialize(ls, t, l);

    if (ts->verbose)
    {
        LOGD("HttpClient: line init version-mode=%d websocket=%s upgrade=%s host=%s path=%s", ts->version_mode,
             ts->websocket_enabled ? "true" : "false", ts->enable_upgrade ? "true" : "false", ts->host, ts->path);
    }

    lineLock(l);

    if (! withLineLocked(l, tunnelNextUpStreamInit, t))
    {
        lineUnlock(l);
        return;
    }

    if (ts->websocket_enabled && ts->version_mode == kHttpClientVersionModeBoth && ts->enable_upgrade)
    {
        ls->runtime_proto              = kHttpClientRuntimeHttp1;
        ls->websocket_waiting_handshake = true;
        if (ts->verbose)
        {
            LOGD("HttpClient: websocket mode keeps both+upgrade on HTTP/1.1 for the opening handshake");
        }
        if (! httpclientTransportSendHttp1RequestHeaders(t, l, false))
        {
            closeOrDestroyLine(t, l, ls);
        }
        lineUnlock(l);
        return;
    }

    if (ts->version_mode == kHttpClientVersionModeHttp1)
    {
        ls->runtime_proto = kHttpClientRuntimeHttp1;
        ls->websocket_waiting_handshake = ts->websocket_enabled;
        if (! httpclientTransportSendHttp1RequestHeaders(t, l, false))
        {
            closeOrDestroyLine(t, l, ls);
        }
        lineUnlock(l);
        return;
    }

    if (ts->version_mode == kHttpClientVersionModeHttp2)
    {
        ls->runtime_proto = kHttpClientRuntimeHttp2;
        ls->websocket_waiting_handshake = ts->websocket_enabled;
        if (! httpclientTransportEnsureHttp2Session(t, l, ls))
        {
            closeOrDestroyLine(t, l, ls);
        }
        lineUnlock(l);
        return;
    }

    if (ts->enable_upgrade)
    {
        ls->runtime_proto = kHttpClientRuntimeWaitUpgrade;
        if (! httpclientTransportSendHttp1RequestHeaders(t, l, true))
        {
            closeOrDestroyLine(t, l, ls);
        }
        lineUnlock(l);
        return;
    }

    ls->runtime_proto = kHttpClientRuntimeHttp2;
    ls->websocket_waiting_handshake = ts->websocket_enabled;
    if (! httpclientTransportEnsureHttp2Session(t, l, ls))
    {
        closeOrDestroyLine(t, l, ls);
    }

    lineUnlock(l);
}
