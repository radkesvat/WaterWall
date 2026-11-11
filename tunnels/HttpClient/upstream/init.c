#include "structure.h"

#include "loggers/network_logger.h"

static void closeOrDestroyLine(tunnel_t *t, line_t *l, httpclient_lstate_t *ls)
{
    if (lineIsAlive(l))
    {
        httpclientTransportCloseBothDirections(t, l, ls);
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
    if (httpclientUsesOwnedCarrier(ts))
    {
        httpclientCarrierStart(t, l);
        return;
    }
    httpclientLinestateInitialize(lineGetState(l, t), t, l);
    httpclientStartTransport(t, l);
}

void httpclientStartTransport(tunnel_t *t, line_t *l)
{
    httpclient_tstate_t *ts = tunnelGetState(t);
    httpclient_lstate_t *ls = lineGetState(l, t);

    if (ts->verbose)
    {
        LOGD("HttpClient: line init version-mode=%d websocket=%s upgrade=%s host_bytes=%zu path_bytes=%zu",
             ts->version_mode,
             boolToTrueFalse(ts->websocket_enabled),
             boolToTrueFalse(ts->enable_upgrade),
             httpclientLogTextBytes(ts->host),
             httpclientLogTextBytes(ts->path));
    }

    lineRef(l);

    if (! lineCallWithRef(l, tunnelNextUpStreamInit, t))
    {
        lineUnref(l);
        return;
    }

    if (ts->websocket_enabled && ts->version_mode == kHttpClientVersionModeBoth && ts->enable_upgrade)
    {
        ls->runtime_proto               = kHttpClientRuntimeHttp1;
        ls->websocket_waiting_handshake = true;
        if (ts->verbose)
        {
            LOGD("HttpClient: websocket mode keeps both+upgrade on HTTP/1.1 for the opening handshake");
        }
        if (! httpclientTransportSendHttp1RequestHeaders(t, l, false))
        {
            closeOrDestroyLine(t, l, ls);
        }
        lineUnref(l);
        return;
    }

    if (ts->version_mode == kHttpClientVersionModeHttp1)
    {
        ls->runtime_proto               = kHttpClientRuntimeHttp1;
        ls->websocket_waiting_handshake = ts->websocket_enabled;
        if (! httpclientTransportSendHttp1RequestHeaders(t, l, false))
        {
            closeOrDestroyLine(t, l, ls);
        }
        lineUnref(l);
        return;
    }

    if (ts->version_mode == kHttpClientVersionModeHttp2)
    {
        ls->runtime_proto               = kHttpClientRuntimeHttp2;
        ls->websocket_waiting_handshake = ts->websocket_enabled;
        if (! httpclientTransportEnsureHttp2Session(t, l, ls))
        {
            closeOrDestroyLine(t, l, ls);
        }
        lineUnref(l);
        return;
    }

    if (ts->enable_upgrade)
    {
        ls->runtime_proto = kHttpClientRuntimeWaitUpgrade;
        if (! httpclientTransportSendHttp1RequestHeaders(t, l, true))
        {
            closeOrDestroyLine(t, l, ls);
        }
        lineUnref(l);
        return;
    }

    ls->runtime_proto               = kHttpClientRuntimeHttp2;
    ls->websocket_waiting_handshake = ts->websocket_enabled;
    if (! httpclientTransportEnsureHttp2Session(t, l, ls))
    {
        closeOrDestroyLine(t, l, ls);
    }

    lineUnref(l);
}
