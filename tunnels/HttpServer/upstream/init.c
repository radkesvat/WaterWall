#include "structure.h"

#include "loggers/network_logger.h"

static void closeOrDestroyLine(tunnel_t *t, line_t *l, httpserver_lstate_t *ls)
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

void httpserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    httpserver_tstate_t *ts = tunnelGetState(t);
    httpserver_lstate_t *ls = lineGetState(l, t);

    httpserverLinestateInitialize(ls, t, l);

    if (ts->verbose)
    {
        LOGD("HttpServer: line init version-mode=%d websocket=%s upgrade=%s", ts->version_mode,
             ts->websocket_enabled ? "true" : "false", ts->enable_upgrade ? "true" : "false");
    }

    lineLock(l);

    if (! withLineLocked(l, tunnelNextUpStreamInit, t))
    {
        lineUnlock(l);
        return;
    }

    if (ts->version_mode == kHttpServerVersionModeHttp1)
    {
        ls->runtime_proto = kHttpServerRuntimeHttp1;
        lineUnlock(l);
        return;
    }

    if (ts->version_mode == kHttpServerVersionModeHttp2)
    {
        if (! httpserverTransportPrepareHttp2Session(t, l, ls))
        {
            closeOrDestroyLine(t, l, ls);
        }
        lineUnlock(l);
        return;
    }

    ls->runtime_proto = kHttpServerRuntimeUnknown;
    lineUnlock(l);
}
