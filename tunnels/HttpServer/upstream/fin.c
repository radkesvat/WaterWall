#include "structure.h"

#include "loggers/network_logger.h"

void httpserverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    httpserver_lstate_t *ls = lineGetState(l, t);
    httpserver_tstate_t *ts = tunnelGetState(t);

    if (ls->split_role == kHttpServerSplitRoleUnknown || ls->split_role == kHttpServerSplitRoleUpload ||
        ls->split_role == kHttpServerSplitRoleDownload)
    {
        httpserverSplitUpStreamFinish(t, l);
        return;
    }

    lineLock(l);

    if (ts->websocket_enabled && ls->websocket_active)
    {
        if (lineIsAlive(l))
        {
            httpserverTransportCloseBothDirections(t, l, ls);
        }
        else
        {
            httpserverLinestateDestroy(ls);
        }
        lineUnlock(l);
        return;
    }

    httpserverLinestateDestroy(ls);
    tunnelNextUpStreamFinish(t, l);

    lineUnlock(l);
}
