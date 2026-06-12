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

    if (ls->next_finished)
    {
        // Re-entrant upstream Finish: our own downStreamFinish is currently flushing the
        // final response bytes toward prev and has already finished next. That frame owns
        // the line-state destruction, and next must not receive another Finish.
        ls->prev_finished = true;
        lineUnlock(l);
        return;
    }

    ls->prev_finished = true;

    if (ts->websocket_enabled && ls->websocket_active)
    {
        if (lineIsAlive(l))
        {
            httpserverTransportCloseNextDirection(t, l, ls);
        }
        lineUnlock(l);
        return;
    }

    httpserverLinestateDestroy(ls);
    tunnelNextUpStreamFinish(t, l);

    lineUnlock(l);
}
