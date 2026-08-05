#include "structure.h"

#include "loggers/network_logger.h"

void httpserverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    httpserver_lstate_t *ls = lineGetState(l, t);
    httpserver_tstate_t *ts = tunnelGetState(t);

    /*
     * A split main line begins at HttpServer and is driven downstream by next,
     * so it cannot legitimately receive an upstream Finish. Transport halves
     * do enter here and are handled by the split lifecycle owner below.
     */
    if (ls->split_role == kHttpServerSplitRoleUnknown || ls->split_role == kHttpServerSplitRoleUpload ||
        ls->split_role == kHttpServerSplitRoleDownload)
    {
        httpserverSplitUpStreamFinish(t, l);
        return;
    }

    lineLock(l);

    if (ls->next_finished)
    {
        /*
         * In single mode next_finished is set only by downStreamFinish or by
         * httpserverTransportCloseDirections. Both paths own state destruction;
         * this is the re-entrant upstream Finish they can trigger while flushing.
         */
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
