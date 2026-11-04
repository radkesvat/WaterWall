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

    lineRef(l);

    if (ls->next_finished)
    {
        /* A nested Finish leaves cleanup to the active final-output call.
         * Between callbacks, carrier loss instead cancels the retained drain. */
        ls->prev_finished = true;
        if (! ls->finish_dispatching)
        {
            httpserverLinestateDestroy(ls);
        }
        lineUnref(l);
        return;
    }

    ls->prev_finished = true;

    if (ts->websocket_enabled && ls->websocket_active)
    {
        if (lineIsAlive(l))
        {
            httpserverTransportCloseNextDirection(t, l, ls);
        }
        lineUnref(l);
        return;
    }

    httpserverLinestateDestroy(ls);
    tunnelNextUpStreamFinish(t, l);

    lineUnref(l);
}
