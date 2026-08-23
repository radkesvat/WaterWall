#include "structure.h"

#include "loggers/network_logger.h"

void httpserverTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    httpserver_lstate_t *ls = lineGetState(l, t);

    if (ls->next_finished)
    {
        return;
    }

    /*
     * Split transport lines never reach Init at next. A paired download maps
     * backpressure to its initialized main line; an unpaired download has no
     * upstream consumer.
     */
    if (ls->split_role == kHttpServerSplitRoleDownload)
    {
        if (ls->split_main_line != NULL)
        {
            tunnelNextUpStreamPause(t, ls->split_main_line);
        }
        return;
    }
    if (ls->split_role == kHttpServerSplitRoleUpload || ls->split_role == kHttpServerSplitRoleUnknown)
    {
        return;
    }
    tunnelNextUpStreamPause(t, l);
}
