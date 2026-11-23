#include "structure.h"

#include "loggers/network_logger.h"

void httpserverTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    httpserver_lstate_t *ls = lineGetState(l, t);

    if (ls->next_finished)
    {
        return;
    }

    /* Before the role or main line is known, remember an outstanding download
     * Pause. Once paired, an immediate relay supersedes any pending replay. */
    if (ls->split_role == kHttpServerSplitRoleDownload)
    {
        ls->prev_paused = ls->split_main_line == NULL;
        if (ls->split_main_line != NULL)
        {
            tunnelNextUpStreamPause(t, ls->split_main_line);
        }
        return;
    }
    if (ls->split_role == kHttpServerSplitRoleUpload || ls->split_role == kHttpServerSplitRoleUnknown)
    {
        ls->prev_paused = ls->split_role == kHttpServerSplitRoleUnknown;
        return;
    }
    ls->prev_paused = true;
    tunnelNextUpStreamPause(t, l);
}
