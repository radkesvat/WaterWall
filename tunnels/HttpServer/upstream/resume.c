#include "structure.h"

#include "loggers/network_logger.h"

void httpserverTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    httpserver_lstate_t *ls = lineGetState(l, t);

    if (ls->next_finished)
    {
        return;
    }

    /* Resume also cancels any pending pre-pair download Pause. */
    ls->prev_paused = false;
    if (ls->split_role == kHttpServerSplitRoleDownload)
    {
        if (ls->split_main_line != NULL)
        {
            tunnelNextUpStreamResume(t, ls->split_main_line);
        }
        return;
    }
    if (ls->split_role == kHttpServerSplitRoleUpload || ls->split_role == kHttpServerSplitRoleUnknown)
    {
        return;
    }
    if (ls->h2_source_paused)
    {
        // The queued HTTP/2 DATA backlog still holds next until nghttp2 drains it.
        return;
    }
    tunnelNextUpStreamResume(t, l);
}
