#include "structure.h"

#include "loggers/network_logger.h"

void httpclientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    httpclient_lstate_t *ls = lineGetState(l, t);

    if (ls->prev_finished)
    {
        return;
    }

    if (ls->line_role == kHttpClientLineCarrier)
    {
        ls->next_paused = false;
        if (! ls->h2_source_paused)
            tunnelPrevDownStreamResume(t, ls->application_line);
        return;
    }

    // Mirror of DownStreamPause: the upload transport's next can accept data again, so resume
    // the request-body source on main's prev.
    if (ls->split_role == kHttpClientSplitRoleUpload && ls->split_main_line != NULL)
    {
        tunnelPrevDownStreamResume(t, ls->split_main_line);
        return;
    }
    if (ls->split_role == kHttpClientSplitRoleDownload)
    {
        return;
    }
    tunnelPrevDownStreamResume(t, l);
}
