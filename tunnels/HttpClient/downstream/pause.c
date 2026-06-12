#include "structure.h"

#include "loggers/network_logger.h"

void httpclientTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    httpclient_lstate_t *ls = lineGetState(l, t);

    if (ls->prev_finished)
    {
        return;
    }

    // A pause arriving on the upload transport means its next (the server's upload connection)
    // cannot accept the request body fast enough, so we must slow the body source: main's prev.
    if (ls->split_role == kHttpClientSplitRoleUpload && ls->split_main_line != NULL)
    {
        tunnelPrevDownStreamPause(t, ls->split_main_line);
        return;
    }
    if (ls->split_role == kHttpClientSplitRoleDownload)
    {
        return;
    }
    tunnelPrevDownStreamPause(t, l);
}
