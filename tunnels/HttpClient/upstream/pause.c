#include "structure.h"

#include "loggers/network_logger.h"

void httpclientTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    httpclient_lstate_t *ls = lineGetState(l, t);

    if (ls->line_role == kHttpClientLineApplication)
    {
        httpclient_lstate_t *carrier_ls     = lineGetState(ls->carrier_line, t);
        carrier_ls->application_read_paused = true;
        tunnelNextUpStreamPause(t, ls->carrier_line);
        return;
    }

    // A pause arriving on the main line means main's prev (the real client) cannot read the
    // response fast enough, so we must slow the response producer: the download transport.
    if (ls->split_role == kHttpClientSplitRoleMain)
    {
        if (ls->split_download_line != NULL)
        {
            tunnelNextUpStreamPause(t, ls->split_download_line);
        }
        return;
    }

    // The created upload/download legs have no real prev tunnel to pause.
    if (ls->split_role == kHttpClientSplitRoleUpload || ls->split_role == kHttpClientSplitRoleDownload)
    {
        return;
    }

    tunnelNextUpStreamPause(t, l);
}
