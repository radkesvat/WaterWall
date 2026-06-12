#include "structure.h"

#include "loggers/network_logger.h"

void httpclientTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    httpclient_lstate_t *ls = lineGetState(l, t);

    // Mirror of UpStreamPause: main's prev can read again, so resume the response producer
    // (the download transport).
    if (ls->split_role == kHttpClientSplitRoleMain)
    {
        if (ls->split_download_line != NULL)
        {
            tunnelNextUpStreamResume(t, ls->split_download_line);
        }
        return;
    }

    if (ls->split_role == kHttpClientSplitRoleUpload || ls->split_role == kHttpClientSplitRoleDownload)
    {
        return;
    }

    tunnelNextUpStreamResume(t, l);
}
