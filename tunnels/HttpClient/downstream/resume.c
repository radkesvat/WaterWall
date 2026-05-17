#include "structure.h"

#include "loggers/network_logger.h"

void httpclientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    httpclient_lstate_t *ls = lineGetState(l, t);

    if (ls->prev_finished)
    {
        return;
    }

    if (ls->split_role == kHttpClientSplitRoleDownload && ls->split_main_line != NULL)
    {
        tunnelPrevDownStreamResume(t, ls->split_main_line);
        return;
    }
    if (ls->split_role == kHttpClientSplitRoleUpload)
    {
        return;
    }
    tunnelPrevDownStreamResume(t, l);
}
