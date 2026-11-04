#include "structure.h"

#include "loggers/network_logger.h"

void httpclientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    httpclient_lstate_t *ls = lineGetState(l, t);

    if (ls->prev_finished)
    {
        return;
    }

    if (ls->line_role == kHttpClientLineCarrier)
    {
        assert(ls->application_line != NULL);
        tunnelPrevDownStreamEst(t, ls->application_line);
        return;
    }

    if (ls->split_role == kHttpClientSplitRoleDownload && ls->split_main_line != NULL)
    {
        tunnelPrevDownStreamEst(t, ls->split_main_line);
        return;
    }
    if (ls->split_role == kHttpClientSplitRoleUpload)
    {
        return;
    }
    tunnelPrevDownStreamEst(t, l);
}
