#include "structure.h"

#include "loggers/network_logger.h"

void httpserverTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    httpserver_lstate_t *ls = lineGetState(l, t);
    if (ls->split_role == kHttpServerSplitRoleMain && ls->split_download_line != NULL)
    {
        tunnelPrevDownStreamEst(t, ls->split_download_line);
        return;
    }
    tunnelPrevDownStreamEst(t, l);
}
