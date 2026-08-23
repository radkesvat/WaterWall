#include "structure.h"

#include "loggers/network_logger.h"

void httpserverTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    httpserver_lstate_t *ls = lineGetState(l, t);
    if (ls->split_role == kHttpServerSplitRoleUnknown || ls->split_role == kHttpServerSplitRoleUpload ||
        ls->split_role == kHttpServerSplitRoleDownload)
    {
        return;
    }

    tunnelNextUpStreamEst(t, l);
}
