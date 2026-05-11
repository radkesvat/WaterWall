#include "structure.h"

#include "loggers/network_logger.h"

void httpserverTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    httpserver_lstate_t *ls = lineGetState(l, t);
    if (ls->split_role == kHttpServerSplitRoleDownload && ls->split_main_line != NULL)
    {
        tunnelNextUpStreamPause(t, ls->split_main_line);
        return;
    }
    if (ls->split_role == kHttpServerSplitRoleUpload || ls->split_role == kHttpServerSplitRoleUnknown)
    {
        return;
    }
    tunnelNextUpStreamPause(t, l);
}
