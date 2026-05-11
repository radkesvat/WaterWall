#include "structure.h"

#include "loggers/network_logger.h"

void httpserverTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    httpserver_lstate_t *ls = lineGetState(l, t);
    if (ls->split_role == kHttpServerSplitRoleMain && ls->split_upload_line != NULL)
    {
        tunnelPrevDownStreamPause(t, ls->split_upload_line);
        return;
    }
    tunnelPrevDownStreamPause(t, l);
}
