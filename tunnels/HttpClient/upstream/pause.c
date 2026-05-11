#include "structure.h"

#include "loggers/network_logger.h"

void httpclientTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    httpclient_lstate_t *ls = lineGetState(l, t);
    if (ls->split_role == kHttpClientSplitRoleMain && ls->split_upload_line != NULL)
    {
        tunnelNextUpStreamPause(t, ls->split_upload_line);
        return;
    }
    tunnelNextUpStreamPause(t, l);
}
