#include "structure.h"

#include "loggers/network_logger.h"

void httpclientTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    httpclient_lstate_t *ls = lineGetState(l, t);
    if (ls->split_role == kHttpClientSplitRoleMain && ls->split_upload_line != NULL)
    {
        tunnelNextUpStreamResume(t, ls->split_upload_line);
        return;
    }
    tunnelNextUpStreamResume(t, l);
}
