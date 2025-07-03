#include "structure.h"

#include "loggers/network_logger.h"

void halfduplexserverTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    halfduplexserver_lstate_t *ls = lineGetState(l, t);
    if (LIKELY(ls->download_line == l))
    {
        if (LIKELY(ls->main_line != NULL))
        {
            tunnelNextUpStreamPause(t, ls->main_line);
        }
    }
    else if (ls->upload_line == l)
    {
        // what?
        LOGW("HalfDuplexServer: upload line got paused but we never write to upload line!");
    }
    else
    {
        assert(false);
    }
}
