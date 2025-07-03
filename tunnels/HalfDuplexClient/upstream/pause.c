#include "structure.h"

#include "loggers/network_logger.h"

void halfduplexclientTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    halfduplexclient_lstate_t *ls = lineGetState(l, t);

    tunnelNextUpStreamPause(t, ls->download_line);
}
