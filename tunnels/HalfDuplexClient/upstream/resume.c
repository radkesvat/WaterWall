#include "structure.h"

#include "loggers/network_logger.h"

void halfduplexclientTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    halfduplexclient_lstate_t *ls = lineGetState(l, t);

    tunnelNextUpStreamResume(t, ls->download_line);
}
