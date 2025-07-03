#include "structure.h"

#include "loggers/network_logger.h"

void halfduplexclientTunnelDownStreamPause(tunnel_t *t, line_t *l)
{

    halfduplexclient_lstate_t *ls = lineGetState(l, t);
    tunnelPrevDownStreamPause(t, ls->main_line);
}
