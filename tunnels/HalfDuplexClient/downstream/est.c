#include "structure.h"

#include "loggers/network_logger.h"

void halfduplexclientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    halfduplexclient_lstate_t *ls = lineGetState(l, t);


    tunnelPrevDownStreamEst(t, ls->main_line);
}
