#include "structure.h"

#include "loggers/network_logger.h"

void halfduplexclientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    halfduplexclient_lstate_t *ls = lineGetState(l, t);

    if (ls->main_line && ! lineIsEstablished(ls->main_line))
    {
        tunnelPrevDownStreamEst(t, ls->main_line);
    }
}
