#include "structure.h"

#include "loggers/network_logger.h"

void halfduplexclientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    halfduplexclient_lstate_t *ls = lineGetState(l, t);
    if (ls->main_line)
    {
        tunnelPrevDownStreamResume(t, ls->main_line);
    }
}
