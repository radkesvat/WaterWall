#include "structure.h"

#include "loggers/network_logger.h"

void trojanclientTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    trojanclient_lstate_t *ls = lineGetState(l, t);

    if (ls->kind == kTrojanClientLineKindUdpApp || ls->kind == kTrojanClientLineKindUdpCarrier)
    {
        return;
    }

    tunnelPrevDownStreamInit(t, l);
}
