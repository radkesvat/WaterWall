#include "structure.h"

#include "loggers/network_logger.h"

void vlessclientTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    vlessclient_lstate_t *ls = lineGetState(l, t);

    if (ls->kind == kVlessClientLineKindUdpApp || ls->kind == kVlessClientLineKindUdpCarrier)
    {
        return;
    }

    tunnelPrevDownStreamInit(t, l);
}
