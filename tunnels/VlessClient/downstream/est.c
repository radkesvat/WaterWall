#include "structure.h"

#include "loggers/network_logger.h"

void vlessclientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    vlessclient_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->phase == kVlessClientPhaseClosing))
    {
        return;
    }

    if (ls->kind == kVlessClientLineKindUdpApp)
    {
        return;
    }

    discard vlessclientOnTransportEstablished(t, l, ls);
}
