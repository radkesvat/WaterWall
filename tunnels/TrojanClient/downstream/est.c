#include "structure.h"

#include "loggers/network_logger.h"

void trojanclientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    trojanclient_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->phase == kTrojanClientPhaseClosing))
    {
        return;
    }

    if (ls->kind == kTrojanClientLineKindUdpApp)
    {
        return;
    }

    discard trojanclientOnTransportEstablished(t, l, ls);
}
