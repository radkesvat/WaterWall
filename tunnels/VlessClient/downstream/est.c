#include "structure.h"

#include "loggers/network_logger.h"

void vlessclientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    vlessclient_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->phase == kVlessClientPhaseClosed))
    {
        return;
    }

    if (ls->kind == kVlessClientLineKindUdpApplication)
    {
        return;
    }

    vlessclientOnNextEstablished(t, l, ls);
}
