#include "internal.h"

#include "loggers/network_logger.h"

void vmessclientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    vmessclient_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->phase == kVmessClientPhaseClosed))
    {
        return;
    }

    if (ls->kind == kVmessClientLineKindUdpApplication)
    {
        return;
    }

    vmessclientOnNextEstablished(t, l, ls);
}
