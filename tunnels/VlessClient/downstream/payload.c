#include "structure.h"

#include "loggers/network_logger.h"

void vlessclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    vlessclient_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->phase == kVlessClientPhaseClosing))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (ls->kind == kVlessClientLineKindUdpCarrier)
    {
        discard vlessclientHandleUdpCarrierPayload(t, l, ls, buf);
        return;
    }

    if (UNLIKELY(ls->kind == kVlessClientLineKindUdpApp))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    discard vlessclientHandleDirectPayload(t, l, ls, buf);
}
