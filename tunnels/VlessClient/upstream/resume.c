#include "structure.h"

#include "loggers/network_logger.h"

void vlessclientTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    vlessclient_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->phase == kVlessClientPhaseClosing))
    {
        return;
    }

    if (ls->kind == kVlessClientLineKindUdpApp)
    {
        line_t *carrier_l = ls->carrier_line;
        if (carrier_l != NULL && lineIsAlive(carrier_l))
        {
            discard withLineLocked(carrier_l, tunnelNextUpStreamResume, t);
        }
        return;
    }

    if (UNLIKELY(ls->kind == kVlessClientLineKindUdpCarrier))
    {
        tunnelNextUpStreamResume(t, l);
        return;
    }

    tunnelNextUpStreamResume(t, l);
}
