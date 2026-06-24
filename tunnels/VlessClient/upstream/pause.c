#include "structure.h"

#include "loggers/network_logger.h"

void vlessclientTunnelUpStreamPause(tunnel_t *t, line_t *l)
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
            discard withLineLocked(carrier_l, tunnelNextUpStreamPause, t);
        }
        return;
    }

    if (UNLIKELY(ls->kind == kVlessClientLineKindUdpCarrier))
    {
        tunnelNextUpStreamPause(t, l);
        return;
    }

    tunnelNextUpStreamPause(t, l);
}
