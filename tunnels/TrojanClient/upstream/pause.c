#include "structure.h"

#include "loggers/network_logger.h"

void trojanclientTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    trojanclient_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->phase == kTrojanClientPhaseClosing))
    {
        return;
    }

    if (ls->kind == kTrojanClientLineKindUdpApp)
    {
        line_t *carrier_l = ls->carrier_line;
        if (carrier_l != NULL && lineIsAlive(carrier_l))
        {
            discard withLineLocked(carrier_l, tunnelNextUpStreamPause, t);
        }
        return;
    }

    if (UNLIKELY(ls->kind == kTrojanClientLineKindUdpCarrier))
    {
        tunnelNextUpStreamPause(t, l);
        return;
    }

    tunnelNextUpStreamPause(t, l);
}
