#include "structure.h"

#include "loggers/network_logger.h"

void vlessclientTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    vlessclient_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->phase == kVlessClientPhaseClosing))
    {
        return;
    }

    if (ls->kind == kVlessClientLineKindUdpCarrier)
    {
        line_t *app_l = ls->app_line;
        if (app_l != NULL && lineIsAlive(app_l))
        {
            discard withLineLocked(app_l, tunnelPrevDownStreamPause, t);
        }
        return;
    }

    if (UNLIKELY(ls->kind == kVlessClientLineKindUdpApp))
    {
        return;
    }

    tunnelPrevDownStreamPause(t, l);
}
