#include "structure.h"

#include "loggers/network_logger.h"

void trojanclientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    trojanclient_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->phase == kTrojanClientPhaseClosing))
    {
        return;
    }

    if (ls->kind == kTrojanClientLineKindUdpCarrier)
    {
        line_t *app_l = ls->app_line;
        if (app_l != NULL && lineIsAlive(app_l))
        {
            discard withLineLocked(app_l, tunnelPrevDownStreamResume, t);
        }
        return;
    }

    if (UNLIKELY(ls->kind == kTrojanClientLineKindUdpApp))
    {
        return;
    }

    tunnelPrevDownStreamResume(t, l);
}
