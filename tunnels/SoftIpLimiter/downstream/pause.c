#include "structure.h"

void softiplimiterTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    softiplimiter_lstate_t *ls = lineGetState(l, t);
    if (softiplimiterPhaseForwards(ls->phase))
    {
        tunnelPrevDownStreamPause(t, l);
    }
}
