#include "structure.h"

void softiplimiterTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    softiplimiter_lstate_t *ls = lineGetState(l, t);
    if (softiplimiterPhaseForwards(ls->phase))
    {
        tunnelNextUpStreamResume(t, l);
    }
}
