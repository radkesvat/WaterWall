#include "structure.h"

void softiplimiterTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    softiplimiter_lstate_t *ls = lineGetState(l, t);
    if (softiplimiterPhaseForwards(ls->phase))
    {
        ls->pending_next_pause = false;
        tunnelNextUpStreamPause(t, l);
    }
    else if (ls->phase == kSoftIpLimiterPhaseWaitIdentity)
    {
        ls->pending_next_pause = true;
    }
}
