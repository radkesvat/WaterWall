#include "structure.h"

void softiplimiterTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    softiplimiter_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kSoftIpLimiterPhaseEstablished)
    {
        tunnelPrevDownStreamEst(t, l);
    }
}

