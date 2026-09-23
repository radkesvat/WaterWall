#include "structure.h"

void softiplimiterTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    softiplimiter_lstate_t *ls = lineGetState(l, t);
    if (softiplimiterPhaseForwards(ls->phase) && ! ls->transport_est_sent)
    {
        ls->transport_est_sent = true;
        tunnelPrevDownStreamEst(t, l);
    }
}
