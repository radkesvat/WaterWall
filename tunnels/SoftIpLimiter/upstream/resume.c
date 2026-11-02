#include "structure.h"

void softiplimiterTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    softiplimiter_lstate_t *ls = lineGetState(l, t);
    if (ls->closing || ls->phase == kSoftIpLimiterPhaseClosing)
    {
        return;
    }
    if (nextinitgateSignal(&ls->gate, false))
    {
        tunnelNextUpStreamResume(t, l);
    }
}
