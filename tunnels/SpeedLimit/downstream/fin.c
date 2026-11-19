#include "structure.h"

void speedlimitTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    speedlimitFinish(t, l, false);
}

void speedlimitTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    speedlimit_lstate_t *state = lineGetState(l, t);
    if (state->close_phase == kSpeedLimitOpen)
        tunnelPrevDownStreamEst(t, l);
}
