#include "structure.h"

void speedlimitTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    speedlimitFinish(t, l, true);
}

void speedlimitTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    speedlimit_lstate_t *state = lineGetState(l, t);
    if (state->close_phase == kSpeedLimitOpen)
        tunnelNextUpStreamEst(t, l);
}
