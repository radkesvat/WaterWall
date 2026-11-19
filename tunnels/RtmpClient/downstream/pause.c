#include "RtmpClient/structure.h"

void rtmpclientTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    rtmpSetCarrierPaused(t, l, true);
}
