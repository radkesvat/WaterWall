#include "RtmpClient/structure.h"

void rtmpclientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    rtmpSetCarrierPaused(t, l, false);
}
