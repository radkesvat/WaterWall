#include "RtmpClient/structure.h"

void rtmpclientTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    rtmpSetApplicationPaused(t, l, false);
}
