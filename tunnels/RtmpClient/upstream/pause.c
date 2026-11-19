#include "RtmpClient/structure.h"

void rtmpclientTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    rtmpSetApplicationPaused(t, l, true);
}
