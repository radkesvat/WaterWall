#include "RtmpClient/structure.h"

void rtmpclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    rtmpApplicationFinish(t, l, kRtmpCloseFromPrev);
}
