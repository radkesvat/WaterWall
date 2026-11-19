#include "RtmpClient/structure.h"

void rtmpclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    rtmpCarrierFinish(t, l, kRtmpCloseFromNext);
}
