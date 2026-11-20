#include "RtmpClient/structure.h"

void rtmpclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    if (rtmpInitLine(t, l))
    {
        rtmpStartCarrier(t, l);
    }
}
