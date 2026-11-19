#include "RtmpClient/structure.h"

void rtmpclientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    rtmpNextEstablished(t, l);
}
