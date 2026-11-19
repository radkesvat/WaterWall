#include "RtmpServer/structure.h"

void rtmpserverTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    rtmpNextEstablished(t, l);
}
