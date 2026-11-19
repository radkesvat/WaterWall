#include "RtmpServer/structure.h"

void rtmpserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    rtmpApplicationFinish(t, l, kRtmpCloseFromNext);
}
