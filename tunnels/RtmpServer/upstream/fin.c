#include "RtmpServer/structure.h"

void rtmpserverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    rtmpCarrierFinish(t, l, kRtmpCloseFromPrev);
}
