#include "RtmpServer/structure.h"

void rtmpserverTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    rtmpSetApplicationPaused(t, l, false);
}
