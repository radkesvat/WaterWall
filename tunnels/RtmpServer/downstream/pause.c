#include "RtmpServer/structure.h"

void rtmpserverTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    rtmpSetApplicationPaused(t, l, true);
}
