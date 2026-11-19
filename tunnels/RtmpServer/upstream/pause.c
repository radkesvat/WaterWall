#include "RtmpServer/structure.h"

void rtmpserverTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    rtmpSetCarrierPaused(t, l, true);
}
