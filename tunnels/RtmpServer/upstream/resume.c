#include "RtmpServer/structure.h"

void rtmpserverTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    rtmpSetCarrierPaused(t, l, false);
}
