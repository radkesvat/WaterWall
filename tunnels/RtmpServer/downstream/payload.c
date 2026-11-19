#include "RtmpServer/structure.h"

void rtmpserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    rtmpSubmitApplication(t, l, buf);
}
