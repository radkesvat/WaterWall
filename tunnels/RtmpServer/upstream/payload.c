#include "RtmpServer/structure.h"

void rtmpserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    rtmpSubmitCarrier(t, l, buf);
}
