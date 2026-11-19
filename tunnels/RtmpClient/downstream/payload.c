#include "RtmpClient/structure.h"

void rtmpclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    rtmpSubmitCarrier(t, l, buf);
}
