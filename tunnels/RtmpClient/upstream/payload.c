#include "RtmpClient/structure.h"

void rtmpclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    rtmpSubmitApplication(t, l, buf);
}
