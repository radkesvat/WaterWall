#include "structure.h"

void httpproxyserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    hpsPayload(t, l, buf, 0);
}
