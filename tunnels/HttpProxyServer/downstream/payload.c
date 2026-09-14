#include "structure.h"

void httpproxyserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    hpsPayload(t, l, buf, 1);
}
