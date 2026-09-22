#include "structure.h"

void bgp4clientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    bgpDecode(t, l, lineGetState(l, t), buf);
}
