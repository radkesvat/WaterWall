#include "structure.h"

void bgp4serverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    bgp4server_tstate_t *ts = tunnelGetState(t);
    bgpEncode(t, l, lineGetState(l, t), buf, ts->as_number, ts->router_id);
}
