#include "structure.h"

void tcpudpconnectorTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tunnelPrevDownStreamPayload(t, l, buf);
}
