#include "structure.h"

void tcpudplistenerTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tunnel_t *listener = tcpudplistenerSelectDownStreamTunnel(t, l);
    tunnelDownStreamPayload(listener, l, buf);
}
