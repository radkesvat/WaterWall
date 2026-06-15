#include "structure.h"

void tcpudpconnectorTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tunnel_t *connector = tcpudpconnectorGetSelectedUpStreamTunnel(t, l);
    tunnelUpStreamPayload(connector, l, buf);
}
