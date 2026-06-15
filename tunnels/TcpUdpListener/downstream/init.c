#include "structure.h"

void tcpudplistenerTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    tunnel_t *listener = tcpudplistenerSelectDownStreamTunnel(t, l);
    tunnelDownStreamInit(listener, l);
}
