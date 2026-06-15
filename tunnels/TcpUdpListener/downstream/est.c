#include "structure.h"

void tcpudplistenerTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    tunnel_t *listener = tcpudplistenerSelectDownStreamTunnel(t, l);
    tunnelDownStreamEst(listener, l);
}
