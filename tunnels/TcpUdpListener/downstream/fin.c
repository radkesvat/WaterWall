#include "structure.h"

void tcpudplistenerTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    tunnel_t *listener = tcpudplistenerSelectDownStreamTunnel(t, l);
    tunnelDownStreamFin(listener, l);
}
