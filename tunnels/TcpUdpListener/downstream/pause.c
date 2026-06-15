#include "structure.h"

void tcpudplistenerTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    tunnel_t *listener = tcpudplistenerSelectDownStreamTunnel(t, l);
    tunnelDownStreamPause(listener, l);
}
