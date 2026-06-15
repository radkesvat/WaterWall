#include "structure.h"

void tcpudplistenerTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    tunnel_t *listener = tcpudplistenerSelectDownStreamTunnel(t, l);
    tunnelDownStreamResume(listener, l);
}
