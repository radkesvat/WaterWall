#include "structure.h"

void tcpudpconnectorTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    tunnel_t *connector = tcpudpconnectorGetSelectedUpStreamTunnel(t, l);
    tunnelUpStreamResume(connector, l);
}
