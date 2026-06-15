#include "structure.h"

void tcpudpconnectorTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    tunnel_t *connector = tcpudpconnectorGetSelectedUpStreamTunnel(t, l);
    tunnelUpStreamPause(connector, l);
}
