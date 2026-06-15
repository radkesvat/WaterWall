#include "structure.h"

void tcpudpconnectorTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    tunnel_t *connector = tcpudpconnectorGetSelectedUpStreamTunnel(t, l);
    tunnelUpStreamEst(connector, l);
}
