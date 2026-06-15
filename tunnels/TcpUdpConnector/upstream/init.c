#include "structure.h"

void tcpudpconnectorTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    tunnel_t                 *connector = tcpudpconnectorSelectUpStreamTunnel(t, l);
    tcpudpconnector_lstate_t *ls        = lineGetState(l, t);

    tcpudpconnectorLinestateInitialize(ls, connector);
    tunnelUpStreamInit(connector, l);
}
