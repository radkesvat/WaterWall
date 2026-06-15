#include "structure.h"

void tcpudpconnectorTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    tcpudpconnector_lstate_t *ls        = lineGetState(l, t);
    tunnel_t                 *connector = tcpudpconnectorGetSelectedUpStreamTunnel(t, l);

    tcpudpconnectorLinestateDestroy(ls);
    tunnelUpStreamFin(connector, l);
}
