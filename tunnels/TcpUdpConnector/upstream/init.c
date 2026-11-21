#include "structure.h"

void tcpudpconnectorTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    // the connector is selected before any line state is committed, so a rejected line never reaches
    // tunnelUpStreamInit() and no next branch has to be unwound
    tunnel_t                 *connector = tcpudpconnectorSelectUpStreamTunnel(t, l);
    tcpudpconnector_lstate_t *ls        = lineGetState(l, t);

    if (connector == NULL)
    {
        tunnelLogTransportRefusal(t, lineGetDestinationAddressContext(l), kAddressContextTransportBoth);
        tcpudpconnectorLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    tcpudpconnectorLinestateInitialize(ls, connector);
    tunnelUpStreamInit(connector, l);
}
