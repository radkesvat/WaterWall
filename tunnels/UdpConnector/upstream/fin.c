#include "structure.h"

#include "loggers/network_logger.h"

void udpconnectorTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    udpconnector_lstate_t *ls = lineGetState(l, t);
    udpconnectorLineDetach(t, l, ls, kUdpConnectorDetachFinish);
}
