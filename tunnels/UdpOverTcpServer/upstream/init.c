#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    udpovertcpserver_lstate_t *ls = lineGetState(l, t);
    udpovertcpserverLinestateInitialize(ls, lineGetBufferPool(l), tunnelGetChain(t)->supports_splice);

    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(l), IP_PROTO_UDP);
    tunnelNextUpStreamInit(t, l);
}
