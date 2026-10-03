#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    udpovertcpserver_lstate_t *ls = lineGetState(l, t);
    udpovertcpserverLinestateInitialize(ls, lineGetBufferPool(l));
    if (UNLIKELY(ls->read_stream == NULL))
    {
        udpovertcpserverLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(l), IP_PROTO_UDP);
    tunnelNextUpStreamInit(t, l);
}
