#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    udpovertcpclient_lstate_t *ls = lineGetState(l, t);

    udpovertcpclientLinestateInitialize(ls, lineGetBufferPool(l), tunnelGetChain(t)->supports_splice);

    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(l), IP_PROTO_TCP);
    tunnelNextUpStreamInit(t, l);
}
