#include "structure.h"

#include "loggers/network_logger.h"

void connectionfisherserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    connectionfisherserverLinestateInitialize(lineGetState(l, t), l);
}
