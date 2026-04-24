#include "structure.h"

#include "loggers/network_logger.h"

void connectionfisherserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    connectionfisherserverCloseLineFromDownstream(t, l);
}
