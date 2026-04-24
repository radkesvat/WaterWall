#include "structure.h"

#include "loggers/network_logger.h"

void connectionfisherserverTunnelDestroy(tunnel_t *t)
{
    tunnelDestroy(t);
}
