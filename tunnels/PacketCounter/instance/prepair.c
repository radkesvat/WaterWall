#include "structure.h"

#include "loggers/network_logger.h"

void packetcounterTunnelOnPrepair(tunnel_t *t)
{
    packetcounterPrepareRuntime(t);
}
