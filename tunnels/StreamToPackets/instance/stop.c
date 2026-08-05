#include "structure.h"

#include "loggers/network_logger.h"

void streamtopacketsTunnelOnStop(tunnel_t *t)
{
    // No new candidate may be tracked and no promotion may start once the node
    // manager begins stopping; queued worker messages still drain afterwards.
    streamtopacketsOwnershipStop(t);
}
