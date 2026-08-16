#include "structure.h"

#include "loggers/network_logger.h"

void streamtopacketsTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;
    // No new candidate may be tracked and no promotion may start once the node
    // manager begins stopping; queued worker messages still drain afterwards.
    streamtopacketsOwnershipStop(t);
}
