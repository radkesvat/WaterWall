#include "structure.h"

#include "loggers/network_logger.h"

void streamtopacketsTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;

    /*
     * Stream lines are borrowed and must already have unregistered after all
     * normal-line owners complete worker drain. This tunnel deliberately stores
     * no state on persistent packet lines; tunnelchainDestroy() releases those
     * lines after this callback returns.
     */
    streamtopacketsOwnershipDestroy(t);

    tunnelDestroy(t);
}
