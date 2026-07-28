#include "structure.h"

#include "loggers/network_logger.h"

void keepaliveclientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    discard t;
    discard chain;
    LOGF("KeepAliveClient: onChain override should not be used");
    abortProgramNow(1);
}
