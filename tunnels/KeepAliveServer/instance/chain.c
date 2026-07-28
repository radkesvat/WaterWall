#include "structure.h"

#include "loggers/network_logger.h"

void keepaliveserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    discard t;
    discard chain;
    LOGF("KeepAliveServer: onChain override should not be used");
    abortProgramNow(1);
}
