#include "structure.h"

#include "loggers/network_logger.h"

void authenticationserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    discard t;
    discard chain;
    LOGF("AuthenticationServer: onChain override is disabled, use the default tunnel chaining");
    terminateProgram(1);
}
