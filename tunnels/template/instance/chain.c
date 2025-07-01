#include "structure.h"

#include "loggers/network_logger.h"

void templateTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    // using tunnel / adapter default handle for this action
    discard t;
    discard chain;
    LOGF("This Function is disabled, using the default Tunnel instead");
    terminateProgram(1);
}
