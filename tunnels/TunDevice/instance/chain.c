#include "structure.h"

#include "loggers/network_logger.h"

void tundeviceTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    // using tunnel / adapter default handle for this action
    (void) t;
    (void) chain;
    LOGF("This Function is disabled, using the default Tunnel instead");
    exit(1);
}
