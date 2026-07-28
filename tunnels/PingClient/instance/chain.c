#include "structure.h"

#include "loggers/network_logger.h"

void pingclientOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    discard t;
    discard chain;
    LOGF("This Function is disabled, using the default Tunnel instead");
    abortProgramNow(1);
}
