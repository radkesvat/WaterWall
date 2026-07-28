#include "structure.h"

#include "loggers/network_logger.h"

void testerclientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    discard t;
    discard chain;
    LOGF("TesterClient: explicit onChain is disabled, use the default tunnel chaining");
    abortProgramNow(1);
}
