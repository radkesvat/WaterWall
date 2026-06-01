#include "structure.h"

#include "loggers/network_logger.h"

void realityclientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    realityclient_tstate_t *ts = tunnelGetState(t);

    if (ts->tls_tunnel == NULL)
    {
        LOGF("RealityClient: internal TlsClient is not available");
        terminateProgram(1);
    }

    if (ts->tls_tunnel->prev != NULL && ts->tls_tunnel->prev != t)
    {
        LOGF("RealityClient: internal TlsClient is already bound");
        terminateProgram(1);
    }

    tunnelBind(t, ts->tls_tunnel);
    tunnelchainInsert(chain, t);
    ts->tls_tunnel->onChain(ts->tls_tunnel, chain);
}
