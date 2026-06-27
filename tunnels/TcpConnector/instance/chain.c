#include "structure.h"

#include "loggers/network_logger.h"

void tcpconnectorTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    tcpconnector_tstate_t *ts = tunnelGetState(t);

    /*
     * Upstream-end adapters may be visited by the node manager before their
     * downstream owner is chained. Leave them unchained in that pass; the real
     * upstream node will bind to this connector and call us again.
     */
    if (t->prev == NULL)
    {
        if (chain->tunnels.len != 0)
        {
            LOGF("TcpConnector: cannot defer internal DomainResolver insertion on a non-empty chain");
            terminateProgram(1);
        }
        tunnelchainDestroy(chain);
        return;
    }

    tunnel_t *resolver = ts->domain_resolver_tunnel;
    tunnel_t *prev     = t->prev;

    if (resolver == NULL)
    {
        LOGF("TcpConnector: internal DomainResolver was not created");
        terminateProgram(1);
    }

    if (resolver->prev != NULL || resolver->next != NULL)
    {
        LOGF("TcpConnector: internal DomainResolver tunnel is already bound");
        terminateProgram(1);
    }

    if (prev->next == t)
    {
        prev->next = resolver;
    }

    resolver->prev  = prev;
    resolver->next  = t;
    t->prev         = resolver;

    tunnelchainInsert(chain, resolver);
    tunnelchainInsert(chain, t);
}
