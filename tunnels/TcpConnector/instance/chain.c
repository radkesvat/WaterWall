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

    tunnel_t *setup    = ts->domain_setup_tunnel;
    tunnel_t *resolver = ts->domain_resolver_tunnel;
    tunnel_t *prev     = t->prev;

    if (setup == NULL || resolver == NULL)
    {
        LOGF("TcpConnector: internal DomainResolver chain was not created");
        terminateProgram(1);
    }

    if ((setup->prev != NULL && setup->prev != prev) || setup->next != NULL)
    {
        LOGF("TcpConnector: internal domain setup tunnel is already bound");
        terminateProgram(1);
    }

    if (resolver->prev != NULL || resolver->next != NULL)
    {
        LOGF("TcpConnector: internal DomainResolver tunnel is already bound");
        terminateProgram(1);
    }

    if (prev->next == t)
    {
        prev->next = setup;
    }

    setup->prev     = prev;
    setup->next     = resolver;
    resolver->prev  = setup;
    resolver->next  = t;
    t->prev         = resolver;

    tunnelchainInsert(chain, setup);
    tunnelchainInsert(chain, resolver);
    tunnelchainInsert(chain, t);
}
