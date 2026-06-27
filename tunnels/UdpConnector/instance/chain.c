#include "structure.h"

#include "loggers/network_logger.h"

void udpconnectorTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    udpconnector_tstate_t *ts = tunnelGetState(t);

    if (t->prev == NULL)
    {
        if (chain->tunnels.len != 0)
        {
            LOGF("UdpConnector: cannot defer internal DomainResolver insertion on a non-empty chain");
            terminateProgram(1);
        }
        tunnelchainDestroy(chain);
        return;
    }

    tunnel_t *resolver = ts->domain_resolver_tunnel;
    tunnel_t *prev     = t->prev;

    if (resolver == NULL)
    {
        LOGF("UdpConnector: internal DomainResolver was not created");
        terminateProgram(1);
    }

    if (resolver->prev != NULL || resolver->next != NULL)
    {
        LOGF("UdpConnector: internal DomainResolver tunnel is already bound");
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
