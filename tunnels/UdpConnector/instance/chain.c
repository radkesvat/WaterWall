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
            startupFailureRecord(1);
            return;
        }
        tunnelchainDestroy(chain);
        return;
    }

    tunnel_t *resolver = ts->domain_resolver_tunnel;

    if (resolver == NULL)
    {
        LOGF("UdpConnector: internal DomainResolver was not created");
        startupFailureRecord(1);
        return;
    }

    if (resolver->prev != NULL || resolver->next != NULL)
    {
        LOGF("UdpConnector: internal DomainResolver tunnel is already bound");
        startupFailureRecord(1);
        return;
    }

    if (! tunnelInsertBefore(t, resolver, chain))
    {
        return;
    }

    tunnelchainInsert(chain, t);
}
