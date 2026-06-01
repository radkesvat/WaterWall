#include "structure.h"

#include "loggers/network_logger.h"

void realityserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    realityserver_tstate_t *ts = tunnelGetState(t);

    tunnelDefaultOnChain(t, chain);
    chain = tunnelGetChain(t);

    tunnel_t *destination = ts->destination_node->instance;
    if (destination == NULL)
    {
        LOGF("RealityServer: destination tunnel is not available");
        terminateProgram(1);
    }

    if (destination == t || destination == t->next)
    {
        LOGF("RealityServer: destination node must differ from RealityServer and its authorized next node");
        terminateProgram(1);
    }

    if (destination->prev != NULL && destination->prev != t)
    {
        LOGF("RealityServer: destination node \"%s\" is already bound to previous node \"%s\"",
             destination->node->name,
             destination->prev->node->name);
        terminateProgram(1);
    }

    ts->destination_tunnel = destination;

    if (destination->prev == NULL)
    {
        tunnelBindDown(t, destination);
    }

    if (destination->chain != NULL)
    {
        if (destination->chain != chain)
        {
            tunnelchainCombine(chain, destination->chain);
        }
    }
    else
    {
        destination->onChain(destination, chain);
    }
}
