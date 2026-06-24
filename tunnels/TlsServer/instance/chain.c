#include "structure.h"

#include "loggers/network_logger.h"
#include "managers/node_manager.h"

void tlsserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    tlsserver_tstate_t *ts = tunnelGetState(t);

    tunnelDefaultOnChain(t, chain);
    chain = tunnelGetChain(t);

    if (ts->fallback_node == NULL)
    {
        return;
    }

    tunnel_t *target = ts->fallback_node->instance;
    if (target == NULL)
    {
        LOGF("TlsServer: fallback tunnel \"%s\" is not available", ts->fallback_node->name);
        terminateProgram(1);
    }

    if (target == t)
    {
        LOGF("TlsServer: fallback target must be different from TlsServer");
        terminateProgram(1);
    }

    ts->fallback_tunnel = target;

    if (target == t->next)
    {
        return;
    }

    if (target->prev != NULL && target->prev != t)
    {
        LOGF("TlsServer: fallback target node \"%s\" is already bound to previous node \"%s\"",
             target->node->name,
             target->prev->node->name);
        terminateProgram(1);
    }

    if (target->chain == chain)
    {
        if (target->prev == t)
        {
            return;
        }

        LOGF("TlsServer: fallback target node \"%s\" is already in the TlsServer chain", target->node->name);
        terminateProgram(1);
    }

    if (target->prev == NULL)
    {
        tunnelBindDown(t, target);
    }

    if (target->chain != NULL)
    {
        tunnelchainCombine(chain, target->chain);
    }
    else
    {
        target->onChain(target, chain);
    }

    // The fallback target may insert internal tunnels in front of itself while
    // chaining (e.g. a connector's domain setup + DomainResolver); call the branch
    // entry bound directly below us, not the raw instance.
    ts->fallback_tunnel = tunnelGetBranchEntry(t, target);
    if (ts->fallback_tunnel == NULL)
    {
        LOGF("TlsServer: fallback target node \"%s\" is not reachable from TlsServer", target->node->name);
        terminateProgram(1);
    }
}
