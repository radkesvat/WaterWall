#include "structure.h"

#include "loggers/network_logger.h"

static void tlsserverBindFallback(tunnel_t *t, tunnel_chain_t *chain)
{
    tlsserver_tstate_t *ts = tunnelGetState(t);

    tunnelDefaultOnChain(t, chain);
    if (startupFailurePending())
        return;
    chain = tunnelGetChain(t);

    if (ts->fallback_node == NULL)
    {
        return;
    }

    tunnel_t *target = ts->fallback_node->instance;
    if (target == NULL)
    {
        LOGF("TlsServer: fallback tunnel \"%s\" is not available", ts->fallback_node->name);
        startupFailureRecord(1);
        return;
    }

    if (target == t)
    {
        LOGF("TlsServer: fallback target must be different from TlsServer");
        startupFailureRecord(1);
        return;
    }

    if (target->chain == chain &&
        (target == t->next || target->prev == t || target->node->hash_name == t->node->hash_next))
    {
        ts->fallback_tunnel = tunnelGetBranchEntry(t, target);
        if (ts->fallback_tunnel != NULL)
            return;
    }

    if (target->prev != NULL && target->prev != t)
    {
        LOGF("TlsServer: fallback target node \"%s\" is already bound to previous node \"%s\"",
             target->node->name,
             target->prev->node->name);
        startupFailureRecord(1);
        return;
    }

    if (target->chain == chain)
    {
        LOGF("TlsServer: fallback target node \"%s\" is already in the TlsServer chain", target->node->name);
        startupFailureRecord(1);
        return;
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

    if (startupFailurePending())
        return;

    // The fallback target may insert internal tunnels in front of itself while
    // chaining (e.g. a connector's domain setup + DomainResolver); call the branch
    // entry bound directly below us, not the raw instance.
    ts->fallback_tunnel = tunnelGetBranchEntry(t, target);
    if (ts->fallback_tunnel == NULL)
    {
        LOGF("TlsServer: fallback target node \"%s\" is not reachable from TlsServer", target->node->name);
        startupFailureRecord(1);
        return;
    }
}

void tlsserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    tlsserverBindFallback(t, chain);
    tlsserver_tstate_t *ts = tunnelGetState(t);
    if (! startupFailurePending() && ts->fallback_tunnel != NULL && ts->fallback_tunnel != t->next)
        discard tunnelchainRegisterLayerRelation(tunnelGetChain(t),
                                                 t,
                                                 kTunnelLayerSidePrev,
                                                 ts->fallback_tunnel,
                                                 kTunnelLayerSidePrev,
                                                 kTunnelLayerRelationSame);
}
