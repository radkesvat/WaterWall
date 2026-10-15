#include "structure.h"

#include "loggers/network_logger.h"

static void sniffrouterSetRouteTargetEntry(tunnel_t *t, sniffrouter_route_t *route, tunnel_t *target)
{
    // Include any private predecessors inserted by the configured target.
    tunnel_t *entry = tunnelGetBranchEntry(t, target);
    if (entry == NULL)
    {
        LOGF("SniffRouter: route target node \"%s\" is not reachable from the router", target->node->name);
        startupFailureRecord(1);
        return;
    }

    route->tunnel = entry;
}

static void sniffrouterBindRouteTarget(tunnel_t *t, tunnel_chain_t *chain, sniffrouter_route_t *route,
                                       uint32_t route_index)
{
    tunnel_t *target = route->node->instance;
    if (target == NULL)
    {
        LOGF("SniffRouter: referenced route tunnel \"%s\" is not available", route->node->name);
        startupFailureRecord(1);
        return;
    }

    if (target == t)
    {
        LOGF("SniffRouter: route target must be different from the router");
        startupFailureRecord(1);
        return;
    }

    if (target->chain == chain)
    {
        // Only our configured default and previously bound targets may reuse
        // private predecessors; sharing a chain does not make a descendant ours.
        bool bound_by_router =
            target->prev == t || (t->node->hash_next != 0 && t->node->hash_next == route->node->hash_name);
        sniffrouter_tstate_t *ts = tunnelGetState(t);
        for (uint32_t i = 0; ! bound_by_router && i < route_index; ++i)
        {
            bound_by_router = ts->routes[i].node == route->node && ts->routes[i].tunnel != NULL;
        }
        if (! bound_by_router)
        {
            LOGF("SniffRouter: route target node \"%s\" belongs to another configured branch", route->node->name);
            startupFailureRecord(1);
            return;
        }
        sniffrouterSetRouteTargetEntry(t, route, target);
        return;
    }

    if (target->prev != NULL && target->prev != t)
    {
        LOGF("SniffRouter: route target node \"%s\" is already bound to previous node \"%s\"",
             target->node->name,
             target->prev->node->name);
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

    if (UNLIKELY(startupFailurePending()))
    {
        return;
    }

    sniffrouterSetRouteTargetEntry(t, route, target);
}

void sniffrouterTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    sniffrouter_tstate_t *ts = tunnelGetState(t);

    tunnelDefaultOnChain(t, chain);
    if (UNLIKELY(startupFailurePending()))
    {
        return;
    }
    chain = tunnelGetChain(t);

    for (uint32_t i = 0; i < ts->routes_count; ++i)
    {
        sniffrouterBindRouteTarget(t, chain, &ts->routes[i], i);
        if (UNLIKELY(startupFailurePending()))
        {
            return;
        }

        // A target's onChain may merge this chain into an already-built downstream chain,
        // destroying the local pointer while updating t->chain. Reacquire it before the
        // next route instead of carrying a potentially freed chain across iterations.
        chain = tunnelGetChain(t);
    }
}
