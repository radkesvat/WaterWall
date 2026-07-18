#include "structure.h"

#include "loggers/network_logger.h"

static void sniffrouterBindRouteTarget(tunnel_t *t, tunnel_chain_t *chain, sniffrouter_route_t *route)
{
    tunnel_t *target = route->node->instance;
    if (target == NULL)
    {
        LOGF("SniffRouter: referenced route tunnel \"%s\" is not available", route->node->name);
        terminateProgram(1);
    }

    if (target == t)
    {
        LOGF("SniffRouter: route target must be different from the router");
        terminateProgram(1);
    }

    route->tunnel = target;

    if (target == t->next)
    {
        return;
    }

    if (target->prev != NULL && target->prev != t)
    {
        LOGF("SniffRouter: route target node \"%s\" is already bound to previous node \"%s\"",
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

        LOGF("SniffRouter: route target node \"%s\" is already in the router chain", target->node->name);
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

    // The route target may insert internal tunnels in front of itself while
    // chaining (e.g. a connector's domain setup + DomainResolver); route to the
    // branch entry bound directly below us, not the raw instance.
    route->tunnel = tunnelGetBranchEntry(t, target);
    if (route->tunnel == NULL)
    {
        LOGF("SniffRouter: route target node \"%s\" is not reachable from the router", target->node->name);
        terminateProgram(1);
    }
}

void sniffrouterTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    sniffrouter_tstate_t *ts = tunnelGetState(t);

    tunnelDefaultOnChain(t, chain);
    chain = tunnelGetChain(t);

    for (uint32_t i = 0; i < ts->routes_count; ++i)
    {
        sniffrouterBindRouteTarget(t, chain, &ts->routes[i]);

        // A target's onChain may merge this chain into an already-built downstream chain,
        // destroying the local pointer while updating t->chain. Reacquire it before the
        // next route instead of carrying a potentially freed chain across iterations.
        chain = tunnelGetChain(t);
    }
}
