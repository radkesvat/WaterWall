#include "structure.h"

#include "loggers/network_logger.h"
#include "managers/node_manager.h"

void trojanclientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    trojanclient_tstate_t *ts   = tunnelGetState(t);
    node_t                *node = tunnelGetNode(t);

    if (t->prev == NULL)
    {
        if (chain->tunnels.len != 0)
        {
            LOGF("TrojanClient: cannot defer chaining without a previous tunnel on a non-empty chain");
            terminateProgram(1);
        }
        tunnelchainDestroy(chain);
        return;
    }

    if (node->hash_next == 0)
    {
        LOGF("TrojanClient: a next node is required");
        terminateProgram(1);
    }

    node_t *next_node = nodemanagerGetConfigNodeByHash(node->node_manager_config, node->hash_next);
    if (next_node == NULL)
    {
        LOGF("Node Map Failure: node (\"%s\")->next (\"%s\") not found", node->name, node->next);
        terminateProgram(1);
    }

    tunnel_t *resolver    = ts->domain_resolver_tunnel;
    tunnel_t *next_tunnel = next_node->instance;
    tunnel_t *prev        = t->prev;

    if (next_tunnel == NULL)
    {
        LOGF("TrojanClient: next node \"%s\" has no tunnel instance", next_node->name);
        terminateProgram(1);
    }
    if (resolver != NULL && (resolver->prev != NULL || resolver->next != NULL))
    {
        LOGF("TrojanClient: internal DomainResolver tunnel is already bound");
        terminateProgram(1);
    }
    if (next_tunnel->prev != NULL && next_tunnel->prev != t)
    {
        LOGF("Node Map Failure: Node (%s) wanted to bind to (%s) which is already bounded by %s",
             t->node->name,
             next_tunnel->node->name,
             next_tunnel->prev->node->name);
        terminateProgram(1);
    }

    if (prev->next == t)
    {
        prev->next = resolver != NULL ? resolver : t;
    }

    if (resolver != NULL)
    {
        resolver->prev = prev;
        resolver->next = t;
        t->prev        = resolver;
    }

    t->next           = next_tunnel;
    next_tunnel->prev = t;

    if (resolver != NULL)
    {
        tunnelchainInsert(chain, resolver);
    }
    tunnelchainInsert(chain, t);

    if (next_tunnel->chain != NULL)
    {
        tunnelchainCombine(next_tunnel->chain, chain);
    }
    else
    {
        next_tunnel->onChain(next_tunnel, chain);
    }
}
