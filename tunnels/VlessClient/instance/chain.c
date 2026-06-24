#include "structure.h"

#include "loggers/network_logger.h"
#include "managers/node_manager.h"

void vlessclientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    vlessclient_tstate_t *ts   = tunnelGetState(t);
    node_t               *node = tunnelGetNode(t);

    if (t->prev == NULL)
    {
        if (chain->tunnels.len != 0)
        {
            LOGF("VlessClient: cannot defer chaining without a previous tunnel on a non-empty chain");
            terminateProgram(1);
        }
        tunnelchainDestroy(chain);
        return;
    }

    if (node->hash_next == 0)
    {
        LOGF("VlessClient: a next node is required");
        terminateProgram(1);
    }

    node_t *next_node = nodemanagerGetConfigNodeByHash(node->node_manager_config, node->hash_next);
    if (next_node == NULL)
    {
        LOGF("Node Map Failure: node (\"%s\")->next (\"%s\") not found", node->name, node->next);
        terminateProgram(1);
    }

    tunnel_t *setup       = ts->domain_setup_tunnel;
    tunnel_t *resolver    = ts->domain_resolver_tunnel;
    tunnel_t *next_tunnel = next_node->instance;
    tunnel_t *prev        = t->prev;

    if (setup == NULL)
    {
        LOGF("VlessClient: internal domain setup tunnel was not created");
        terminateProgram(1);
    }
    if (next_tunnel == NULL)
    {
        LOGF("VlessClient: next node \"%s\" has no tunnel instance", next_node->name);
        terminateProgram(1);
    }
    if ((setup->prev != NULL && setup->prev != prev) || setup->next != NULL)
    {
        LOGF("VlessClient: internal domain setup tunnel is already bound");
        terminateProgram(1);
    }
    if (resolver != NULL && (resolver->prev != NULL || resolver->next != NULL))
    {
        LOGF("VlessClient: internal DomainResolver tunnel is already bound");
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
        prev->next = setup;
    }

    setup->prev = prev;
    setup->next = resolver != NULL ? resolver : t;
    if (resolver != NULL)
    {
        resolver->prev = setup;
        resolver->next = t;
        t->prev        = resolver;
    }
    else
    {
        t->prev = setup;
    }

    t->next           = next_tunnel;
    next_tunnel->prev = t;

    tunnelchainInsert(chain, setup);
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
