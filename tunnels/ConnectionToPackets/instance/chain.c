#include "structure.h"

#include "loggers/network_logger.h"

/*
 * Inserts the internal DomainResolver between prev and this node, then continues
 * into next. This mirrors Socks5Client's chaining: the connectors do the same
 * thing but end their chain, while this node still has a packet side to chain.
 */
void ctpTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    ctp_tstate_t *ts   = tunnelGetState(t);
    node_t       *node = tunnelGetNode(t);

    /*
     * The node manager may visit this node before its downstream owner is
     * chained. Leave it unchained in that pass; the real previous node binds to
     * it and calls back.
     */
    if (t->prev == NULL)
    {
        if (chain->tunnels.len != 0)
        {
            LOGF("ConnectionToPackets: cannot defer internal DomainResolver insertion on a non-empty chain");
            startupFailureRecord(1);
            return;
        }
        tunnelchainDestroy(chain);
        return;
    }

    if (node->hash_next == 0)
    {
        LOGF("ConnectionToPackets: a next node is required, it is where the raw packets go");
        startupFailureRecord(1);
        return;
    }

    node_t *next_node = nodemanagerGetConfigNodeByHash(node->node_manager_config, node->hash_next);
    if (next_node == NULL)
    {
        LOGF("Node Map Failure: node (\"%s\")->next (\"%s\") not found", node->name, node->next);
        startupFailureRecord(1);
        return;
    }

    tunnel_t *resolver    = ts->domain_resolver_tunnel;
    tunnel_t *next_tunnel = next_node->instance;
    tunnel_t *prev        = t->prev;

    if (next_tunnel == NULL)
    {
        LOGF("ConnectionToPackets: next node \"%s\" has no tunnel instance", next_node->name);
        startupFailureRecord(1);
        return;
    }
    if (resolver == NULL)
    {
        LOGF("ConnectionToPackets: internal DomainResolver was not created");
        startupFailureRecord(1);
        return;
    }
    if (resolver->prev != NULL || resolver->next != NULL)
    {
        LOGF("ConnectionToPackets: internal DomainResolver tunnel is already bound");
        startupFailureRecord(1);
        return;
    }
    if (next_tunnel->prev != NULL && next_tunnel->prev != t)
    {
        LOGF("Node Map Failure: Node (%s) wanted to bind to (%s) which is already bounded by %s",
             t->node->name,
             next_tunnel->node->name,
             next_tunnel->prev->node->name);
        startupFailureRecord(1);
        return;
    }

    if (prev->next == t)
    {
        prev->next = resolver;
    }

    resolver->prev = prev;
    resolver->next = t;
    t->prev        = resolver;

    t->next           = next_tunnel;
    next_tunnel->prev = t;

    tunnelchainInsert(chain, resolver);
    tunnelchainInsert(chain, t);

    if (next_tunnel->chain != NULL)
    {
        // A bridge-like node already built the packet side; merge into it.
        tunnelchainCombine(next_tunnel->chain, chain);
    }
    else
    {
        next_tunnel->onChain(next_tunnel, chain);
    }
}
