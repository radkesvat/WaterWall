#include "structure.h"

#include "loggers/network_logger.h"
#include "managers/node_manager.h"

static tunnel_t *tcpudplistenerGetNextTunnel(tunnel_t *t)
{
    node_t *node = tunnelGetNode(t);

    if (node->hash_next == 0)
    {
        LOGF("TcpUdpListener: a next node is required");
        terminateProgram(1);
    }

    node_t *next_node = nodemanagerGetConfigNodeByHash(node->node_manager_config, node->hash_next);
    if (next_node == NULL)
    {
        LOGF("Node Map Failure: node (\"%s\")->next (\"%s\") not found", node->name, node->next);
        terminateProgram(1);
    }

    tunnel_t *next_tunnel = next_node->instance;
    if (next_tunnel == NULL)
    {
        LOGF("TcpUdpListener: next tunnel instance \"%s\" is not available", next_node->name);
        terminateProgram(1);
    }

    return next_tunnel;
}

void tcpudplistenerTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    tcpudplistener_tstate_t *ts          = tunnelGetState(t);
    tunnel_t                *next_tunnel = tcpudplistenerGetNextTunnel(t);

    if (ts->tcp_listener == NULL || ts->udp_listener == NULL)
    {
        LOGF("TcpUdpListener: internal listener tunnels are not available");
        terminateProgram(1);
    }

    if (next_tunnel == t || next_tunnel == ts->tcp_listener || next_tunnel == ts->udp_listener)
    {
        LOGF("TcpUdpListener: next tunnel must be outside the internal listener wrapper");
        terminateProgram(1);
    }

    if (next_tunnel->prev != NULL && next_tunnel->prev != t)
    {
        LOGF("TcpUdpListener: next node \"%s\" is already bound to previous node \"%s\"",
             next_tunnel->node->name,
             next_tunnel->prev->node->name);
        terminateProgram(1);
    }

    tunnelBindUp(ts->tcp_listener, t);
    tunnelBindUp(ts->udp_listener, t);
    tunnelBind(t, next_tunnel);

    tunnelchainInsert(chain, ts->tcp_listener);
    tunnelchainInsert(chain, ts->udp_listener);
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
