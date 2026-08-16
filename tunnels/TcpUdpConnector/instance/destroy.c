#include "structure.h"

static void tcpudpconnectorDestroyChildTunnel(tunnel_t **child_tunnel, node_t *child_node)
{
    if (*child_tunnel != NULL)
    {
        tunnelOwnedChildDestroy(*child_tunnel);
        *child_tunnel = NULL;
    }
    child_node->instance = NULL;
}

static void tcpudpconnectorClearChildNode(node_t *child_node)
{
    memoryFree(child_node->name);
    memoryFree(child_node->type);
    memoryFree(child_node->next);
    memoryZero(child_node, sizeof(*child_node));
}

void tcpudpconnectorTunnelstateDestroy(tcpudpconnector_tstate_t *ts)
{
    tcpudpconnectorDestroyChildTunnel(&ts->tcp_connector, &ts->tcp_node);
    tcpudpconnectorDestroyChildTunnel(&ts->udp_connector, &ts->udp_node);

    tcpudpconnectorClearChildNode(&ts->tcp_node);
    tcpudpconnectorClearChildNode(&ts->udp_node);
}

void tcpudpconnectorTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                   context;
    tcpudpconnector_tstate_t *ts = tunnelGetState(t);
    tcpudpconnectorTunnelstateDestroy(ts);
    tunnelDestroy(t);
}
