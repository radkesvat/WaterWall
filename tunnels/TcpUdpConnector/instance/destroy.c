#include "structure.h"

static void tcpudpconnectorDestroyChildTunnel(tunnel_t **child_tunnel, node_t *child_node)
{
    if (*child_tunnel != NULL)
    {
        (*child_tunnel)->onDestroy(*child_tunnel);
        *child_tunnel = NULL;
    }
    child_node->instance = NULL;
}

static void tcpudpconnectorClearChildNode(node_t *child_node)
{
    memoryFree(child_node->name);
    memoryFree(child_node->type);
    memoryFree(child_node->next);
    memorySet(child_node, 0, sizeof(*child_node));
}

void tcpudpconnectorTunnelstateDestroy(tcpudpconnector_tstate_t *ts)
{
    tcpudpconnectorDestroyChildTunnel(&ts->tcp_connector, &ts->tcp_node);
    tcpudpconnectorDestroyChildTunnel(&ts->udp_connector, &ts->udp_node);

    tcpudpconnectorClearChildNode(&ts->tcp_node);
    tcpudpconnectorClearChildNode(&ts->udp_node);
}

void tcpudpconnectorTunnelDestroy(tunnel_t *t)
{
    tcpudpconnector_tstate_t *ts = tunnelGetState(t);
    tcpudpconnectorTunnelstateDestroy(ts);
    tunnelDestroy(t);
}
