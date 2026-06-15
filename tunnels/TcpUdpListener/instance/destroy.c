#include "structure.h"

static void tcpudplistenerDestroyChildTunnel(tunnel_t **child_tunnel, node_t *child_node)
{
    if (*child_tunnel != NULL)
    {
        (*child_tunnel)->onDestroy(*child_tunnel);
        *child_tunnel = NULL;
    }
    child_node->instance = NULL;
}

static void tcpudplistenerClearChildNode(node_t *child_node)
{
    memoryFree(child_node->name);
    memoryFree(child_node->type);
    memoryFree(child_node->next);
    memorySet(child_node, 0, sizeof(*child_node));
}

void tcpudplistenerTunnelstateDestroy(tcpudplistener_tstate_t *ts)
{
    tcpudplistenerDestroyChildTunnel(&ts->tcp_listener, &ts->tcp_node);
    tcpudplistenerDestroyChildTunnel(&ts->udp_listener, &ts->udp_node);

    tcpudplistenerClearChildNode(&ts->tcp_node);
    tcpudplistenerClearChildNode(&ts->udp_node);
}

void tcpudplistenerTunnelDestroy(tunnel_t *t)
{
    tcpudplistener_tstate_t *ts = tunnelGetState(t);
    tcpudplistenerTunnelstateDestroy(ts);
    tunnelDestroy(t);
}
