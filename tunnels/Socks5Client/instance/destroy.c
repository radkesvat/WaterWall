#include "structure.h"

#include "loggers/network_logger.h"

static void socks5clientClearInternalNode(node_t *node)
{
    memoryFree(node->name);
    memoryFree(node->type);
    memoryFree(node->next);
    memorySet(node, 0, sizeof(*node));
}

static void socks5clientDestroyInternalDomainResolverChain(socks5client_tstate_t *ts)
{
    if (ts->domain_resolver_tunnel != NULL)
    {
        ts->domain_resolver_tunnel->onDestroy(ts->domain_resolver_tunnel);
        ts->domain_resolver_tunnel = NULL;
    }

    if (ts->domain_resolver_settings != NULL)
    {
        cJSON_Delete(ts->domain_resolver_settings);
        ts->domain_resolver_settings = NULL;
    }

    socks5clientClearInternalNode(&ts->domain_resolver_node);
}

void socks5clientTunnelDestroy(tunnel_t *t)
{
    if (t == NULL)
    {
        return;
    }

    socks5client_tstate_t *ts = tunnelGetState(t);

    socks5clientDestroyInternalDomainResolverChain(ts);
    socks5clientTunnelstateDestroy(ts);
    tunnelDestroy(t);
}
