#include "structure.h"

#include "loggers/network_logger.h"

static void vlessclientClearInternalNode(node_t *node)
{
    memoryFree(node->name);
    memoryFree(node->type);
    memoryFree(node->next);
    memorySet(node, 0, sizeof(*node));
}

static void vlessclientDestroyInternalDomainResolverChain(vlessclient_tstate_t *ts)
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

    vlessclientClearInternalNode(&ts->domain_resolver_node);
}

void vlessclientTunnelDestroy(tunnel_t *t)
{
    if (t == NULL)
    {
        return;
    }

    vlessclient_tstate_t *ts = tunnelGetState(t);

    vlessclientDestroyInternalDomainResolverChain(ts);
    vlessclientTunnelstateDestroy(ts);
    tunnelDestroy(t);
}
