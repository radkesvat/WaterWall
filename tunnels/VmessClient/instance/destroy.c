#include "internal.h"

#include "loggers/network_logger.h"

static void vmessclientClearInternalNode(node_t *node)
{
    memoryFree(node->name);
    memoryFree(node->type);
    memoryFree(node->next);
    memoryZero(node, sizeof(*node));
}

static void vmessclientDestroyInternalDomainResolverChain(vmessclient_tstate_t *ts)
{
    if (ts->domain_resolver_tunnel != NULL)
    {
        tunnelOwnedChildDestroy(ts->domain_resolver_tunnel);
        ts->domain_resolver_tunnel = NULL;
    }

    if (ts->domain_resolver_settings != NULL)
    {
        cJSON_Delete(ts->domain_resolver_settings);
        ts->domain_resolver_settings = NULL;
    }

    vmessclientClearInternalNode(&ts->domain_resolver_node);
}

void vmessclientTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(t != NULL);

    vmessclient_tstate_t *ts = tunnelGetState(t);

    vmessclientDestroyInternalDomainResolverChain(ts);
    vmessclientTunnelstateDestroy(ts);
    tunnelDestroy(t);
}
