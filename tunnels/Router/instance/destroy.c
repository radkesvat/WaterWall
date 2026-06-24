#include "structure.h"

static void routerClearInternalNode(node_t *node)
{
    memoryFree(node->name);
    memoryFree(node->type);
    memoryFree(node->next);
    memorySet(node, 0, sizeof(*node));
}

static void routerDestroyInternalDomainResolver(router_tstate_t *ts)
{
    if (ts->domain_resolver_tunnel != NULL)
    {
        ts->domain_resolver_tunnel->onDestroy(ts->domain_resolver_tunnel);
        ts->domain_resolver_tunnel = NULL;
    }

    routerClearInternalNode(&ts->domain_resolver_node);
}

void routerTunnelDestroy(tunnel_t *t)
{
    router_tstate_t *ts = tunnelGetState(t);
    routerDestroyInternalDomainResolver(ts);
    routerGeoipClose(ts);
    routerGeositeClose(ts);
    routerRuleTableDestroy(ts);
    tunnelDestroy(t);
}
