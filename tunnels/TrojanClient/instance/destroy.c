#include "structure.h"

#include "loggers/network_logger.h"

static void trojanclientClearInternalNode(node_t *node)
{
    memoryFree(node->name);
    memoryFree(node->type);
    memoryFree(node->next);
    memorySet(node, 0, sizeof(*node));
}

static void trojanclientDestroyInternalDomainResolverChain(trojanclient_tstate_t *ts)
{
    if (ts->domain_setup_tunnel != NULL)
    {
        ts->domain_setup_tunnel->onDestroy(ts->domain_setup_tunnel);
        ts->domain_setup_tunnel = NULL;
    }

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

    trojanclientClearInternalNode(&ts->domain_setup_node);
    trojanclientClearInternalNode(&ts->domain_resolver_node);
}

void trojanclientTunnelDestroy(tunnel_t *t)
{
    if (t == NULL)
    {
        return;
    }

    trojanclient_tstate_t *ts = tunnelGetState(t);

    trojanclientDestroyInternalDomainResolverChain(ts);
    trojanclientTunnelstateDestroy(ts);
    tunnelDestroy(t);
}
