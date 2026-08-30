#include "structure.h"

#include "loggers/network_logger.h"

static void udpconnectorClearInternalNode(node_t *node)
{
    memoryFree(node->name);
    memoryFree(node->type);
    memoryFree(node->next);
    memoryZero(node, sizeof(*node));
}

static void udpconnectorDestroyInternalDomainResolverChain(udpconnector_tstate_t *ts)
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

    udpconnectorClearInternalNode(&ts->domain_resolver_node);
}

void udpconnectorTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                context;
    udpconnector_tstate_t *ts = tunnelGetState(t);

    if (ts->worker_pools != NULL)
    {
        for (wid_t wid = 0; wid < getWorkersCount(); ++wid)
        {
            udpconnector_worker_pool_t *pool = &ts->worker_pools[wid];
            if (UNLIKELY(pool->wid != wid || pool->idle_table != NULL || pool->v4_sockets != NULL ||
                         pool->v6_sockets != NULL || pool->v4_sockets_count != 0 || pool->v6_sockets_count != 0 ||
                         pool->active_bindings_count != 0))
            {
                LOGF("UdpConnector: destroy reached undrained worker resources for worker %u", (unsigned int) wid);
                abortProgramNow(1);
            }
        }
        memoryFree(ts->worker_pools);
        ts->worker_pools = NULL;
    }

    udpconnectorDestroyInternalDomainResolverChain(ts);

    if (ts->destinations != NULL)
    {
        for (uint32_t i = 0; i < ts->destinations_count; ++i)
        {
            udpconnectorDestinationDeinit(&ts->destinations[i]);
        }
        memoryFree(ts->destinations);
    }

    dynamicvalueDestroy(ts->dest_addr_selected);
    dynamicvalueDestroy(ts->dest_port_selected);
    if (ts->interface_name != NULL)
    {
        memoryFree(ts->interface_name);
    }
    if (ts->source_ip != NULL)
    {
        memoryFree(ts->source_ip);
    }

    tunnelDestroy(t);
}
