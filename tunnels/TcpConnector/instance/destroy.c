#include "structure.h"

#include "loggers/network_logger.h"

static void tcpconnectorClearInternalNode(node_t *node)
{
    memoryFree(node->name);
    memoryFree(node->type);
    memoryFree(node->next);
    memorySet(node, 0, sizeof(*node));
}

static void tcpconnectorDestroyInternalDomainResolverChain(tcpconnector_tstate_t *ts)
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

    tcpconnectorClearInternalNode(&ts->domain_resolver_node);
}

void tcpconnectorTunnelDestroy(tunnel_t *t)
{
    tcpconnector_tstate_t *ts = tunnelGetState(t);

    tcpconnectorDestroyInternalDomainResolverChain(ts);

    if (ts->idle_tables != NULL)
    {
        for (wid_t wid = 0; wid < getWorkersCount(); ++wid)
        {
            if (ts->idle_tables[wid] != NULL)
            {
                LOGW("TcpConnector: destroying with active worker-local idle table for worker %u", (unsigned int) wid);
            }
        }
        memoryFree(ts->idle_tables);
        ts->idle_tables = NULL;
    }

    if (ts->destinations != NULL)
    {
        for (uint32_t i = 0; i < ts->destinations_count; ++i)
        {
            tcpconnectorDestinationDeinit(&ts->destinations[i]);
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
