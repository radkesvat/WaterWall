#include "structure.h"

#include "loggers/network_logger.h"

static void ctpClearInternalNode(node_t *node)
{
    memoryFree(node->name);
    memoryFree(node->type);
    memoryFree(node->next);
    memoryZero(node, sizeof(*node));
}

static void ctpDestroyInternalDomainResolver(ctp_tstate_t *ts)
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

    ctpClearInternalNode(&ts->domain_resolver_node);
}

void ctpTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard       context;
    ctp_tstate_t *ts = tunnelGetState(t);

    // Idempotent: Stop already ran this on the normal shutdown path.
    ctpDestroyLwipResources(t);

    ctpDestroyInternalDomainResolver(ts);
    addresscontextReset(&ts->target_addr);

    ctpFlowRegistryDestroy(ts);

    if (ts->terminal_lines != NULL)
    {
        for (wid_t wid = 0; wid < ts->netifs_count; ++wid)
        {
            assert(ts->terminal_lines[wid] == NULL);
        }
        memoryFree(ts->terminal_lines);
        ts->terminal_lines = NULL;
    }

    memoryFree(ts->owned_lines);
    ts->owned_lines = NULL;

    if (ts->netifs != NULL)
    {
        memoryFree(ts->netifs);
        ts->netifs       = NULL;
        ts->netifs_count = 0;
    }

    ctpHandoffBudgetDetach(ts->handoff_budget);
    ts->handoff_budget            = NULL;
    const uint64_t fragment_drops = atomicLoadU64Relaxed(&ts->fragment_drops);
    if (fragment_drops != 0)
        LOGI("ConnectionToPackets: unsupported IPv4 fragments dropped=%llu", (unsigned long long) fragment_drops);
    tunnelDestroy(t);
}
