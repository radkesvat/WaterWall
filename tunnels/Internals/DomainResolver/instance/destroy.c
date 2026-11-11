#include "structure.h"

static void domainresolverClearChildNode(node_t *node)
{
    memoryFree(node->name);
    memoryFree(node->type);
    memoryFree(node->next);
}

void domainresolverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                  context;
    domainresolver_tstate_t *ts = tunnelGetState(t);
    for (unsigned wid = 0; wid < ts->dns_workers_count; ++wid)
        assert(ts->dns_workers[wid] == NULL);
    if (ts->dns_connector != NULL)
        tunnelOwnedChildDestroy(ts->dns_connector);
    if (ts->dns_head != NULL)
        tunnelOwnedChildDestroy(ts->dns_head);
    domainresolverClearChildNode(&ts->dns_connector_node);
    domainresolverClearChildNode(&ts->dns_head_node);
    cJSON_Delete(ts->dns_connector_settings);
    memoryFree(ts->dns_servers);
    memoryFree(ts->dns_next);
    memoryFree(ts->dns_workers);
    memoryFree(ts->dns_worker_closed);
    memoryFree(ts->pending_logs);
    tunnelDestroy(t);
}
