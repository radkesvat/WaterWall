#include "structure.h"
void httpproxyclientTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard       context;
    hpc_tstate_t *ts = tunnelGetState(t);
    if (ts->domain_resolver_tunnel)
        tunnelOwnedChildDestroy(ts->domain_resolver_tunnel);
    cJSON_Delete(ts->domain_resolver_settings);
    memoryFree(ts->domain_resolver_node.name);
    memoryFree(ts->domain_resolver_node.type);
    memoryFree(ts->domain_resolver_node.next);
    memoryFree(ts->target);
    memoryFree(ts->path);
    if (ts->headers)
    {
        memoryZero(ts->headers, stringLength(ts->headers));
        memoryFree(ts->headers);
    }
    memoryZero(ts->authorization, sizeof(ts->authorization));
    if (ts->workers)
    {
        for (wid_t i = 0; i < ts->worker_count; ++i)
            assert(! ts->workers[i].timers);
        memoryFree(ts->workers);
    }
    tunnelDestroy(t);
}
