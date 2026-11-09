#include "structure.h"

void domainresolverTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard                  context;
    domainresolver_tstate_t *ts = tunnelGetState(t);
    if (ts->mode == kDomainResolverModeNative)
        return;
    assert(currentThreadOwnsWorker(wid));
    assert(wid < ts->dns_workers_count);
    ts->dns_worker_closed[wid] = true;
    if (ts->dns_workers[wid] != NULL)
        domainresolverTransportQuiesce(ts->dns_workers[wid]);
}

void domainresolverTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard                  context;
    domainresolver_tstate_t *ts = tunnelGetState(t);
    if (ts->mode == kDomainResolverModeNative)
        return;
    assert(currentThreadOwnsWorker(wid));
    assert(wid < ts->dns_workers_count);
    domainresolver_transport_t *transport = ts->dns_workers[wid];
    ts->dns_workers[wid]                  = NULL;
    if (transport != NULL)
        domainresolverTransportDestroy(transport);
}

domainresolver_transport_t *domainresolverGetTransportForLine(tunnel_t *t, line_t *l)
{
    domainresolver_tstate_t *ts  = tunnelGetState(t);
    const wid_t              wid = lineGetWID(l);
    assert(lineIsOnCurrentWorker(l));
    assert(wid < ts->dns_workers_count);
    if (ts->dns_worker_closed[wid])
        return NULL;
    assert(ts->dns_egress != NULL);
    if (ts->dns_workers[wid] == NULL)
        ts->dns_workers[wid] = domainresolverTransportCreate(t, ts->dns_egress, wid, &ts->dns_options);
    return ts->dns_workers[wid];
}
