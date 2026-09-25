#include "DomainResolver/interface.h"
#include "loggers/network_logger.h"
#include "structure.h"
tunnel_t *httpproxyclientTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(hpc_tstate_t), sizeof(hpc_lstate_t));
    if (! t)
        return NULL;
    hpc_tstate_t *ts   = tunnelGetState(t);
    t->fnInitU         = httpproxyclientTunnelUpStreamInit;
    t->fnPayloadU      = httpproxyclientTunnelUpStreamPayload;
    t->fnFinU          = httpproxyclientTunnelUpStreamFinish;
    t->fnPauseU        = httpproxyclientTunnelUpStreamPause;
    t->fnResumeU       = httpproxyclientTunnelUpStreamResume;
    t->fnEstD          = httpproxyclientTunnelDownStreamEst;
    t->fnPayloadD      = httpproxyclientTunnelDownStreamPayload;
    t->fnFinD          = httpproxyclientTunnelDownStreamFinish;
    t->fnPauseD        = httpproxyclientTunnelDownStreamPause;
    t->fnResumeD       = httpproxyclientTunnelDownStreamResume;
    t->onDestroy       = httpproxyclientTunnelDestroy;
    t->onWorkerQuiesce = httpproxyclientTunnelOnWorkerQuiesce;
    if (! hpcParseSettings(ts, node))
    {
        LOGF("HttpProxyClient: invalid settings or missing next node");
        httpproxyclientTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }
    ts->worker_count = getWorkersCount();
    ts->workers      = memoryAllocateZero(sizeof(*ts->workers) * ts->worker_count);
    if (! ts->workers)
    {
        httpproxyclientTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }
    if (ts->resolve_domains)
    {
        ts->domain_resolver_settings = cJSON_CreateObject();
        if (! ts->domain_resolver_settings ||
            ! cJSON_AddNumberToObject(ts->domain_resolver_settings, "strategy", ts->domain_strategy) ||
            ! nodeConfigureChild(&ts->domain_resolver_node,
                                 nodeDomainResolverGet(),
                                 node,
                                 ".domain-resolver",
                                 kNodeChildLinkNone,
                                 ts->domain_resolver_settings))
            goto failed;
        ts->domain_resolver_tunnel = nodemanagerCreateTunnelInstance(&ts->domain_resolver_node);
        if (! ts->domain_resolver_tunnel)
            goto failed;
        ts->domain_resolver_node.instance = ts->domain_resolver_tunnel;
        domainresolverTunnelUseLineStrategy(ts->domain_resolver_tunnel, true);
        domainresolverTunnelSetPrepareHook(ts->domain_resolver_tunnel, t, 0, hpcDomainResolverPrepare, NULL);
        t->onChain = httpproxyclientTunnelOnChain;
    }
    return t;
failed:
    LOGF("HttpProxyClient: failed to construct internal DomainResolver");
    httpproxyclientTunnelDestroy(t, wwLifecycleStartupRollback());
    return NULL;
}
