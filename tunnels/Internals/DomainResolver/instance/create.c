#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *domainresolverTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(domainresolver_tstate_t), sizeof(domainresolver_lstate_t));
    if (! t)
    {
        return NULL;
    }

    t->fnInitU    = &domainresolverTunnelUpStreamInit;
    t->fnFinU     = &domainresolverTunnelUpStreamFinish;
    t->fnPayloadU = &domainresolverTunnelUpStreamPayload;
    t->fnPauseU   = &domainresolverTunnelUpStreamPause;
    t->fnResumeU  = &domainresolverTunnelUpStreamResume;

    t->fnEstD     = &domainresolverTunnelDownStreamEst;
    t->fnFinD     = &domainresolverTunnelDownStreamFinish;
    t->fnPayloadD = &domainresolverTunnelDownStreamPayload;
    t->fnPauseD   = &domainresolverTunnelDownStreamPause;
    t->fnResumeD  = &domainresolverTunnelDownStreamResume;

    t->onChain         = &domainresolverTunnelOnChain;
    t->onIndex         = &domainresolverTunnelOnIndex;
    t->onWorkerQuiesce = &domainresolverTunnelOnWorkerQuiesce;
    t->onWorkerStop    = &domainresolverTunnelOnWorkerStop;
    t->onDestroy       = &domainresolverTunnelDestroy;

    domainresolver_tstate_t *ts       = tunnelGetState(t);
    const cJSON             *settings = node->node_settings_json;

    if (settings != NULL && ! cJSON_IsObject(settings))
    {
        LOGF("JSON Error: DomainResolver->settings must be an object when provided");
        domainresolverTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    getBoolFromJsonObjectOrDefault(&ts->verbose, settings, "verbose", false);
    if (! domainresolverConfigureTransport(t, settings))
    {
        domainresolverTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    ts->pending_logs = memoryCalloc(getWorkersCount(), sizeof(*ts->pending_logs));
    return t;
}
