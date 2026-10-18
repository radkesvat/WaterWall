#include "APIServer/structure.h"
#include "loggers/network_logger.h"

tunnel_t *apiserverTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(apiserver_tstate_t), sizeof(apiserver_lstate_t));
    if (! t)
        return NULL;
    t->fnInitU             = apiserverUpStreamInit;
    t->fnFinU              = apiserverUpStreamFinish;
    t->fnPayloadU          = apiserverUpStreamPayload;
    t->fnPauseU            = apiserverUpStreamPause;
    t->fnResumeU           = apiserverUpStreamResume;
    t->onPrepare           = apiserverOnPrepair;
    t->onQuiesceRequest    = apiserverOnQuiesceRequest;
    t->onWorkerQuiesce     = apiserverOnWorkerQuiesce;
    t->onDestroy           = apiserverDestroy;
    apiserver_tstate_t *ts = tunnelGetState(t);
    atomic_init(&ts->session_count, 0);
    atomic_init(&ts->serial, 0);
    atomic_init(&ts->stopping, false);
    if (! apiserverLoadSettings(ts, node->node_settings_json))
    {
        LOGF("APIServer: invalid clients, allowlist, or limit geometry");
        apiserverDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }
    ts->domain = nodeApiDomainCreate(ts->limits.max_memory, ts->limits.max_jobs, apiserverComplete, t);
    if (! ts->domain)
    {
        apiserverDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }
    ts->sessions = memoryAllocateZero(getWorkersCount() * sizeof(*ts->sessions));
    nodeApiRequireEnabled();
    return t;
}
