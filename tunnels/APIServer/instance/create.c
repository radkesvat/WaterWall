#include "APIServer/structure.h"
#include "loggers/network_logger.h"
#include "node_builder/config_lexical.h"

tunnel_t *apiserverTunnelCreate(node_t *node)
{
    /* The gateway's own name identifies authenticated actors in node audit logs. */
    if (node->name == NULL || node->name[0] == '\0' || strlen(node->name) > 256 ||
        ! configLexicalCheckEncoding(node->name, strlen(node->name)))
    {
        LOGE("APIServer: gateway name must contain 1..256 UTF-8 bytes");
        return NULL;
    }
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
        LOGE("APIServer: invalid clients, allowlist, or limit geometry");
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
