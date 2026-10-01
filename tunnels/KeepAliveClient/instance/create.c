#include "structure.h"

#include "loggers/network_logger.h"

static bool keepaliveclientLoadSettings(keepaliveclient_tstate_t *ts, const cJSON *settings)
{
    int     ping_interval_ms = kKeepAliveDefaultPingMs;
    int64_t tolerance_ms     = kKeepAliveDefaultToleranceMs;

    ts->sensitive_mode = false;
    if (jsonGetObjectBoolean(settings, "sensitive-mode", &ts->sensitive_mode) == kJsonValueInvalid)
    {
        LOGF("JSON Error: KeepAliveClient->settings->sensitive-mode (boolean field) : expected true or false");
        return false;
    }
    if (jsonGetObjectIntegerInRange(settings, "tolerance-ms", 1, INT_MAX, &tolerance_ms) == kJsonValueInvalid)
    {
        LOGF("JSON Error: KeepAliveClient->settings->tolerance-ms (int field) : expected an integer in 1..INT_MAX");
        return false;
    }

    if (settings != NULL)
    {
        getIntFromJsonObjectOrDefault(&ping_interval_ms, settings, "ping-interval", kKeepAliveDefaultPingMs);
    }

    if (ping_interval_ms < 1)
    {
        LOGF("JSON Error: KeepAliveClient->settings->ping-interval (int field) : expected a value >= 1");
        return false;
    }

    ts->ping_interval_ms = (uint32_t) ping_interval_ms;
    ts->tolerance_ms     = (uint32_t) tolerance_ms;
    return true;
}

tunnel_t *keepaliveclientTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(keepaliveclient_tstate_t), sizeof(keepaliveclient_lstate_t));
    if (! t)
    {
        return NULL;
    }

    keepaliveclient_tstate_t *ts = tunnelGetState(t);

    t->fnInitU    = &keepaliveclientTunnelUpStreamInit;
    t->fnFinU     = &keepaliveclientTunnelUpStreamFinish;
    t->fnPayloadU = &keepaliveclientTunnelUpStreamPayload;
    t->fnPauseU   = &keepaliveclientTunnelUpStreamPause;
    t->fnResumeU  = &keepaliveclientTunnelUpStreamResume;
    t->fnFinD     = &keepaliveclientTunnelDownStreamFinish;
    t->fnPayloadD = &keepaliveclientTunnelDownStreamPayload;
    t->fnEstD     = &keepaliveclientTunnelDownStreamEst;
    t->fnPauseD   = &keepaliveclientTunnelDownStreamPause;
    t->fnResumeD  = &keepaliveclientTunnelDownStreamResume;

    t->onStart         = &keepaliveclientTunnelOnStart;
    t->onWorkerQuiesce = &keepaliveclientTunnelOnWorkerQuiesce;
    t->onDestroy       = &keepaliveclientTunnelDestroy;

    if (UNLIKELY(! mutexTryInit(&ts->lines_mutex)))
    {
        LOGF("KeepAliveClient: failed to initialize line-registry mutex");
        tunnelDestroy(t);
        return NULL;
    }
    ts->lines_head       = NULL;
    ts->worker_timers    = memoryAllocateZero(sizeof(wtimer_t *) * getWorkersCount());
    ts->ping_interval_ms = kKeepAliveDefaultPingMs;

    if (UNLIKELY(ts->worker_timers == NULL))
    {
        LOGF("KeepAliveClient: failed to allocate worker timers");
        keepaliveclientTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    if (! keepaliveclientLoadSettings(ts, node->node_settings_json))
    {
        keepaliveclientTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    return t;
}
