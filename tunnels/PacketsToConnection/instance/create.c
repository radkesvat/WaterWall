#include "structure.h"

#include "loggers/network_logger.h"

static bool ptcLoadSettings(ptc_tstate_t *ts, const cJSON *settings)
{
    /*
     * Present but invalid is an error, not a default. getIntFromJsonObjectOrDefault()
     * cannot separate the two, so `"udp-idle-timeout-ms": "60000"` silently
     * configured the default and `60000.5` silently truncated.
     */
    int64_t udp_idle_timeout_ms = (int64_t) kPtcDefaultUdpIdleTimeoutMs;

    if (! ptcLoadOptionalInteger(settings,
                                 "udp-idle-timeout-ms",
                                 1,
                                 (int64_t) UINT32_MAX,
                                 &udp_idle_timeout_ms,
                                 "PacketsToConnection->settings->udp-idle-timeout-ms"))
    {
        return false;
    }

    ts->udp_idle_timeout_ms = (uint32_t) udp_idle_timeout_ms;

    int64_t max_pending_bytes = (int64_t) kPtcDefaultMaxPendingBytes;

    if (! ptcLoadOptionalInteger(settings,
                                 "max-pending-bytes",
                                 (int64_t) kPtcMinMaxPendingBytes,
                                 (int64_t) kPtcMaxMaxPendingBytes,
                                 &max_pending_bytes,
                                 "PacketsToConnection->settings->max-pending-bytes"))
    {
        return false;
    }

    ts->max_pending_bytes = (uint32_t) max_pending_bytes;
    return ptcFakeDnsLoadSettings(ts, settings);
}

tunnel_t *ptcTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(ptc_tstate_t), sizeof(ptc_lstate_t));
    if (! t)
    {
        return NULL;
    }
    ptc_tstate_t *ts       = tunnelGetState(t);
    const cJSON  *settings = node->node_settings_json;

    t->fnInitU    = &ptcTunnelUpStreamInit;
    t->fnPayloadU = &ptcTunnelUpStreamPayload;
    // The packet adapter on the prev side only sends upstream Init/Payload on the packet
    // line; Est/Finish/Pause/Resume are never expected there, so wire them as guards.
    t->fnEstU     = &ptcTunnelUpStreamEst;
    t->fnFinU     = &ptcTunnelUpStreamFinish;
    t->fnPauseU   = &ptcTunnelUpStreamPause;
    t->fnResumeU  = &ptcTunnelUpStreamResume;
    t->fnPayloadD = &ptcTunnelDownStreamPayload;
    t->fnFinD     = &ptcTunnelDownStreamFinish;
    t->fnInitD    = &ptcTunnelDownStreamInit;
    t->fnEstD     = &ptcTunnelDownStreamEst;
    t->fnPauseD   = &ptcTunnelDownStreamPause;
    t->fnResumeD  = &ptcTunnelDownStreamResume;

    t->onStart          = &ptcTunnelOnStart;
    t->onQuiesceRequest = &ptcTunnelOnQuiesceRequest;
    t->onQuiesceWait    = &ptcTunnelOnQuiesceWait;
    t->onStop           = &ptcTunnelOnStop;
    t->onWorkerStop     = &ptcTunnelOnWorkerStop;
    t->onDestroy        = &ptcTunnelDestroy;

    *ts = (ptc_tstate_t) {
        .max_pending_bytes   = kPtcDefaultMaxPendingBytes,
        .max_pending_entries = kPtcMaxPendingEntries,
        .udp_idle_timeout_ms = kPtcDefaultUdpIdleTimeoutMs,
    };
    if (settings != NULL && ! cJSON_IsObject(settings))
    {
        LOGF("JSON Error: PacketsToConnection->settings (object field) : expected an object");
        tunnelDestroy(t);
        return NULL;
    }

    if (settings != NULL && ! ptcLoadSettings(ts, settings))
    {
        tunnelDestroy(t);
        return NULL;
    }

    deviceLifetimeGateInit(&ts->output_gate);
    deviceLifetimeGateInit(&ts->next_gate);
    atomic_init(&ts->stopping, false);
    if (UNLIKELY(! mutexTryInit(&ts->owned_lines_lock)))
    {
        ptcTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }
    ts->owned_lines_lock_initialized = true;

    initTcpIpStack();
    ptcRxWrapperPoolInitializeOnce();

    ts->async_session = tunnelasyncsessionCreate(t, "PacketsToConnection");
    if (UNLIKELY(ts->async_session == NULL))
    {
        ptcTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    return t;
}
