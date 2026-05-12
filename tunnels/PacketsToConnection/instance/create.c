#include "structure.h"

#include "loggers/network_logger.h"

static bool ptcLoadSettings(ptc_tstate_t *ts, const cJSON *settings)
{
    int udp_idle_timeout_ms = (int) kPtcDefaultUdpIdleTimeoutMs;

    getIntFromJsonObjectOrDefault(&udp_idle_timeout_ms, settings, "udp-idle-timeout-ms",
                                  (int) kPtcDefaultUdpIdleTimeoutMs);

    if (udp_idle_timeout_ms < 1)
    {
        LOGF("JSON Error: PacketsToConnection->settings->udp-idle-timeout-ms (int field) : expected a value >= 1");
        return false;
    }

    ts->udp_idle_timeout_ms = (uint32_t) udp_idle_timeout_ms;
    return ptcFakeDnsLoadSettings(ts, settings);
}

tunnel_t *ptcTunnelCreate(node_t *node)
{
    tunnel_t     *t  = tunnelCreate(node, sizeof(ptc_tstate_t), sizeof(ptc_lstate_t));
    ptc_tstate_t *ts = tunnelGetState(t);
    const cJSON  *settings = node->node_settings_json;

    t->fnInitU    = &ptcTunnelUpStreamInit;
    t->fnPayloadU = &ptcTunnelUpStreamPayload;
    t->fnPayloadD = &ptcTunnelDownStreamPayload;
    t->fnFinD     = &ptcTunnelDownStreamFinish;
    t->fnInitD    = &ptcTunnelDownStreamInit;
    t->fnEstD     = &ptcTunnelDownStreamEst;
    t->fnPauseD   = &ptcTunnelDownStreamPause;
    t->fnResumeD  = &ptcTunnelDownStreamResume;

    t->onPrepare = &ptcTunnelOnPrepair;
    t->onStart   = &ptcTunnelOnStart;
    t->onDestroy = &ptcTunnelDestroy;

    *ts = (ptc_tstate_t) {
        .route_context4      = {0},
        .route_context6      = {0},
        .udp_idle_timeout_ms = kPtcDefaultUdpIdleTimeoutMs,
        .ipv4_identification = 0,
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

    initTcpIpStack();
    LWIP_MEMPOOL_INIT(RX_POOL);

    return t;
}
