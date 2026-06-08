#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *speedtestserverTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(speedtestserver_tstate_t), sizeof(speedtestserver_lstate_t));

    if (t == NULL)
    {
        return NULL;
    }

    t->fnInitU    = &speedtestserverTunnelUpStreamInit;
    t->fnEstU     = &speedtestserverTunnelUpStreamEst;
    t->fnFinU     = &speedtestserverTunnelUpStreamFinish;
    t->fnPayloadU = &speedtestserverTunnelUpStreamPayload;
    t->fnPauseU   = &speedtestserverTunnelUpStreamPause;
    t->fnResumeU  = &speedtestserverTunnelUpStreamResume;

    t->fnInitD    = &speedtestserverTunnelDownStreamInit;
    t->fnEstD     = &speedtestserverTunnelDownStreamEst;
    t->fnFinD     = &speedtestserverTunnelDownStreamFinish;
    t->fnPayloadD = &speedtestserverTunnelDownStreamPayload;
    t->fnPauseD   = &speedtestserverTunnelDownStreamPause;
    t->fnResumeD  = &speedtestserverTunnelDownStreamResume;

    t->onPrepare = &speedtestserverTunnelOnPrepair;
    t->onStart   = &speedtestserverTunnelOnStart;
    t->onStop    = &speedtestserverTunnelOnStop;
    t->onDestroy = &speedtestserverTunnelDestroy;

    speedtestserver_tstate_t *state              = tunnelGetState(t);
    const cJSON              *settings           = node->node_settings_json;
    int                       report_interval_ms = kSpeedTestServerDefaultIntervalMs;

    mutexInit(&state->aggregate_mutex);
    getBoolFromJsonObjectOrDefault(&state->json_summary, settings, "json-summary", false);
    getBoolFromJsonObjectOrDefault(&state->quiet, settings, "quiet", false);
    getIntFromJsonObjectOrDefault(
        &report_interval_ms, settings, "report-interval-ms", kSpeedTestServerDefaultIntervalMs);

    if (report_interval_ms <= 0)
    {
        LOGF("JSON Error: SpeedTestServer->settings->report-interval-ms (int field) : expected a positive value");
        speedtestserverTunnelDestroy(t);
        return NULL;
    }

    state->report_interval_ms = (uint32_t) report_interval_ms;
    atomicStoreRelaxed(&state->completed_streams, 0);
    return t;
}
