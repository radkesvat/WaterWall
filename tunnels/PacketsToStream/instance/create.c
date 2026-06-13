#include "structure.h"

#include "loggers/network_logger.h"

static bool packetstostreamLoadPacketValidationLevel(packetstostream_packet_validation_level_t *level,
                                                     const cJSON                               *settings)
{
    const cJSON *jlevel = cJSON_GetObjectItemCaseSensitive(settings, "packet-validation-level");

    *level = kPacketsToStreamPacketValidationNone;

    if (jlevel == NULL)
    {
        return true;
    }

    if (! cJSON_IsString(jlevel) || jlevel->valuestring == NULL)
    {
        LOGF("JSON Error: PacketsToStream->settings->packet-validation-level (string field) : expected none, loose, or "
             "hard");
        return false;
    }

    if (stringCompare(jlevel->valuestring, "none") == 0)
    {
        *level = kPacketsToStreamPacketValidationNone;
        return true;
    }

    if (stringCompare(jlevel->valuestring, "loose") == 0)
    {
        *level = kPacketsToStreamPacketValidationLoose;
        return true;
    }

    if (stringCompare(jlevel->valuestring, "hard") == 0)
    {
        *level = kPacketsToStreamPacketValidationHard;
        return true;
    }

    LOGF("JSON Error: PacketsToStream->settings->packet-validation-level (string field) : expected none, loose, or "
         "hard");
    return false;
}

static bool packetstostreamLoadSettings(packetstostream_tstate_t *ts, const cJSON *settings)
{
    int interval_ms  = kSensitiveDefaultIntervalMs;
    int tolerance_ms = kSensitiveDefaultToleranceMs;

    getBoolFromJsonObjectOrDefault(&ts->sensitive_mode, settings, "sensitive-mode", false);
    getIntFromJsonObjectOrDefault(&interval_ms, settings, "interval-ms", kSensitiveDefaultIntervalMs);
    getIntFromJsonObjectOrDefault(&tolerance_ms, settings, "tolerance-ms", kSensitiveDefaultToleranceMs);

    if (interval_ms < 1)
    {
        LOGF("JSON Error: PacketsToStream->settings->interval-ms (int field) : expected a value >= 1");
        return false;
    }

    if (tolerance_ms < 1)
    {
        LOGF("JSON Error: PacketsToStream->settings->tolerance-ms (int field) : expected a value >= 1");
        return false;
    }

    if (! packetstostreamLoadPacketValidationLevel(&ts->packet_validation_level, settings))
    {
        return false;
    }

    ts->interval_ms  = (uint32_t) interval_ms;
    ts->tolerance_ms = (uint32_t) tolerance_ms;

    return true;
}

tunnel_t *packetstostreamTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(packetstostream_tstate_t), sizeof(packetstostream_lstate_t));
    packetstostream_tstate_t *ts = tunnelGetState(t);

    t->fnInitU    = &packetstostreamTunnelUpStreamInit;
    t->fnEstU     = &packetstostreamTunnelUpStreamEst;
    t->fnFinU     = &packetstostreamTunnelUpStreamFinish;
    t->fnPayloadU = &packetstostreamTunnelUpStreamPayload;
    t->fnPauseU   = &packetstostreamTunnelUpStreamPause;
    t->fnResumeU  = &packetstostreamTunnelUpStreamResume;

    t->fnInitD    = &packetstostreamTunnelDownStreamInit;
    t->fnEstD     = &packetstostreamTunnelDownStreamEst;
    t->fnFinD     = &packetstostreamTunnelDownStreamFinish;
    t->fnPayloadD = &packetstostreamTunnelDownStreamPayload;
    t->fnPauseD   = &packetstostreamTunnelDownStreamPause;
    t->fnResumeD  = &packetstostreamTunnelDownStreamResume;

    t->onPrepare    = &packetstostreamTunnelOnPrepair;
    t->onStart      = &packetstostreamTunnelOnStart;
    t->onStop       = &packetstostreamTunnelOnStop;
    t->onWorkerStop = &packetstostreamTunnelOnWorkerStop;
    t->onDestroy    = &packetstostreamTunnelDestroy;

    ts->worker_timers           = NULL;
    ts->worker_timeout_timers   = NULL;
    ts->interval_ms             = kSensitiveDefaultIntervalMs;
    ts->tolerance_ms            = kSensitiveDefaultToleranceMs;
    ts->packet_validation_level = kPacketsToStreamPacketValidationNone;
    ts->sensitive_mode          = false;

    if (! packetstostreamLoadSettings(ts, node->node_settings_json))
    {
        tunnelDestroy(t);
        return NULL;
    }

    if (ts->sensitive_mode)
    {
        ts->worker_timers         = memoryAllocateZero(sizeof(wtimer_t *) * getWorkersCount());
        ts->worker_timeout_timers = memoryAllocateZero(sizeof(wtimer_t *) * getWorkersCount());
    }

    return t;
}
