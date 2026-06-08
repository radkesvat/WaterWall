#include "structure.h"

#include "loggers/network_logger.h"

static bool streamtopacketsLoadPacketValidationLevel(streamtopackets_packet_validation_level_t *level,
                                                     const cJSON                               *settings)
{
    const cJSON *jlevel = cJSON_GetObjectItemCaseSensitive(settings, "packet-validation-level");

    *level = kStreamToPacketsPacketValidationNone;

    if (jlevel == NULL)
    {
        return true;
    }

    if (! cJSON_IsString(jlevel) || jlevel->valuestring == NULL)
    {
        LOGF("JSON Error: StreamToPackets->settings->packet-validation-level (string field) : expected none, loose, or "
             "hard");
        return false;
    }

    if (stringCompare(jlevel->valuestring, "none") == 0)
    {
        *level = kStreamToPacketsPacketValidationNone;
        return true;
    }

    if (stringCompare(jlevel->valuestring, "loose") == 0)
    {
        *level = kStreamToPacketsPacketValidationLoose;
        return true;
    }

    if (stringCompare(jlevel->valuestring, "hard") == 0)
    {
        *level = kStreamToPacketsPacketValidationHard;
        return true;
    }

    LOGF("JSON Error: StreamToPackets->settings->packet-validation-level (string field) : expected none, loose, or "
         "hard");
    return false;
}

static bool streamtopacketsLoadSettings(streamtopackets_tstate_t *ts, const cJSON *settings)
{
    getBoolFromJsonObjectOrDefault(&ts->sensitive_mode, settings, "sensitive-mode", false);
    return streamtopacketsLoadPacketValidationLevel(&ts->packet_validation_level, settings);
}

tunnel_t *streamtopacketsTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(streamtopackets_tstate_t), sizeof(streamtopackets_lstate_t));
    streamtopackets_tstate_t *ts = tunnelGetState(t);

    t->fnInitU    = &streamtopacketsTunnelUpStreamInit;
    t->fnEstU     = &streamtopacketsTunnelUpStreamEst;
    t->fnFinU     = &streamtopacketsTunnelUpStreamFinish;
    t->fnPayloadU = &streamtopacketsTunnelUpStreamPayload;
    t->fnPauseU   = &streamtopacketsTunnelUpStreamPause;
    t->fnResumeU  = &streamtopacketsTunnelUpStreamResume;

    t->fnInitD    = &streamtopacketsTunnelDownStreamInit;
    t->fnEstD     = &streamtopacketsTunnelDownStreamEst;
    t->fnFinD     = &streamtopacketsTunnelDownStreamFinish;
    t->fnPayloadD = &streamtopacketsTunnelDownStreamPayload;
    t->fnPauseD   = &streamtopacketsTunnelDownStreamPause;
    t->fnResumeD  = &streamtopacketsTunnelDownStreamResume;

    t->onPrepare = &streamtopacketsTunnelOnPrepair;
    t->onStart   = &streamtopacketsTunnelOnStart;
    t->onStop    = &streamtopacketsTunnelOnStop;
    t->onDestroy = &streamtopacketsTunnelDestroy;

    ts->packet_validation_level = kStreamToPacketsPacketValidationNone;
    ts->sensitive_mode          = false;

    if (! streamtopacketsLoadSettings(ts, node->node_settings_json))
    {
        tunnelDestroy(t);
        return NULL;
    }

    return t;
}
