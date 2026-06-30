#include "structure.h"

#include "loggers/network_logger.h"

static bool softiplimiterParseIdentifierMode(softiplimiter_tstate_t *ts, const cJSON *settings)
{
    const cJSON *identifier = cJSON_GetObjectItemCaseSensitive(settings, "identifier");
    if (! cJSON_IsString(identifier) || identifier->valuestring == NULL || identifier->valuestring[0] == '\0')
    {
        LOGF("JSON Error: SoftIpLimiter->settings->identifier (string field) must be either vless or trojan");
        return false;
    }

    if (stringCompare(identifier->valuestring, "vless") == 0)
    {
        ts->identifier_mode = kSoftIpLimiterIdentifierVless;
        return true;
    }

    if (stringCompare(identifier->valuestring, "trojan") == 0)
    {
        ts->identifier_mode = kSoftIpLimiterIdentifierTrojan;
        return true;
    }

    LOGF("JSON Error: SoftIpLimiter->settings->identifier (string field) must be either vless or trojan");
    return false;
}

static bool softiplimiterParseRequiredInt(int *out, const cJSON *settings, const char *key)
{
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(settings, key);
    if (! cJSON_IsNumber(value) || value->valuedouble != (double) value->valueint)
    {
        LOGF("JSON Error: SoftIpLimiter->settings->%s (int field) is required", key);
        return false;
    }

    *out = value->valueint;
    return true;
}

static bool softiplimiterParseSettings(softiplimiter_tstate_t *ts, const cJSON *settings)
{
    int simultaneous_user_limit = 0;
    int tolerance_ms = 0;

    if (! softiplimiterParseIdentifierMode(ts, settings) ||
        ! softiplimiterParseRequiredInt(&simultaneous_user_limit, settings, "simultaneous-user-limit") ||
        ! softiplimiterParseRequiredInt(&tolerance_ms, settings, "tolerance-ms"))
    {
        return false;
    }

    if (simultaneous_user_limit < 1 || simultaneous_user_limit > kSoftIpLimiterMaxIps)
    {
        LOGF("JSON Error: SoftIpLimiter->settings->simultaneous-user-limit (int field) must be in range [1, %u]",
             (unsigned int) kSoftIpLimiterMaxIps);
        return false;
    }

    if (tolerance_ms < 1)
    {
        LOGF("JSON Error: SoftIpLimiter->settings->tolerance-ms (int field) must be >= 1");
        return false;
    }

    ts->simultaneous_user_limit = (uint8_t) simultaneous_user_limit;
    ts->tolerance_ms            = (uint64_t) tolerance_ms;
    getBoolFromJsonObjectOrDefault(&ts->verbose, settings, "verbose", false);
    return true;
}

tunnel_t *softiplimiterTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(softiplimiter_tstate_t), sizeof(softiplimiter_lstate_t));

    t->fnInitU    = &softiplimiterTunnelUpStreamInit;
    t->fnEstU     = &softiplimiterTunnelUpStreamEst;
    t->fnFinU     = &softiplimiterTunnelUpStreamFinish;
    t->fnPayloadU = &softiplimiterTunnelUpStreamPayload;
    t->fnPauseU   = &softiplimiterTunnelUpStreamPause;
    t->fnResumeU  = &softiplimiterTunnelUpStreamResume;

    t->fnInitD    = &softiplimiterTunnelDownStreamInit;
    t->fnEstD     = &softiplimiterTunnelDownStreamEst;
    t->fnFinD     = &softiplimiterTunnelDownStreamFinish;
    t->fnPayloadD = &softiplimiterTunnelDownStreamPayload;
    t->fnPauseD   = &softiplimiterTunnelDownStreamPause;
    t->fnResumeD  = &softiplimiterTunnelDownStreamResume;

    t->onDestroy = &softiplimiterTunnelDestroy;

    const cJSON *settings = node->node_settings_json;
    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: SoftIpLimiter->settings (object field) must be a non-empty object");
        tunnelDestroy(t);
        return NULL;
    }

    softiplimiter_tstate_t *ts = tunnelGetState(t);
    softiplimiterTunnelstateInitialize(ts);

    if (! softiplimiterParseSettings(ts, settings))
    {
        softiplimiterTunnelstateDestroy(ts);
        tunnelDestroy(t);
        return NULL;
    }

    return t;
}

