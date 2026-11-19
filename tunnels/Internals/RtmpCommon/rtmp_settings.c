#include "rtmp_tunnel.h"

#include "loggers/network_logger.h"
#include "rtmp_session.h"

enum
{
    kRtmpDefaultBlockSize    = 16384,
    kRtmpDefaultSetupTimeout = 10000,
    kRtmpDefaultSendTimeout  = 30000,
    kRtmpMaximumTimeout      = INT32_MAX
};

bool rtmpReadString(const cJSON *settings, const char *key, const char *fallback, char *target, size_t capacity,
                    const char *role)
{
    const cJSON *item  = cJSON_GetObjectItemCaseSensitive(settings, key);
    const char  *value = item == NULL ? fallback : (cJSON_IsString(item) ? item->valuestring : NULL);
    if (value == NULL || value[0] == '\0' || strlen(value) >= capacity ||
        (item != NULL && ! jsonObjectFieldStringsAreExact(settings, key)))
    {
        LOGE("%s: %s must be a nonempty string of at most %zu bytes", role, key, capacity - 1);
        return false;
    }
    memoryCopy(target, value, strlen(value) + 1);
    return true;
}

static bool rtmpReadNumber(const cJSON *settings, const char *key, uint32_t fallback, uint32_t max, uint32_t *target,
                           const char *role)
{
    const cJSON *item  = cJSON_GetObjectItemCaseSensitive(settings, key);
    const double value = item == NULL ? (double) fallback : (cJSON_IsNumber(item) ? item->valuedouble : 0);
    if (! (value >= 1 && value <= max) || value != (uint32_t) value)
    {
        LOGE("%s: %s must be an integer between 1 and %u", role, key, max);
        return false;
    }
    *target = (uint32_t) value;
    return true;
}

bool rtmpValidateSettingsObject(const node_t *node)
{
    assert(node != NULL);
    const cJSON *settings = node->node_settings_json;
    if (settings != NULL && ! cJSON_IsObject(settings))
    {
        LOGE("%s: settings must be an object", node->type);
        return false;
    }
    return true;
}

bool rtmpReadCommonSettings(node_t *node, rtmp_settings_t *parsed)
{
    const cJSON *settings = node->node_settings_json;
    const char  *role     = node->type;
    return rtmpReadString(settings, "app", "waterwall", parsed->app, sizeof(parsed->app), role) &&
           rtmpReadString(settings, "stream", "tunnel", parsed->stream, sizeof(parsed->stream), role) &&
           rtmpReadNumber(settings,
                          "payload-block-size",
                          kRtmpDefaultBlockSize,
                          RTMP_SESSION_DATA_MAX,
                          &parsed->block_size,
                          role) &&
           rtmpReadNumber(settings,
                          "handshake-timeout-ms",
                          kRtmpDefaultSetupTimeout,
                          kRtmpMaximumTimeout,
                          &parsed->setup_timeout_ms,
                          role) &&
           rtmpReadNumber(settings,
                          "send-stall-timeout-ms",
                          kRtmpDefaultSendTimeout,
                          kRtmpMaximumTimeout,
                          &parsed->send_timeout_ms,
                          role);
}
