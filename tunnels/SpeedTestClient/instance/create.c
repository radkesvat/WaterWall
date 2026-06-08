#include "structure.h"

#include "loggers/network_logger.h"

static bool speedtestclientStringEquals(const char *value, const char *a, const char *b, const char *c)
{
    return (value != NULL) &&
           ((a != NULL && stringCompare(value, a) == 0) || (b != NULL && stringCompare(value, b) == 0) ||
            (c != NULL && stringCompare(value, c) == 0));
}

static bool speedtestclientParseMode(speedtestclient_tstate_t *state, const cJSON *settings)
{
    char *mode = NULL;
    getStringFromJsonObjectOrDefault(&mode, settings, "mode", "tcp");

    if (speedtestclientStringEquals(mode, "tcp", "TCP", NULL))
    {
        state->mode = kSpeedTestClientModeTcp;
        memoryFree(mode);
        return true;
    }
    if (speedtestclientStringEquals(mode, "udp", "UDP", NULL))
    {
        state->mode = kSpeedTestClientModeUdp;
        memoryFree(mode);
        return true;
    }

    LOGF("JSON Error: SpeedTestClient->settings->mode (string field) : expected tcp or udp");
    memoryFree(mode);
    return false;
}

static bool speedtestclientParseDirection(speedtestclient_tstate_t *state, const cJSON *settings)
{
    char *direction = NULL;
    getStringFromJsonObjectOrDefault(&direction, settings, "direction", "upload");

    if (speedtestclientStringEquals(direction, "upload", "UPLOAD", "send"))
    {
        state->upload   = true;
        state->download = false;
        memoryFree(direction);
        return true;
    }
    if (speedtestclientStringEquals(direction, "download", "DOWNLOAD", "receive"))
    {
        state->upload   = false;
        state->download = true;
        memoryFree(direction);
        return true;
    }
    if (speedtestclientStringEquals(direction, "bidirectional", "both", "BOTH"))
    {
        state->upload   = true;
        state->download = true;
        memoryFree(direction);
        return true;
    }

    LOGF("JSON Error: SpeedTestClient->settings->direction (string field) : expected upload, download, or "
         "bidirectional");
    memoryFree(direction);
    return false;
}

static bool speedtestclientParsePositiveInt(const cJSON *settings, const char *key, int default_value, int *out,
                                            const char *json_path)
{
    int value = default_value;
    getIntFromJsonObjectOrDefault(&value, settings, key, default_value);
    if (value <= 0)
    {
        LOGF("JSON Error: %s (int field) : expected a positive value", json_path);
        return false;
    }
    *out = value;
    return true;
}

static bool speedtestclientParseNonNegativeInt(const cJSON *settings, const char *key, int default_value, int *out,
                                               const char *json_path)
{
    int value = default_value;
    getIntFromJsonObjectOrDefault(&value, settings, key, default_value);
    if (value < 0)
    {
        LOGF("JSON Error: %s (int field) : expected a non-negative value", json_path);
        return false;
    }
    *out = value;
    return true;
}

static bool speedtestclientLoadBandwidth(speedtestclient_tstate_t *state, const cJSON *settings)
{
    const cJSON *bits     = cJSON_GetObjectItemCaseSensitive(settings, "target-bits-per-sec");
    const cJSON *udp_bits = cJSON_GetObjectItemCaseSensitive(settings, "udp-target-bits-per-sec");
    const cJSON *mbits    = cJSON_GetObjectItemCaseSensitive(settings, "target-megabits-per-sec");
    int          selected = 0;
    double       value    = 0.0;

    if (bits != NULL)
    {
        if (! cJSON_IsNumber(bits) || bits->valuedouble < 0.0)
        {
            LOGF("JSON Error: SpeedTestClient->settings->target-bits-per-sec (number field) : expected a non-negative "
                 "value");
            return false;
        }
        value = bits->valuedouble;
        selected += 1;
    }

    if (udp_bits != NULL)
    {
        if (! cJSON_IsNumber(udp_bits) || udp_bits->valuedouble < 0.0)
        {
            LOGF("JSON Error: SpeedTestClient->settings->udp-target-bits-per-sec (number field) : expected a "
                 "non-negative value");
            return false;
        }
        value = udp_bits->valuedouble;
        selected += 1;
    }

    if (mbits != NULL)
    {
        if (! cJSON_IsNumber(mbits) || mbits->valuedouble < 0.0)
        {
            LOGF("JSON Error: SpeedTestClient->settings->target-megabits-per-sec (number field) : expected a "
                 "non-negative value");
            return false;
        }
        value = mbits->valuedouble * 1000.0 * 1000.0;
        selected += 1;
    }

    if (selected > 1)
    {
        LOGF("SpeedTestClient: configure only one target bandwidth field");
        return false;
    }

    if (selected == 0)
    {
        state->target_bandwidth_bps =
            (state->mode == kSpeedTestClientModeUdp) ? kSpeedTestClientDefaultUdpBandwidthBps : 0;
        return true;
    }

    if (value > (double) UINT64_MAX)
    {
        LOGF("SpeedTestClient: configured target bandwidth is too large");
        return false;
    }

    state->target_bandwidth_bps = (uint64_t) (value + 0.5);
    return true;
}

tunnel_t *speedtestclientTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(speedtestclient_tstate_t), sizeof(speedtestclient_lstate_t));

    if (t == NULL)
    {
        return NULL;
    }

    t->fnInitU    = &speedtestclientTunnelUpStreamInit;
    t->fnEstU     = &speedtestclientTunnelUpStreamEst;
    t->fnFinU     = &speedtestclientTunnelUpStreamFinish;
    t->fnPayloadU = &speedtestclientTunnelUpStreamPayload;
    t->fnPauseU   = &speedtestclientTunnelUpStreamPause;
    t->fnResumeU  = &speedtestclientTunnelUpStreamResume;

    t->fnInitD    = &speedtestclientTunnelDownStreamInit;
    t->fnEstD     = &speedtestclientTunnelDownStreamEst;
    t->fnFinD     = &speedtestclientTunnelDownStreamFinish;
    t->fnPayloadD = &speedtestclientTunnelDownStreamPayload;
    t->fnPauseD   = &speedtestclientTunnelDownStreamPause;
    t->fnResumeD  = &speedtestclientTunnelDownStreamResume;

    t->onPrepare = &speedtestclientTunnelOnPrepair;
    t->onStart   = &speedtestclientTunnelOnStart;
    t->onStop    = &speedtestclientTunnelOnStop;
    t->onDestroy = &speedtestclientTunnelDestroy;

    speedtestclient_tstate_t *state            = tunnelGetState(t);
    const cJSON              *settings         = node->node_settings_json;
    int                       duration_ms      = kSpeedTestClientDefaultDurationMs;
    int                       warmup_ms        = 0;
    int                       interval_ms      = kSpeedTestClientDefaultIntervalMs;
    int                       start_delay_ms   = kSpeedTestClientDefaultStartDelayMs;
    int                       timeout_ms       = 0;
    int                       payload_size     = 0;
    int                       connection_count = 1;

    mutexInit(&state->aggregate_mutex);
    getBoolFromJsonObjectOrDefault(&state->json_summary, settings, "json-summary", false);
    getBoolFromJsonObjectOrDefault(&state->terminate_on_complete, settings, "terminate-on-complete", true);

    if (! speedtestclientParseMode(state, settings) || ! speedtestclientParseDirection(state, settings) ||
        ! speedtestclientParsePositiveInt(
            settings, "duration-ms", duration_ms, &duration_ms, "SpeedTestClient->settings->duration-ms") ||
        ! speedtestclientParseNonNegativeInt(
            settings, "warmup-ms", warmup_ms, &warmup_ms, "SpeedTestClient->settings->warmup-ms") ||
        ! speedtestclientParsePositiveInt(settings,
                                          "report-interval-ms",
                                          interval_ms,
                                          &interval_ms,
                                          "SpeedTestClient->settings->report-interval-ms") ||
        ! speedtestclientParseNonNegativeInt(
            settings, "start-delay-ms", start_delay_ms, &start_delay_ms, "SpeedTestClient->settings->start-delay-ms") ||
        ! speedtestclientParsePositiveInt(settings,
                                          "connection-count",
                                          connection_count,
                                          &connection_count,
                                          "SpeedTestClient->settings->connection-count"))
    {
        speedtestclientTunnelDestroy(t);
        return NULL;
    }

    getIntFromJsonObjectOrDefault(&payload_size,
                                  settings,
                                  "payload-size",
                                  state->mode == kSpeedTestClientModeUdp ? kSpeedTestClientDefaultUdpPayloadSize
                                                                         : kSpeedTestClientDefaultTcpPayloadSize);

    if (payload_size <= 0 || payload_size > (int) kSpeedTestClientMaxPayloadSize)
    {
        LOGF("JSON Error: SpeedTestClient->settings->payload-size (int field) : expected a value between 1 and %u",
             (unsigned int) kSpeedTestClientMaxPayloadSize);
        speedtestclientTunnelDestroy(t);
        return NULL;
    }

    if (state->mode == kSpeedTestClientModeUdp && payload_size > (int) kSpeedTestClientMaxUdpPayloadSize)
    {
        LOGF("SpeedTestClient: UDP payload-size must be at most %u bytes",
             (unsigned int) kSpeedTestClientMaxUdpPayloadSize);
        speedtestclientTunnelDestroy(t);
        return NULL;
    }

    getIntFromJsonObjectOrDefault(&timeout_ms, settings, "timeout-ms", duration_ms + warmup_ms + 30000);
    if (timeout_ms <= duration_ms + warmup_ms)
    {
        LOGF("JSON Error: SpeedTestClient->settings->timeout-ms (int field) : expected a value greater than warmup-ms "
             "+ duration-ms");
        speedtestclientTunnelDestroy(t);
        return NULL;
    }

    state->duration_ms        = (uint32_t) duration_ms;
    state->warmup_ms          = (uint32_t) warmup_ms;
    state->report_interval_ms = (uint32_t) interval_ms;
    state->start_delay_ms     = (uint32_t) start_delay_ms;
    state->timeout_ms         = (uint32_t) timeout_ms;
    state->payload_size       = (uint32_t) payload_size;
    state->connection_count   = (uint32_t) connection_count;

    if (! speedtestclientLoadBandwidth(state, settings))
    {
        speedtestclientTunnelDestroy(t);
        return NULL;
    }

    atomicStoreRelaxed(&state->completed_streams, 0);
    atomicStoreRelaxed(&state->failed_streams, 0);

    return t;
}
