#include "structure.h"

#include "loggers/network_logger.h"

static bool speedlimitMulOverflowU64(uint64_t a, uint64_t b)
{
    return b != 0 && a > (UINT64_MAX / b);
}

static bool parsePositiveRateField(const cJSON *settings, const char *key, uint64_t multiplier, uint64_t *out_rate,
                                   int *selected_fields)
{
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(settings, key);
    if (value == NULL)
    {
        return true;
    }

    if (! cJSON_IsNumber(value))
    {
        LOGF("SpeedLimit: settings.%s must be a number", key);
        return false;
    }

    if (value->valuedouble <= 0.0)
    {
        LOGF("SpeedLimit: settings.%s must be greater than 0", key);
        return false;
    }

    double scaled = value->valuedouble * (double) multiplier;
    if (scaled > (double) UINT64_MAX)
    {
        LOGF("SpeedLimit: settings.%s is too large", key);
        return false;
    }

    *out_rate = (uint64_t) (scaled + 0.5);
    if (*out_rate == 0)
    {
        LOGF("SpeedLimit: settings.%s rounded down to 0 bytes per second", key);
        return false;
    }

    *selected_fields += 1;
    return true;
}

static bool parseRateSettings(speedlimit_tstate_t *state, const cJSON *settings)
{
    int      selected_fields = 0;
    uint64_t bytes_per_sec   = 0;

    if (! parsePositiveRateField(settings, "bytes-per-sec", 1, &bytes_per_sec, &selected_fields) ||
        ! parsePositiveRateField(settings, "kilo-bytes-per-sec", 1024, &bytes_per_sec, &selected_fields) ||
        ! parsePositiveRateField(settings, "mega-bytes-per-sec", 1024ULL * 1024ULL, &bytes_per_sec, &selected_fields))
    {
        return false;
    }

    if (selected_fields == 0)
    {
        LOGF("SpeedLimit: configure exactly one of settings.bytes-per-sec, settings.kilo-bytes-per-sec, or "
             "settings.mega-bytes-per-sec");
        return false;
    }

    if (selected_fields > 1)
    {
        LOGF("SpeedLimit: only one rate field may be set at a time");
        return false;
    }

    state->bytes_per_sec = bytes_per_sec;
    return true;
}

static bool parseLimitMode(speedlimit_tstate_t *state, const cJSON *settings)
{
    const cJSON *mode = cJSON_GetObjectItemCaseSensitive(settings, "limit-mode");

    if (! (cJSON_IsString(mode) && mode->valuestring != NULL))
    {
        LOGF("SpeedLimit: settings.limit-mode is required");
        return false;
    }

    if (stringCompare(mode->valuestring, "per-connection") == 0 || stringCompare(mode->valuestring, "per-line") == 0)
    {
        state->limit_mode = kSpeedLimitLimitModePerLine;
        return true;
    }

    if (stringCompare(mode->valuestring, "all-connections") == 0 || stringCompare(mode->valuestring, "all-lines") == 0)
    {
        state->limit_mode = kSpeedLimitLimitModeAllLines;
        return true;
    }

    if (stringCompare(mode->valuestring, "per-worker") == 0)
    {
        state->limit_mode = kSpeedLimitLimitModePerWorker;
        return true;
    }

    LOGF("SpeedLimit: settings.limit-mode must be one of per-connection, per-line, all-connections, all-lines, or "
         "per-worker");
    return false;
}

static bool parseWorkMode(speedlimit_tstate_t *state, const cJSON *settings)
{
    const cJSON *mode = cJSON_GetObjectItemCaseSensitive(settings, "work-mode");

    if (! (cJSON_IsString(mode) && mode->valuestring != NULL))
    {
        LOGF("SpeedLimit: settings.work-mode is required");
        return false;
    }

    if (stringCompare(mode->valuestring, "drop") == 0)
    {
        state->work_mode = kSpeedLimitWorkModeDrop;
        return true;
    }

    if (stringCompare(mode->valuestring, "pause") == 0)
    {
        state->work_mode = kSpeedLimitWorkModePause;
        return true;
    }

    LOGF("SpeedLimit: settings.work-mode must be either drop or pause");
    return false;
}

static bool parseRechargeInterval(speedlimit_tstate_t *state, const cJSON *settings)
{
    int recharge_interval_ms = 0;
    getIntFromJsonObjectOrDefault(&recharge_interval_ms, settings, "token-recharge-rate", kSpeedLimitDefaultTickMs);

    if (recharge_interval_ms <= 0)
    {
        LOGF("SpeedLimit: settings.token-recharge-rate must be greater than 0 milliseconds");
        return false;
    }

    state->recharge_interval_ms = (uint32_t) recharge_interval_ms;
    return true;
}

static bool finalizeRateMath(speedlimit_tstate_t *state, int workers_count)
{
    if (speedlimitMulOverflowU64(state->bytes_per_sec, kSpeedLimitUnitsPerByte))
    {
        LOGF("SpeedLimit: configured rate is too large");
        return false;
    }

    if (speedlimitMulOverflowU64(state->bytes_per_sec, state->recharge_interval_ms))
    {
        LOGF("SpeedLimit: configured rate and token-recharge-rate combination is too large");
        return false;
    }

    state->bucket_capacity_units = state->bytes_per_sec * kSpeedLimitUnitsPerByte;
    state->refill_units_per_step = state->bytes_per_sec * state->recharge_interval_ms;

    atomicStoreRelaxed(&state->global_bucket.tokens_units, state->bucket_capacity_units);
    atomicStoreRelaxed(&state->global_bucket.last_refill_ms, 0);

    for (int wi = 0; wi < workers_count; ++wi)
    {
        state->worker_buckets[wi].tokens_units   = state->bucket_capacity_units;
        state->worker_buckets[wi].last_refill_ms = 0;
    }

    return true;
}

tunnel_t *speedlimitTunnelCreate(node_t *node)
{
    const int workers_count = getWorkersCount();

    tunnel_t *t = tunnelCreate(node,
                               sizeof(speedlimit_tstate_t) + ((uint32_t) workers_count * sizeof(speedlimit_bucket_t)),
                               sizeof(speedlimit_lstate_t));

    t->fnInitU    = &speedlimitTunnelUpStreamInit;
    t->fnEstU     = &speedlimitTunnelUpStreamEst;
    t->fnFinU     = &speedlimitTunnelUpStreamFinish;
    t->fnPayloadU = &speedlimitTunnelUpStreamPayload;
    t->fnPauseU   = &speedlimitTunnelUpStreamPause;
    t->fnResumeU  = &speedlimitTunnelUpStreamResume;

    t->fnInitD    = &speedlimitTunnelDownStreamInit;
    t->fnEstD     = &speedlimitTunnelDownStreamEst;
    t->fnFinD     = &speedlimitTunnelDownStreamFinish;
    t->fnPayloadD = &speedlimitTunnelDownStreamPayload;
    t->fnPauseD   = &speedlimitTunnelDownStreamPause;
    t->fnResumeD  = &speedlimitTunnelDownStreamResume;

    t->onPrepare = &speedlimitTunnelOnPrepair;
    t->onStart   = &speedlimitTunnelOnStart;
    t->onStop    = &speedlimitTunnelOnStop;
    t->onDestroy = &speedlimitTunnelDestroy;

    const cJSON         *settings = node->node_settings_json;
    speedlimit_tstate_t *state    = tunnelGetState(t);

    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("SpeedLimit: settings must be a non-empty object");
        tunnelDestroy(t);
        return NULL;
    }

    if (! parseRateSettings(state, settings) || ! parseLimitMode(state, settings) || ! parseWorkMode(state, settings) ||
        ! parseRechargeInterval(state, settings) || ! finalizeRateMath(state, workers_count))
    {
        tunnelDestroy(t);
        return NULL;
    }

    return t;
}
