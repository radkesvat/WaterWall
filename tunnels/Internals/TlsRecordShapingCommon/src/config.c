#include "TlsRecordShapingCommon/record_shaping.h"

static bool keyIsOneOf(const char *key, const char *const *allowed, size_t allowed_count)
{
    for (size_t i = 0; i < allowed_count; ++i)
    {
        if (stringCompare(key, allowed[i]) == 0)
        {
            return true;
        }
    }
    return false;
}

static bool rejectUnknownKeys(const cJSON *object, const char *path, const char *const *allowed, size_t allowed_count,
                              char error[kTlsRecordShapingErrorSize])
{
    const cJSON *item = NULL;
    cJSON_ArrayForEach(item, object)
    {
        if (item->string == NULL || ! keyIsOneOf(item->string, allowed, allowed_count))
        {
            return tlsrecordshapingSetError(
                error, "%s contains unknown key \"%s\"", path, item->string != NULL ? item->string : "<null>");
        }
    }
    return true;
}

static bool parseRange(const cJSON *item, uint32_t minimum, uint32_t maximum, const char *path,
                       tlsrecordshaping_range_t *range, char error[kTlsRecordShapingErrorSize])
{
    int64_t value = 0;
    if (jsonGetIntegerInRange(item, minimum, maximum, &value))
    {
        range->minimum = (uint32_t) value;
        range->maximum = (uint32_t) value;
        return true;
    }

    if (! cJSON_IsArray(item) || cJSON_GetArraySize(item) != 2)
    {
        return tlsrecordshapingSetError(error,
                                        "%s must be an integer or a two-integer range [%u, %u]",
                                        path,
                                        (unsigned int) minimum,
                                        (unsigned int) maximum);
    }

    int64_t lower = 0;
    int64_t upper = 0;
    if (! jsonGetIntegerInRange(cJSON_GetArrayItem(item, 0), minimum, maximum, &lower) ||
        ! jsonGetIntegerInRange(cJSON_GetArrayItem(item, 1), minimum, maximum, &upper))
    {
        return tlsrecordshapingSetError(
            error, "%s values must be integers in [%u, %u]", path, (unsigned int) minimum, (unsigned int) maximum);
    }
    if (lower > upper)
    {
        return tlsrecordshapingSetError(error, "%s minimum must not exceed its maximum", path);
    }

    range->minimum = (uint32_t) lower;
    range->maximum = (uint32_t) upper;
    return true;
}

static bool parseDelay(const cJSON *delay, int outcome_index, tlsrecordshaping_outcome_t *outcome,
                       char error[kTlsRecordShapingErrorSize])
{
    static const char *const allowed[] = {"probability", "ms"};
    char                     path[96];
    snprintf(path, sizeof(path), "tls13-record-shaping.outcomes[%d].delay", outcome_index);

    if (! cJSON_IsObject(delay) || ! rejectUnknownKeys(delay, path, allowed, ARRAY_SIZE(allowed), error))
    {
        return cJSON_IsObject(delay) ? false : tlsrecordshapingSetError(error, "%s must be an object", path);
    }

    int64_t probability = 0;
    if (! jsonGetIntegerInRange(cJSON_GetObjectItemCaseSensitive(delay, "probability"), 0, 100, &probability))
    {
        return tlsrecordshapingSetError(error, "%s.probability must be an integer in [0, 100]", path);
    }
    if (! parseRange(cJSON_GetObjectItemCaseSensitive(delay, "ms"),
                     0,
                     kTlsRecordShapingMaxDelayMs,
                     "tls13-record-shaping outcome delay.ms",
                     &outcome->delay_ms,
                     error))
    {
        return false;
    }

    outcome->has_delay         = true;
    outcome->delay_probability = (uint8_t) probability;
    return true;
}

static bool parseOutcome(const cJSON *item, int index, tlsrecordshaping_outcome_t *outcome,
                         char error[kTlsRecordShapingErrorSize])
{
    static const char *const allowed[] = {"probability", "padding-bytes", "delay"};
    char                     path[80];
    snprintf(path, sizeof(path), "tls13-record-shaping.outcomes[%d]", index);

    if (! cJSON_IsObject(item) || ! rejectUnknownKeys(item, path, allowed, ARRAY_SIZE(allowed), error))
    {
        return cJSON_IsObject(item) ? false : tlsrecordshapingSetError(error, "%s must be an object", path);
    }

    int64_t probability = 0;
    if (! jsonGetIntegerInRange(cJSON_GetObjectItemCaseSensitive(item, "probability"), 1, 100, &probability))
    {
        return tlsrecordshapingSetError(error, "%s.probability must be an integer in [1, 100]", path);
    }
    outcome->probability = (uint8_t) probability;

    const cJSON *padding = cJSON_GetObjectItemCaseSensitive(item, "padding-bytes");
    if (padding != NULL)
    {
        if (! parseRange(padding,
                         1,
                         kTlsRecordShapingMaxPaddingBytes,
                         "tls13-record-shaping outcome padding-bytes",
                         &outcome->padding_bytes,
                         error))
        {
            return false;
        }
        outcome->has_padding = true;
    }

    const cJSON *delay = cJSON_GetObjectItemCaseSensitive(item, "delay");
    if (delay != NULL && ! parseDelay(delay, index, outcome, error))
    {
        return false;
    }

    bool effective_delay = outcome->has_delay && outcome->delay_probability > 0 && outcome->delay_ms.maximum > 0;
    if (! outcome->has_padding && ! effective_delay)
    {
        return tlsrecordshapingSetError(error, "%s has no effective padding or delay action", path);
    }
    return true;
}

static bool parseCustom(const cJSON *shaping, tlsrecordshaping_config_t *config, char error[kTlsRecordShapingErrorSize])
{
    const cJSON *scope    = cJSON_GetObjectItemCaseSensitive(shaping, "scope");
    const cJSON *outcomes = cJSON_GetObjectItemCaseSensitive(shaping, "outcomes");
    if (scope == NULL || outcomes == NULL)
    {
        return tlsrecordshapingSetError(error, "custom tls13-record-shaping requires both scope and outcomes");
    }

    static const char *const scope_allowed[] = {"first-application-records"};
    if (! cJSON_IsObject(scope) ||
        ! rejectUnknownKeys(scope, "tls13-record-shaping.scope", scope_allowed, ARRAY_SIZE(scope_allowed), error))
    {
        return cJSON_IsObject(scope) ? false
                                     : tlsrecordshapingSetError(error, "tls13-record-shaping.scope must be an object");
    }

    int64_t first_records = 0;
    if (! jsonGetIntegerInRange(cJSON_GetObjectItemCaseSensitive(scope, "first-application-records"),
                                1,
                                kTlsRecordShapingMaxApplicationRecords,
                                &first_records))
    {
        return tlsrecordshapingSetError(
            error, "tls13-record-shaping.scope.first-application-records must be an integer in [1, 1024]");
    }
    config->first_application_records = (uint16_t) first_records;

    if (! cJSON_IsArray(outcomes))
    {
        return tlsrecordshapingSetError(
            error, "tls13-record-shaping.outcomes must be a non-empty array with at most 16 items");
    }
    int count = cJSON_GetArraySize(outcomes);
    if (count < 1 || count > kTlsRecordShapingMaxOutcomes)
    {
        return tlsrecordshapingSetError(error, "tls13-record-shaping.outcomes must contain between 1 and 16 items");
    }

    unsigned int probability_sum = 0;
    for (int i = 0; i < count; ++i)
    {
        if (! parseOutcome(cJSON_GetArrayItem(outcomes, i), i, &config->outcomes[i], error))
        {
            return false;
        }
        probability_sum += config->outcomes[i].probability;
        if (probability_sum > 100)
        {
            return tlsrecordshapingSetError(error, "tls13-record-shaping outcome probabilities sum to more than 100");
        }
    }

    config->enabled       = true;
    config->outcome_count = (uint8_t) count;
    return true;
}

bool tlsrecordshapingParse(const cJSON *settings, tlsrecordshaping_sender_role_t sender_role,
                           tlsrecordshaping_config_t *config, char error[kTlsRecordShapingErrorSize])
{
    if (config == NULL)
    {
        return tlsrecordshapingSetError(error, "tls13-record-shaping parser received a null configuration destination");
    }
    memoryZero(config, sizeof(*config));
    config->sender_role = sender_role;
    if (error != NULL)
    {
        error[0] = '\0';
    }

    const cJSON *shaping = cJSON_GetObjectItemCaseSensitive(settings, "tls13-record-shaping");
    if (shaping == NULL)
    {
        return true;
    }
    if (! cJSON_IsObject(shaping))
    {
        return tlsrecordshapingSetError(error, "tls13-record-shaping must be an object");
    }

    static const char *const allowed[] = {"scope", "outcomes"};
    if (! rejectUnknownKeys(shaping, "tls13-record-shaping", allowed, ARRAY_SIZE(allowed), error))
    {
        return false;
    }

    return parseCustom(shaping, config, error);
}

const char *tlsrecordshapingConfigModeName(const tlsrecordshaping_config_t *config)
{
    if (config == NULL || ! config->enabled)
    {
        return "disabled";
    }
    return "custom";
}

bool tlsrecordshapingConfigCanDelay(const tlsrecordshaping_config_t *config)
{
    if (config == NULL || ! config->enabled)
    {
        return false;
    }
    for (uint8_t i = 0; i < config->outcome_count; ++i)
    {
        const tlsrecordshaping_outcome_t *outcome = &config->outcomes[i];
        if (outcome->has_delay && outcome->delay_probability > 0 && outcome->delay_ms.maximum > 0)
        {
            return true;
        }
    }
    return false;
}
