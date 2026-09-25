#include "loggers/network_logger.h"
#include "structure.h"

bool streamfragmenterLoadSettings(streamfragmenter_tstate_t *ts, const cJSON *settings)
{
    static const char *const keys[] = {"mode", "count", "duration-ms", "bypass_chance", "cuts", "wait-for-est"};
    if (! cJSON_IsObject(settings))
    {
        LOGF("JSON Error: StreamFragmenter->settings must be an object");
        return false;
    }
    unsigned     seen = 0;
    const cJSON *item;
    cJSON_ArrayForEach(item, settings)
    {
        size_t index = 0;
        while (index < ARRAY_SIZE(keys) && stringCompare(item->string, keys[index]) != 0)
            ++index;
        if (index == ARRAY_SIZE(keys) || (seen & (1U << index)))
        {
            LOGF("JSON Error: StreamFragmenter->settings has an unknown or duplicate key");
            return false;
        }
        seen |= 1U << index;
    }
    const cJSON *mode = cJSON_GetObjectItemCaseSensitive(settings, "mode");
    if (! cJSON_IsString(mode) ||
        (stringCompare(mode->valuestring, "counter") != 0 && stringCompare(mode->valuestring, "timed") != 0))
    {
        LOGF("JSON Error: StreamFragmenter->settings->mode must be counter or timed");
        return false;
    }
    ts->timed         = stringCompare(mode->valuestring, "timed") == 0;
    const char *scope = ts->timed ? "duration-ms" : "count";
    const char *other = ts->timed ? "count" : "duration-ms";
    int64_t     value;
    if (cJSON_GetObjectItemCaseSensitive(settings, other) != NULL ||
        ! jsonGetIntegerInRange(cJSON_GetObjectItemCaseSensitive(settings, scope), 0, UINT32_MAX, &value))
    {
        LOGF("JSON Error: StreamFragmenter requires %s as an integer in [0, 4294967295] and forbids %s", scope, other);
        return false;
    }
    ts->scope = (uint32_t) value;
    item      = cJSON_GetObjectItemCaseSensitive(settings, "wait-for-est");
    if (item != NULL && ! cJSON_IsBool(item))
    {
        LOGF("JSON Error: StreamFragmenter->settings->wait-for-est must be a boolean");
        return false;
    }
    ts->wait_for_est  = item == NULL || cJSON_IsTrue(item);
    ts->bypass_chance = 0;
    item              = cJSON_GetObjectItemCaseSensitive(settings, "bypass_chance");
    if (item != NULL)
    {
        if (! jsonGetIntegerInRange(item, 0, 100, &value))
        {
            LOGF("JSON Error: StreamFragmenter->settings->bypass_chance must be an integer in [0, 100]");
            return false;
        }
        ts->bypass_chance = (uint8_t) value;
    }
    const cJSON *cuts = cJSON_GetObjectItemCaseSensitive(settings, "cuts");
    if (! cJSON_IsArray(cuts) || cJSON_GetArraySize(cuts) > kStreamFragmenterMaxCuts)
    {
        LOGF("JSON Error: StreamFragmenter->settings->cuts must be an array with at most 64 entries");
        return false;
    }
    ts->cut_count     = 0;
    uint32_t previous = 0;
    cJSON_ArrayForEach(item, cuts)
    {
        int64_t offset, delay, chance;
        if (! cJSON_IsArray(item) || cJSON_GetArraySize(item) != 3 ||
            ! jsonGetIntegerInRange(cJSON_GetArrayItem(item, 0), 1, UINT32_MAX, &offset) ||
            ! jsonGetIntegerInRange(cJSON_GetArrayItem(item, 1), 0, UINT32_MAX, &delay) ||
            ! jsonGetIntegerInRange(cJSON_GetArrayItem(item, 2), 0, 100, &chance) || (uint32_t) offset <= previous)
        {
            LOGF("JSON Error: StreamFragmenter->settings->cuts[%u] must be [offset, delay_ms, chance_percent] with "
                 "strictly increasing positive uint32 offsets, uint32 delays, and integer chances in [0, 100]",
                 (unsigned) ts->cut_count);
            return false;
        }
        ts->cuts[ts->cut_count++] = (streamfragmenter_cut_t) {(uint32_t) offset, (uint32_t) delay, (uint8_t) chance};
        previous                  = (uint32_t) offset;
    }
    return true;
}
