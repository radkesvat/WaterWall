#include "structure.h"

#include "loggers/network_logger.h"

static bool routerParsePortNumber(const cJSON *item, uint16_t *out, const char *json_path)
{
    if (! cJSON_IsNumber(item) || item->valueint < 0 || item->valueint > UINT16_MAX ||
        item->valuedouble != (double) item->valueint)
    {
        LOGF("JSON Error: %s : expected a port integer in range 0-65535", json_path);
        return false;
    }

    *out = (uint16_t) item->valueint;
    return true;
}

static bool routerParseSinglePortItem(const cJSON *item, router_port_range_t *out, const char *json_path)
{
    uint16_t port = 0;
    if (! routerParsePortNumber(item, &port, json_path))
    {
        return false;
    }

    out->low  = port;
    out->high = port;
    return true;
}

static bool routerExactPortsParse(const cJSON *value_json, router_port_range_t **out_ranges, uint32_t *out_count,
                                  const char *json_path)
{
    *out_ranges = NULL;
    *out_count  = 0;

    if (cJSON_IsNumber(value_json))
    {
        router_port_range_t *ranges = memoryAllocateZero(sizeof(*ranges));
        if (! routerParseSinglePortItem(value_json, &ranges[0], json_path))
        {
            memoryFree(ranges);
            return false;
        }

        *out_ranges = ranges;
        *out_count  = 1;
        return true;
    }

    if (! cJSON_IsArray(value_json))
    {
        LOGF("JSON Error: %s : expected a port integer or array of port integers", json_path);
        return false;
    }

    int n = cJSON_GetArraySize(value_json);
    if (n <= 0)
    {
        LOGF("JSON Error: %s (array field) : expected one or more port integers", json_path);
        return false;
    }

    router_port_range_t *ranges = memoryAllocateZero(sizeof(*ranges) * (size_t) n);
    uint32_t             index  = 0;
    const cJSON         *item   = NULL;
    cJSON_ArrayForEach(item, value_json)
    {
        if (! routerParseSinglePortItem(item, &ranges[index], json_path))
        {
            memoryFree(ranges);
            return false;
        }
        ++index;
    }

    *out_ranges = ranges;
    *out_count  = (uint32_t) n;
    return true;
}

static bool routerInclusivePortRangeParse(const cJSON *value_json, router_port_range_t **out_ranges,
                                          uint32_t *out_count, const char *json_path)
{
    *out_ranges = NULL;
    *out_count  = 0;

    if (! cJSON_IsArray(value_json))
    {
        LOGF("JSON Error: %s : expected an array with exactly two port integers", json_path);
        return false;
    }

    if (cJSON_GetArraySize(value_json) != 2)
    {
        LOGF("JSON Error: %s (array field) : expected exactly two port integers", json_path);
        return false;
    }

    uint16_t     low   = 0;
    uint16_t     high  = 0;
    const cJSON *first = cJSON_GetArrayItem(value_json, 0);
    const cJSON *last  = cJSON_GetArrayItem(value_json, 1);
    if (! routerParsePortNumber(first, &low, json_path) || ! routerParsePortNumber(last, &high, json_path))
    {
        return false;
    }

    if (low > high)
    {
        LOGF("JSON Error: %s : port range start is greater than end", json_path);
        return false;
    }

    router_port_range_t *ranges = memoryAllocateZero(sizeof(*ranges));
    ranges[0].low               = low;
    ranges[0].high              = high;

    *out_ranges = ranges;
    *out_count  = 1;
    return true;
}

bool routerPortRangesParse(const cJSON *ports_json, const cJSON *range_json, router_port_range_t **out_ranges,
                           uint32_t *out_count, const char *ports_json_path, const char *range_json_path)
{
    *out_ranges = NULL;
    *out_count  = 0;

    router_port_range_t *ports      = NULL;
    uint32_t             ports_count = 0;
    if (ports_json != NULL && ! routerExactPortsParse(ports_json, &ports, &ports_count, ports_json_path))
    {
        return false;
    }

    router_port_range_t *range      = NULL;
    uint32_t             range_count = 0;
    if (range_json != NULL && ! routerInclusivePortRangeParse(range_json, &range, &range_count, range_json_path))
    {
        if (ports != NULL)
        {
            memoryFree(ports);
        }
        return false;
    }

    uint32_t total_count = ports_count + range_count;
    if (total_count == 0)
    {
        return true;
    }

    if (ports_count == 0)
    {
        *out_ranges = range;
        *out_count  = range_count;
        return true;
    }

    if (range_count == 0)
    {
        *out_ranges = ports;
        *out_count  = ports_count;
        return true;
    }

    router_port_range_t *ranges = memoryAllocateZero(sizeof(*ranges) * (size_t) total_count);
    memoryCopy(ranges, ports, sizeof(*ranges) * (size_t) ports_count);
    memoryCopy(ranges + ports_count, range, sizeof(*ranges) * (size_t) range_count);

    memoryFree(ports);
    memoryFree(range);

    *out_ranges = ranges;
    *out_count  = total_count;
    return true;
}

bool routerPortRangesMatch(uint16_t port, const router_port_range_t *ranges, uint32_t count)
{
    for (uint32_t i = 0; i < count; ++i)
    {
        if (port >= ranges[i].low && port <= ranges[i].high)
        {
            return true;
        }
    }
    return false;
}
