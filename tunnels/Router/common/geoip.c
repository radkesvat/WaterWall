#include "structure.h"

#include "loggers/network_logger.h"

static bool routerGeoipCodeParse(const char *pattern, router_geoip_code_t *out, const char *json_path)
{
    if (stringLength(pattern) != 8U || ! asciiIsAlpha((uint8_t) pattern[6]) ||
        ! asciiIsAlpha((uint8_t) pattern[7]))
    {
        LOGF("JSON Error: %s : \"%s\" is not a valid geoip:<ISO-3166-alpha-2> token", json_path, pattern);
        return false;
    }

    out->code[0] = (char) asciiUpper((uint8_t) pattern[6]);
    out->code[1] = (char) asciiUpper((uint8_t) pattern[7]);
    out->code[2] = '\0';
    return true;
}

bool routerGeoipCodesParse(const router_string_list_t *patterns, router_geoip_code_t **out_codes, uint32_t *out_count,
                           const char *json_path)
{
    *out_codes = NULL;
    *out_count = 0;

    if (patterns->count == 0)
    {
        return true;
    }

    router_geoip_code_t *codes = memoryAllocateZero(sizeof(*codes) * (size_t) patterns->count);
    uint32_t             count = 0;

    for (uint32_t i = 0; i < patterns->count; ++i)
    {
        const char *pattern = patterns->items[i];
        if (! stringStartsWithIgnoreCase(pattern, "geoip:"))
        {
            continue;
        }

        if (! routerGeoipCodeParse(pattern, &codes[count], json_path))
        {
            memoryFree(codes);
            return false;
        }
        ++count;
    }

    *out_codes = codes;
    *out_count = count;
    return true;
}

void routerGeoipCodesDestroy(router_geoip_code_t **codes, uint32_t *count)
{
    if (*codes != NULL)
    {
        memoryFree(*codes);
        *codes = NULL;
    }
    *count = 0;
}

bool routerRuleTableNeedsGeoip(const router_tstate_t *ts)
{
    for (uint32_t i = 0; i < ts->rules_count; ++i)
    {
        const router_rule_t *rule = &ts->rules[i];
        if (rule->source_ips.geoip_codes_count > 0 || rule->destination_ip.geoip_codes_count > 0)
        {
            return true;
        }
    }
    return false;
}

static bool routerGeoipContextToSockaddr(const address_context_t *ctx, sockaddr_u *addr)
{
    if (! addresscontextIsIpType(ctx))
    {
        return false;
    }

    *addr = (sockaddr_u) {0};
    if (ctx->ip_address.type == IPADDR_TYPE_V4)
    {
        addr->sin.sin_family      = AF_INET;
        addr->sin.sin_addr.s_addr = ctx->ip_address.u_addr.ip4.addr;
        return true;
    }

    if (ctx->ip_address.type == IPADDR_TYPE_V6)
    {
        addr->sin6.sin6_family = AF_INET6;
        memoryCopy(&addr->sin6.sin6_addr.s6_addr, &ctx->ip_address.u_addr.ip6, sizeof(addr->sin6.sin6_addr.s6_addr));
        return true;
    }

    return false;
}

static bool routerGeoipReadIsoCode(MMDB_entry_s *entry, const char *map_name, char out_code[3])
{
    MMDB_entry_data_s data   = {0};
    int               status = MMDB_get_value(entry, &data, map_name, "iso_code", NULL);

    if (status == MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR)
    {
        return false;
    }

    if (UNLIKELY(status != MMDB_SUCCESS))
    {
        LOGF("Router: MaxMind lookup failed at %s.iso_code: %s", map_name, MMDB_strerror(status));
        terminateProgram(1);
        return false;
    }

    if (! data.has_data)
    {
        return false;
    }

    if (UNLIKELY(data.type != MMDB_DATA_TYPE_UTF8_STRING || data.data_size != 2U))
    {
        LOGF("Router: MaxMind %s.iso_code is not a two-letter string", map_name);
        terminateProgram(1);
        return false;
    }

    out_code[0] = (char) asciiUpper((uint8_t) data.utf8_string[0]);
    out_code[1] = (char) asciiUpper((uint8_t) data.utf8_string[1]);
    out_code[2] = '\0';
    return true;
}

static bool routerGeoipLookupCountry(router_tstate_t *ts, const address_context_t *ctx, char out_code[3])
{
    if (UNLIKELY(ts == NULL || ! ts->geoip_db_opened))
    {
        LOGF("Router: GeoIP rule evaluated without an open MaxMind database");
        terminateProgram(1);
        return false;
    }

    sockaddr_u addr = {0};
    if (! routerGeoipContextToSockaddr(ctx, &addr))
    {
        return false;
    }

    int                  mmdb_error = MMDB_SUCCESS;
    MMDB_lookup_result_s result     = MMDB_lookup_sockaddr(&ts->geoip_db, &addr.sa, &mmdb_error);

    if (mmdb_error == MMDB_IPV6_LOOKUP_IN_IPV4_DATABASE_ERROR)
    {
        return false;
    }

    if (UNLIKELY(mmdb_error != MMDB_SUCCESS))
    {
        LOGF("Router: MaxMind IP lookup failed: %s", MMDB_strerror(mmdb_error));
        terminateProgram(1);
        return false;
    }

    if (! result.found_entry)
    {
        return false;
    }

    if (routerGeoipReadIsoCode(&result.entry, "country", out_code))
    {
        return true;
    }

    return routerGeoipReadIsoCode(&result.entry, "registered_country", out_code);
}

bool routerGeoipCodesMatch(router_tstate_t *ts, const address_context_t *ctx, const router_geoip_code_t *codes,
                           uint32_t count)
{
    if (count == 0)
    {
        return false;
    }

    char country_code[3] = {0};
    if (! routerGeoipLookupCountry(ts, ctx, country_code))
    {
        return false;
    }

    for (uint32_t i = 0; i < count; ++i)
    {
        if (codes[i].code[0] == country_code[0] && codes[i].code[1] == country_code[1])
        {
            return true;
        }
    }

    return false;
}

bool routerGeoipOpenIfNeeded(router_tstate_t *ts, const cJSON *settings)
{
    if (! routerRuleTableNeedsGeoip(ts))
    {
        return true;
    }

    if (settings == NULL)
    {
        LOGF("JSON Error: Router->settings->geoip-db-path (string field) : required when geoip rules are used");
        return false;
    }

    const cJSON *path_json = cJSON_GetObjectItemCaseSensitive(settings, "geoip-db-path");
    if (! cJSON_IsString(path_json) || path_json->valuestring == NULL || path_json->valuestring[0] == '\0')
    {
        LOGF("JSON Error: Router->settings->geoip-db-path (string field) : required when geoip rules are used");
        return false;
    }

    ts->geoip_db_path = stringDuplicate(path_json->valuestring);
    if (UNLIKELY(ts->geoip_db_path == NULL))
    {
        LOGF("Router: failed to allocate geoip-db-path");
        return false;
    }

    int status = MMDB_open(ts->geoip_db_path, MMDB_MODE_MMAP, &ts->geoip_db);
    if (UNLIKELY(status != MMDB_SUCCESS))
    {
        LOGF("Router: failed to open MaxMind DB \"%s\": %s", ts->geoip_db_path, MMDB_strerror(status));
        routerGeoipClose(ts);
        return false;
    }

    ts->geoip_db_opened = true;
    return true;
}

void routerGeoipClose(router_tstate_t *ts)
{
    if (ts->geoip_db_opened)
    {
        MMDB_close(&ts->geoip_db);
        ts->geoip_db_opened = false;
    }

    if (ts->geoip_db_path != NULL)
    {
        memoryFree(ts->geoip_db_path);
        ts->geoip_db_path = NULL;
    }
}
