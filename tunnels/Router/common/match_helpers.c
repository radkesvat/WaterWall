#include "structure.h"

#include "loggers/network_logger.h"

// ============================================================================
// IP / CIDR ranges (source-ips, destination-ip)
// ============================================================================

static bool routerHasPrefix(const char *s, const char *prefix)
{
    for (uint32_t i = 0; prefix[i] != '\0'; ++i)
    {
        if (asciiLower((uint8_t) s[i]) != (uint8_t) prefix[i])
        {
            return false;
        }
    }
    return true;
}

static bool routerHasChar(const char *s, char c)
{
    for (uint32_t i = 0; s[i] != '\0'; ++i)
    {
        if (s[i] == c)
        {
            return true;
        }
    }
    return false;
}

// Parse one "ip" or "ip/prefix" pattern into a numeric range. A bare IP becomes
// a host route (/32 or /128). geoip patterns are handled by the caller.
static bool routerParseIpEntry(const char *pattern, router_ip_range_t *out)
{
    if (routerHasChar(pattern, '/'))
    {
        int family = parseIPWithSubnetMask(pattern, &out->ip, &out->mask);
        if (family != 4 && family != 6)
        {
            return false;
        }
        out->family = (uint8_t) family;
        return true;
    }

    int type = parseIpAddress(pattern, &out->ip);
    if (type == IPADDR_TYPE_V4)
    {
        out->mask.type            = IPADDR_TYPE_V4;
        out->mask.u_addr.ip4.addr = 0xFFFFFFFFU; // /32 host route
        out->family               = 4;
        return true;
    }
    if (type == IPADDR_TYPE_V6)
    {
        out->mask.type = IPADDR_TYPE_V6;
        for (int i = 0; i < 4; ++i)
        {
            out->mask.u_addr.ip6.addr[i] = 0xFFFFFFFFU; // /128 host route
        }
        out->family = 6;
        return true;
    }

    return false;
}

bool routerIpRangesParse(const router_string_list_t *patterns, router_ip_range_t **out_ranges, uint32_t *out_count,
                         const char *json_path)
{
    *out_ranges = NULL;
    *out_count  = 0;

    if (patterns->count == 0)
    {
        return true;
    }

    // geoip entries are parsed by routerGeoipCodesParse(), so at most
    // patterns->count numeric ranges exist here.
    router_ip_range_t *ranges = memoryAllocateZero(sizeof(*ranges) * (size_t) patterns->count);
    uint32_t           count  = 0;

    for (uint32_t i = 0; i < patterns->count; ++i)
    {
        const char *pattern = patterns->items[i];

        if (routerHasPrefix(pattern, "geoip:"))
        {
            continue;
        }

        if (! routerParseIpEntry(pattern, &ranges[count]))
        {
            LOGF("JSON Error: %s : \"%s\" is not a valid IP or CIDR range", json_path, pattern);
            memoryFree(ranges);
            return false;
        }
        ++count;
    }

    *out_ranges = ranges;
    *out_count  = count;
    return true;
}

bool routerIpRangesMatch(const address_context_t *ctx, const router_ip_range_t *ranges, uint32_t count)
{
    // Only IP-typed endpoints can match an IP rule; a domain destination has no
    // IP to compare against here.
    if (! addresscontextIsIpType(ctx))
    {
        return false;
    }

    const ip_addr_t *test = &ctx->ip_address;

    for (uint32_t i = 0; i < count; ++i)
    {
        const router_ip_range_t *range = &ranges[i];

        if (range->family == 4 && test->type == IPADDR_TYPE_V4)
        {
            if (checkIPRange4(test->u_addr.ip4, range->ip.u_addr.ip4, range->mask.u_addr.ip4))
            {
                return true;
            }
        }
        else if (range->family == 6 && test->type == IPADDR_TYPE_V6)
        {
            if (checkIPRange6(test->u_addr.ip6, range->ip.u_addr.ip6, range->mask.u_addr.ip6))
            {
                return true;
            }
        }
    }

    return false;
}

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
        if (! routerHasPrefix(pattern, "geoip:"))
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

bool routerRuleTableNeedsGeosite(const router_tstate_t *ts)
{
    for (uint32_t i = 0; i < ts->rules_count; ++i)
    {
        const router_rule_t *rule = &ts->rules[i];
        if (! rule->destination_domain.present)
        {
            continue;
        }

        for (uint32_t j = 0; j < rule->destination_domain.patterns.count; ++j)
        {
            if (routerHasPrefix(rule->destination_domain.patterns.items[j], "geosite:"))
            {
                return true;
            }
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

// ============================================================================
// Port lists and inclusive ranges
// ============================================================================

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
    if (ports_json != NULL &&
        ! routerExactPortsParse(ports_json, &ports, &ports_count, ports_json_path))
    {
        return false;
    }

    router_port_range_t *range      = NULL;
    uint32_t             range_count = 0;
    if (range_json != NULL &&
        ! routerInclusivePortRangeParse(range_json, &range, &range_count, range_json_path))
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

// ============================================================================
// Network tokens (network)
// ============================================================================

static bool routerTokenEquals(const char *p, uint32_t len, const char *word)
{
    for (uint32_t i = 0; i < len; ++i)
    {
        if (word[i] == '\0' || asciiLower((uint8_t) p[i]) != (uint8_t) word[i])
        {
            return false;
        }
    }
    return word[len] == '\0';
}

static bool routerNetworkTokenMask(const char *p, uint32_t len, uint8_t *mask, const char *json_path)
{
    // trim spaces
    while (len > 0 && (p[0] == ' ' || p[0] == '\t'))
    {
        ++p;
        --len;
    }
    while (len > 0 && (p[len - 1U] == ' ' || p[len - 1U] == '\t'))
    {
        --len;
    }

    if (len == 0)
    {
        return true; // empty token between commas is ignored
    }

    if (routerTokenEquals(p, len, "tcp"))
    {
        *mask |= kRouterNetworkTcp;
        return true;
    }
    if (routerTokenEquals(p, len, "udp"))
    {
        *mask |= kRouterNetworkUdp;
        return true;
    }
    if (routerTokenEquals(p, len, "icmp"))
    {
        *mask |= kRouterNetworkIcmp;
        return true;
    }
    if (routerTokenEquals(p, len, "packet"))
    {
        *mask |= kRouterNetworkPacket;
        return true;
    }

    LOGF("JSON Error: %s : unsupported network type (expected tcp, udp, icmp or packet)", json_path);
    return false;
}

bool routerNetworkMaskParse(const router_string_list_t *values, uint8_t *out_mask, const char *json_path)
{
    uint8_t mask = 0;

    for (uint32_t i = 0; i < values->count; ++i)
    {
        const char *value = values->items[i];
        uint32_t    len   = (uint32_t) stringLength(value);

        // Each value may itself be a comma-combined list such as "tcp,udp".
        uint32_t start = 0;
        for (uint32_t j = 0; j <= len; ++j)
        {
            if (j == len || value[j] == ',')
            {
                if (! routerNetworkTokenMask(value + start, j - start, &mask, json_path))
                {
                    return false;
                }
                start = j + 1U;
            }
        }
    }

    if (mask == 0)
    {
        LOGF("JSON Error: %s : no valid network type configured", json_path);
        return false;
    }

    *out_mask = mask;
    return true;
}

// ============================================================================
// Domain matching (destination-domain)
// ============================================================================

static bool routerHostEndsWith(const uint8_t *host, uint32_t host_len, const char *suffix, uint32_t suffix_len)
{
    if (host_len < suffix_len)
    {
        return false;
    }

    uint32_t offset = host_len - suffix_len;
    for (uint32_t i = 0; i < suffix_len; ++i)
    {
        if (asciiLower(host[offset + i]) != (uint8_t) asciiLower((uint8_t) suffix[i]))
        {
            return false;
        }
    }

    return true;
}

static bool routerHostEquals(const uint8_t *host, uint32_t host_len, const char *domain, uint32_t domain_len)
{
    if (host_len != domain_len)
    {
        return false;
    }

    for (uint32_t i = 0; i < domain_len; ++i)
    {
        if (asciiLower(host[i]) != (uint8_t) asciiLower((uint8_t) domain[i]))
        {
            return false;
        }
    }

    return true;
}

bool routerDomainMatches(const char *pattern, const uint8_t *host, uint32_t host_len)
{
    // Geosite tokens are resolved into compiled list handles during Router creation.
    if (routerHasPrefix(pattern, "geosite:"))
    {
        return false;
    }

    uint32_t pattern_len = (uint32_t) stringLength(pattern);

    if (pattern_len == 1U && pattern[0] == '*')
    {
        return host_len > 0;
    }

    if (pattern_len > 2U && pattern[0] == '*' && pattern[1] == '.')
    {
        // "*.example.com" matches subdomains but not "example.com" itself.
        const char *suffix     = pattern + 1; // ".example.com"
        uint32_t    suffix_len = pattern_len - 1U;

        return host_len > suffix_len && routerHostEndsWith(host, host_len, suffix, suffix_len);
    }

    return routerHostEquals(host, host_len, pattern, pattern_len);
}
