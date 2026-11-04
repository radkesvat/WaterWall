#include "DnsLineClient/internal.h"

#include "loggers/network_logger.h"

static void dnslineclientConfigSetDefaults(dnslineclient_config_t *cfg)
{
    memoryZero(cfg, sizeof(*cfg));
    cfg->timeout_ms       = kDnsLineClientDefaultTimeoutMs;
    cfg->tries            = kDnsLineClientDefaultTries;
    cfg->cache_size       = kDnsLineClientDefaultCacheSize;
    cfg->min_ttl          = kDnsLineClientDefaultMinTtl;
    cfg->max_ttl          = kDnsLineClientDefaultMaxTtl;
    cfg->fallback_to_core = false;
}

static bool dnslineclientParseU32(const cJSON *object, const char *json_path, const char *key, uint32_t minimum,
                                  uint32_t maximum, uint32_t *dest)
{
    int64_t value = 0;
    switch (jsonGetObjectIntegerInRange(object, key, minimum, maximum, &value))
    {
    case kJsonValueMissing:
        return true;
    case kJsonValuePresent:
        *dest = (uint32_t) value;
        return true;
    case kJsonValueInvalid:
    default:
        LOGF("JSON Error: %s->%s must be an integer between %u and %u",
             json_path,
             key,
             (unsigned) minimum,
             (unsigned) maximum);
        return false;
    }
}

static bool dnslineclientParsePort(const char *text, uint16_t *port)
{
    if (text[0] == '\0' || stringLength(text) > 5)
    {
        return false;
    }
    uint32_t value = 0;
    for (const char *p = text; *p != '\0'; ++p)
    {
        if (*p < '0' || *p > '9')
        {
            return false;
        }
        value = value * 10U + (uint32_t) (*p - '0');
    }
    if (value == 0 || value > 65535U)
    {
        return false;
    }
    *port = (uint16_t) value;
    return true;
}

/* "1.1.1.1", "1.1.1.1:5353", "2001:db8::1", "[2001:db8::1]", "[2001:db8::1]:5353". Literals only. */
static bool dnslineclientParseServer(const char *text, dnslineclient_server_t *server)
{
    char        host[INET6_ADDRSTRLEN + 1];
    const char *port_text = NULL;
    size_t      len       = stringLength(text);
    int         family    = AF_INET;

    server->port = kDnsLineClientDefaultPort;

    if (text[0] == '[')
    {
        const char *close = strchr(text, ']');
        if (close == NULL || close == text + 1 || (size_t) (close - text - 1) >= sizeof(host))
        {
            return false;
        }
        memoryCopy(host, text + 1, (size_t) (close - text - 1));
        host[close - text - 1] = '\0';
        if (close[1] == ':')
        {
            port_text = close + 2;
        }
        else if (close[1] != '\0')
        {
            return false;
        }
        family = AF_INET6;
    }
    else
    {
        const char *first_colon = strchr(text, ':');
        const char *last_colon  = strrchr(text, ':');
        if (len >= sizeof(host))
        {
            return false;
        }
        if (first_colon != NULL && first_colon == last_colon)
        {
            // IPv4 with a port.
            memoryCopy(host, text, (size_t) (first_colon - text));
            host[first_colon - text] = '\0';
            port_text                = first_colon + 1;
        }
        else
        {
            memoryCopy(host, text, len + 1);
            family = first_colon != NULL ? AF_INET6 : AF_INET;
        }
    }

    if (port_text != NULL && ! dnslineclientParsePort(port_text, &server->port))
    {
        return false;
    }

    // inet_pton is strict (no shorthand IPv4, no zone ids); lwIP then fills ip_addr_t from the same text.
    struct in6_addr probe;
    if (inet_pton(family, host, &probe) != 1)
    {
        return false;
    }
    if (! ipaddr_aton(host, &server->ip))
    {
        return false;
    }
    return (family == AF_INET) ? IP_IS_V4(&server->ip) : IP_IS_V6(&server->ip);
}

static bool dnslineclientParseServers(const cJSON *object, const char *json_path, dnslineclient_config_t *cfg)
{
    const cJSON *servers = cJSON_GetObjectItemCaseSensitive(object, "servers");
    if (servers == NULL)
    {
        return true;
    }

    if (! cJSON_IsArray(servers))
    {
        LOGF("JSON Error: %s->servers must be an array of IP address strings", json_path);
        return false;
    }

    int count = cJSON_GetArraySize(servers);
    if (count < 1 || count > kDnsLineClientMaxServers)
    {
        LOGF("JSON Error: %s->servers must contain between 1 and %d entries", json_path, kDnsLineClientMaxServers);
        return false;
    }

    int          index = 0;
    const cJSON *item  = NULL;
    cJSON_ArrayForEach(item, servers)
    {
        if (! cJSON_IsString(item) || item->valuestring == NULL || item->valuestring[0] == '\0')
        {
            LOGF("JSON Error: %s->servers[%d] must be a non-empty string", json_path, index);
            return false;
        }
        if (! dnslineclientParseServer(item->valuestring, &cfg->servers[index]))
        {
            LOGF("JSON Error: %s->servers[%d] (\"%s\") must be an IPv4 or IPv6 literal with an optional :port "
                 "(IPv6 as \"[addr]:port\"); domain names are not allowed",
                 json_path,
                 index,
                 item->valuestring);
            return false;
        }
        ++index;
    }
    cfg->servers_count = (uint32_t) index;
    return true;
}

static const char *const kDnsLineClientConfigKeys[] = {
    "mode", "servers", "timeout-ms", "tries", "cache-size", "min-ttl", "max-ttl", "fallback-to-core",
};

bool dnslineclientConfigIsKnownKey(const char *key)
{
    if (key == NULL)
    {
        return false;
    }
    for (size_t i = 0; i < sizeof(kDnsLineClientConfigKeys) / sizeof(kDnsLineClientConfigKeys[0]); ++i)
    {
        if (stringCompare(key, kDnsLineClientConfigKeys[i]) == 0)
        {
            return true;
        }
    }
    return false;
}

bool dnslineclientConfigParse(const cJSON *object, const char *json_path, dnslineclient_mode_e *out_mode,
                              dnslineclient_config_t *out_cfg)
{
    dnslineclient_config_t cfg;
    dnslineclient_mode_e   mode = kDnsLineClientModeCore;

    dnslineclientConfigSetDefaults(&cfg);
    if (json_path == NULL)
    {
        json_path = "settings";
    }

    if (object != NULL)
    {
        if (! cJSON_IsObject(object))
        {
            LOGF("JSON Error: %s must be an object when provided", json_path);
            return false;
        }

        const char *mode_text = NULL;
        switch (jsonGetObjectNonEmptyString(object, "mode", &mode_text))
        {
        case kJsonValueMissing:
            break;
        case kJsonValuePresent:
            if (stringCompare(mode_text, "core") == 0)
            {
                mode = kDnsLineClientModeCore;
                break;
            }
            if (stringCompare(mode_text, "chain") == 0)
            {
                mode = kDnsLineClientModeChain;
                break;
            }
            /* fallthrough */
        case kJsonValueInvalid:
        default:
            LOGF("JSON Error: %s->mode must be \"core\" or \"chain\"", json_path);
            return false;
        }

        if (! dnslineclientParseServers(object, json_path, &cfg) ||
            ! dnslineclientParseU32(object,
                                    json_path,
                                    "timeout-ms",
                                    kDnsLineClientMinTimeoutMs,
                                    kDnsLineClientMaxTimeoutMs,
                                    &cfg.timeout_ms) ||
            ! dnslineclientParseU32(object, json_path, "tries", 1, kDnsLineClientMaxTries, &cfg.tries) ||
            ! dnslineclientParseU32(object, json_path, "cache-size", 0, kDnsLineClientMaxCacheSize, &cfg.cache_size) ||
            ! dnslineclientParseU32(object, json_path, "min-ttl", 0, kDnsLineClientMaxTtlLimit, &cfg.min_ttl) ||
            ! dnslineclientParseU32(object, json_path, "max-ttl", 0, kDnsLineClientMaxTtlLimit, &cfg.max_ttl))
        {
            return false;
        }

        if (jsonGetObjectBoolean(object, "fallback-to-core", &cfg.fallback_to_core) == kJsonValueInvalid)
        {
            LOGF("JSON Error: %s->fallback-to-core must be a boolean", json_path);
            return false;
        }

        if (cfg.max_ttl < cfg.min_ttl)
        {
            LOGF("JSON Error: %s->max-ttl (%u) must be greater than or equal to %s->min-ttl (%u)",
                 json_path,
                 (unsigned) cfg.max_ttl,
                 json_path,
                 (unsigned) cfg.min_ttl);
            return false;
        }
    }

    if (mode == kDnsLineClientModeChain && cfg.servers_count == 0)
    {
        LOGF("JSON Error: %s->servers is required and must not be empty when %s->mode is \"chain\"",
             json_path,
             json_path);
        return false;
    }

    *out_mode = mode;
    *out_cfg  = cfg;
    return true;
}
