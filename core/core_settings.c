#include "core_settings.h"
#include "wwapi.h"

// Default logging configurations
#define DEFAULT_INTERNAL_LOG_LEVEL      "INFO"
#define DEFAULT_INTERNAL_LOG_FILE       "internal.log"
#define DEFAULT_INTERNAL_ENABLE_CONSOLE true
#define DEFAULT_CORE_LOG_LEVEL          "INFO"
#define DEFAULT_CORE_LOG_FILE           "core.log"
#define DEFAULT_CORE_ENABLE_CONSOLE     true
#define DEFAULT_NETWORK_LOG_LEVEL       "INFO"
#define DEFAULT_NETWORK_LOG_FILE        "network.log"
#define DEFAULT_NETWORK_ENABLE_CONSOLE  true
#define DEFAULT_DNS_LOG_LEVEL           "INFO"
#define DEFAULT_DNS_LOG_FILE            "dns.log"
#define DEFAULT_DNS_ENABLE_CONSOLE      true
#define DEFAULT_RAM_PROFILE             kRamProfileServer
#define DEFAULT_TRY_ENABLING_BBR        true

#define DEFAULT_MTU_PROFILE             1500

enum settings_ram_profiles
{
    kRamProfileServer        = kRamProfileL2Memory,
    kRamProfileClientGeneric = kRamProfileM1Memory,
    kRamProfileClientLarger  = kRamProfileM2Memory,
    kRamProfileMinimal       = kRamProfileS1Memory,
};

#define DEFAULT_LIBS_PATH "libs/"
#define DEFAULT_LOG_PATH  "log/"

static struct core_settings_s *settings = NULL;

static void initCoreSettings(void)
{
    assert(settings == NULL);

    settings = memoryAllocateZero(sizeof(struct core_settings_s));

    settings->config_paths = vec_config_path_t_with_capacity(2);
}

static void dnsJsonError(const char *key, const char *message)
{
    if (key == NULL || key[0] == '\0')
    {
        printError("CoreSettings: dns %s\n", message);
    }
    else
    {
        printError("CoreSettings: dns.%s %s\n", key, message);
    }
    terminateProgram(1);
}

static bool dnsJsonGetOptionalInt(const cJSON *json_obj, const char *key, int *dest)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(json_obj, key);
    if (item == NULL)
    {
        return false;
    }
    if (! cJSON_IsNumber(item) || item->valuedouble != (double) item->valueint)
    {
        dnsJsonError(key, "must be an integer");
    }

    *dest = (int) item->valueint;
    return true;
}

static bool dnsJsonGetOptionalBool(const cJSON *json_obj, const char *key, bool *dest)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(json_obj, key);
    if (item == NULL)
    {
        return false;
    }
    if (! cJSON_IsBool(item))
    {
        dnsJsonError(key, "must be a boolean");
    }

    *dest = cJSON_IsTrue(item);
    return true;
}

static bool dnsJsonGetOptionalString(const cJSON *json_obj, const char *key, char **dest)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(json_obj, key);
    if (item == NULL)
    {
        return false;
    }
    if (! cJSON_IsString(item) || item->valuestring == NULL || item->valuestring[0] == '\0')
    {
        dnsJsonError(key, "must be a non-empty string");
    }

    *dest = stringDuplicate(item->valuestring);
    return true;
}

static char **dnsJsonParseStringArray(const cJSON *array, const char *key, int *count_out)
{
    if (! cJSON_IsArray(array))
    {
        dnsJsonError(key, "must be an array of non-empty strings");
    }

    int          count = 0;
    const cJSON *item  = NULL;
    cJSON_ArrayForEach(item, array)
    {
        if (! cJSON_IsString(item) || item->valuestring == NULL || item->valuestring[0] == '\0')
        {
            dnsJsonError(key, "must contain only non-empty strings");
        }
        ++count;
    }

    if (count <= 0)
    {
        dnsJsonError(key, "must not be empty");
    }

    char **values = memoryAllocate(sizeof(*values) * (size_t) count);
    int    index  = 0;
    cJSON_ArrayForEach(item, array)
    {
        values[index++] = stringDuplicate(item->valuestring);
    }

    *count_out = count;
    return values;
}

static char *dnsJsonParseStringOrArrayAsCsv(const cJSON *item, const char *key)
{
    if (cJSON_IsString(item) && item->valuestring != NULL && item->valuestring[0] != '\0')
    {
        return stringDuplicate(item->valuestring);
    }

    if (! cJSON_IsArray(item))
    {
        dnsJsonError(key, "must be a non-empty string or an array of non-empty strings");
    }

    size_t       total = 1;
    int          count = 0;
    const cJSON *child = NULL;
    cJSON_ArrayForEach(child, item)
    {
        if (! cJSON_IsString(child) || child->valuestring == NULL || child->valuestring[0] == '\0')
        {
            dnsJsonError(key, "must contain only non-empty strings");
        }
        if (strchr(child->valuestring, ',') != NULL)
        {
            dnsJsonError(key, "array items must not contain commas");
        }
        total += stringLength(child->valuestring) + (count > 0 ? 1U : 0U);
        ++count;
    }

    if (count <= 0)
    {
        dnsJsonError(key, "must not be empty");
    }

    char  *csv = memoryAllocate(total);
    size_t pos = 0;
    count      = 0;
    cJSON_ArrayForEach(child, item)
    {
        if (count > 0)
        {
            csv[pos++] = ',';
        }
        size_t len = stringLength(child->valuestring);
        memoryCopy(csv + pos, child->valuestring, len);
        pos += len;
        ++count;
    }
    csv[pos] = '\0';

    return csv;
}

static void dnsJsonValidateLookups(const char *lookups)
{
    bool seen_dns   = false;
    bool seen_hosts = false;

    for (const char *ch = lookups; *ch != '\0'; ++ch)
    {
        if (*ch == 'b')
        {
            if (seen_dns)
            {
                dnsJsonError("lookups", "must not repeat lookup source 'b'");
            }
            seen_dns = true;
        }
        else if (*ch == 'f')
        {
            if (seen_hosts)
            {
                dnsJsonError("lookups", "must not repeat lookup source 'f'");
            }
            seen_hosts = true;
        }
        else
        {
            dnsJsonError("lookups", "may only contain 'b' for DNS and 'f' for hosts-file");
        }
    }
}

typedef struct dns_flag_name_s
{
    const char *name;
    int         flag;
} dns_flag_name_t;

static bool dnsJsonFlagFromName(const char *name, int *flag)
{
    static const dns_flag_name_t flag_names[] = {
        {.name = "usevc", .flag = ARES_FLAG_USEVC},
        {.name = "use-vc", .flag = ARES_FLAG_USEVC},
        {.name = "tcp", .flag = ARES_FLAG_USEVC},
        {.name = "primary", .flag = ARES_FLAG_PRIMARY},
        {.name = "igntc", .flag = ARES_FLAG_IGNTC},
        {.name = "ignore-truncated", .flag = ARES_FLAG_IGNTC},
        {.name = "norecurse", .flag = ARES_FLAG_NORECURSE},
        {.name = "no-recurse", .flag = ARES_FLAG_NORECURSE},
        {.name = "stayopen", .flag = ARES_FLAG_STAYOPEN},
        {.name = "stay-open", .flag = ARES_FLAG_STAYOPEN},
        {.name = "no-search", .flag = ARES_FLAG_NOSEARCH},
        {.name = "no-aliases", .flag = ARES_FLAG_NOALIASES},
        {.name = "nocheckresp", .flag = ARES_FLAG_NOCHECKRESP},
        {.name = "no-check-response", .flag = ARES_FLAG_NOCHECKRESP},
        {.name = "edns", .flag = ARES_FLAG_EDNS},
        {.name = "no-default-server", .flag = ARES_FLAG_NO_DFLT_SVR},
        {.name = "no-dflt-svr", .flag = ARES_FLAG_NO_DFLT_SVR},
        {.name = "dns0x20", .flag = ARES_FLAG_DNS0x20},
    };

    for (size_t i = 0; i < sizeof(flag_names) / sizeof(flag_names[0]); ++i)
    {
        if (stringCompare(name, flag_names[i].name) == 0)
        {
            *flag = flag_names[i].flag;
            return true;
        }
    }

    return false;
}

static void dnsJsonParseFlags(const cJSON *dns_obj, asyncdns_options_t *options)
{
    enum
    {
        kSupportedDnsFlags = ARES_FLAG_USEVC | ARES_FLAG_PRIMARY | ARES_FLAG_IGNTC | ARES_FLAG_NORECURSE |
                             ARES_FLAG_STAYOPEN | ARES_FLAG_NOSEARCH | ARES_FLAG_NOALIASES |
                             ARES_FLAG_NOCHECKRESP | ARES_FLAG_EDNS | ARES_FLAG_NO_DFLT_SVR |
                             ARES_FLAG_DNS0x20
    };

    const cJSON *flags_json = cJSON_GetObjectItemCaseSensitive(dns_obj, "flags");
    if (flags_json == NULL)
    {
        return;
    }

    int flags = 0;
    if (cJSON_IsNumber(flags_json))
    {
        if (flags_json->valuedouble != (double) flags_json->valueint || flags_json->valueint < 0 ||
            (flags_json->valueint & ~kSupportedDnsFlags) != 0)
        {
            dnsJsonError("flags", "must be a supported c-ares flag bitmask");
        }
        flags = (int) flags_json->valueint;
    }
    else if (cJSON_IsString(flags_json) && flags_json->valuestring != NULL && flags_json->valuestring[0] != '\0')
    {
        int flag = 0;
        if (! dnsJsonFlagFromName(flags_json->valuestring, &flag))
        {
            dnsJsonError("flags", "contains an unknown flag name");
        }
        flags = flag;
    }
    else if (cJSON_IsArray(flags_json))
    {
        const cJSON *item = NULL;
        cJSON_ArrayForEach(item, flags_json)
        {
            if (! cJSON_IsString(item) || item->valuestring == NULL || item->valuestring[0] == '\0')
            {
                dnsJsonError("flags", "array must contain only non-empty flag names");
            }
            int flag = 0;
            if (! dnsJsonFlagFromName(item->valuestring, &flag))
            {
                dnsJsonError("flags", "contains an unknown flag name");
            }
            flags |= flag;
        }
    }
    else if (cJSON_IsObject(flags_json))
    {
        const cJSON *item = NULL;
        cJSON_ArrayForEach(item, flags_json)
        {
            if (item->string == NULL || ! cJSON_IsBool(item))
            {
                dnsJsonError("flags", "object values must be booleans");
            }
            int flag = 0;
            if (! dnsJsonFlagFromName(item->string, &flag))
            {
                dnsJsonError("flags", "contains an unknown flag name");
            }
            if (cJSON_IsTrue(item))
            {
                flags |= flag;
            }
        }
    }
    else
    {
        dnsJsonError("flags", "must be a bitmask, flag name, flag-name array, or boolean object");
    }

    options->flags_set = true;
    options->flags     = flags;
}

static void parseDnsPartOfJson(const cJSON *dns_obj)
{
    asyncdnsOptionsSetDefaults(&settings->dns_options);
    settings->domain_strategy = kDsPreferIpV4;

    if (dns_obj == NULL)
    {
        return;
    }
    if (! cJSON_IsObject(dns_obj))
    {
        dnsJsonError("", "block must be an object");
    }
    if (dns_obj->child == NULL)
    {
        return;
    }

    asyncdns_options_t *options = &settings->dns_options;
    int                 value   = 0;

    const cJSON *domain_strategy_json = cJSON_GetObjectItemCaseSensitive(dns_obj, "domain-strategy");
    if (domain_strategy_json != NULL &&
        ! getDomainStrategyFromJson(domain_strategy_json, &settings->domain_strategy))
    {
        dnsJsonError("domain-strategy",
                     "must be one of \"accept-dns-returned-order\", \"prefer-ipv4\", \"prefer-ipv6\", "
                     "\"only-ipv4\", or \"only-ipv6\"");
    }

    if (dnsJsonGetOptionalInt(dns_obj, "timeout-ms", &value))
    {
        if (value <= 0)
        {
            dnsJsonError("timeout-ms", "must be greater than 0");
        }
        options->timeout_ms = value;
    }
    if (dnsJsonGetOptionalInt(dns_obj, "max-timeout-ms", &value))
    {
        if (value <= 0)
        {
            dnsJsonError("max-timeout-ms", "must be greater than 0");
        }
        options->max_timeout_ms = value;
    }
    if (dnsJsonGetOptionalInt(dns_obj, "tries", &value))
    {
        if (value <= 0)
        {
            dnsJsonError("tries", "must be greater than 0");
        }
        options->tries = value;
    }
    if (dnsJsonGetOptionalInt(dns_obj, "query-cache-max-ttl", &value))
    {
        if (value < 0)
        {
            dnsJsonError("query-cache-max-ttl", "must be zero or greater");
        }
        options->query_cache_max_ttl = (unsigned int) value;
    }
    if (dnsJsonGetOptionalInt(dns_obj, "ndots", &value))
    {
        if (value < 0 || value > 15)
        {
            dnsJsonError("ndots", "must be in range [0, 15]");
        }
        options->ndots_set = true;
        options->ndots     = value;
    }
    if (dnsJsonGetOptionalInt(dns_obj, "udp-port", &value))
    {
        if (value <= 0 || value > 65535)
        {
            dnsJsonError("udp-port", "must be in range [1, 65535]");
        }
        options->udp_port_set = true;
        options->udp_port     = (unsigned short) value;
    }
    if (dnsJsonGetOptionalInt(dns_obj, "tcp-port", &value))
    {
        if (value <= 0 || value > 65535)
        {
            dnsJsonError("tcp-port", "must be in range [1, 65535]");
        }
        options->tcp_port_set = true;
        options->tcp_port     = (unsigned short) value;
    }
    if (dnsJsonGetOptionalInt(dns_obj, "socket-send-buffer-size", &value))
    {
        if (value <= 0)
        {
            dnsJsonError("socket-send-buffer-size", "must be greater than 0");
        }
        options->socket_send_buffer_size_set = true;
        options->socket_send_buffer_size     = value;
    }
    if (dnsJsonGetOptionalInt(dns_obj, "socket-receive-buffer-size", &value))
    {
        if (value <= 0)
        {
            dnsJsonError("socket-receive-buffer-size", "must be greater than 0");
        }
        options->socket_receive_buffer_size_set = true;
        options->socket_receive_buffer_size     = value;
    }
    if (dnsJsonGetOptionalInt(dns_obj, "edns-packet-size", &value))
    {
        if (value <= 0 || value > 65535)
        {
            dnsJsonError("edns-packet-size", "must be in range [1, 65535]");
        }
        options->ednspsz_set = true;
        options->ednspsz     = value;
    }
    if (dnsJsonGetOptionalInt(dns_obj, "udp-max-queries", &value))
    {
        if (value < 0)
        {
            dnsJsonError("udp-max-queries", "must be zero or greater");
        }
        options->udp_max_queries_set = true;
        options->udp_max_queries     = value;
    }

    dnsJsonParseFlags(dns_obj, options);

    if (dnsJsonGetOptionalBool(dns_obj, "rotate", &options->rotate))
    {
        options->rotate_set = true;
    }

    const cJSON *domains_json = cJSON_GetObjectItemCaseSensitive(dns_obj, "domains");
    if (domains_json != NULL)
    {
        options->domains = dnsJsonParseStringArray(domains_json, "domains", &options->ndomains);
    }

    if (dnsJsonGetOptionalString(dns_obj, "lookups", &options->lookups))
    {
        dnsJsonValidateLookups(options->lookups);
    }
    discard dnsJsonGetOptionalString(dns_obj, "resolvconf-path", &options->resolvconf_path);
    discard dnsJsonGetOptionalString(dns_obj, "hosts-path", &options->hosts_path);
    discard dnsJsonGetOptionalString(dns_obj, "sortlist", &options->sortlist);

    const cJSON *servers_json = cJSON_GetObjectItemCaseSensitive(dns_obj, "servers");
    if (servers_json != NULL)
    {
        options->servers_csv = dnsJsonParseStringOrArrayAsCsv(servers_json, "servers");
    }

    const cJSON *failover_json = cJSON_GetObjectItemCaseSensitive(dns_obj, "server-failover");
    if (failover_json != NULL)
    {
        if (! cJSON_IsObject(failover_json))
        {
            dnsJsonError("server-failover", "must be an object");
        }
        options->server_failover_set = true;

        if (dnsJsonGetOptionalInt(failover_json, "retry-chance", &value))
        {
            if (value < 0 || value > 65535)
            {
                dnsJsonError("server-failover.retry-chance", "must be in range [0, 65535]");
            }
            options->server_failover_retry_chance = (unsigned short) value;
        }
        if (dnsJsonGetOptionalInt(failover_json, "retry-delay-ms", &value))
        {
            if (value < 0)
            {
                dnsJsonError("server-failover.retry-delay-ms", "must be zero or greater");
            }
            options->server_failover_retry_delay_ms = (size_t) value;
        }
    }
}

static void destroyDnsOptions(asyncdns_options_t *options)
{
    if (options->domains != NULL)
    {
        for (int i = 0; i < options->ndomains; ++i)
        {
            memoryFree(options->domains[i]);
        }
        memoryFree(options->domains);
    }

    memoryFree(options->lookups);
    memoryFree(options->resolvconf_path);
    memoryFree(options->hosts_path);
    memoryFree(options->servers_csv);
    memoryFree(options->sortlist);
    memoryZero(options, sizeof(*options));
}

static void parseLogPartOfJsonNoCheck(const cJSON *log_obj)
{
    getStringFromJsonObjectOrDefault(&(settings->log_path), log_obj, "path", DEFAULT_LOG_PATH);

    const cJSON *internal_obj = cJSON_GetObjectItemCaseSensitive(log_obj, "internal");
    if (cJSON_IsObject(internal_obj) && (internal_obj->child != NULL))
    {
        getStringFromJsonObjectOrDefault(&(settings->internal_log_level), internal_obj, "loglevel",
                                         DEFAULT_INTERNAL_LOG_LEVEL);
        getStringFromJsonObjectOrDefault(&(settings->internal_log_file), internal_obj, "file",
                                         DEFAULT_INTERNAL_LOG_FILE);
        getBoolFromJsonObjectOrDefault(&(settings->internal_log_console), internal_obj, "console",
                                       DEFAULT_INTERNAL_ENABLE_CONSOLE);
    }
    else
    {
        settings->internal_log_level   = stringDuplicate(DEFAULT_INTERNAL_LOG_LEVEL);
        settings->internal_log_file    = stringDuplicate(DEFAULT_INTERNAL_LOG_FILE);
        settings->internal_log_console = DEFAULT_INTERNAL_ENABLE_CONSOLE;
    }

    const cJSON *core_obj = cJSON_GetObjectItemCaseSensitive(log_obj, "core");
    if (cJSON_IsObject(core_obj) && (core_obj->child != NULL))
    {
        getStringFromJsonObjectOrDefault(&(settings->core_log_level), core_obj, "loglevel", DEFAULT_CORE_LOG_LEVEL);
        getStringFromJsonObjectOrDefault(&(settings->core_log_file), core_obj, "file", DEFAULT_CORE_LOG_FILE);
        getBoolFromJsonObjectOrDefault(&(settings->core_log_console), core_obj, "console", DEFAULT_CORE_ENABLE_CONSOLE);
    }
    else
    {
        settings->core_log_level   = stringDuplicate(DEFAULT_CORE_LOG_LEVEL);
        settings->core_log_file    = stringDuplicate(DEFAULT_CORE_LOG_FILE);
        settings->core_log_console = DEFAULT_CORE_ENABLE_CONSOLE;
    }

    const cJSON *network_obj = cJSON_GetObjectItemCaseSensitive(log_obj, "network");
    if (cJSON_IsObject(network_obj) && (network_obj->child != NULL))
    {
        getStringFromJsonObjectOrDefault(&(settings->network_log_level), network_obj, "loglevel",
                                         DEFAULT_NETWORK_LOG_LEVEL);
        getStringFromJsonObjectOrDefault(&(settings->network_log_file), network_obj, "file", DEFAULT_NETWORK_LOG_FILE);
        getBoolFromJsonObjectOrDefault(&(settings->network_log_console), network_obj, "console",
                                       DEFAULT_NETWORK_ENABLE_CONSOLE);
    }
    else
    {
        settings->network_log_level   = stringDuplicate(DEFAULT_NETWORK_LOG_LEVEL);
        settings->network_log_file    = stringDuplicate(DEFAULT_NETWORK_LOG_FILE);
        settings->network_log_console = DEFAULT_NETWORK_ENABLE_CONSOLE;
    }

    const cJSON *dns_obj = cJSON_GetObjectItemCaseSensitive(log_obj, "dns");
    if (cJSON_IsObject(dns_obj) && (dns_obj->child != NULL))
    {
        getStringFromJsonObjectOrDefault(&(settings->dns_log_level), dns_obj, "loglevel", DEFAULT_DNS_LOG_LEVEL);
        getStringFromJsonObjectOrDefault(&(settings->dns_log_file), dns_obj, "file", DEFAULT_DNS_LOG_FILE);
        getBoolFromJsonObjectOrDefault(&(settings->dns_log_console), dns_obj, "console", DEFAULT_DNS_ENABLE_CONSOLE);
    }
    else
    {
        settings->dns_log_level   = stringDuplicate(DEFAULT_DNS_LOG_LEVEL);
        settings->dns_log_file    = stringDuplicate(DEFAULT_DNS_LOG_FILE);
        settings->dns_log_console = DEFAULT_DNS_ENABLE_CONSOLE;
    }
}

static void parseLogPartOfJson(cJSON *log_obj)
{
    if (cJSON_IsObject(log_obj) && (log_obj->child != NULL))
    {
        parseLogPartOfJsonNoCheck(log_obj);
    }
    else
    {
        // Set default values when log object is invalid
        settings->log_path           = stringDuplicate(DEFAULT_LOG_PATH);
        settings->core_log_file      = stringDuplicate(DEFAULT_CORE_LOG_FILE);
        settings->core_log_level     = stringDuplicate(DEFAULT_CORE_LOG_LEVEL);
        settings->network_log_file   = stringDuplicate(DEFAULT_NETWORK_LOG_FILE);
        settings->network_log_level  = stringDuplicate(DEFAULT_NETWORK_LOG_LEVEL);
        settings->dns_log_file       = stringDuplicate(DEFAULT_DNS_LOG_FILE);
        settings->dns_log_level      = stringDuplicate(DEFAULT_DNS_LOG_LEVEL);
        settings->internal_log_file  = stringDuplicate(DEFAULT_INTERNAL_LOG_FILE);
        settings->internal_log_level = stringDuplicate(DEFAULT_INTERNAL_LOG_LEVEL);

        settings->core_log_console     = DEFAULT_CORE_ENABLE_CONSOLE;
        settings->network_log_console  = DEFAULT_NETWORK_ENABLE_CONSOLE;
        settings->dns_log_console      = DEFAULT_DNS_ENABLE_CONSOLE;
        settings->internal_log_console = DEFAULT_INTERNAL_ENABLE_CONSOLE;
    }

    // Construct full paths
    settings->core_log_file_fullpath     = stringConcat(settings->log_path, settings->core_log_file);
    settings->network_log_file_fullpath  = stringConcat(settings->log_path, settings->network_log_file);
    settings->dns_log_file_fullpath      = stringConcat(settings->log_path, settings->dns_log_file);
    settings->internal_log_file_fullpath = stringConcat(settings->log_path, settings->internal_log_file);
}

static void parseConfigPartOfJson(const cJSON *config_array)
{
    if (! cJSON_IsArray(config_array) || (config_array->child == NULL))
    {
        printError("Error: \"configs\" array in core json is empty or invalid \n");
        terminateProgram(1);
    }
    const cJSON *path      = NULL;
    bool         had_child = false;
    cJSON_ArrayForEach(path, config_array)
    {
        if (cJSON_IsString(path) && path->valuestring != NULL)
        {
            had_child          = true;
            unsigned long size = stringLength(path->valuestring) + 1;
            char         *buf  = memoryAllocate(size);
#if defined(OS_UNIX)
            strcpy(buf, path->valuestring);
#else
            strcpy_s(buf, size, path->valuestring);
#endif
            vec_config_path_t_push(&settings->config_paths, buf);
        }
    }

    if (! had_child)
    {
        printError("Error: \"configs\" array in core json is empty or invalid \n");
        terminateProgram(1);
    }
}

static void parseMiscPartOfJson(cJSON *misc_obj)
{
    if (cJSON_IsObject(misc_obj) && (misc_obj->child != NULL))
    {
        int mtu_size = DEFAULT_MTU_PROFILE;
        getIntFromJsonObjectOrDefault(&mtu_size, misc_obj, "mtu", DEFAULT_MTU_PROFILE);
        if (mtu_size <= 0)
        {
            printError("CoreSettings: mtu-size must be greater than 0, using default value %d\n", DEFAULT_MTU_PROFILE);
            mtu_size = DEFAULT_MTU_PROFILE;
        }
        settings->mtu_size = (uint16_t) mtu_size;

        getBoolFromJsonObjectOrDefault(&settings->try_enabling_bbr, misc_obj, "try-enabling-bbr",
                                       DEFAULT_TRY_ENABLING_BBR);
        getStringFromJsonObjectOrDefault(&(settings->libs_path), misc_obj, "libs-path", DEFAULT_LIBS_PATH);
        if (! getIntFromJsonObjectOrDefault((int *) &(settings->workers_count), misc_obj, "workers", getNCPU()))
        {
            printf("workers unspecified in json (misc), fallback to cpu cores: %d\n", settings->workers_count);
        }
        // user could just enter 0 as value
        if (settings->workers_count <= 0)
        {
            settings->workers_count = (unsigned int) getNCPU();
        }

        const cJSON *json_ram_profile = cJSON_GetObjectItemCaseSensitive(misc_obj, "ram-profile");
        if (cJSON_IsNumber(json_ram_profile))
        {
            int profile = (int) json_ram_profile->valueint;

            switch (profile)
            {
            case 0:
            case 1:
                settings->ram_profile = kRamProfileS1Memory;
                break;
            case 2:
                settings->ram_profile = kRamProfileS2Memory;
                break;
            case 3:
                settings->ram_profile = kRamProfileM1Memory;
                break;
            case 4:
                settings->ram_profile = kRamProfileM2Memory;
                break;
            case 5:
                settings->ram_profile = kRamProfileL1Memory;
                break;
            case 6:
                settings->ram_profile = kRamProfileL2Memory;
                break;
            default:
                printError("CoreSettings: ram-profile must be in range [1 - 6]\n");
                terminateProgram(1);
                break;
            }
        }
        else if (cJSON_IsString(json_ram_profile))
        {
            char *string_ram_profile = NULL;
            getStringFromJsonObject(&string_ram_profile, misc_obj, "ram-profile");
            stringLowerCase(string_ram_profile);

            if (0 == strcmp(string_ram_profile, "server"))
            {
                settings->ram_profile = kRamProfileServer;
            }
            else if (0 == strcmp(string_ram_profile, "client"))
            {
                settings->ram_profile = kRamProfileClientGeneric;
            }
            else if (0 == strcmp(string_ram_profile, "client-larger"))
            {
                settings->ram_profile = kRamProfileClientLarger;
            }
            else if (0 == strcmp(string_ram_profile, "ultralow") || 0 == strcmp(string_ram_profile, "minimal"))
            {
                settings->ram_profile = kRamProfileMinimal;
            }

            if (settings->ram_profile <= 0)
            {
                printError("CoreSettings: ram-profile can hold \"server\" or \"client\" "
                           "or \"client-larger\" or \"minimal\" or \"ultralow\" \n");

                terminateProgram(1);
            }
            memoryFree(string_ram_profile);
        }
        else
        {
            settings->ram_profile = DEFAULT_RAM_PROFILE;
        }
    }
    else
    {
        settings->try_enabling_bbr = DEFAULT_TRY_ENABLING_BBR;
        settings->libs_path        = stringDuplicate(DEFAULT_LIBS_PATH);
        settings->workers_count    = (unsigned int) getNCPU();
        printf("misc block unspecified in json, using defaults. cpu cores: %d\n", settings->workers_count);
    }
}

void parseCoreSettings(const char *data_json)
{
    if (settings == NULL)
    {
        initCoreSettings();
    }

    cJSON *json = cJSON_Parse(data_json);
    if (json == NULL)
    {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
        {
            printError("JSON Error before: %s\n", error_ptr);
        }
        terminateProgram(1);
    }

    if (cJSON_GetObjectItemCaseSensitive(json, "domain-strategy") != NULL)
    {
        printError("CoreSettings: domain-strategy must be configured inside the dns object as dns.domain-strategy\n");
        terminateProgram(1);
    }

    parseLogPartOfJson(cJSON_GetObjectItemCaseSensitive(json, "log"));
    parseConfigPartOfJson(cJSON_GetObjectItemCaseSensitive(json, "configs"));
    parseMiscPartOfJson(cJSON_GetObjectItemCaseSensitive(json, "misc"));
    parseDnsPartOfJson(cJSON_GetObjectItemCaseSensitive(json, "dns"));

    if (settings->workers_count <= 0)
    {
        printError("CoreSettings: the workers count is invalid");
        terminateProgram(1);
    }
    if (settings->workers_count > 254)
    {
        printError("CoreSettings: workers count is shrinked to maximum supported value -> 254");
        settings->workers_count = 254;
    }

    cJSON_Delete(json);
}

struct core_settings_s *getCoreSettings(void)
{
    return settings;
}

void destroyCoreSettings(void)
{
    if (settings == NULL)
    {
        return;
    }
    c_foreach(k, vec_config_path_t, settings->config_paths){
        memoryFree(*k.ref);
    }

    // Free all strings
    memoryFree(settings->log_path);
    memoryFree(settings->internal_log_file);
    memoryFree(settings->internal_log_level);
    memoryFree(settings->core_log_file);
    memoryFree(settings->core_log_level);
    memoryFree(settings->network_log_file);
    memoryFree(settings->network_log_level);
    memoryFree(settings->dns_log_file);
    memoryFree(settings->dns_log_level);
    memoryFree(settings->libs_path);
    destroyDnsOptions(&settings->dns_options);

    // Free full paths
    memoryFree(settings->internal_log_file_fullpath);
    memoryFree(settings->core_log_file_fullpath);
    memoryFree(settings->network_log_file_fullpath);
    memoryFree(settings->dns_log_file_fullpath);

    vec_config_path_t_drop(&settings->config_paths);

    // Free the settings structure itself
    memoryFree(settings);
    settings = NULL;
}
