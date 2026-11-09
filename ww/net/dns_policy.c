#include "dns_policy.h"

#include "instance/global_state.h"
#include "loggers/network_logger.h"
#include "utils/json_helpers.h"

static bool dnsPolicyValidateEndpoint(const char *endpoint)
{
    if (endpoint == NULL || endpoint[0] == '\0' || strlen(endpoint) > 64)
        return false;
    char        host[64];
    const char *port = NULL;
    size_t      host_length;
    if (endpoint[0] == '[')
    {
        const char *end = strchr(endpoint, ']');
        if (end == NULL || (end[1] != '\0' && end[1] != ':'))
            return false;
        host_length = (size_t) (end - endpoint - 1);
        if (host_length == 0 || host_length >= sizeof(host))
            return false;
        memoryCopy(host, endpoint + 1, host_length);
        if (end[1] == ':')
            port = end + 2;
    }
    else
    {
        const char *colon = strchr(endpoint, ':');
        if (colon != NULL && strchr(colon + 1, ':') == NULL)
        {
            host_length = (size_t) (colon - endpoint);
            port        = colon + 1;
        }
        else
            host_length = strlen(endpoint);
        if (host_length == 0 || host_length >= sizeof(host))
            return false;
        memoryCopy(host, endpoint, host_length);
    }
    host[host_length] = '\0';
    // Use strict endpoint syntax: lwIP and ares_inet_pton also accept network
    // shorthand, while DNS servers need a complete unambiguous host address.
    uint8_t address[16];
    if (inet_pton(endpoint[0] == '[' ? AF_INET6 : AF_INET, host, address) != 1 &&
        (endpoint[0] == '[' || inet_pton(AF_INET6, host, address) != 1))
        return false;
    if (port != NULL)
    {
        unsigned value = 0;
        if (*port == '\0')
            return false;
        for (; *port != '\0'; ++port)
        {
            if (*port < '0' || *port > '9')
                return false;
            value = value * 10U + (unsigned) (*port - '0');
            if (value > UINT16_MAX)
                return false;
        }
        if (value == 0)
            return false;
    }
    return true;
}

bool dnsPolicyParseStrategy(const cJSON *value, enum domain_strategy core_strategy, enum domain_strategy *strategy)
{
    if (! cJSON_IsString(value) || value->valuestring == NULL || (value->type & cJSON_StringHasEmbeddedNul) != 0 ||
        ! configLexicalCheckEncodingQuiet(value->valuestring, strlen(value->valuestring)))
        return false;
    const char *name = value->valuestring;
    if (strcmp(name, "core-settings") == 0)
        *strategy = core_strategy;
    else if (strcmp(name, "accept-dns-returned-order") == 0)
        *strategy = kDsInvalid;
    else if (strcmp(name, "prefer-ipv4") == 0)
        *strategy = kDsPreferIpV4;
    else if (strcmp(name, "prefer-ipv6") == 0)
        *strategy = kDsPreferIpV6;
    else if (strcmp(name, "only-ipv4") == 0)
        *strategy = kDsOnlyIpV4;
    else if (strcmp(name, "only-ipv6") == 0)
        *strategy = kDsOnlyIpV6;
    else
        return false;
    return true;
}

const char *dnsPolicyStrategyName(enum domain_strategy strategy)
{
    switch (strategy)
    {
    case kDsPreferIpV4:
        return "prefer-ipv4";
    case kDsPreferIpV6:
        return "prefer-ipv6";
    case kDsOnlyIpV4:
        return "only-ipv4";
    case kDsOnlyIpV6:
        return "only-ipv6";
    default:
        return "accept-dns-returned-order";
    }
}

void dnsPolicyDestroy(dns_policy_t *policy)
{
    memoryFree(policy->servers_csv);
    memoryFree(policy->dns_next);
    *policy = (dns_policy_t) {0};
}

static bool dnsPolicyObjectFieldsAreExact(const cJSON *object)
{
    const cJSON *field;
    cJSON_ArrayForEach(field, object)
    {
        if (field->string == NULL || ! jsonObjectFieldStringsAreExact(object, field->string))
            return false;
        for (const cJSON *earlier = object->child; earlier != field; earlier = earlier->next)
            if (strcmp(earlier->string, field->string) == 0)
                return false;
    }
    return true;
}

static bool dnsPolicyParseObject(dns_policy_t *policy, const cJSON *object, const dns_policy_defaults_t *defaults,
                                 const char *path, bool flat)
{
    *policy = (dns_policy_t) {.resolve = defaults->resolve, .strategy = defaults->strategy, .supplied = object != NULL};
    if (object == NULL)
        return true;
    if (! cJSON_IsObject(object) || (! flat && object->child == NULL) || ! dnsPolicyObjectFieldsAreExact(object))
    {
        LOGF("JSON Error: %s must be a nonempty DNS policy object", path);
        return false;
    }
    const cJSON *field;
    cJSON_ArrayForEach(field, object)
    {
        if (field->string == NULL ||
            (strcmp(field->string, "resolve") != 0 && strcmp(field->string, "mode") != 0 &&
             strcmp(field->string, "strategy") != 0 && strcmp(field->string, "servers") != 0 &&
             strcmp(field->string, "dns-next") != 0 && (! flat || strcmp(field->string, "verbose") != 0)))
        {
            LOGF("JSON Error: %s contains an unsupported field: %s", path, field->string);
            return false;
        }
    }
    const cJSON *resolve  = cJSON_GetObjectItemCaseSensitive(object, "resolve");
    const cJSON *mode     = cJSON_GetObjectItemCaseSensitive(object, "mode");
    const cJSON *strategy = cJSON_GetObjectItemCaseSensitive(object, "strategy");
    const cJSON *servers  = cJSON_GetObjectItemCaseSensitive(object, "servers");
    const cJSON *next     = cJSON_GetObjectItemCaseSensitive(object, "dns-next");
    if ((! flat || resolve != NULL) && ! cJSON_IsBool(resolve))
    {
        LOGF("JSON Error: %s.resolve requires a boolean", path);
        return false;
    }
    if (resolve != NULL)
        policy->resolve = cJSON_IsTrue(resolve);
    if (! policy->resolve)
    {
        if (mode != NULL || strategy != NULL || servers != NULL || next != NULL)
        {
            LOGF("JSON Error: %s with resolve false rejects mode, strategy, servers and dns-next", path);
            return false;
        }
        return true;
    }
    if (mode != NULL)
    {
        if (! cJSON_IsString(mode) || mode->valuestring == NULL)
            goto invalid_mode;
        if (strcmp(mode->valuestring, "native") == 0)
            policy->mode = kDnsPolicyModeNative;
        else if (strcmp(mode->valuestring, "direct") == 0)
            policy->mode = kDnsPolicyModeDirect;
        else if (strcmp(mode->valuestring, "chain") == 0)
            policy->mode = kDnsPolicyModeChain;
        else
            goto invalid_mode;
    }
    if (strategy != NULL && ! dnsPolicyParseStrategy(strategy, defaults->core_strategy, &policy->strategy))
    {
        LOGF("JSON Error: %s.strategy requires core-settings, accept-dns-returned-order, prefer-ipv4, prefer-ipv6, "
             "only-ipv4 or only-ipv6",
             path);
        return false;
    }
    if (defaults->ipv4_only && policy->strategy != kDsOnlyIpV4)
    {
        LOGF("JSON Error: %s requires the only-ipv4 strategy", path);
        return false;
    }
    if (policy->mode == kDnsPolicyModeNative)
    {
        if (servers != NULL || next != NULL)
        {
            LOGF("JSON Error: %s native mode rejects servers and dns-next", path);
            return false;
        }
        return true;
    }
    if (policy->mode == kDnsPolicyModeDirect && next != NULL)
    {
        LOGF("JSON Error: %s direct mode rejects dns-next", path);
        return false;
    }
    if (next != NULL)
    {
        if (! cJSON_IsString(next) || next->valuestring == NULL || next->valuestring[0] == '\0')
        {
            LOGF("JSON Error: %s.dns-next requires a nonempty configured entry name", path);
            return false;
        }
    }
    else if (policy->mode == kDnsPolicyModeChain && defaults->require_dns_next)
    {
        LOGF("JSON Error: %s chain mode requires an explicit dns-next branch", path);
        return false;
    }
    const int count = cJSON_GetArraySize(servers);
    if (! cJSON_IsArray(servers) || count < 1 || count > 32)
    {
        LOGF("JSON Error: %s.servers requires 1 to 32 numeric DNS endpoints", path);
        return false;
    }
    size_t total = 1;
    for (int i = 0; i < count; ++i)
    {
        const cJSON *server = cJSON_GetArrayItem(servers, i);
        if (! cJSON_IsString(server) || (server->type & cJSON_StringHasEmbeddedNul) != 0 ||
            ! dnsPolicyValidateEndpoint(server->valuestring))
        {
            LOGF("JSON Error: %s.servers[%d] requires a numeric IP, IP:port or [IPv6]:port", path, i);
            return false;
        }
        total += strlen(server->valuestring) + 1;
    }
    policy->servers_csv = memoryAllocate(total);
    size_t used         = 0;
    for (int i = 0; i < count; ++i)
    {
        const char *endpoint = cJSON_GetArrayItem(servers, i)->valuestring;
        if (i != 0)
            policy->servers_csv[used++] = ',';
        const size_t length = strlen(endpoint);
        memoryCopy(policy->servers_csv + used, endpoint, length);
        used += length;
    }
    policy->servers_csv[used] = '\0';
    if (next != NULL)
        policy->dns_next = stringDuplicate(next->valuestring);
    return true;

invalid_mode:
    LOGF("JSON Error: %s.mode requires native, direct or chain", path);
    return false;
}

static bool dnsPolicyFieldIsUniqueAndExact(const cJSON *settings, const char *key)
{
    if (! jsonObjectFieldStringsAreExact(settings, key))
        return false;
    unsigned count = 0;
    if (cJSON_IsObject(settings))
        for (const cJSON *field = settings->child; field != NULL; field = field->next)
            if (field->string != NULL && strcmp(field->string, key) == 0 && ++count > 1)
                return false;
    return true;
}

static bool dnsPolicyRejectRemovedFields(const cJSON *settings, const char *path)
{
    if (cJSON_HasObjectItem(settings, "domain-strategy") || cJSON_HasObjectItem(settings, "resolve-domains"))
    {
        LOGF("JSON Error: %s no longer accepts domain-strategy or resolve-domains; use dns-behaviour", path);
        return false;
    }
    return true;
}

bool dnsPolicyParseSettings(dns_policy_t *policy, const cJSON *settings, const dns_policy_defaults_t *defaults,
                            const char *path)
{
    const cJSON *object = cJSON_GetObjectItemCaseSensitive(settings, "dns-behaviour");
    *policy             = (dns_policy_t) {0};
    if (! dnsPolicyFieldIsUniqueAndExact(settings, "dns-behaviour"))
    {
        LOGF("JSON Error: %s requires exact DNS policy field names", path);
        return false;
    }
    if (! dnsPolicyRejectRemovedFields(settings, path))
        return false;
    return dnsPolicyParseObject(policy, object, defaults, path, false);
}

bool dnsPolicyParseFlat(dns_policy_t *policy, const cJSON *settings, const dns_policy_defaults_t *defaults,
                        const char *path)
{
    return dnsPolicyParseObject(policy, settings, defaults, path, true);
}

cJSON *dnsPolicyCreateResolverSettings(const dns_policy_t *policy)
{
    cJSON *settings = cJSON_CreateObject();
    cJSON_AddBoolToObject(settings, "resolve", policy->resolve);
    if (! policy->resolve)
        return settings;
    const char *mode = policy->mode == kDnsPolicyModeChain    ? "chain"
                       : policy->mode == kDnsPolicyModeDirect ? "direct"
                                                              : "native";
    cJSON_AddStringToObject(settings, "mode", mode);
    cJSON_AddStringToObject(settings, "strategy", dnsPolicyStrategyName(policy->strategy));
    if (policy->servers_csv != NULL)
    {
        cJSON      *servers = cJSON_AddArrayToObject(settings, "servers");
        const char *begin   = policy->servers_csv;
        while (*begin != '\0')
        {
            const char *end    = strchr(begin, ',');
            size_t      length = end == NULL ? strlen(begin) : (size_t) (end - begin);
            char        endpoint[65];
            assert(length < sizeof(endpoint));
            memoryCopy(endpoint, begin, length);
            endpoint[length] = '\0';
            cJSON_AddItemToArray(servers, cJSON_CreateString(endpoint));
            if (end == NULL)
                break;
            begin = end + 1;
        }
    }
    if (policy->dns_next != NULL)
        cJSON_AddStringToObject(settings, "dns-next", policy->dns_next);
    return settings;
}

bool dnsPolicyParseStrategyOverride(enum domain_strategy *strategy, const cJSON *settings, bool resolve_enabled,
                                    const char *path)
{
    const cJSON *object = cJSON_GetObjectItemCaseSensitive(settings, "dns-behaviour");
    if (! dnsPolicyRejectRemovedFields(settings, path))
        return false;
    if (object == NULL)
        return true;
    if (! resolve_enabled || ! dnsPolicyFieldIsUniqueAndExact(settings, "dns-behaviour") || ! cJSON_IsObject(object) ||
        ! dnsPolicyObjectFieldsAreExact(object) || object->child == NULL || object->child->next != NULL ||
        object->child->string == NULL || strcmp(object->child->string, "strategy") != 0 ||
        ! dnsPolicyParseStrategy(object->child, GSTATE.domain_strategy, strategy))
    {
        LOGF("JSON Error: %s.dns-behaviour requires only a canonical string strategy and enabled node resolution",
             path);
        return false;
    }
    return true;
}
