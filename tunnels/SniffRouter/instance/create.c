#include "structure.h"

#include "loggers/network_logger.h"

static bool normalizeDomainPattern(char *domain, const char *json_path)
{
    stringLowerCase(domain);

    uint32_t len = (uint32_t) stringLength(domain);
    if (len == 2U && domain[0] == '*' && domain[1] == '.')
    {
        LOGF("JSON Error: %s (string field) : wildcard domains must use \"*.example.com\" form", json_path);
        return false;
    }

    while (len > 0 && domain[len - 1U] == '.')
    {
        domain[--len] = '\0';
    }

    if (len == 0)
    {
        LOGF("JSON Error: %s (string field) : domain pattern must not be empty", json_path);
        return false;
    }

    if (len == 1U && domain[0] == '*')
    {
        return true;
    }

    for (uint32_t i = 0; i < len; ++i)
    {
        if (domain[i] == '*')
        {
            if (i != 0 || len <= 2U || domain[1] != '.')
            {
                LOGF("JSON Error: %s (string field) : wildcard domains must use \"*.example.com\" form", json_path);
                return false;
            }
        }
        else if (domain[i] == ':' || domain[i] == '/' || domain[i] == '\\')
        {
            LOGF("JSON Error: %s (string field) : expected a domain pattern, not a URL or host:port", json_path);
            return false;
        }
    }

    return true;
}

static bool loadDomainString(char **dest, const cJSON *domain_json, const char *json_path)
{
    if (! getStringFromJson(dest, domain_json))
    {
        LOGF("JSON Error: %s (string field) : expected a domain pattern", json_path);
        return false;
    }

    if (! normalizeDomainPattern(*dest, json_path))
    {
        memoryFree(*dest);
        *dest = NULL;
        return false;
    }

    return true;
}

static bool loadRouteDomains(sniffrouter_route_t *route, const cJSON *route_json, uint32_t route_index)
{
    const cJSON *domains = cJSON_GetObjectItemCaseSensitive(route_json, "domains");
    const cJSON *domain  = cJSON_GetObjectItemCaseSensitive(route_json, "domain");

    // Host/SNI detection needs domain patterns to match against; signature-based
    // detection (reverse) does not. Detection is parsed before domains so the
    // requirement is known here.
    bool domains_required = (route->detection & (kSniffDetectionHttp | kSniffDetectionTlsClientHello)) != 0;

    if (domains == NULL && domain == NULL)
    {
        if (domains_required)
        {
            LOGF("SniffRouter: route %u uses http/tls detection and requires \"domains\" or \"domain\"",
                 (unsigned int) route_index);
            return false;
        }

        route->domains       = NULL;
        route->domains_count = 0;
        return true;
    }

    if (domains != NULL && domain != NULL)
    {
        LOGF("SniffRouter: route %u must use either \"domains\" or \"domain\", not both", (unsigned int) route_index);
        return false;
    }

    if (domain != NULL)
    {
        route->domains_count = 1;
        route->domains       = memoryAllocateZero(sizeof(*route->domains));
        return loadDomainString(&route->domains[0], domain, "SniffRouter->settings->routes[]->domain");
    }

    if (cJSON_IsString(domains))
    {
        route->domains_count = 1;
        route->domains       = memoryAllocateZero(sizeof(*route->domains));
        return loadDomainString(&route->domains[0], domains, "SniffRouter->settings->routes[]->domains");
    }

    if (! cJSON_IsArray(domains) || cJSON_GetArraySize(domains) <= 0)
    {
        LOGF("JSON Error: SniffRouter->settings->routes[]->domains (array field) : expected one or more domain "
             "patterns");
        return false;
    }

    int count            = cJSON_GetArraySize(domains);
    route->domains_count = (uint32_t) count;
    route->domains       = memoryAllocateZero(sizeof(*route->domains) * (size_t) route->domains_count);

    uint32_t     index = 0;
    const cJSON *item  = NULL;
    cJSON_ArrayForEach(item, domains)
    {
        if (! loadDomainString(&route->domains[index], item, "SniffRouter->settings->routes[]->domains[]"))
        {
            return false;
        }
        ++index;
    }

    return true;
}

static bool loadDetectionString(uint8_t *detection, const cJSON *detection_json, const char *json_path)
{
    char *value = NULL;
    if (! getStringFromJson(&value, detection_json))
    {
        LOGF("JSON Error: %s (string field) : expected http, tls, client-hello, tls-client-hello, or reverse", json_path);
        return false;
    }

    stringLowerCase(value);

    if (stringCompare(value, "http") == 0)
    {
        *detection |= kSniffDetectionHttp;
        memoryFree(value);
        return true;
    }

    if (stringCompare(value, "tls") == 0 || stringCompare(value, "client-hello") == 0 ||
        stringCompare(value, "tls-client-hello") == 0)
    {
        *detection |= kSniffDetectionTlsClientHello;
        memoryFree(value);
        return true;
    }

    if (stringCompare(value, "reverse") == 0 || stringCompare(value, "reverse-tls") == 0 ||
        stringCompare(value, "reverse-handshake") == 0)
    {
        *detection |= kSniffDetectionReverse;
        memoryFree(value);
        return true;
    }

    LOGF("JSON Error: %s (string field) : unsupported detection \"%s\"", json_path, value);
    memoryFree(value);
    return false;
}

static bool loadRouteDetection(sniffrouter_route_t *route, const cJSON *route_json)
{
    const cJSON *detection = cJSON_GetObjectItemCaseSensitive(route_json, "detection");

    if (detection == NULL)
    {
        route->detection = kSniffDetectionHttp;
        return true;
    }

    route->detection = 0;

    if (cJSON_IsString(detection))
    {
        return loadDetectionString(&route->detection, detection, "SniffRouter->settings->routes[]->detection");
    }

    if (! cJSON_IsArray(detection) || cJSON_GetArraySize(detection) <= 0)
    {
        LOGF("JSON Error: SniffRouter->settings->routes[]->detection (string or array field) : expected one or more "
             "detection modes");
        return false;
    }

    const cJSON *item = NULL;
    cJSON_ArrayForEach(item, detection)
    {
        if (! loadDetectionString(&route->detection, item, "SniffRouter->settings->routes[]->detection[]"))
        {
            return false;
        }
    }

    return route->detection != 0;
}

static bool loadRouteTarget(sniffrouter_route_t *route, node_t *node, const cJSON *route_json, uint32_t route_index)
{
    char *target_name = NULL;
    if (! getStringFromJsonObject(&target_name, route_json, "next") &&
        ! getStringFromJsonObject(&target_name, route_json, "target"))
    {
        LOGF("SniffRouter: route %u requires \"next\" (target node name)", (unsigned int) route_index);
        return false;
    }

    route->node = nodemanagerGetConfigNodeByName(node->node_manager_config, target_name);
    if (route->node == NULL)
    {
        LOGF("SniffRouter: route %u target node \"%s\" not found", (unsigned int) route_index, target_name);
        memoryFree(target_name);
        return false;
    }

    memoryFree(target_name);

    if (route->node == node)
    {
        LOGF("SniffRouter: route %u must not reference the SniffRouter itself", (unsigned int) route_index);
        return false;
    }

    return true;
}

static bool loadRoutes(sniffrouter_tstate_t *ts, node_t *node, const cJSON *settings)
{
    const cJSON *routes = cJSON_GetObjectItemCaseSensitive(settings, "routes");

    if (routes == NULL)
    {
        ts->routes       = NULL;
        ts->routes_count = 0;
        return true;
    }

    if (! cJSON_IsArray(routes))
    {
        LOGF("JSON Error: SniffRouter->settings->routes (array field) : expected an array of route objects");
        return false;
    }

    int routes_count = cJSON_GetArraySize(routes);
    if (routes_count <= 0)
    {
        LOGF("JSON Error: SniffRouter->settings->routes (array field) : The array was empty or invalid");
        return false;
    }

    ts->routes_count = (uint32_t) routes_count;
    ts->routes       = memoryAllocateZero(sizeof(*ts->routes) * (size_t) ts->routes_count);

    uint32_t     index      = 0;
    const cJSON *route_json = NULL;
    cJSON_ArrayForEach(route_json, routes)
    {
        if (! checkJsonIsObjectAndHasChild(route_json))
        {
            LOGF("JSON Error: SniffRouter->settings->routes[%u] (object field) : The object was empty or invalid",
                 (unsigned int) index);
            return false;
        }

        // Detection must be parsed before domains: signature-based detection
        // (reverse) makes "domains" optional, so loadRouteDomains needs to know
        // the detection mode first.
        if (! loadRouteTarget(&ts->routes[index], node, route_json, index) ||
            ! loadRouteDetection(&ts->routes[index], route_json) ||
            ! loadRouteDomains(&ts->routes[index], route_json, index))
        {
            return false;
        }

        ++index;
    }

    return true;
}

tunnel_t *sniffrouterTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(sniffrouter_tstate_t), sizeof(sniffrouter_lstate_t));

    t->fnInitU    = &sniffrouterTunnelUpStreamInit;
    t->fnEstU     = &sniffrouterTunnelUpStreamEst;
    t->fnFinU     = &sniffrouterTunnelUpStreamFinish;
    t->fnPayloadU = &sniffrouterTunnelUpStreamPayload;
    t->fnPauseU   = &sniffrouterTunnelUpStreamPause;
    t->fnResumeU  = &sniffrouterTunnelUpStreamResume;

    t->fnInitD    = &sniffrouterTunnelDownStreamInit;
    t->fnEstD     = &sniffrouterTunnelDownStreamEst;
    t->fnFinD     = &sniffrouterTunnelDownStreamFinish;
    t->fnPayloadD = &sniffrouterTunnelDownStreamPayload;
    t->fnPauseD   = &sniffrouterTunnelDownStreamPause;
    t->fnResumeD  = &sniffrouterTunnelDownStreamResume;

    t->onChain   = &sniffrouterTunnelOnChain;
    t->onIndex   = &sniffrouterTunnelOnIndex;
    t->onPrepare = &sniffrouterTunnelOnPrepair;
    t->onStart   = &sniffrouterTunnelOnStart;
    t->onStop    = &sniffrouterTunnelOnStop;
    t->onDestroy = &sniffrouterTunnelDestroy;

    if (! nodeHasNext(node))
    {
        LOGF("SniffRouter: must have a \"next\" fallback node");
        sniffrouterTunnelDestroy(t);
        return NULL;
    }

    const cJSON *settings = node->node_settings_json;
    if (settings != NULL && ! cJSON_IsObject(settings))
    {
        LOGF("JSON Error: SniffRouter->settings (object field) : expected an object");
        sniffrouterTunnelDestroy(t);
        return NULL;
    }

    sniffrouter_tstate_t *ts = tunnelGetState(t);
    if (! reverseclientHandshakeBuildFromSettings(settings, "SniffRouter", &ts->reverse_handshake_bytes,
                                                  &ts->reverse_handshake_length))
    {
        sniffrouterTunnelDestroy(t);
        return NULL;
    }

    if (settings != NULL && ! loadRoutes(ts, node, settings))
    {
        sniffrouterTunnelDestroy(t);
        return NULL;
    }

    return t;
}
