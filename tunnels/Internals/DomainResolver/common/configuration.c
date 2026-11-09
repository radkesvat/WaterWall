#include "structure.h"

#include "loggers/network_logger.h"

/* The endpoint grammar deliberately excludes hostnames and scoped addresses.
 * A port suffix applies to both DNS transports; bare addresses inherit the
 * corresponding core UDP/TCP port (53 by default). */
static bool domainresolverValidateEndpoint(const char *endpoint)
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

static bool domainresolverParseServers(domainresolver_tstate_t *ts, const cJSON *servers)
{
    const int count = cJSON_GetArraySize(servers);
    if (! cJSON_IsArray(servers) || count < 1 || count > 32)
    {
        LOGF("JSON Error: DomainResolver->settings->servers requires 1 to 32 numeric DNS endpoints");
        return false;
    }
    size_t total = 1;
    for (int i = 0; i < count; ++i)
    {
        const cJSON *server = cJSON_GetArrayItem(servers, i);
        if (! cJSON_IsString(server) || ! domainresolverValidateEndpoint(server->valuestring))
        {
            LOGF("JSON Error: DomainResolver->settings->servers[%d] must be a numeric IP, IP:port, or [IPv6]:port", i);
            return false;
        }
        total += strlen(server->valuestring) + 1;
    }
    ts->dns_servers = memoryAllocate(total);
    size_t used     = 0;
    for (int i = 0; i < count; ++i)
    {
        const char *endpoint = cJSON_GetArrayItem(servers, i)->valuestring;
        if (i != 0)
            ts->dns_servers[used++] = ',';
        const size_t length = strlen(endpoint);
        memoryCopy(ts->dns_servers + used, endpoint, length);
        used += length;
    }
    ts->dns_servers[used]       = '\0';
    ts->dns_options.servers_csv = ts->dns_servers;
    return true;
}

static bool domainresolverCreateDirectConnector(tunnel_t *t)
{
    domainresolver_tstate_t *ts             = tunnelGetState(t);
    node_t                   connector_node = nodelibraryLoadByTypeName("TcpUdpConnector");
    if (connector_node.createHandle == NULL)
    {
        LOGF("DomainResolver: direct mode requires the TcpUdpConnector node in this build");
        return false;
    }

    // Registry metadata is borrowed; private child metadata has owner lifetime.
    connector_node.type        = stringDuplicate(connector_node.type);
    ts->dns_connector_settings = cJSON_CreateObject();
    cJSON_AddStringToObject(ts->dns_connector_settings, "address", "dest_context->address");
    cJSON_AddStringToObject(ts->dns_connector_settings, "port", "dest_context->port");
    if (! nodeConfigureChild(&ts->dns_connector_node,
                             connector_node,
                             t->node,
                             ".dns-connector",
                             kNodeChildLinkNone,
                             ts->dns_connector_settings))
        return false;

    /* These are fresh connector settings. In particular the connector's own
     * resolver receives its existing native settings, never this node's mode. */
    ts->dns_connector               = nodemanagerCreateTunnelInstance(&ts->dns_connector_node);
    ts->dns_connector_node.instance = ts->dns_connector;
    return ts->dns_connector != NULL;
}

bool domainresolverConfigureTransport(tunnel_t *t, const cJSON *settings)
{
    domainresolver_tstate_t *ts      = tunnelGetState(t);
    const cJSON             *mode    = cJSON_GetObjectItemCaseSensitive(settings, "mode");
    const cJSON             *servers = cJSON_GetObjectItemCaseSensitive(settings, "servers");
    const cJSON             *next    = cJSON_GetObjectItemCaseSensitive(settings, "dns-next");
    if (mode != NULL)
    {
        if (! cJSON_IsString(mode) || mode->valuestring == NULL)
            goto invalid_mode;
        if (strcmp(mode->valuestring, "native") == 0)
            ts->mode = kDomainResolverModeNative;
        else if (strcmp(mode->valuestring, "direct") == 0)
            ts->mode = kDomainResolverModeDirect;
        else if (strcmp(mode->valuestring, "chain") == 0)
            ts->mode = kDomainResolverModeChain;
        else
            goto invalid_mode;
    }
    if (ts->mode == kDomainResolverModeNative)
    {
        if (servers != NULL || next != NULL)
        {
            LOGF("JSON Error: DomainResolver native mode does not accept servers or dns-next");
            return false;
        }
        return true;
    }

    ts->dns_options = GSTATE.dns_options;
    if (! ts->dns_options.defaults_initialized)
        asyncdnsOptionsSetDefaults(&ts->dns_options);
    if (ts->dns_options.socket_send_buffer_size_set || ts->dns_options.socket_receive_buffer_size_set ||
        ts->dns_options.sortlist != NULL || ts->dns_options.resolvconf_path != NULL)
    {
        LOGF("DomainResolver: line DNS modes do not support core DNS socket-buffer-size, sortlist, or resolvconf-path "
             "options");
        return false;
    }
    if (! domainresolverParseServers(ts, servers))
        return false;

    if (ts->mode == kDomainResolverModeChain)
    {
        if (next != NULL)
        {
            if (! cJSON_IsString(next) || next->valuestring == NULL || next->valuestring[0] == '\0')
            {
                LOGF("JSON Error: DomainResolver chain mode dns-next must be a nonempty node name when supplied");
                return false;
            }
            if (t->node->name != NULL && strcmp(next->valuestring, t->node->name) == 0)
            {
                LOGF("DomainResolver: dns-next must not refer to the resolver itself");
                return false;
            }
            ts->dns_next = stringDuplicate(next->valuestring);
        }
        // An omitted DNS entry follows the ordinary next during chain binding.
    }
    else
    {
        if (next != NULL)
        {
            LOGF("JSON Error: DomainResolver direct mode does not accept dns-next");
            return false;
        }
        if (! domainresolverCreateDirectConnector(t))
            return false;
    }
    ts->dns_workers_count = getWorkersCount();
    ts->dns_workers       = memoryCalloc(ts->dns_workers_count, sizeof(*ts->dns_workers));
    ts->dns_worker_closed = memoryCalloc(ts->dns_workers_count, sizeof(*ts->dns_worker_closed));
    return true;

invalid_mode:
    LOGF("JSON Error: DomainResolver->settings->mode must be native, direct, or chain");
    return false;
}
