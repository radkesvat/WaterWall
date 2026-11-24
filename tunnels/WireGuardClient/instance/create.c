#include "loggers/network_logger.h"
#include "structure.h"

/* The packet line and owned carrier have independent lifecycles. */
static void absorb(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
}

static bool endpointParse(address_context_t *endpoint, const cJSON *value)
{
    if (! cJSON_IsString(value) || value->valuestring == NULL)
        return false;

    const char *host_start = value->valuestring;
    const bool  ipv6       = *host_start == '[';
    const char *host_end;
    const char *port_text;
    if (ipv6)
    {
        ++host_start;
        host_end = strchr(host_start, ']');
        if (host_end == NULL || host_end[1] != ':')
            return false;
        port_text = host_end + 2;
    }
    else
    {
        host_end = host_start + strcspn(host_start, ":[]");
        if (*host_end != ':')
            return false;
        port_text = host_end + 1;
    }

    const size_t length = (size_t) (host_end - host_start);
    if (length == 0 || length > UINT8_MAX)
        return false;
    uint32_t port = 0;
    for (const char *p = port_text; *p != '\0'; ++p)
    {
        if (*p < '0' || *p > '9')
            return false;
        port = port * 10U + (uint32_t) (*p - '0');
        if (port > UINT16_MAX)
            return false;
    }
    if (port == 0)
        return false;

    char host[UINT8_MAX + 1];
    memoryCopy(host, host_start, length);
    host[length] = '\0';
    if (ipv6)
    {
        ip_addr_t ip = {.type = IPADDR_TYPE_V6};
#ifdef OS_WIN
        WSAInit();
#endif
        if (inet_pton(AF_INET6, host, ip.u_addr.ip6.addr) != 1)
            return false;
        addresscontextSetIp(endpoint, &ip);
    }
    else if (! addresscontextSetIpAddress(endpoint, host))
        addresscontextDomainSet(endpoint, host, (uint8_t) length);

    addresscontextSetPort(endpoint, (uint16_t) port);
    addresscontextSetOnlyProtocol(endpoint, IP_PROTO_UDP);
    return true;
}

tunnel_t *wireguardclientTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(wireguardclient_tstate_t), sizeof(wireguardclient_carrier_phase_t));
    if (t == NULL)
        return NULL;
    wireguardclient_tstate_t *state = tunnelGetState(t);
    state->tunnel                   = t;
    wireguardDispatchInit(&state->dispatch);
    const cJSON *settings = node->node_settings_json;
    const cJSON *key      = cJSON_GetObjectItemCaseSensitive(settings, "privatekey");
    const cJSON *peers    = cJSON_GetObjectItemCaseSensitive(settings, "peers");
    size_t       index    = 0;
    if (! jsonObjectFieldStringsAreExact(settings, "privatekey") || ! cJSON_IsString(key) || ! cJSON_IsArray(peers) ||
        cJSON_GetArraySize(peers) != 1 ||
        ! wireguardCommonInit(&state->engine, key->valuestring, state, wireguardclientEngineCallbacks) ||
        ! wireguardCommonConfigureMtu(&state->engine, settings) ||
        ! wireguardCommonAddConfiguredPeer(&state->engine, cJSON_GetArrayItem(peers, 0), &index) ||
        ! jsonObjectFieldStringsAreExact(cJSON_GetArrayItem(peers, 0), "endpoint") ||
        ! endpointParse(&state->endpoint, cJSON_GetObjectItemCaseSensitive(cJSON_GetArrayItem(peers, 0), "endpoint")))
    {
        LOGF("WireGuardClient: requires privatekey and exactly one peer with publickey, allowedips and endpoint "
             "host:port or [IPv6]:port; optional mtu must be an integer between 68 and 65535");
        wireguardclientTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }
    t->fnInitU          = absorb;
    t->fnEstU           = absorb;
    t->fnEstD           = absorb;
    t->fnPauseU         = absorb;
    t->fnPauseD         = wireguardclientTunnelDownStreamPause;
    t->fnResumeU        = absorb;
    t->fnResumeD        = wireguardclientTunnelDownStreamResume;
    t->fnFinU           = wireguardclientTunnelUpStreamFinish;
    t->fnFinD           = wireguardclientTunnelDownStreamFinish;
    t->fnPayloadU       = wireguardclientTunnelUpStreamPayload;
    t->fnPayloadD       = wireguardclientTunnelDownStreamPayload;
    t->onStart          = wireguardclientTunnelOnStart;
    t->onQuiesceRequest = wireguardclientTunnelOnQuiesceRequest;
    t->onWorkerQuiesce  = wireguardclientTunnelOnWorkerQuiesce;
    t->onWorkerStop     = wireguardclientTunnelOnWorkerStop;
    t->onDestroy        = wireguardclientTunnelDestroy;
    return t;
}
