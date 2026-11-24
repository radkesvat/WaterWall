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
    char *text = stringDuplicate(value->valuestring), *host = text, *colon = strrchr(text, ':');
    bool  result = false;
    if (colon == NULL)
        goto finish;
    *colon++ = '\0';
    char         *end;
    unsigned long port = strtoul(colon, &end, 10);
    if (*colon == '\0' || *end != '\0' || port == 0 || port > UINT16_MAX)
        goto finish;
    size_t length = strlen(host);
    if (length >= 2 && host[0] == '[' && host[length - 1] == ']')
    {
        host[length - 1] = '\0';
        ++host;
        length -= 2;
    }
    if (length == 0 || length > UINT8_MAX)
        goto finish;
    if (! addresscontextSetIpAddress(endpoint, host))
        addresscontextDomainSet(endpoint, host, (uint8_t) length);
    addresscontextSetPort(endpoint, (uint16_t) port);
    addresscontextSetOnlyProtocol(endpoint, IP_PROTO_UDP);
    result = true;
finish:
    memoryFree(text);
    return result;
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
             "host:port; optional mtu must be an integer between 68 and 65535");
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
