#include "structure.h"

#include "loggers/network_logger.h"

static const cJSON *getSettingsItemByKeys(const cJSON *settings, const char *key1, const char *key2)
{
    const char *keys[2] = {key1, key2};

    for (size_t i = 0; i < ARRAY_SIZE(keys); ++i)
    {
        if (keys[i] == NULL)
        {
            continue;
        }

        const cJSON *item = cJSON_GetObjectItemCaseSensitive(settings, keys[i]);
        if (item != NULL)
        {
            return item;
        }
    }

    return NULL;
}

static hash_t socks5serverAuthenticationClientTypeHash(void)
{
    const char *type_name = "AuthenticationClient";
    return calcHashBytes(type_name, stringLength(type_name));
}

static bool rejectLegacyAuthSettings(const cJSON *settings)
{
    const char *legacy_keys[] = {"username", "password", "users", "accounts"};

    for (size_t i = 0; i < ARRAY_SIZE(legacy_keys); ++i)
    {
        if (cJSON_GetObjectItemCaseSensitive(settings, legacy_keys[i]) != NULL)
        {
            LOGF("JSON Error: Socks5Server->settings->%s is no longer supported; use auth-client-node-name",
                 legacy_keys[i]);
            return false;
        }
    }

    return true;
}

static bool parseAuthClientNode(socks5server_tstate_t *ts, node_t *node, const cJSON *settings)
{
    char *auth_client_node_name = NULL;

    if (! getStringFromJsonObject(&auth_client_node_name, settings, "auth-client-node-name") ||
        auth_client_node_name[0] == '\0')
    {
        memoryFree(auth_client_node_name);
        LOGF("JSON Error: Socks5Server->settings->auth-client-node-name (string field) is required");
        return false;
    }

    node_t *auth_client_node = nodemanagerGetConfigNodeByName(node->node_manager_config, auth_client_node_name);
    if (auth_client_node == NULL)
    {
        LOGF("Socks5Server: auth-client-node-name \"%s\" was not found", auth_client_node_name);
        memoryFree(auth_client_node_name);
        return false;
    }

    if (auth_client_node == node)
    {
        LOGF("Socks5Server: auth-client-node-name must not point back to Socks5Server itself");
        memoryFree(auth_client_node_name);
        return false;
    }

    if (auth_client_node->hash_type != socks5serverAuthenticationClientTypeHash())
    {
        LOGF("Socks5Server: auth-client-node-name \"%s\" must point to an AuthenticationClient node",
             auth_client_node_name);
        memoryFree(auth_client_node_name);
        return false;
    }

    ts->auth_client_node = auth_client_node;
    memoryFree(auth_client_node_name);
    return true;
}

static bool parseUdpReplyAddress(socks5server_tstate_t *ts, const cJSON *settings)
{
    const cJSON *ipv4_json = getSettingsItemByKeys(settings, "ipv4", "udp-ipv4");

    if (! ts->allow_udp)
    {
        return true;
    }

    if (! cJSON_IsString(ipv4_json) || ipv4_json->valuestring == NULL)
    {
        LOGF("JSON Error: Socks5Server->settings->ipv4 is required when udp is enabled");
        return false;
    }

    if (! ip4addr_aton(ipv4_json->valuestring, ip_2_ip4(&ts->udp_reply_ip)))
    {
        LOGF("JSON Error: Socks5Server->settings->ipv4 must be a valid IPv4 address");
        return false;
    }

    ts->udp_reply_ip.type = IPADDR_TYPE_V4;
    ts->udp_reply_ipv4    = stringDuplicate(ipv4_json->valuestring);
    return true;
}

tunnel_t *socks5serverTunnelCreate(node_t *node)
{
    tunnel_t              *t        = tunnelCreate(node, sizeof(socks5server_tstate_t), sizeof(socks5server_lstate_t));
    socks5server_tstate_t *ts       = tunnelGetState(t);
    const cJSON           *settings = node->node_settings_json;

    t->fnInitU    = &socks5serverTunnelUpStreamInit;
    t->fnEstU     = &socks5serverTunnelUpStreamEst;
    t->fnFinU     = &socks5serverTunnelUpStreamFinish;
    t->fnPayloadU = &socks5serverTunnelUpStreamPayload;
    t->fnPauseU   = &socks5serverTunnelUpStreamPause;
    t->fnResumeU  = &socks5serverTunnelUpStreamResume;

    t->fnInitD    = &socks5serverTunnelDownStreamInit;
    t->fnEstD     = &socks5serverTunnelDownStreamEst;
    t->fnFinD     = &socks5serverTunnelDownStreamFinish;
    t->fnPayloadD = &socks5serverTunnelDownStreamPayload;
    t->fnPauseD   = &socks5serverTunnelDownStreamPause;
    t->fnResumeD  = &socks5serverTunnelDownStreamResume;

    t->onPrepare = &socks5serverTunnelOnPrepair;
    t->onStart   = &socks5serverTunnelOnStart;
    t->onStop    = &socks5serverTunnelOnStop;
    t->onDestroy = &socks5serverTunnelDestroy;

    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: Socks5Server->settings (object field) : The object was empty or invalid");
        tunnelDestroy(t);
        return NULL;
    }

    ts->allow_connect = true;
    ts->allow_udp     = false;
    getBoolFromJsonObjectOrDefault(&ts->allow_connect, settings, "connect", true);
    getBoolFromJsonObjectOrDefault(&ts->allow_udp, settings, "udp", false);
    getBoolFromJsonObjectOrDefault(&ts->verbose, settings, "verbose", false);

    if (! rejectLegacyAuthSettings(settings) || ! parseAuthClientNode(ts, node, settings) ||
        ! parseUdpReplyAddress(ts, settings))
    {
        socks5serverTunnelstateDestroy(ts);
        tunnelDestroy(t);
        return NULL;
    }

    if (! ts->allow_connect && ! ts->allow_udp)
    {
        LOGF("JSON Error: Socks5Server must enable at least one of connect/udp");
        socks5serverTunnelstateDestroy(ts);
        tunnelDestroy(t);
        return NULL;
    }

    return t;
}
