#include "structure.h"

#include "loggers/network_logger.h"

static bool getOptionalStringFromKeys(char **dest, const cJSON *settings, const char *key1, const char *key2,
                                      const char *key3)
{
    const char *keys[3] = {key1, key2, key3};

    for (size_t i = 0; i < ARRAY_SIZE(keys); i++)
    {
        if (keys[i] == NULL)
        {
            continue;
        }

        const cJSON *node = cJSON_GetObjectItemCaseSensitive(settings, keys[i]);
        if (cJSON_IsString(node) && node->valuestring != NULL)
        {
            *dest = memoryAllocate(stringLength(node->valuestring) + 1);
            stringCopy(*dest, node->valuestring);
            return true;
        }
    }

    return false;
}

static const cJSON *getSettingsItemByKeys(const cJSON *settings, const char *key1, const char *key2, const char *key3)
{
    const char *keys[3] = {key1, key2, key3};

    for (size_t i = 0; i < ARRAY_SIZE(keys); i++)
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

static bool parseTargetAddress(socks5client_tstate_t *ts, const cJSON *settings)
{
    const cJSON *address_json = getSettingsItemByKeys(settings, "target-address", "address", "target");
    if (address_json == NULL)
    {
        LOGF("JSON Error: Socks5Client->settings->target-address (string field) is required");
        return false;
    }

    if (! cJSON_IsString(address_json) || address_json->valuestring == NULL)
    {
        LOGF("JSON Error: Socks5Client->settings->target-address must be a string");
        return false;
    }

    const char *address = address_json->valuestring;

    if (stringLength(address) == 0)
    {
        LOGF("JSON Error: Socks5Client->settings->target-address must not be empty");
        return false;
    }

    if (stringCompare(address, "dest_context->address") == 0 || stringCompare(address, "line->dest_ctx->address") == 0)
    {
        ts->target_addr_source = kDvsFirstOption;
        return true;
    }

    ts->target_addr_source = kDvsConstant;

    if (! addresscontextSetIpAddress(&ts->target_addr, address))
    {
        addresscontextDomainSet(&ts->target_addr, address, (uint8_t) stringLength(address));
    }

    return true;
}

static bool parseTargetPort(socks5client_tstate_t *ts, const cJSON *settings)
{
    const cJSON *port_json = cJSON_GetObjectItemCaseSensitive(settings, "port");
    if (port_json == NULL)
    {
        LOGF("JSON Error: Socks5Client->settings->port is required");
        return false;
    }

    if (cJSON_IsString(port_json) && port_json->valuestring != NULL)
    {
        if (stringCompare(port_json->valuestring, "dest_context->port") == 0 ||
            stringCompare(port_json->valuestring, "line->dest_ctx->port") == 0)
        {
            ts->target_port_source = kDvsFirstOption;
            return true;
        }

        LOGF("JSON Error: Socks5Client->settings->port string supports only \"dest_context->port\"");
        return false;
    }

    if (! cJSON_IsNumber(port_json) || port_json->valueint <= 0 || port_json->valueint > UINT16_MAX)
    {
        LOGF("JSON Error: Socks5Client->settings->port must be a valid number in range [1, %u] or "
             "\"dest_context->port\"",
             (unsigned int) UINT16_MAX);
        return false;
    }

    ts->target_port_source = kDvsConstant;
    addresscontextSetPort(&ts->target_addr, (uint16_t) port_json->valueint);
    return true;
}

static bool parseProtocol(socks5client_tstate_t *ts, const cJSON *settings)
{
    char *protocol = NULL;
    if (! getOptionalStringFromKeys(&protocol, settings, "protocol", "proto", NULL))
    {
        ts->protocol = kSocks5ClientProtocolTcp;
        return true;
    }

    stringLowerCase(protocol);

    if (stringCompare(protocol, "tcp") == 0 || stringCompare(protocol, "connect") == 0)
    {
        ts->protocol = kSocks5ClientProtocolTcp;
        memoryFree(protocol);
        return true;
    }

    if (stringCompare(protocol, "udp") == 0 || stringCompare(protocol, "udp-associate") == 0)
    {
        ts->protocol = kSocks5ClientProtocolUdp;
        memoryFree(protocol);
        return true;
    }

    if (stringCompare(protocol, "dest_context->protocol") == 0 ||
        stringCompare(protocol, "line->dest_ctx->protocol") == 0)
    {
        ts->protocol = kSocks5ClientProtocolDestContext;
        memoryFree(protocol);
        return true;
    }

    LOGF("JSON Error: Socks5Client->settings->protocol supports only \"tcp\", \"udp\", or "
         "\"dest_context->protocol\"");
    memoryFree(protocol);
    return false;
}

static bool parseCredentials(socks5client_tstate_t *ts, const cJSON *settings)
{
    char *user = NULL;
    char *pass = NULL;

    getOptionalStringFromKeys(&user, settings, "user", "username", NULL);
    getOptionalStringFromKeys(&pass, settings, "pass", "password", NULL);

    if ((user == NULL) != (pass == NULL))
    {
        memoryFree(user);
        memoryFree(pass);
        LOGF("JSON Error: Socks5Client username and password must be provided together");
        return false;
    }

    if (user == NULL)
    {
        return true;
    }

    size_t user_len = stringLength(user);
    size_t pass_len = stringLength(pass);

    if (user_len == 0 || pass_len == 0 || user_len > UINT8_MAX || pass_len > UINT8_MAX)
    {
        memoryFree(user);
        memorySet(pass, 0, pass_len);
        memoryFree(pass);
        LOGF("JSON Error: Socks5Client credentials must be non-empty and at most %u bytes each",
             (unsigned int) UINT8_MAX);
        return false;
    }

    ts->username     = user;
    ts->password     = pass;
    ts->username_len = (uint8_t) user_len;
    ts->password_len = (uint8_t) pass_len;

    return true;
}

static bool parseDomainStrategy(socks5client_tstate_t *ts, const cJSON *settings)
{
    const cJSON *strategy_json = cJSON_GetObjectItemCaseSensitive(settings, "domain-strategy");

    ts->resolve_domains = false;
    ts->domain_strategy = kDsInvalid;

    if (strategy_json == NULL)
    {
        return true;
    }

    if (! cJSON_IsString(strategy_json) || strategy_json->valuestring == NULL || strategy_json->valuestring[0] == '\0')
    {
        LOGF("JSON Error: Socks5Client->settings->domain-strategy must be a non-empty string");
        return false;
    }

    const char *strategy = strategy_json->valuestring;

    if (stricmp(strategy, "do-not-resolve-domains") == 0)
    {
        ts->resolve_domains = false;
        return true;
    }

    ts->resolve_domains = true;

    if (stricmp(strategy, "resolve-domains-with-core-settings") == 0)
    {
        ts->domain_strategy = GSTATE.domain_strategy;
        return true;
    }
    if (stricmp(strategy, "resolve-domains-and-accept-dns-returned-order") == 0)
    {
        ts->domain_strategy = kDsInvalid;
        return true;
    }
    if (stricmp(strategy, "resolve-domains-and-prefer-ipv4") == 0)
    {
        ts->domain_strategy = kDsPreferIpV4;
        return true;
    }
    if (stricmp(strategy, "resolve-domains-and-prefer-ipv6") == 0)
    {
        ts->domain_strategy = kDsPreferIpV6;
        return true;
    }
    if (stricmp(strategy, "resolve-domains-and-use-only-ipv4") == 0)
    {
        ts->domain_strategy = kDsOnlyIpV4;
        return true;
    }
    if (stricmp(strategy, "resolve-domains-and-use-only-ipv6") == 0)
    {
        ts->domain_strategy = kDsOnlyIpV6;
        return true;
    }

    LOGF("JSON Error: Socks5Client->settings->domain-strategy has an unsupported value");
    return false;
}

tunnel_t *socks5clientTunnelCreate(node_t *node)
{
    tunnel_t              *t        = tunnelCreate(node, sizeof(socks5client_tstate_t), sizeof(socks5client_lstate_t));
    socks5client_tstate_t *ts       = tunnelGetState(t);
    const cJSON           *settings = node->node_settings_json;

    t->fnInitU    = &socks5clientTunnelUpStreamInit;
    t->fnEstU     = &socks5clientTunnelUpStreamEst;
    t->fnFinU     = &socks5clientTunnelUpStreamFinish;
    t->fnPayloadU = &socks5clientTunnelUpStreamPayload;
    t->fnPauseU   = &socks5clientTunnelUpStreamPause;
    t->fnResumeU  = &socks5clientTunnelUpStreamResume;

    t->fnInitD    = &socks5clientTunnelDownStreamInit;
    t->fnEstD     = &socks5clientTunnelDownStreamEst;
    t->fnFinD     = &socks5clientTunnelDownStreamFinish;
    t->fnPayloadD = &socks5clientTunnelDownStreamPayload;
    t->fnPauseD   = &socks5clientTunnelDownStreamPause;
    t->fnResumeD  = &socks5clientTunnelDownStreamResume;

    t->onPrepare = &socks5clientTunnelOnPrepair;
    t->onStart   = &socks5clientTunnelOnStart;
    t->onStop    = &socks5clientTunnelOnStop;
    t->onDestroy = &socks5clientTunnelDestroy;

    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: Socks5Client->settings (object field) : The object was empty or invalid");
        tunnelDestroy(t);
        return NULL;
    }

    getBoolFromJsonObjectOrDefault(&ts->verbose, settings, "verbose", false);

    if (! parseTargetAddress(ts, settings) || ! parseTargetPort(ts, settings) || ! parseProtocol(ts, settings) ||
        ! parseCredentials(ts, settings) || ! parseDomainStrategy(ts, settings))
    {
        socks5clientTunnelstateDestroy(ts);
        tunnelDestroy(t);
        return NULL;
    }

    return t;
}
