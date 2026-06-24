#include "structure.h"

#include "DomainResolver/interface.h"

#include "loggers/network_logger.h"

static char *trojanclientMakeChildName(const node_t *node, const char *suffix)
{
    const char *base = node->name != NULL ? node->name : "TrojanClient";
    return stringConcat(base, suffix);
}

static bool trojanclientAddDomainStrategySetting(cJSON *settings, enum domain_strategy strategy)
{
    cJSON *strategy_json = cJSON_AddNumberToObject(settings, "strategy", (double) strategy);
    if (strategy_json == NULL)
    {
        return false;
    }

    strategy_json->valueint    = (int) strategy;
    strategy_json->valuedouble = (double) strategy_json->valueint;
    return true;
}

static cJSON *trojanclientCreateDomainResolverSettings(enum domain_strategy strategy)
{
    cJSON *settings = cJSON_CreateObject();
    if (settings == NULL)
    {
        return NULL;
    }

    if (! trojanclientAddDomainStrategySetting(settings, strategy))
    {
        cJSON_Delete(settings);
        return NULL;
    }

    return settings;
}

static bool trojanclientConfigureDomainSetupNode(node_t *child, const node_t *owner)
{
    memorySet(child, 0, sizeof(*child));

    const char *type_name = "TrojanClientDomainSetup";
    child->name           = trojanclientMakeChildName(owner, ".domain-setup");
    child->type           = stringDuplicate(type_name);
    if (child->name == NULL || child->type == NULL)
    {
        return false;
    }

    child->hash_name             = calcHashBytes(child->name, stringLength(child->name));
    child->hash_type             = calcHashBytes(type_name, stringLength(type_name));
    child->version               = owner->version;
    child->flags                 = kNodeFlagNone;
    child->required_padding_left = 0;
    child->node_json             = owner->node_json;
    child->node_settings_json    = owner->node_settings_json;
    child->node_manager_config   = owner->node_manager_config;
    child->layer_group           = owner->layer_group;
    child->layer_group_next_node = kNodeLayerAnything;
    child->layer_group_prev_node = kNodeLayerAnything;
    child->can_have_next         = true;
    child->can_have_prev         = true;
    return true;
}

static bool trojanclientConfigureDomainResolverNode(node_t *child, node_t template_node, const node_t *owner,
                                                    cJSON *settings)
{
    *child = template_node;

    child->name = trojanclientMakeChildName(owner, ".domain-resolver");
    if (child->name == NULL)
    {
        return false;
    }

    child->hash_name           = calcHashBytes(child->name, stringLength(child->name));
    child->next                = NULL;
    child->hash_next           = 0;
    child->version             = owner->version;
    child->node_json           = owner->node_json;
    child->node_settings_json  = settings;
    child->node_manager_config = owner->node_manager_config;
    child->instance            = NULL;
    return true;
}

static bool trojanclientCreateInternalDomainSetup(tunnel_t *t, node_t *node)
{
    trojanclient_tstate_t *ts = tunnelGetState(t);

    if (! trojanclientConfigureDomainSetupNode(&ts->domain_setup_node, node))
    {
        LOGF("TrojanClient: failed to configure internal domain setup node");
        return false;
    }

    ts->domain_setup_tunnel = tunnelCreate(&ts->domain_setup_node,
                                           sizeof(trojanclient_domain_setup_tstate_t),
                                           sizeof(trojanclient_domain_setup_lstate_t));
    if (ts->domain_setup_tunnel == NULL)
    {
        LOGF("TrojanClient: failed to create internal domain setup tunnel");
        return false;
    }

    trojanclient_domain_setup_tstate_t *setup_ts = tunnelGetState(ts->domain_setup_tunnel);
    setup_ts->client_tunnel                       = t;
    ts->domain_setup_tunnel->fnInitU              = &trojanclientDomainSetupTunnelUpStreamInit;
    ts->domain_setup_tunnel->fnFinU               = &trojanclientDomainSetupTunnelUpStreamFinish;
    ts->domain_setup_tunnel->fnFinD               = &trojanclientDomainSetupTunnelDownStreamFinish;
    ts->domain_setup_node.instance                = ts->domain_setup_tunnel;
    return true;
}

static bool trojanclientCreateInternalDomainResolver(tunnel_t *t, node_t *node)
{
    trojanclient_tstate_t *ts = tunnelGetState(t);

    if (! ts->resolve_domains)
    {
        return true;
    }

    ts->domain_resolver_settings =
        trojanclientCreateDomainResolverSettings((enum domain_strategy) ts->domain_strategy);
    if (ts->domain_resolver_settings == NULL)
    {
        LOGF("TrojanClient: failed to create internal DomainResolver settings");
        return false;
    }

    if (! trojanclientConfigureDomainResolverNode(
            &ts->domain_resolver_node, nodeDomainResolverGet(), node, ts->domain_resolver_settings))
    {
        LOGF("TrojanClient: failed to configure internal DomainResolver node");
        return false;
    }

    ts->domain_resolver_tunnel = ts->domain_resolver_node.createHandle(&ts->domain_resolver_node);
    if (ts->domain_resolver_tunnel == NULL)
    {
        LOGF("TrojanClient: failed to create internal DomainResolver");
        return false;
    }

    domainresolverTunnelUseLineStrategy(ts->domain_resolver_tunnel, true);
    ts->domain_resolver_node.instance = ts->domain_resolver_tunnel;
    return true;
}

static bool trojanclientCreateInternalDomainResolverChain(tunnel_t *t, node_t *node)
{
    return trojanclientCreateInternalDomainSetup(t, node) && trojanclientCreateInternalDomainResolver(t, node);
}

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
            *dest = memoryAllocate(stringLength(node->valuestring) + 1U);
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

static int hexValue(uint8_t c)
{
    if (c >= '0' && c <= '9')
    {
        return (int) (c - '0');
    }

    if (c >= 'a' && c <= 'f')
    {
        return (int) (c - 'a' + 10);
    }

    if (c >= 'A' && c <= 'F')
    {
        return (int) (c - 'A' + 10);
    }

    return -1;
}

static void sha224ToHex(const uint8_t sha224[SHA224_DIGEST_SIZE], uint8_t out[kTrojanClientPasswordHexLen])
{
    static const uint8_t hex[] = "0123456789abcdef";

    for (size_t i = 0; i < SHA224_DIGEST_SIZE; ++i)
    {
        out[i * 2U]      = hex[(sha224[i] >> 4U) & 0x0FU];
        out[i * 2U + 1U] = hex[sha224[i] & 0x0FU];
    }
}

static bool normalizeSha224Hex(const char *hex, uint8_t out[kTrojanClientPasswordHexLen])
{
    if (stringLength(hex) != kTrojanClientPasswordHexLen)
    {
        return false;
    }

    for (size_t i = 0; i < kTrojanClientPasswordHexLen; ++i)
    {
        int value = hexValue((uint8_t) hex[i]);
        if (value < 0)
        {
            return false;
        }

        out[i] = (uint8_t) (value < 10 ? '0' + value : 'a' + value - 10);
    }

    return true;
}

static bool parsePassword(trojanclient_tstate_t *ts, const cJSON *settings)
{
    const cJSON *password_json = getSettingsItemByKeys(settings, "password", "pass", NULL);
    const cJSON *sha224_json   = getSettingsItemByKeys(settings, "sha224", "password-sha224", "password_sha224");

    if (password_json != NULL && sha224_json != NULL)
    {
        LOGF("JSON Error: TrojanClient->settings must use either password or sha224, not both");
        return false;
    }

    if (sha224_json != NULL)
    {
        if (! cJSON_IsString(sha224_json) || sha224_json->valuestring == NULL ||
            ! normalizeSha224Hex(sha224_json->valuestring, ts->password_hex))
        {
            LOGF("JSON Error: TrojanClient->settings->sha224 must be a 56-character hexadecimal SHA224 digest");
            return false;
        }

        return true;
    }

    if (password_json == NULL || ! cJSON_IsString(password_json) || password_json->valuestring == NULL)
    {
        LOGF("JSON Error: TrojanClient->settings->password (string field) is required unless sha224 is provided");
        return false;
    }

    size_t password_len = stringLength(password_json->valuestring);
    if (password_len == 0)
    {
        LOGF("JSON Error: TrojanClient->settings->password must not be empty");
        return false;
    }

    sha224_hash_t digest = {0};
    if (wCryptoSHA224(&digest, (const unsigned char *) password_json->valuestring, password_len) != 0)
    {
        wCryptoZero(&digest, sizeof(digest));
        LOGF("TrojanClient: failed to calculate SHA224 password digest");
        return false;
    }

    sha224ToHex(digest.bytes, ts->password_hex);
    wCryptoZero(&digest, sizeof(digest));
    return true;
}

static bool parseTargetAddress(trojanclient_tstate_t *ts, const cJSON *settings)
{
    const cJSON *address_json = getSettingsItemByKeys(settings, "target-address", "address", "target");
    if (address_json == NULL)
    {
        LOGF("JSON Error: TrojanClient->settings->target-address (string field) is required");
        return false;
    }

    if (! cJSON_IsString(address_json) || address_json->valuestring == NULL)
    {
        LOGF("JSON Error: TrojanClient->settings->target-address must be a string");
        return false;
    }

    const char *address = address_json->valuestring;
    size_t      len     = stringLength(address);

    if (len == 0 || len > UINT8_MAX)
    {
        LOGF("JSON Error: TrojanClient->settings->target-address must be 1..%u bytes", (unsigned int) UINT8_MAX);
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
        addresscontextDomainSet(&ts->target_addr, address, (uint8_t) len);
    }

    return true;
}

static bool parseTargetPort(trojanclient_tstate_t *ts, const cJSON *settings)
{
    const cJSON *port_json = cJSON_GetObjectItemCaseSensitive(settings, "port");
    if (port_json == NULL)
    {
        LOGF("JSON Error: TrojanClient->settings->port is required");
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

        LOGF("JSON Error: TrojanClient->settings->port string supports only \"dest_context->port\"");
        return false;
    }

    if (! cJSON_IsNumber(port_json) || port_json->valueint <= 0 || port_json->valueint > UINT16_MAX)
    {
        LOGF("JSON Error: TrojanClient->settings->port must be a valid number in range [1, %u] or "
             "\"dest_context->port\"",
             (unsigned int) UINT16_MAX);
        return false;
    }

    ts->target_port_source = kDvsConstant;
    addresscontextSetPort(&ts->target_addr, (uint16_t) port_json->valueint);
    return true;
}

static bool parseProtocol(trojanclient_tstate_t *ts, const cJSON *settings)
{
    char *protocol = NULL;
    if (! getOptionalStringFromKeys(&protocol, settings, "protocol", "proto", NULL))
    {
        ts->protocol = kTrojanClientProtocolTcp;
        return true;
    }

    stringLowerCase(protocol);

    if (stringCompare(protocol, "tcp") == 0 || stringCompare(protocol, "connect") == 0)
    {
        ts->protocol = kTrojanClientProtocolTcp;
        memoryFree(protocol);
        return true;
    }

    if (stringCompare(protocol, "udp") == 0 || stringCompare(protocol, "udp-associate") == 0)
    {
        ts->protocol = kTrojanClientProtocolUdp;
        memoryFree(protocol);
        return true;
    }

    if (stringCompare(protocol, "dest_context->protocol") == 0 ||
        stringCompare(protocol, "line->dest_ctx->protocol") == 0)
    {
        ts->protocol = kTrojanClientProtocolDestContext;
        memoryFree(protocol);
        return true;
    }

    LOGF("JSON Error: TrojanClient->settings->protocol supports only \"tcp\", \"udp\", or "
         "\"dest_context->protocol\"");
    memoryFree(protocol);
    return false;
}

static bool parseDomainStrategy(trojanclient_tstate_t *ts, const cJSON *settings)
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
        LOGF("JSON Error: TrojanClient->settings->domain-strategy must be a non-empty string");
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

    LOGF("JSON Error: TrojanClient->settings->domain-strategy has an unsupported value");
    return false;
}

tunnel_t *trojanclientTunnelCreate(node_t *node)
{
    tunnel_t              *t        = tunnelCreate(node, sizeof(trojanclient_tstate_t), sizeof(trojanclient_lstate_t));
    trojanclient_tstate_t *ts       = tunnelGetState(t);
    const cJSON           *settings = node->node_settings_json;

    t->fnInitU    = &trojanclientTunnelUpStreamInit;
    t->fnEstU     = &trojanclientTunnelUpStreamEst;
    t->fnFinU     = &trojanclientTunnelUpStreamFinish;
    t->fnPayloadU = &trojanclientTunnelUpStreamPayload;
    t->fnPauseU   = &trojanclientTunnelUpStreamPause;
    t->fnResumeU  = &trojanclientTunnelUpStreamResume;

    t->fnInitD    = &trojanclientTunnelDownStreamInit;
    t->fnEstD     = &trojanclientTunnelDownStreamEst;
    t->fnFinD     = &trojanclientTunnelDownStreamFinish;
    t->fnPayloadD = &trojanclientTunnelDownStreamPayload;
    t->fnPauseD   = &trojanclientTunnelDownStreamPause;
    t->fnResumeD  = &trojanclientTunnelDownStreamResume;

    t->onPrepare = &trojanclientTunnelOnPrepair;
    t->onChain   = &trojanclientTunnelOnChain;
    t->onStart   = &trojanclientTunnelOnStart;
    t->onStop    = &trojanclientTunnelOnStop;
    t->onDestroy = &trojanclientTunnelDestroy;

    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: TrojanClient->settings (object field) : The object was empty or invalid");
        tunnelDestroy(t);
        return NULL;
    }

    getBoolFromJsonObjectOrDefault(&ts->verbose, settings, "verbose", false);

    if (! parsePassword(ts, settings) || ! parseTargetAddress(ts, settings) || ! parseTargetPort(ts, settings) ||
        ! parseProtocol(ts, settings) || ! parseDomainStrategy(ts, settings))
    {
        trojanclientTunnelstateDestroy(ts);
        tunnelDestroy(t);
        return NULL;
    }

    if (! trojanclientCreateInternalDomainResolverChain(t, node))
    {
        trojanclientTunnelDestroy(t);
        return NULL;
    }

    return t;
}
