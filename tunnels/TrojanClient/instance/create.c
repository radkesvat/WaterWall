#include "structure.h"

#include "DomainResolver/interface.h"

#include "loggers/network_logger.h"

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

    if (! nodeConfigureChild(&ts->domain_resolver_node,
                             nodeDomainResolverGet(),
                             node,
                             ".domain-resolver",
                             kNodeChildLinkNone,
                             ts->domain_resolver_settings))
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
    domainresolverTunnelSetPrepareHook(ts->domain_resolver_tunnel,
                                       t,
                                       sizeof(trojanclient_domain_resolver_lstate_t),
                                       trojanclientDomainResolverPrepare,
                                       NULL);
    ts->domain_resolver_node.instance = ts->domain_resolver_tunnel;
    return true;
}

static bool normalizeSha224Hex(const char *hex, uint8_t out[kTrojanClientPasswordHexLen])
{
    if (stringLength(hex) != kTrojanClientPasswordHexLen)
    {
        return false;
    }

    return asciiHexNormalizeLower((const uint8_t *) hex, kTrojanClientPasswordHexLen, out);
}

static bool parsePassword(trojanclient_tstate_t *ts, const cJSON *settings)
{
    const cJSON *password_json = getJsonObjectItemByKeys(settings, "password", "pass", NULL);
    const cJSON *sha224_json   = getJsonObjectItemByKeys(settings, "sha224", "password-sha224", "password_sha224");

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

    asciiHexEncodeBytesLower(digest.bytes, SHA224_DIGEST_SIZE, ts->password_hex);
    wCryptoZero(&digest, sizeof(digest));
    return true;
}

static bool parseTargetAddress(trojanclient_tstate_t *ts, const cJSON *settings)
{
    const cJSON *address_json = getJsonObjectItemByKeys(settings, "target-address", "address", "target");
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
    if (! getStringFromJsonObjectByKeys(&protocol, settings, "protocol", "proto", NULL))
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

    if (! trojanclientCreateInternalDomainResolver(t, node))
    {
        trojanclientTunnelDestroy(t);
        return NULL;
    }

    return t;
}
