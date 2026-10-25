#include "internal.h"

#include "DomainResolver/interface.h"

#include "loggers/network_logger.h"

static bool vmessclientCreateInternalDomainResolver(tunnel_t *t, node_t *node)
{
    vmessclient_tstate_t *ts = tunnelGetState(t);

    if (! ts->resolve_domains)
    {
        return true;
    }

    ts->domain_resolver_settings = cJSON_CreateObject();
    cJSON_AddNumberToObject(ts->domain_resolver_settings, "strategy", (double) ts->domain_strategy);

    if (! nodeConfigureChild(&ts->domain_resolver_node,
                             nodeDomainResolverGet(),
                             node,
                             ".domain-resolver",
                             kNodeChildLinkNone,
                             ts->domain_resolver_settings))
    {
        LOGF("VmessClient: failed to configure internal DomainResolver node");
        return false;
    }

    ts->domain_resolver_tunnel = nodemanagerCreateTunnelInstance(&ts->domain_resolver_node);
    if (ts->domain_resolver_tunnel == NULL)
    {
        LOGF("VmessClient: failed to create internal DomainResolver");
        return false;
    }

    domainresolverTunnelUseLineStrategy(ts->domain_resolver_tunnel, true);
    domainresolverTunnelSetPrepareHook(ts->domain_resolver_tunnel, t, 0, vmessclientDomainResolverPrepare, NULL);
    ts->domain_resolver_node.instance = ts->domain_resolver_tunnel;
    return true;
}

static bool parseUuid(vmessclient_tstate_t *ts, const cJSON *settings)
{
    const cJSON *uuid_json = getJsonObjectItemByKeys(settings, "uuid", "id", "user-id");

    if (! cJSON_IsString(uuid_json) || uuid_json->valuestring == NULL || uuid_json->valuestring[0] == '\0')
    {
        LOGF("JSON Error: VmessClient->settings->uuid (string field) is required");
        return false;
    }

    if (vmessNormalizeId(uuid_json->valuestring, strlen(uuid_json->valuestring), ts->uuid) != kWCryptoOk)
    {
        LOGF("JSON Error: VmessClient->settings->uuid must be a UUID or a nonempty UTF-8 ID of at most 30 bytes");
        return false;
    }

    return true;
}

static bool parseTargetAddress(vmessclient_tstate_t *ts, const cJSON *settings)
{
    const cJSON *address_json = getJsonObjectItemByKeys(settings, "target-address", "address", "target");
    if (address_json == NULL)
    {
        LOGF("JSON Error: VmessClient->settings->target-address (string field) is required");
        return false;
    }

    if (! cJSON_IsString(address_json) || address_json->valuestring == NULL)
    {
        LOGF("JSON Error: VmessClient->settings->target-address must be a string");
        return false;
    }

    const char *address = address_json->valuestring;
    size_t      len     = stringLength(address);

    if (len == 0 || len > UINT8_MAX)
    {
        LOGF("JSON Error: VmessClient->settings->target-address must be 1..%u bytes", (unsigned int) UINT8_MAX);
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

static bool parseTargetPort(vmessclient_tstate_t *ts, const cJSON *settings)
{
    const cJSON *port_json = cJSON_GetObjectItemCaseSensitive(settings, "port");
    if (port_json == NULL)
    {
        LOGF("JSON Error: VmessClient->settings->port is required");
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

        LOGF("JSON Error: VmessClient->settings->port string supports only \"dest_context->port\"");
        return false;
    }

    int64_t val = 0;
    if (! jsonGetIntegerInRange(port_json, 1, UINT16_MAX, &val))
    {
        LOGF("JSON Error: VmessClient->settings->port must be a valid number in range [1, %u] or "
             "\"dest_context->port\"",
             (unsigned int) UINT16_MAX);
        return false;
    }

    ts->target_port_source = kDvsConstant;
    addresscontextSetPort(&ts->target_addr, (uint16_t) val);
    return true;
}

static bool parseProtocol(vmessclient_tstate_t *ts, const cJSON *settings)
{
    const cJSON *value = getJsonObjectItemByKeys(settings, "protocol", "proto", NULL);
    ts->protocol       = kVmessClientProtocolTcp;
    if (value == NULL)
        return true;
    if (! cJSON_IsString(value) || value->valuestring == NULL)
        return false;
    const char *protocol = value->valuestring;
    if (stricmp(protocol, "tcp") == 0 || stricmp(protocol, "connect") == 0)
        ts->protocol = kVmessClientProtocolTcp;
    else if (stricmp(protocol, "udp") == 0 || stricmp(protocol, "udp-associate") == 0)
        ts->protocol = kVmessClientProtocolUdp;
    else if (stricmp(protocol, "dest_context->protocol") == 0 || stricmp(protocol, "line->dest_ctx->protocol") == 0)
        ts->protocol = kVmessClientProtocolDestContext;
    else
        return false;
    return true;
}

static bool parseDomainStrategy(vmessclient_tstate_t *ts, const cJSON *settings)
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
        LOGF("JSON Error: VmessClient->settings->domain-strategy must be a non-empty string");
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

    LOGF("JSON Error: VmessClient->settings->domain-strategy has an unsupported value");
    return false;
}

static bool parseFirstPayloadTimeout(vmessclient_tstate_t *ts, const cJSON *settings)
{
    const cJSON *value   = cJSON_GetObjectItemCaseSensitive(settings, "first-payload-timeout-ms");
    int64_t      timeout = 400;
    if (value != NULL && ! jsonGetIntegerInRange(value, 0, UINT32_MAX, &timeout))
    {
        LOGF("JSON Error: VmessClient->settings->first-payload-timeout-ms must be an integer in [0, 4294967295]");
        return false;
    }
    ts->first_payload_timeout_ms = (uint32_t) timeout;
    return true;
}

/* Reject unknown settings, duplicate keys and ambiguous aliases before interpreting values. */
static bool validateSettings(const cJSON *settings)
{
    static const char *names[]     = {"uuid",
                                      "id",
                                      "user-id",
                                      "target-address",
                                      "address",
                                      "target",
                                      "port",
                                      "protocol",
                                      "proto",
                                      "domain-strategy",
                                      "first-payload-timeout-ms",
                                      "security",
                                      "encrypted-counter-policy",
                                      "send-termination",
                                      "packet-encoding",
                                      "chunk-masking",
                                      "global-padding",
                                      "authenticated-length",
                                      "verbose"};
    unsigned           credentials = 0, addresses = 0, protocols = 0;
    for (const cJSON *item = settings->child; item != NULL; item = item->next)
    {
        bool known = false;
        for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
            known |= stringCompare(item->string, names[i]) == 0;
        if (! known || ! jsonObjectFieldStringsAreExact(settings, item->string))
            return false;
        for (const cJSON *prior = settings->child; prior != item; prior = prior->next)
            if (stringCompare(prior->string, item->string) == 0)
                return false;
        credentials += stringCompare(item->string, "uuid") == 0 || stringCompare(item->string, "id") == 0 ||
                       stringCompare(item->string, "user-id") == 0;
        addresses += stringCompare(item->string, "target-address") == 0 ||
                     stringCompare(item->string, "address") == 0 || stringCompare(item->string, "target") == 0;
        protocols += stringCompare(item->string, "protocol") == 0 || stringCompare(item->string, "proto") == 0;
    }
    return credentials == 1 && addresses == 1 && protocols <= 1;
}

static bool parseBoolean(const cJSON *settings, const char *name, bool fallback, bool *result)
{
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(settings, name);
    if (value != NULL && ! cJSON_IsBool(value))
        return false;
    *result = value == NULL ? fallback : cJSON_IsTrue(value);
    return true;
}

static bool parseSecurity(vmessclient_tstate_t *ts, const cJSON *settings)
{
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(settings, "security");
    bool         zero  = false;
    ts->security       = VMESS_SECURITY_AES128_GCM;
    if (value != NULL)
    {
        if (! cJSON_IsString(value) || value->valuestring == NULL)
            return false;
        const char *name = value->valuestring;
        if (stricmp(name, "aes-128-gcm") == 0)
            ts->security = VMESS_SECURITY_AES128_GCM;
        else if (stricmp(name, "auto") == 0)
        {
            ts->security_auto = true;
            if (vmessAutoSecurity(&ts->security) != kWCryptoOk)
                return false;
        }
        else if (stricmp(name, "chacha20-poly1305") == 0)
            ts->security = VMESS_SECURITY_CHACHA20_POLY1305;
        else if (stricmp(name, "none") == 0 || stricmp(name, "zero") == 0)
        {
            ts->security = VMESS_SECURITY_NONE;
            zero         = stricmp(name, "zero") == 0;
        }
        else
            return false;
    }
    bool encrypted = ts->security != VMESS_SECURITY_NONE;
    bool mask, padding, auth_length;
    if (! parseBoolean(settings, "chunk-masking", ! zero, &mask) ||
        ! parseBoolean(settings, "global-padding", encrypted, &padding) ||
        ! parseBoolean(settings, "authenticated-length", false, &auth_length) ||
        ! parseBoolean(settings, "verbose", false, &ts->verbose) ||
        ! parseBoolean(settings, "send-termination", true, &ts->send_termination))
        return false;
    ts->options = (zero ? 0 : VMESS_OPTION_CHUNK) | (mask ? VMESS_OPTION_MASK : 0) |
                  (padding ? VMESS_OPTION_PADDING : 0) | (auth_length ? VMESS_OPTION_AUTH_LENGTH : 0);
    if ((zero && ts->options != 0) ||
        (ts->protocol == kVmessClientProtocolTcp && ! vmessModeValid(ts->security, ts->options, 1)) ||
        (ts->protocol == kVmessClientProtocolUdp && ! vmessModeValid(ts->security, ts->options, 2)) ||
        (ts->protocol == kVmessClientProtocolDestContext && ! vmessModeValid(ts->security, ts->options, 1) &&
         ! vmessModeValid(ts->security, ts->options, 2)))
        return false;
    if (! vmessCipherAvailable(ts->security))
    {
        LOGF("VmessClient: configured body cipher is unavailable from the VMess crypto provider");
        return false;
    }
    return vmessPrepareKey(ts->uuid, &ts->key) == kWCryptoOk;
}

static bool parseMaturityOptions(vmessclient_tstate_t *ts, const cJSON *settings)
{
    ts->counter_policy  = kVmessCounterWrap;
    const cJSON *policy = cJSON_GetObjectItemCaseSensitive(settings, "encrypted-counter-policy");
    if (policy != NULL)
    {
        if (! cJSON_IsString(policy) || policy->valuestring == NULL)
            return false;
        if (strcmp(policy->valuestring, "strict") == 0)
            ts->counter_policy = kVmessCounterStrict;
        else if (strcmp(policy->valuestring, "wrap") != 0)
            return false;
    }
    const cJSON *encoding = cJSON_GetObjectItemCaseSensitive(settings, "packet-encoding");
    if (encoding != NULL)
    {
        if (! cJSON_IsString(encoding) || encoding->valuestring == NULL)
            return false;
        if (strcmp(encoding->valuestring, "packetaddr") == 0)
            ts->packetaddr = true;
        else if (strcmp(encoding->valuestring, "none") != 0)
            return false;
    }
    return ! ts->packetaddr || ts->protocol != kVmessClientProtocolTcp;
}

tunnel_t *vmessclientTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(vmessclient_tstate_t), sizeof(vmessclient_lstate_t));
    if (! t)
    {
        return NULL;
    }

    vmessclient_tstate_t *ts       = tunnelGetState(t);
    const cJSON          *settings = node->node_settings_json;
#define INIT_STAT(field) atomic_init(&ts->stats.field, 0)
    INIT_STAT(active_applications);
    INIT_STAT(active_carriers);
    INIT_STAT(tx_records);
    INIT_STAT(rx_records);
    INIT_STAT(tx_application_bytes);
    INIT_STAT(rx_application_bytes);
    INIT_STAT(tx_wire_bytes);
    INIT_STAT(rx_wire_bytes);
    INIT_STAT(tx_wraps);
    INIT_STAT(rx_wraps);
    INIT_STAT(verbose_after_ms);
    INIT_STAT(verbose_suppressed);
#undef INIT_STAT
    for (unsigned i = 0; i < kVmessClientReasonCount; ++i)
        atomic_init(&ts->stats.reasons[i], 0);

    t->fnInitU    = &vmessclientTunnelUpStreamInit;
    t->fnFinU     = &vmessclientTunnelUpStreamFinish;
    t->fnPayloadU = &vmessclientTunnelUpStreamPayload;
    t->fnPauseU   = &vmessclientTunnelUpStreamPause;
    t->fnResumeU  = &vmessclientTunnelUpStreamResume;
    t->fnEstD     = &vmessclientTunnelDownStreamEst;
    t->fnFinD     = &vmessclientTunnelDownStreamFinish;
    t->fnPayloadD = &vmessclientTunnelDownStreamPayload;
    t->fnPauseD   = &vmessclientTunnelDownStreamPause;
    t->fnResumeD  = &vmessclientTunnelDownStreamResume;

    t->onChain   = &vmessclientTunnelOnChain;
    t->onDestroy = &vmessclientTunnelDestroy;

    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: VmessClient->settings (object field) : The object was empty or invalid");
        tunnelDestroy(t);
        return NULL;
    }

    if (! validateSettings(settings) || ! parseUuid(ts, settings) || ! parseTargetAddress(ts, settings) ||
        ! parseTargetPort(ts, settings) || ! parseProtocol(ts, settings) || ! parseDomainStrategy(ts, settings) ||
        ! parseFirstPayloadTimeout(ts, settings) || ! parseSecurity(ts, settings) ||
        ! parseMaturityOptions(ts, settings))
    {
        LOGF("VmessClient: invalid or unsupported client settings");
        vmessclientTunnelstateDestroy(ts);
        tunnelDestroy(t);
        return NULL;
    }

    if (! vmessclientCreateInternalDomainResolver(t, node) || ! vmessclientRegisterApi(t))
    {
        vmessclientTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    return t;
}
