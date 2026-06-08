#include "structure.h"

#include "loggers/network_logger.h"

static bool pingclientLoadIntSetting(int *dest, const cJSON *settings, const char *key, int default_value,
                                     int min_value, int max_value, const char *json_path)
{
    assert(default_value >= min_value && default_value <= max_value);

    const cJSON *item = cJSON_GetObjectItemCaseSensitive(settings, key);
    if (item == NULL)
    {
        *dest = default_value;
        return true;
    }

    if (! cJSON_IsNumber(item))
    {
        LOGF("JSON Error: %s (int field) : expected a whole number between %d and %d", json_path, min_value, max_value);
        return false;
    }

    const double value = item->valuedouble;
    if (! (value >= (double) min_value && value <= (double) max_value))
    {
        LOGF("JSON Error: %s (int field) : expected a whole number between %d and %d", json_path, min_value, max_value);
        return false;
    }

    const int int_value = (int) value;
    if ((double) int_value < value || (double) int_value > value)
    {
        LOGF("JSON Error: %s (int field) : expected a whole number between %d and %d", json_path, min_value, max_value);
        return false;
    }

    *dest = int_value;
    return true;
}

static bool pingclientLoadUint16Setting(uint16_t *dest, const cJSON *settings, const char *key, int default_value,
                                        const char *json_path)
{
    int value;
    if (! pingclientLoadIntSetting(&value, settings, key, default_value, 0, UINT16_MAX, json_path))
    {
        return false;
    }

    *dest = (uint16_t) value;
    return true;
}

static bool pingclientLoadUint8Setting(uint8_t *dest, const cJSON *settings, const char *key, int default_value,
                                       const char *json_path)
{
    int value;
    if (! pingclientLoadIntSetting(&value, settings, key, default_value, 0, UINT8_MAX, json_path))
    {
        return false;
    }

    *dest = (uint8_t) value;
    return true;
}

static bool pingclientLoadBoolSetting(bool *dest, const cJSON *settings, const char *key, bool default_value,
                                      const char *json_path)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(settings, key);
    if (item == NULL)
    {
        *dest = default_value;
        return true;
    }

    if (! cJSON_IsBool(item))
    {
        LOGF("JSON Error: %s (boolean field) : expected true or false", json_path);
        return false;
    }

    *dest = cJSON_IsTrue(item);
    return true;
}

static bool pingclientLoadOptionalXorByteSetting(bool *enabled_out, uint8_t *value_out, const cJSON *settings,
                                                 const char *key, const char *json_path)
{
    int value;
    if (! pingclientLoadIntSetting(&value, settings, key, kPingClientDefaultPayloadXorByte, -1, UINT8_MAX, json_path))
    {
        return false;
    }

    *enabled_out = (value != -1);
    *value_out   = (value == -1) ? 0 : (uint8_t) value;
    return true;
}

static bool pingclientParseIpv4String(uint32_t *dest, const char *ipbuf, const char *json_path)
{
    ip4_addr_t parsed_ipv4;

    if (ip4AddrAddressToNetwork(ipbuf, &parsed_ipv4) == 0)
    {
        LOGF("JSON Error: %s (string field) : expected a single IPv4 address", json_path);
        return false;
    }

    *dest = ip4AddrGetU32(&parsed_ipv4);
    return true;
}

static bool pingclientLoadOptionalIpv4Setting(uint32_t *dest, bool *configured, const cJSON *settings, const char *key,
                                              const char *json_path)
{
    char *ipbuf = NULL;
    *dest       = 0;
    *configured = false;

    if (! getStringFromJsonObject(&ipbuf, settings, key))
    {
        return true;
    }

    *configured   = true;
    const bool ok = pingclientParseIpv4String(dest, ipbuf, json_path);
    memoryFree(ipbuf);
    return ok;
}

static bool pingclientLoadStrategy(pingclient_tstate_t *state, const cJSON *settings)
{
    char *strategy = NULL;

    if (! getStringFromJsonObject(&strategy, settings, "strategy"))
    {
        state->strategy = kPingClientDefaultStrategy;
        return true;
    }

    bool ok = true;

    if (stringCompare(strategy, "wrap-in-new-ip-and-icmp-header") == 0 ||
        stringCompare(strategy, "warp-in-new-ip-and-icmp-header") == 0 ||
        stringCompare(strategy, "wrap-in-new-ipv4-and-icmp-header") == 0 ||
        stringCompare(strategy, "warp-in-new-ipv4-and-icmp-header") == 0)
    {
        state->strategy = kPingClientStrategyWrapNewIpAndIcmpHeader;
    }
    else if (stringCompare(strategy, "wrap-in-icmp-header-and-reuse-ipv4-addresses") == 0 ||
             stringCompare(strategy, "warp-in-icmp-header-and-reuse-ipv4-addresses") == 0 ||
             stringCompare(strategy, "wrap-in-icmp-header-and-reuse-ip-addresses") == 0 ||
             stringCompare(strategy, "warp-in-icmp-header-and-reuse-ip-addresses") == 0 ||
             stringCompare(strategy, "wrap-in-icmp-header-and-update-ipv4-header") == 0 ||
             stringCompare(strategy, "warp-in-icmp-header-and-update-ipv4-header") == 0)
    {
        state->strategy = kPingClientStrategyWrapIcmpHeaderAndReuseIpv4Addrs;
    }
    else if (stringCompare(strategy, "wrap-in-only-icmp-header") == 0 ||
             stringCompare(strategy, "warp-in-only-icmp-header") == 0 ||
             stringCompare(strategy, "wrap-payload-in-only-icmp-header") == 0 ||
             stringCompare(strategy, "warp-payload-in-only-icmp-header") == 0)
    {
        state->strategy = kPingClientStrategyWrapOnlyIcmpHeader;
    }
    else if (stringCompare(strategy, "change-only-ipv4-protocol-number") == 0 ||
             stringCompare(strategy, "change-only-ip4-protocol-number") == 0 ||
             stringCompare(strategy, "change-only-ip4-packet-identifier-number") == 0)
    {
        state->strategy = kPingClientStrategyChangeOnlyIpv4ProtocolNumber;
    }
    else
    {
        LOGF("JSON Error: PingClient->settings->strategy (string field) : unsupported strategy '%s'", strategy);
        ok = false;
    }

    memoryFree(strategy);
    return ok;
}

static bool pingclientParseProtocolNumber(uint8_t *dest, const cJSON *settings, const char *key, const char *json_path)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(settings, key);
    if (item == NULL)
    {
        LOGF("JSON Error: %s (string or int field) : expected TCP, UDP, ICMP, or a protocol number", json_path);
        return false;
    }

    if (cJSON_IsNumber(item))
    {
        int value;
        if (! pingclientLoadIntSetting(&value, settings, key, 0, 0, UINT8_MAX, json_path))
        {
            return false;
        }

        *dest = (uint8_t) value;
        return true;
    }

    if (cJSON_IsString(item) && item->valuestring != NULL)
    {
        if (stringCompare(item->valuestring, "TCP") == 0 || stringCompare(item->valuestring, "tcp") == 0)
        {
            *dest = IP_PROTO_TCP;
            return true;
        }
        if (stringCompare(item->valuestring, "UDP") == 0 || stringCompare(item->valuestring, "udp") == 0)
        {
            *dest = IP_PROTO_UDP;
            return true;
        }
        if (stringCompare(item->valuestring, "ICMP") == 0 || stringCompare(item->valuestring, "icmp") == 0)
        {
            *dest = IP_PROTO_ICMP;
            return true;
        }
    }

    LOGF("JSON Error: %s (string or int field) : expected TCP, UDP, ICMP, or a protocol number", json_path);
    return false;
}

static bool pingclientLoadSwapProtocol(uint8_t *dest, const cJSON *settings)
{
    if (cJSON_GetObjectItemCaseSensitive(settings, "swap-protocol") != NULL)
    {
        return pingclientParseProtocolNumber(dest, settings, "swap-protocol", "PingClient->settings->swap-protocol");
    }

    return pingclientParseProtocolNumber(dest, settings, "swap-identifier", "PingClient->settings->swap-protocol");
}

tunnel_t *pingclientCreate(node_t *node)
{
    tunnel_t *t = packettunnelCreate(node, sizeof(pingclient_tstate_t), 0);

    t->fnInitD    = &pingclientDownStreamInit;
    t->fnPayloadU = &pingclientUpStreamPayload;
    t->fnPayloadD = &pingclientDownStreamPayload;
    t->onPrepare  = &pingclientOnPrepair;
    t->onStart    = &pingclientOnStart;
    t->onStop     = &pingclientOnStop;
    t->onDestroy  = &pingclientDestroy;

    pingclient_tstate_t *state    = tunnelGetState(t);
    const cJSON         *settings = node->node_settings_json;

    if (settings != NULL && ! cJSON_IsObject(settings))
    {
        LOGF("JSON Error: PingClient->settings (object field) : expected an object when settings is provided");
        pingclientDestroy(t);
        return NULL;
    }

    if (! pingclientLoadUint16Setting(&state->identifier,
                                      settings,
                                      "identifier",
                                      kPingClientDefaultIdentifier,
                                      "PingClient->settings->identifier") ||
        ! pingclientLoadBoolSetting(&state->identifier_check_enabled,
                                    settings,
                                    "check-identifier",
                                    kPingClientDefaultIdentifierCheck,
                                    "PingClient->settings->check-identifier") ||
        ! pingclientLoadStrategy(state, settings) ||
        ! pingclientLoadUint8Setting(
            &state->ttl, settings, "ttl", kPingClientDefaultTtl, "PingClient->settings->ttl") ||
        ! pingclientLoadUint8Setting(
            &state->tos, settings, "tos", kPingClientDefaultTos, "PingClient->settings->tos") ||
        ! pingclientLoadOptionalXorByteSetting(&state->payload_xor_enabled,
                                               &state->payload_xor_byte,
                                               settings,
                                               "xor-byte",
                                               "PingClient->settings->xor-byte"))
    {
        pingclientDestroy(t);
        return NULL;
    }

    getBoolFromJsonObjectOrDefault(
        &state->roundup_payload_size, settings, "roundup-size", kPingClientDefaultRoundupPayload);

    if (! state->roundup_payload_size)
    {
        getBoolFromJsonObjectOrDefault(
            &state->roundup_payload_size, settings, "roundup", kPingClientDefaultRoundupPayload);
    }

    uint16_t sequence_start = kPingClientDefaultSequenceStart;
    uint16_t ipv4_id_start  = kPingClientDefaultIpv4IdStart;

    if (! pingclientLoadUint16Setting(&sequence_start,
                                      settings,
                                      "sequence-start",
                                      kPingClientDefaultSequenceStart,
                                      "PingClient->settings->sequence-start") ||
        ! pingclientLoadUint16Setting(&ipv4_id_start,
                                      settings,
                                      "ipv4-id-start",
                                      kPingClientDefaultIpv4IdStart,
                                      "PingClient->settings->ipv4-id-start"))
    {
        pingclientDestroy(t);
        return NULL;
    }

    atomicStoreRelaxed(&state->icmp_sequence, sequence_start);
    atomicStoreRelaxed(&state->ipv4_identification, ipv4_id_start);

    if (state->strategy == kPingClientStrategyWrapNewIpAndIcmpHeader)
    {
        if (! pingclientLoadOptionalIpv4Setting(&state->source_addr,
                                                &state->source_addr_configured,
                                                settings,
                                                "source",
                                                "PingClient->settings->source") ||
            ! pingclientLoadOptionalIpv4Setting(
                &state->dest_addr, &state->dest_addr_configured, settings, "dest", "PingClient->settings->dest"))
        {
            pingclientDestroy(t);
            return NULL;
        }
    }

    if (state->strategy == kPingClientStrategyChangeOnlyIpv4ProtocolNumber &&
        ! pingclientLoadSwapProtocol(&state->swap_protocol, settings))
    {
        pingclientDestroy(t);
        return NULL;
    }

    return t;
}
