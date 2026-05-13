#include "structure.h"

#include "loggers/network_logger.h"

static bool pingserverLoadUint16Setting(uint16_t *dest, const cJSON *settings, const char *key, int default_value,
                                        const char *json_path)
{
    int value = default_value;
    getIntFromJsonObjectOrDefault(&value, settings, key, default_value);

    if (value < 0 || value > UINT16_MAX)
    {
        LOGF("JSON Error: %s (int field) : expected a value between 0 and %u", json_path, (unsigned int) UINT16_MAX);
        return false;
    }

    *dest = (uint16_t) value;
    return true;
}

static bool pingserverLoadUint8Setting(uint8_t *dest, const cJSON *settings, const char *key, int default_value,
                                       const char *json_path)
{
    int value = default_value;
    getIntFromJsonObjectOrDefault(&value, settings, key, default_value);

    if (value < 0 || value > UINT8_MAX)
    {
        LOGF("JSON Error: %s (int field) : expected a value between 0 and %u", json_path, (unsigned int) UINT8_MAX);
        return false;
    }

    *dest = (uint8_t) value;
    return true;
}

static bool pingserverLoadOptionalXorByteSetting(bool *enabled_out, uint8_t *value_out, const cJSON *settings,
                                                 const char *key, const char *json_path)
{
    int value = -1;
    getIntFromJsonObjectOrDefault(&value, settings, key, -1);

    if (value < -1 || value > UINT8_MAX)
    {
        LOGF("JSON Error: %s (int field) : expected a value between 0 and %u, or omit the field",
             json_path, (unsigned int) UINT8_MAX);
        return false;
    }

    *enabled_out = (value != -1);
    *value_out   = (value == -1) ? 0 : (uint8_t) value;
    return true;
}

static bool pingserverParseIpv4String(uint32_t *dest, const char *ipbuf, const char *json_path)
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

static bool pingserverLoadRequiredIpv4Setting(uint32_t *dest, const cJSON *settings, const char *key, const char *json_path)
{
    char *ipbuf = NULL;
    if (! getStringFromJsonObject(&ipbuf, settings, key))
    {
        LOGF("JSON Error: %s (string field) : expected an IPv4 address", json_path);
        return false;
    }

    const bool ok = pingserverParseIpv4String(dest, ipbuf, json_path);
    memoryFree(ipbuf);
    return ok;
}

static bool pingserverLoadStrategy(pingserver_tstate_t *state, const cJSON *settings)
{
    char *strategy = NULL;

    if (! getStringFromJsonObject(&strategy, settings, "strategy"))
    {
        state->strategy = kPingServerStrategyWrapIcmpHeaderAndReuseIpv4Addrs;
        return true;
    }

    bool ok = true;

    if (stringCompare(strategy, "wrap-in-new-ip-and-icmp-header") == 0 ||
        stringCompare(strategy, "warp-in-new-ip-and-icmp-header") == 0 ||
        stringCompare(strategy, "wrap-in-new-ipv4-and-icmp-header") == 0 ||
        stringCompare(strategy, "warp-in-new-ipv4-and-icmp-header") == 0)
    {
        state->strategy = kPingServerStrategyWrapNewIpAndIcmpHeader;
    }
    else if (stringCompare(strategy, "wrap-in-icmp-header-and-reuse-ipv4-addresses") == 0 ||
             stringCompare(strategy, "warp-in-icmp-header-and-reuse-ipv4-addresses") == 0 ||
             stringCompare(strategy, "wrap-in-icmp-header-and-reuse-ip-addresses") == 0 ||
             stringCompare(strategy, "warp-in-icmp-header-and-reuse-ip-addresses") == 0 ||
             stringCompare(strategy, "wrap-in-icmp-header-and-update-ipv4-header") == 0 ||
             stringCompare(strategy, "warp-in-icmp-header-and-update-ipv4-header") == 0)
    {
        state->strategy = kPingServerStrategyWrapIcmpHeaderAndReuseIpv4Addrs;
    }
    else if (stringCompare(strategy, "wrap-in-only-icmp-header") == 0 ||
             stringCompare(strategy, "warp-in-only-icmp-header") == 0 ||
             stringCompare(strategy, "wrap-payload-in-only-icmp-header") == 0 ||
             stringCompare(strategy, "warp-payload-in-only-icmp-header") == 0)
    {
        state->strategy = kPingServerStrategyWrapOnlyIcmpHeader;
    }
    else if (stringCompare(strategy, "change-only-ipv4-protocol-number") == 0 ||
             stringCompare(strategy, "change-only-ip4-protocol-number") == 0 ||
             stringCompare(strategy, "change-only-ip4-packet-identifier-number") == 0)
    {
        state->strategy = kPingServerStrategyChangeOnlyIpv4ProtocolNumber;
    }
    else
    {
        LOGF("JSON Error: PingServer->settings->strategy (string field) : unsupported strategy '%s'", strategy);
        ok = false;
    }

    memoryFree(strategy);
    return ok;
}

static bool pingserverParseProtocolNumber(uint8_t *dest, const cJSON *settings, const char *key, const char *json_path)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(settings, key);
    if (item == NULL)
    {
        LOGF("JSON Error: %s (string or int field) : expected TCP, UDP, ICMP, or a protocol number", json_path);
        return false;
    }

    if (cJSON_IsNumber(item))
    {
        if (item->valueint < 0 || item->valueint > UINT8_MAX)
        {
            LOGF("JSON Error: %s (int field) : expected a value between 0 and %u", json_path, (unsigned int) UINT8_MAX);
            return false;
        }

        *dest = (uint8_t) item->valueint;
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

static bool pingserverLoadSwapProtocol(uint8_t *dest, const cJSON *settings)
{
    if (cJSON_GetObjectItemCaseSensitive(settings, "swap-protocol") != NULL)
    {
        return pingserverParseProtocolNumber(dest, settings, "swap-protocol", "PingServer->settings->swap-protocol");
    }

    return pingserverParseProtocolNumber(dest, settings, "swap-identifier", "PingServer->settings->swap-protocol");
}

tunnel_t *pingserverCreate(node_t *node)
{
    tunnel_t *t = packettunnelCreate(node, sizeof(pingserver_tstate_t), 0);

    t->fnPayloadU = &pingserverUpStreamPayload;
    t->fnPayloadD = &pingserverDownStreamPayload;
    t->onPrepare  = &pingserverOnPrepair;
    t->onStart    = &pingserverOnStart;
    t->onDestroy  = &pingserverDestroy;

    pingserver_tstate_t *state    = tunnelGetState(t);
    const cJSON         *settings = node->node_settings_json;

    if (settings != NULL && ! cJSON_IsObject(settings))
    {
        LOGF("JSON Error: PingServer->settings (object field) : expected an object when settings is provided");
        pingserverDestroy(t);
        return NULL;
    }

    if (! pingserverLoadUint16Setting(&state->identifier, settings, "identifier", kPingServerDefaultIdentifier,
                                      "PingServer->settings->identifier") ||
        ! pingserverLoadStrategy(state, settings) ||
        ! pingserverLoadUint8Setting(&state->ttl, settings, "ttl", kPingServerDefaultTtl, "PingServer->settings->ttl") ||
        ! pingserverLoadUint8Setting(&state->tos, settings, "tos", 0, "PingServer->settings->tos") ||
        ! pingserverLoadOptionalXorByteSetting(&state->payload_xor_enabled, &state->payload_xor_byte, settings,
                                               "xor-byte", "PingServer->settings->xor-byte"))
    {
        pingserverDestroy(t);
        return NULL;
    }

    getBoolFromJsonObjectOrDefault(&state->roundup_payload_size, settings, "roundup-size", false);

    if (! state->roundup_payload_size)
    {
        getBoolFromJsonObjectOrDefault(&state->roundup_payload_size, settings, "roundup", false);
    }

    uint16_t sequence_start = 0;
    uint16_t ipv4_id_start  = 0;

    if (! pingserverLoadUint16Setting(&sequence_start, settings, "sequence-start", 0,
                                      "PingServer->settings->sequence-start") ||
        ! pingserverLoadUint16Setting(&ipv4_id_start, settings, "ipv4-id-start", 0,
                                      "PingServer->settings->ipv4-id-start"))
    {
        pingserverDestroy(t);
        return NULL;
    }

    atomicStoreRelaxed(&state->icmp_sequence, sequence_start);
    atomicStoreRelaxed(&state->ipv4_identification, ipv4_id_start);

    if (state->strategy == kPingServerStrategyWrapNewIpAndIcmpHeader)
    {
        if (! pingserverLoadRequiredIpv4Setting(&state->source_addr, settings, "source", "PingServer->settings->source") ||
            ! pingserverLoadRequiredIpv4Setting(&state->dest_addr, settings, "dest", "PingServer->settings->dest"))
        {
            pingserverDestroy(t);
            return NULL;
        }
    }

    if (state->strategy == kPingServerStrategyChangeOnlyIpv4ProtocolNumber &&
        ! pingserverLoadSwapProtocol(&state->swap_protocol, settings))
    {
        pingserverDestroy(t);
        return NULL;
    }

    return t;
}
