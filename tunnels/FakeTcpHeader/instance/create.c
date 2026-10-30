#include "structure.h"

#include "loggers/network_logger.h"

static bool faketcpheaderLoadNumber(const cJSON *settings, const char *key, uint32_t maximum, uint32_t fallback,
                                    uint32_t *result)
{
    int64_t                   value;
    const json_value_status_t status = jsonGetObjectIntegerInRange(settings, key, 0, maximum, &value);
    if (status == kJsonValueInvalid)
    {
        LOGF("JSON Error: FakeTcpHeader->settings->%s : expected an integer from 0 to %u", key, maximum);
        return false;
    }
    *result = status == kJsonValueMissing ? fallback : (uint32_t) value;
    return true;
}

static int faketcpheaderHexDigit(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static bool faketcpheaderLoadOptions(faketcpheader_tstate_t *state, const cJSON *settings)
{
    const cJSON *options = cJSON_GetObjectItemCaseSensitive(settings, "options");
    if (options == NULL)
        return true;
    if (! cJSON_IsString(options) || options->valuestring == NULL)
        return false;
    const size_t length = stringLength(options->valuestring);
    if (length > 2U * kFakeTcpHeaderMaxOptions || length % 8U != 0)
        return false;
    for (size_t i = 0; i < length; i += 2)
    {
        const int high = faketcpheaderHexDigit(options->valuestring[i]);
        const int low  = faketcpheaderHexDigit(options->valuestring[i + 1]);
        if (high < 0 || low < 0)
            return false;
        state->options[i / 2] = (uint8_t) ((high << 4) | low);
    }
    state->options_length = (uint8_t) (length / 2);
    return true;
}

static bool faketcpheaderLoadAddress(uint32_t *destination, const cJSON *settings, const char *key)
{
    const char *address = NULL;
    ip4_addr_t  parsed;
    if (jsonGetObjectNonEmptyString(settings, key, &address) != kJsonValuePresent ||
        ! ip4AddrAddressToNetwork(address, &parsed))
    {
        LOGF("JSON Error: FakeTcpHeader->settings->%s : expected a required IPv4 unicast address", key);
        return false;
    }
    const uint32_t host = lwip_ntohl(ip4AddrGetU32(&parsed));
    if ((host >> 24) == 0 || (host >> 24) == 127 || (host >> 24) >= 224)
    {
        LOGF("JSON Error: FakeTcpHeader->settings->%s : expected a non-loopback IPv4 unicast address", key);
        return false;
    }
    *destination = ip4AddrGetU32(&parsed);
    return true;
}

tunnel_t *faketcpheaderCreate(node_t *node)
{
    tunnel_t *t = packettunnelCreate(node, sizeof(faketcpheader_tstate_t), 0);
    if (t == NULL)
        return NULL;
    t->fnPayloadU = faketcpheaderUpStreamPayload;
    t->fnPayloadD = faketcpheaderDownStreamPayload;
    t->onDestroy  = faketcpheaderDestroy;

    faketcpheader_tstate_t *state    = tunnelGetState(t);
    const cJSON            *settings = node->node_settings_json;
    if (settings != NULL && ! cJSON_IsObject(settings))
    {
        LOGF("JSON Error: FakeTcpHeader->settings : expected an object");
        goto invalid;
    }
    const cJSON *item;
    cJSON_ArrayForEach(item, settings)
    {
        static const char *const supported[] = {"role",
                                                "flags",
                                                "protocol-number",
                                                "sequence",
                                                "acknowledgment",
                                                "window",
                                                "urgent-pointer",
                                                "options",
                                                "local-ipv4",
                                                "peer-ipv4",
                                                "local-port",
                                                "peer-port",
                                                "mtu"};
        bool                     known       = false;
        for (size_t i = 0; i < ARRAY_SIZE(supported); ++i)
            known |= item->string != NULL && stringCompare(item->string, supported[i]) == 0;
        if (! known || ! jsonObjectFieldStringsAreExact(settings, item->string))
        {
            LOGF("JSON Error: FakeTcpHeader->settings->%s : unknown setting",
                 item->string != NULL ? item->string : "<unnamed>");
            goto invalid;
        }
    }
    const cJSON *role = cJSON_GetObjectItemCaseSensitive(settings, "role");
    if (role != NULL)
    {
        if (! cJSON_IsString(role) || role->valuestring == NULL ||
            (stringCompare(role->valuestring, "client") != 0 && stringCompare(role->valuestring, "server") != 0))
        {
            LOGF("JSON Error: FakeTcpHeader->settings->role : expected 'client' or 'server'");
            goto invalid;
        }
        state->server = stringCompare(role->valuestring, "server") == 0;
    }
    if (! faketcpheaderLoadAddress(&state->local_ipv4, settings, "local-ipv4") ||
        ! faketcpheaderLoadAddress(&state->peer_ipv4, settings, "peer-ipv4"))
        goto invalid;
    uint32_t protocol, flags, window, urgent, local_port, peer_port, mtu;
    if (! faketcpheaderLoadNumber(settings, "protocol-number", UINT8_MAX, IPPROTO_TCP, &protocol) ||
        ! faketcpheaderLoadNumber(settings, "flags", UINT8_MAX, 0, &flags) ||
        ! faketcpheaderLoadNumber(settings, "sequence", UINT32_MAX, 0, &state->sequence) ||
        ! faketcpheaderLoadNumber(settings, "acknowledgment", UINT32_MAX, 0, &state->acknowledgment) ||
        ! faketcpheaderLoadNumber(settings, "window", UINT16_MAX, UINT16_MAX, &window) ||
        ! faketcpheaderLoadNumber(settings, "urgent-pointer", UINT16_MAX, 0, &urgent) ||
        ! faketcpheaderLoadNumber(settings, "local-port", UINT16_MAX, 40000, &local_port) ||
        ! faketcpheaderLoadNumber(settings, "peer-port", UINT16_MAX, 40000, &peer_port) ||
        ! faketcpheaderLoadNumber(settings, "mtu", kMaxAllowedPacketLength, kMaxAllowedPacketLength, &mtu))
        goto invalid;
    state->protocol       = (uint8_t) protocol;
    state->flags          = (uint8_t) flags;
    state->window         = (uint16_t) window;
    state->urgent_pointer = (uint16_t) urgent;
    state->local_port     = (uint16_t) local_port;
    state->peer_port      = (uint16_t) peer_port;
    state->mtu            = (uint16_t) mtu;
    if (! faketcpheaderLoadOptions(state, settings))
    {
        LOGF("JSON Error: FakeTcpHeader->settings->options : expected 0..40 bytes of hexadecimal in four-byte groups");
        goto invalid;
    }
    if (local_port == 0 || peer_port == 0 || mtu < faketcpheaderOverhead(state) + 68U)
    {
        LOGF("JSON Error: FakeTcpHeader requires ports 1..65535 and mtu >= 68 + outer header size (%u)",
             (unsigned int) faketcpheaderOverhead(state));
        goto invalid;
    }
    atomicLogRateLimiterInitialize(&state->drop_log);
    return t;

invalid:
    faketcpheaderDestroy(t, wwLifecycleStartupRollback());
    return NULL;
}
