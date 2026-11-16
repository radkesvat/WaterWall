#include "structure.h"

#include "loggers/network_logger.h"

static bool ping6clientSettingIsSupported(const char *key)
{
    static const char *const supported[] = {
        "local-ipv4",
        "peer-ipv4",
        "local-ipv6",
        "peer-ipv6",
        "identifier",
        "sequence-start",
        "ttl",
        "tos",
        "send-replies",
    };

    if (key == NULL)
    {
        return false;
    }

    for (size_t i = 0; i < ARRAY_SIZE(supported); ++i)
    {
        if (stringCompare(key, supported[i]) == 0)
        {
            return true;
        }
    }
    return false;
}

static bool ping6clientRejectUnknownSettings(const cJSON *settings)
{
    for (const cJSON *item = settings != NULL ? settings->child : NULL; item != NULL; item = item->next)
    {
        if (item->string == NULL || (item->type & cJSON_NameHasEmbeddedNul) != 0 ||
            ! configLexicalCheckEncodingQuiet(item->string, stringLength(item->string)))
        {
            LOGF("Ping6Client: configuration contains an invalid or embedded-NUL setting name");
            return false;
        }
        if (ping6clientSettingIsSupported(item->string))
        {
            continue;
        }

        LOGF("Ping6Client: unknown setting '%s'; expected only local-ipv4, peer-ipv4, local-ipv6, peer-ipv6, "
             "identifier, sequence-start, ttl, tos, and send-replies",
             item->string != NULL ? item->string : "<unnamed>");
        return false;
    }
    return true;
}

static bool ping6clientLoadInteger(int *dest, const cJSON *settings, const char *key, int default_value, int minimum,
                                   int maximum)
{
    int64_t             value  = 0;
    json_value_status_t status = jsonGetObjectIntegerInRange(settings, key, minimum, maximum, &value);
    if (status == kJsonValueMissing)
    {
        *dest = default_value;
        return true;
    }
    if (status == kJsonValueInvalid)
    {
        LOGF("JSON Error: Ping6Client->settings->%s (int field) : expected a whole number between %d and %d",
             key,
             minimum,
             maximum);
        return false;
    }

    *dest = (int) value;
    return true;
}

static bool ping6clientLoadRequiredIpv4(uint32_t *destination, const cJSON *settings, const char *key)
{
    if (! jsonObjectFieldStringsAreExact(settings, key))
    {
        LOGF("JSON Error: Ping6Client->settings->%s (string field) : invalid embedded-NUL or encoding", key);
        return false;
    }
    const char         *address = NULL;
    json_value_status_t status  = jsonGetObjectNonEmptyString(settings, key, &address);
    if (status == kJsonValueMissing)
    {
        LOGF("JSON Error: Ping6Client->settings->%s (required string field) : expected a single IPv4 address", key);
        return false;
    }
    if (status == kJsonValueInvalid)
    {
        LOGF("JSON Error: Ping6Client->settings->%s (string field) : expected a single IPv4 address", key);
        return false;
    }

    if (! ping6wireParseIpv4Text(address, destination))
    {
        LOGF("JSON Error: Ping6Client->settings->%s (string field) : expected a single IPv4 address as four decimal "
             "fields without leading zeros",
             key);
        return false;
    }
    return true;
}

static bool ping6clientLoadOptionalIpv6(ip6_addr_t *destination, const cJSON *settings, const char *key,
                                        uint32_t mapped_ipv4)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(settings, key);
    if (item == NULL)
    {
        ping6wireIpv4MappedAddress(mapped_ipv4, destination);
        return true;
    }
    if (! jsonObjectFieldStringsAreExact(settings, key) || ! cJSON_IsString(item) || item->valuestring == NULL ||
        ! ping6wireParseIpv6Text(item->valuestring, destination))
    {
        LOGF("JSON Error: Ping6Client->settings->%s (string field) : expected one IPv6 address without brackets, "
             "zone, or prefix",
             key);
        return false;
    }
    return true;
}

static bool ping6clientLoadIdentifier(ping6client_tstate_t *state, const cJSON *settings)
{
    if (! jsonObjectFieldStringsAreExact(settings, "identifier"))
    {
        LOGF("JSON Error: Ping6Client->settings->identifier (int or string field) : invalid embedded-NUL or encoding");
        return false;
    }
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(settings, "identifier");
    if (item == NULL ||
        (cJSON_IsString(item) && item->valuestring != NULL && stringCompare(item->valuestring, "random") == 0))
    {
        state->identifier_is_random = true;
        state->wire.identifier      = 0;
        return true;
    }

    int64_t value = 0;
    if (! jsonGetIntegerInRange(item, 0, UINT16_MAX, &value))
    {
        LOGF("JSON Error: Ping6Client->settings->identifier (int or string field) : expected 'random' or a whole "
             "number between 0 and %u",
             (unsigned int) UINT16_MAX);
        return false;
    }

    state->identifier_is_random = false;
    state->wire.identifier      = (uint16_t) value;
    return true;
}

tunnel_t *ping6clientCreate(node_t *node)
{
    tunnel_t *t = packettunnelCreate(node, sizeof(ping6client_tstate_t), 0);
    if (t == NULL)
    {
        return NULL;
    }

    t->fnPayloadU = &ping6clientUpStreamPayload;
    t->fnPayloadD = &ping6clientDownStreamPayload;
    t->onPrepare  = &ping6clientOnPrepair;
    t->onStart    = &ping6clientOnStart;

    t->onDestroy = &ping6clientDestroy;

    ping6client_tstate_t *state    = tunnelGetState(t);
    const cJSON          *settings = node->node_settings_json;

    if (settings != NULL && ! cJSON_IsObject(settings))
    {
        LOGF("JSON Error: Ping6Client->settings (object field) : expected an object when settings is provided");
        ping6clientDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    if (! ping6clientRejectUnknownSettings(settings) ||
        ! ping6clientLoadRequiredIpv4(&state->wire.local_ipv4, settings, "local-ipv4") ||
        ! ping6clientLoadRequiredIpv4(&state->wire.peer_ipv4, settings, "peer-ipv4") ||
        ! ping6clientLoadOptionalIpv6(&state->wire.local_ipv6, settings, "local-ipv6", state->wire.local_ipv4) ||
        ! ping6clientLoadOptionalIpv6(&state->wire.peer_ipv6, settings, "peer-ipv6", state->wire.peer_ipv4) ||
        ! ping6clientLoadIdentifier(state, settings))
    {
        ping6clientDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    state->send_replies = false;
    if (jsonGetObjectBoolean(settings, "send-replies", &state->send_replies) == kJsonValueInvalid)
    {
        LOGF("JSON Error: Ping6Client->settings->send-replies (boolean field) : expected true or false");
        ping6clientDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    int sequence_start;
    int ttl;
    int tos;
    if (! ping6clientLoadInteger(
            &sequence_start, settings, "sequence-start", kPing6ClientDefaultSequenceStart, 0, UINT16_MAX) ||
        ! ping6clientLoadInteger(&ttl, settings, "ttl", kPing6ClientDefaultTtl, 0, UINT8_MAX) ||
        ! ping6clientLoadInteger(&tos, settings, "tos", kPing6ClientDefaultTos, 0, UINT8_MAX))
    {
        ping6clientDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    state->wire.ttl = (uint8_t) ttl;
    state->wire.tos = (uint8_t) tos;
    atomicStoreRelaxed(&state->next_sequence, (unsigned int) sequence_start);
    atomicLogRateLimiterInitialize(&state->drop_log_limiter);
    return t;
}
