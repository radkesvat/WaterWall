#include "structure.h"

#include "loggers/network_logger.h"

static bool ping6serverSettingIsSupported(const char *key)
{
    static const char *const supported[] = {
        "mode",
        "local-ipv6",
        "peer-ipv6",
        "identifier",
        "sequence-start",
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

static bool ping6serverRejectUnknownSettings(const cJSON *settings)
{
    for (const cJSON *item = settings != NULL ? settings->child : NULL; item != NULL; item = item->next)
    {
        if (item->string == NULL || (item->type & cJSON_NameHasEmbeddedNul) != 0 ||
            ! configLexicalCheckEncodingQuiet(item->string, stringLength(item->string)))
        {
            LOGF("Ping6Server: configuration contains an invalid or embedded-NUL setting name");
            return false;
        }
        if (ping6serverSettingIsSupported(item->string))
        {
            continue;
        }

        LOGF("Ping6Server: unknown setting '%s'; expected only mode, local-ipv6, peer-ipv6, identifier, "
             "sequence-start, and "
             "send-replies",
             item->string != NULL ? item->string : "<unnamed>");
        return false;
    }
    return true;
}

static bool ping6serverLoadInteger(int *dest, const cJSON *settings, const char *key, int default_value, int minimum,
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
        LOGF("JSON Error: Ping6Server->settings->%s (int field) : expected a whole number between %d and %d",
             key,
             minimum,
             maximum);
        return false;
    }

    *dest = (int) value;
    return true;
}

static bool ping6serverLoadMode(ping6_wire_config_t *wire, const cJSON *settings)
{
    const cJSON *mode = cJSON_GetObjectItemCaseSensitive(settings, "mode");
    wire->mode        = kPing6WireDirect;
    if (mode != NULL)
    {
        if (! jsonObjectFieldStringsAreExact(settings, "mode") || ! cJSON_IsString(mode) || mode->valuestring == NULL)
        {
            LOGF("Ping6Server: mode must be the exact string direct or ipv6-in-ipv4");
            return false;
        }
        if (stringCompare(mode->valuestring, "ipv6-in-ipv4") == 0)
        {
            wire->mode = kPing6WireIpv6InIpv4;
        }
        else if (stringCompare(mode->valuestring, "direct") != 0)
        {
            LOGF("Ping6Server: mode must be direct or ipv6-in-ipv4");
            return false;
        }
    }
    if (wire->mode == kPing6WireDirect && (cJSON_GetObjectItemCaseSensitive(settings, "local-ipv6") != NULL ||
                                           cJSON_GetObjectItemCaseSensitive(settings, "peer-ipv6") != NULL))
    {
        LOGF("Ping6Server: direct mode forbids local-ipv6 and peer-ipv6 settings");
        return false;
    }
    return true;
}

static bool ping6serverLoadIpv6(ip6_addr_t *destination, const cJSON *settings, const char *key)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(settings, key);
    if (item == NULL)
    {
        LOGF("Ping6Server: ipv6-in-ipv4 mode requires %s", key);
        return false;
    }
    if (! jsonObjectFieldStringsAreExact(settings, key) || ! cJSON_IsString(item) || item->valuestring == NULL ||
        ! ping6wireParseIpv6Text(item->valuestring, destination) || ! ping6wireEndpointIsAdmissible(destination))
    {
        LOGF("Ping6Server: invalid %s; expected a bare unicast IPv6 endpoint excluding unspecified, loopback, "
             "multicast and IPv4-mapped addresses",
             key);
        return false;
    }
    return true;
}

static bool ping6serverLoadIdentifier(ping6server_tstate_t *state, const cJSON *settings)
{
    if (! jsonObjectFieldStringsAreExact(settings, "identifier"))
    {
        LOGF("JSON Error: Ping6Server->settings->identifier (int or string field) : invalid embedded-NUL or encoding");
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
        LOGF("JSON Error: Ping6Server->settings->identifier (int or string field) : expected 'random' or a whole "
             "number between 0 and %u",
             (unsigned int) UINT16_MAX);
        return false;
    }

    state->identifier_is_random = false;
    state->wire.identifier      = (uint16_t) value;
    return true;
}

tunnel_t *ping6serverCreate(node_t *node)
{
    tunnel_t *t = packettunnelCreate(node, sizeof(ping6server_tstate_t), 0);
    if (t == NULL)
    {
        return NULL;
    }

    t->fnPayloadU = &ping6serverUpStreamPayload;
    t->fnPayloadD = &ping6serverDownStreamPayload;
    t->onPrepare  = &ping6serverOnPrepair;
    t->onStart    = &ping6serverOnStart;

    t->onDestroy = &ping6serverDestroy;

    ping6server_tstate_t *state    = tunnelGetState(t);
    const cJSON          *settings = node->node_settings_json;

    if (settings != NULL && ! cJSON_IsObject(settings))
    {
        LOGF("JSON Error: Ping6Server->settings (object field) : expected an object when settings is provided");
        ping6serverDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    if (! ping6serverRejectUnknownSettings(settings) || ! ping6serverLoadMode(&state->wire, settings) ||
        (state->wire.mode == kPing6WireIpv6InIpv4 &&
         (! ping6serverLoadIpv6(&state->wire.local_ipv6, settings, "local-ipv6") ||
          ! ping6serverLoadIpv6(&state->wire.peer_ipv6, settings, "peer-ipv6"))) ||
        ! ping6serverLoadIdentifier(state, settings))
    {
        ping6serverDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    state->send_replies = false;
    if (jsonGetObjectBoolean(settings, "send-replies", &state->send_replies) == kJsonValueInvalid)
    {
        LOGF("JSON Error: Ping6Server->settings->send-replies (boolean field) : expected true or false");
        ping6serverDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    int sequence_start;
    if (! ping6serverLoadInteger(
            &sequence_start, settings, "sequence-start", kPing6ServerDefaultSequenceStart, 0, UINT16_MAX))
    {
        ping6serverDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    node->required_padding_left = ping6wireOverhead(&state->wire);
    atomicStoreRelaxed(&state->next_sequence, (unsigned int) sequence_start);
    atomicLogRateLimiterInitialize(&state->drop_log_limiter);
    return t;
}
