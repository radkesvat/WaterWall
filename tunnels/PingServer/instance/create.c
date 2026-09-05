#include "structure.h"

#include "loggers/network_logger.h"

static bool pingserverSettingIsSupported(const char *key)
{
    static const char *const supported[] = {
        "local-ipv4",
        "peer-ipv4",
        "identifier",
        "sequence-start",
        "ttl",
        "tos",
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

static bool pingserverRejectLegacySettings(const cJSON *settings)
{
    for (const cJSON *item = settings != NULL ? settings->child : NULL; item != NULL; item = item->next)
    {
        if (pingserverSettingIsSupported(item->string))
        {
            continue;
        }

        LOGF("PingServer: configuration uses removed Ping wire v1 setting '%s'; Ping wire v2 accepts only "
             "local-ipv4, peer-ipv4, identifier, sequence-start, ttl, and tos",
             item->string != NULL ? item->string : "<unnamed>");
        return false;
    }
    return true;
}

static bool pingserverLoadInteger(int *dest, const cJSON *settings, const char *key, int default_value, int minimum,
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
        LOGF("JSON Error: PingServer->settings->%s (int field) : expected a whole number between %d and %d",
             key,
             minimum,
             maximum);
        return false;
    }

    *dest = (int) value;
    return true;
}

static bool pingserverLoadRequiredIpv4(uint32_t *destination, const cJSON *settings, const char *key)
{
    const char         *address = NULL;
    json_value_status_t status  = jsonGetObjectNonEmptyString(settings, key, &address);
    if (status == kJsonValueMissing)
    {
        LOGF("JSON Error: PingServer->settings->%s (required string field) : expected a single IPv4 address", key);
        return false;
    }
    if (status == kJsonValueInvalid)
    {
        LOGF("JSON Error: PingServer->settings->%s (string field) : expected a single IPv4 address", key);
        return false;
    }

    ip4_addr_t parsed = {0};
    if (ip4AddrAddressToNetwork(address, &parsed) == 0)
    {
        LOGF("JSON Error: PingServer->settings->%s (string field) : expected a single IPv4 address", key);
        return false;
    }

    *destination = ip4AddrGetU32(&parsed);
    return true;
}

static bool pingserverLoadIdentifier(pingserver_tstate_t *state, const cJSON *settings)
{
    const cJSON *item = settings != NULL ? cJSON_GetObjectItemCaseSensitive(settings, "identifier") : NULL;
    if (item == NULL)
    {
        state->identifier_is_random = true;
        state->wire.identifier      = 0;
        return true;
    }

    if (cJSON_IsString(item) && item->valuestring != NULL && stringCompare(item->valuestring, "random") == 0)
    {
        state->identifier_is_random = true;
        state->wire.identifier      = 0;
        return true;
    }

    int64_t value = 0;
    if (! jsonGetIntegerInRange(item, 0, UINT16_MAX, &value))
    {
        LOGF("JSON Error: PingServer->settings->identifier (int or string field) : expected 'random' or a whole "
             "number between 0 and %u",
             (unsigned int) UINT16_MAX);
        return false;
    }

    state->identifier_is_random = false;
    state->wire.identifier      = (uint16_t) value;
    return true;
}

tunnel_t *pingserverCreate(node_t *node)
{
    tunnel_t *t = packettunnelCreate(node, sizeof(pingserver_tstate_t), 0);
    if (t == NULL)
    {
        return NULL;
    }

    t->fnPayloadU = &pingserverUpStreamPayload;

    t->fnPayloadD = &pingserverDownStreamPayload;

    t->onPrepare  = &pingserverOnPrepair;
    t->onStart    = &pingserverOnStart;

    t->onDestroy = &pingserverDestroy;

    pingserver_tstate_t *state    = tunnelGetState(t);
    const cJSON         *settings = node->node_settings_json;

    if (settings != NULL && ! cJSON_IsObject(settings))
    {
        LOGF("JSON Error: PingServer->settings (object field) : expected an object when settings is provided");
        pingserverDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    if (! pingserverRejectLegacySettings(settings) ||
        ! pingserverLoadRequiredIpv4(&state->wire.local_ipv4, settings, "local-ipv4") ||
        ! pingserverLoadRequiredIpv4(&state->wire.peer_ipv4, settings, "peer-ipv4") ||
        ! pingserverLoadIdentifier(state, settings))
    {
        pingserverDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    int sequence_start = kPingServerDefaultSequenceStart;
    int ttl            = kPingServerDefaultTtl;
    int tos            = kPingServerDefaultTos;
    if (! pingserverLoadInteger(
            &sequence_start, settings, "sequence-start", kPingServerDefaultSequenceStart, 0, UINT16_MAX) ||
        ! pingserverLoadInteger(&ttl, settings, "ttl", kPingServerDefaultTtl, 0, UINT8_MAX) ||
        ! pingserverLoadInteger(&tos, settings, "tos", kPingServerDefaultTos, 0, UINT8_MAX))
    {
        pingserverDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    state->wire.ttl = (uint8_t) ttl;
    state->wire.tos = (uint8_t) tos;
    atomicStoreRelaxed(&state->next_sequence, (unsigned int) sequence_start);
    atomicLogRateLimiterInitialize(&state->drop_log_limiter);
    return t;
}
