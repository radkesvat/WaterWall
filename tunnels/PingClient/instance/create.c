#include "structure.h"

#include "loggers/network_logger.h"

static bool pingclientSettingIsSupported(const char *key)
{
    static const char *const supported[] = {
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

static bool pingclientRejectUnknownSettings(const cJSON *settings)
{
    for (const cJSON *item = settings != NULL ? settings->child : NULL; item != NULL; item = item->next)
    {
        if (pingclientSettingIsSupported(item->string))
        {
            continue;
        }

        LOGF("PingClient: unknown setting '%s'; expected only identifier, sequence-start, and send-replies",
             item->string != NULL ? item->string : "<unnamed>");
        return false;
    }
    return true;
}

static bool pingclientLoadInteger(int *dest, const cJSON *settings, const char *key, int default_value, int minimum,
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
        LOGF("JSON Error: PingClient->settings->%s (int field) : expected a whole number between %d and %d",
             key,
             minimum,
             maximum);
        return false;
    }

    *dest = (int) value;
    return true;
}

static bool pingclientLoadIdentifier(pingclient_tstate_t *state, const cJSON *settings)
{
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
        LOGF("JSON Error: PingClient->settings->identifier (int or string field) : expected 'random' or a whole "
             "number between 0 and %u",
             (unsigned int) UINT16_MAX);
        return false;
    }

    state->identifier_is_random = false;
    state->wire.identifier      = (uint16_t) value;
    return true;
}

tunnel_t *pingclientCreate(node_t *node)
{
    tunnel_t *t = packettunnelCreate(node, sizeof(pingclient_tstate_t), 0);
    if (t == NULL)
    {
        return NULL;
    }

    t->fnPayloadU = &pingclientUpStreamPayload;
    t->fnPayloadD = &pingclientDownStreamPayload;
    t->onPrepare  = &pingclientOnPrepair;
    t->onStart    = &pingclientOnStart;

    t->onDestroy = &pingclientDestroy;

    pingclient_tstate_t *state    = tunnelGetState(t);
    const cJSON         *settings = node->node_settings_json;

    if (settings != NULL && ! cJSON_IsObject(settings))
    {
        LOGF("JSON Error: PingClient->settings (object field) : expected an object when settings is provided");
        pingclientDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    if (! pingclientRejectUnknownSettings(settings) || ! pingclientLoadIdentifier(state, settings))
    {
        pingclientDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    state->send_replies = false;
    if (jsonGetObjectBoolean(settings, "send-replies", &state->send_replies) == kJsonValueInvalid)
    {
        LOGF("JSON Error: PingClient->settings->send-replies (boolean field) : expected true or false");
        pingclientDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    int sequence_start;
    if (! pingclientLoadInteger(
            &sequence_start, settings, "sequence-start", kPingClientDefaultSequenceStart, 0, UINT16_MAX))
    {
        pingclientDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    atomicStoreRelaxed(&state->next_sequence, (unsigned int) sequence_start);
    atomicLogRateLimiterInitialize(&state->drop_log_limiter);
    return t;
}
