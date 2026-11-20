#include "structure.h"

#include "loggers/network_logger.h"

static bool pingserverSettingIsSupported(const char *key)
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

static bool pingserverRejectUnknownSettings(const cJSON *settings)
{
    for (const cJSON *item = settings != NULL ? settings->child : NULL; item != NULL; item = item->next)
    {
        if (pingserverSettingIsSupported(item->string))
        {
            continue;
        }

        LOGF("PingServer: unknown setting '%s'; expected only identifier, sequence-start, and send-replies",
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

static bool pingserverLoadIdentifier(pingserver_tstate_t *state, const cJSON *settings)
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

    t->onPrepare = &pingserverOnPrepair;
    t->onStart   = &pingserverOnStart;

    t->onDestroy = &pingserverDestroy;

    pingserver_tstate_t *state    = tunnelGetState(t);
    const cJSON         *settings = node->node_settings_json;

    if (settings != NULL && ! cJSON_IsObject(settings))
    {
        LOGF("JSON Error: PingServer->settings (object field) : expected an object when settings is provided");
        pingserverDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    if (! pingserverRejectUnknownSettings(settings) || ! pingserverLoadIdentifier(state, settings))
    {
        pingserverDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    state->send_replies = false;
    if (jsonGetObjectBoolean(settings, "send-replies", &state->send_replies) == kJsonValueInvalid)
    {
        LOGF("JSON Error: PingServer->settings->send-replies (boolean field) : expected true or false");
        pingserverDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    int sequence_start;
    if (! pingserverLoadInteger(
            &sequence_start, settings, "sequence-start", kPingServerDefaultSequenceStart, 0, UINT16_MAX))
    {
        pingserverDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    atomicStoreRelaxed(&state->next_sequence, (unsigned int) sequence_start);
    atomicLogRateLimiterInitialize(&state->drop_log_limiter);
    return t;
}
