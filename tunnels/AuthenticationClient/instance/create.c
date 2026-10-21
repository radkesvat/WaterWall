#include "../../Internals/AuthenticationCommon/credentials.h"
#include "structure.h"

#include "loggers/network_logger.h"
#include <math.h>

static void authenticationclientInitializeCallbacks(tunnel_t *t)
{
    t->fnInitU    = &authenticationclientTunnelUpStreamInit;
    t->fnFinU     = &authenticationclientTunnelUpStreamFinish;
    t->fnPayloadU = &authenticationclientTunnelUpStreamPayload;
    t->fnPauseU   = &authenticationclientTunnelUpStreamPause;
    t->fnResumeU  = &authenticationclientTunnelUpStreamResume;
    t->fnEstD     = &authenticationclientTunnelDownStreamEst;
    t->fnFinD     = &authenticationclientTunnelDownStreamFinish;
    t->fnPayloadD = &authenticationclientTunnelDownStreamPayload;
    t->fnPauseD   = &authenticationclientTunnelDownStreamPause;
    t->fnResumeD  = &authenticationclientTunnelDownStreamResume;

    t->onStart          = &authenticationclientTunnelOnStart;
    t->onQuiesceRequest = &authenticationclientTunnelOnQuiesceRequest;
    t->onWorkerQuiesce  = &authenticationclientTunnelOnWorkerQuiesce;
    t->onWorkerStop     = &authenticationclientTunnelOnWorkerStop;
    t->onDestroy        = &authenticationclientTunnelDestroy;
}

static bool authenticationclientReadInteger(const cJSON *settings, const char *name, uint32_t default_value,
                                            uint32_t minimum, uint32_t *out)
{
    int64_t value = default_value;
    if (UNLIKELY(jsonGetObjectIntegerInRange(settings, name, minimum, INT_MAX, &value) == kJsonValueInvalid))
    {
        LOGF("AuthenticationClient: settings->%s must be an integer from %u through %d", name, minimum, INT_MAX);
        return false;
    }

    *out = (uint32_t) value;
    return true;
}

static bool authenticationclientReadTrafficMultiplier(const cJSON *settings, uint32_t *out)
{
    *out                 = kUserTrafficMultiplierScale;
    const cJSON *setting = NULL;
    for (const cJSON *item = settings->child; item != NULL; item = item->next)
    {
        if (item->string == NULL || strcmp(item->string, "traffic-multiplier") != 0)
            continue;
        if (setting != NULL)
        {
            LOGE("AuthenticationClient: duplicate traffic-multiplier setting");
            return false;
        }
        setting = item;
    }
    if (setting == NULL)
        return true;

    if (! cJSON_IsNumber(setting) || ! isfinite(setting->valuedouble) ||
        setting->valuedouble < 1.0 / kUserTrafficMultiplierScale ||
        setting->valuedouble > (double) kUserTrafficMultiplierMax / kUserTrafficMultiplierScale)
    {
        LOGE("AuthenticationClient: traffic-multiplier must be a number from 0.001 through 1000");
        return false;
    }

    /* Convert once at startup. Reconstructing the value accepts the ordinary
     * JSON representation of a three-decimal rate without silently rounding a
     * finer rate. Payload accounting uses only this integer coefficient. */
    const uint32_t multiplier = (uint32_t) (setting->valuedouble * kUserTrafficMultiplierScale + 0.5);
    if ((double) multiplier / kUserTrafficMultiplierScale != setting->valuedouble)
    {
        LOGE("AuthenticationClient: traffic-multiplier supports at most three decimal places");
        return false;
    }
    *out = multiplier;
    return true;
}

static bool authenticationclientReadSyncLimit(const cJSON *settings, const char *name, uint64_t fallback, uint64_t *out)
{
    const cJSON *value = NULL;
    for (const cJSON *item = settings->child; item != NULL; item = item->next)
        if (item->string != NULL && strcmp(item->string, name) == 0)
        {
            if (value != NULL)
                return false;
            value = item;
        }
    *out = fallback;
    if (value == NULL)
        return true;
    if (! cJSON_IsNumber(value) || ! getUint64FromJson(out, value) || *out == 0 || *out > SIZE_MAX)
    {
        LOGE("AuthenticationClient: %s must be a positive representable integer", name);
        return false;
    }
    return true;
}

static bool authenticationclientParseSettings(authenticationclient_tstate_t *ts, node_t *node)
{
    const cJSON *settings = node->node_settings_json;

    if (UNLIKELY(! nodeHasNext(node)))
    {
        LOGF("AuthenticationClient: a next node is required");
        return false;
    }

    if (UNLIKELY(! checkJsonIsObjectAndHasChild(settings)))
    {
        LOGF("JSON Error: AuthenticationClient->settings (object field) : The object was empty or invalid");
        return false;
    }

    if (UNLIKELY(! getStringFromJsonObject(&ts->name, settings, "name") || ts->name[0] == '\0'))
    {
        LOGF("JSON Error: AuthenticationClient->settings->name (string field) : invalid value");
        return false;
    }

    if (UNLIKELY(! getStringFromJsonObject(&ts->secret, settings, "secret") || ts->secret[0] == '\0'))
    {
        LOGF("JSON Error: AuthenticationClient->settings->secret (string field) : invalid value");
        return false;
    }

    if (! authenticationCredentialsFit(ts->name, ts->secret))
    {
        LOGE("AuthenticationClient: configured credentials exceed the Authenticate input limit");
        return false;
    }

    getBoolFromJsonObjectOrDefault(&ts->verbose, settings, "verbose", false);

    if (! authenticationclientReadSyncLimit(
            settings, "sync-max-users", kAuthenticationDefaultSyncMaxUsers, &ts->sync_max_users) ||
        ! authenticationclientReadSyncLimit(
            settings, "sync-max-bytes", kAuthenticationDefaultSyncMaxBytes, &ts->sync_max_bytes))
        return false;

    if (! authenticationclientReadTrafficMultiplier(settings, &ts->traffic_multiplier))
        return false;

    if (UNLIKELY(
            ! authenticationclientReadInteger(
                settings, "ping-interval-ms", kAuthenticationClientDefaultPingIntervalMs, 0, &ts->ping_interval_ms) ||
            ! authenticationclientReadInteger(
                settings, "pull-interval-ms", kAuthenticationClientDefaultPullIntervalMs, 0, &ts->pull_interval_ms) ||
            ! authenticationclientReadInteger(
                settings, "push-interval-ms", kAuthenticationClientDefaultPushIntervalMs, 0, &ts->push_interval_ms) ||
            ! authenticationclientReadInteger(settings,
                                              "reconnect-interval-ms",
                                              kAuthenticationClientDefaultReconnectIntervalMs,
                                              0,
                                              &ts->reconnect_interval_ms) ||
            ! authenticationclientReadInteger(settings,
                                              "request-timeout-ms",
                                              kAuthenticationClientDefaultRequestTimeoutMs,
                                              0,
                                              &ts->request_timeout_ms)))
    {
        return false;
    }

    if (! authenticationclientReadInteger(settings,
                                          "max-pending-requests",
                                          kAuthenticationClientDefaultMaxPendingRequests,
                                          1,
                                          &ts->max_pending_requests))
    {
        return false;
    }

    return true;
}

tunnel_t *authenticationclientTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(authenticationclient_tstate_t), sizeof(authenticationclient_lstate_t));
    if (! t)
    {
        return NULL;
    }

    authenticationclient_tstate_t *ts = tunnelGetState(t);
    if (UNLIKELY(! mutexTryInit(&ts->control_mutex)))
    {
        LOGF("AuthenticationClient: failed to initialize control mutex");
        tunnelDestroy(t);
        return NULL;
    }
    if (UNLIKELY(! rwlockTryInit(&ts->users_lock)))
    {
        LOGF("AuthenticationClient: failed to initialize users lock");
        mutexDestroy(&ts->control_mutex);
        tunnelDestroy(t);
        return NULL;
    }

    authenticationclientInitializeCallbacks(t);

    ts->next_correlation_id = 1U;
    ts->users_generation    = 1U;

    if (UNLIKELY(! authenticationclientParseSettings(ts, node)))
    {
        authenticationclientTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    if (ts->verbose)
    {
        LOGD("AuthenticationClient: verbose flow logging is enabled");
    }

    /* Paired with memoryFreeAligned() in authenticationclientTunnelDestroy(). */
    users_t *users = memoryAllocateAligned(sizeof(*users), 32);

    if (UNLIKELY(! usersCreate(users)))
    {
        LOGE("AuthenticationClient: failed to create local users table");
        memoryFreeAligned(users);
        authenticationclientTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }
    ts->users = users;

    if (! authenticationclientRegisterApi(t))
    {
        authenticationclientTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    return t;
}
