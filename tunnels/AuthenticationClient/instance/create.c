#include "structure.h"

#include "loggers/network_logger.h"

static void authenticationclientInitializeCallbacks(tunnel_t *t)
{
    t->fnInitU    = &authenticationclientTunnelUpStreamInit;
    t->fnEstU     = &authenticationclientTunnelUpStreamEst;
    t->fnFinU     = &authenticationclientTunnelUpStreamFinish;
    t->fnPayloadU = &authenticationclientTunnelUpStreamPayload;
    t->fnPauseU   = &authenticationclientTunnelUpStreamPause;
    t->fnResumeU  = &authenticationclientTunnelUpStreamResume;

    t->fnInitD    = &authenticationclientTunnelDownStreamInit;
    t->fnEstD     = &authenticationclientTunnelDownStreamEst;
    t->fnFinD     = &authenticationclientTunnelDownStreamFinish;
    t->fnPayloadD = &authenticationclientTunnelDownStreamPayload;
    t->fnPauseD   = &authenticationclientTunnelDownStreamPause;
    t->fnResumeD  = &authenticationclientTunnelDownStreamResume;

    t->onPrepare    = &authenticationclientTunnelOnPrepair;
    t->onStart      = &authenticationclientTunnelOnStart;
    t->onStop       = &authenticationclientTunnelOnStop;
    t->onWorkerStop = &authenticationclientTunnelOnWorkerStop;
    t->onDestroy    = &authenticationclientTunnelDestroy;
}

static bool authenticationclientReadInterval(const cJSON *settings, const char *name, int default_value, uint32_t *out)
{
    int value = default_value;
    getIntFromJsonObjectOrDefault(&value, settings, name, default_value);
    if (UNLIKELY(value < 0))
    {
        LOGF("AuthenticationClient: settings->%s must be zero or a positive integer", name);
        return false;
    }

    *out = (uint32_t) value;
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

    if (UNLIKELY(
            ! authenticationclientReadInterval(
                settings, "ping-interval-ms", kAuthenticationClientDefaultPingIntervalMs, &ts->ping_interval_ms) ||
            ! authenticationclientReadInterval(
                settings, "pull-interval-ms", kAuthenticationClientDefaultPullIntervalMs, &ts->pull_interval_ms) ||
            ! authenticationclientReadInterval(
                settings, "push-interval-ms", kAuthenticationClientDefaultPushIntervalMs, &ts->push_interval_ms) ||
            ! authenticationclientReadInterval(settings,
                                               "reconnect-interval-ms",
                                               kAuthenticationClientDefaultReconnectIntervalMs,
                                               &ts->reconnect_interval_ms) ||
            ! authenticationclientReadInterval(
                settings, "request-timeout-ms", kAuthenticationClientDefaultRequestTimeoutMs, &ts->request_timeout_ms)))
    {
        return false;
    }

    int max_pending_requests = kAuthenticationClientDefaultMaxPendingRequests;
    getIntFromJsonObjectOrDefault(
        &max_pending_requests, settings, "max-pending-requests", kAuthenticationClientDefaultMaxPendingRequests);
    if (UNLIKELY(max_pending_requests <= 0))
    {
        LOGF("JSON Error: AuthenticationClient->settings->max-pending-requests must be positive");
        return false;
    }
    ts->max_pending_requests = (uint32_t) max_pending_requests;

    return true;
}

tunnel_t *authenticationclientTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(authenticationclient_tstate_t), sizeof(authenticationclient_lstate_t));
    if (UNLIKELY(t == NULL))
    {
        return NULL;
    }

    authenticationclientInitializeCallbacks(t);

    authenticationclient_tstate_t *ts = tunnelGetState(t);
    mutexInit(&ts->control_mutex);
    rwlockinit(&ts->users_lock);
    ts->next_correlation_id = 1U;
    ts->users_generation    = 1U;

    if (UNLIKELY(! authenticationclientParseSettings(ts, node)))
    {
        authenticationclientTunnelDestroy(t);
        return NULL;
    }

    users_t *users = memoryAllocate(sizeof(*users));
    if (UNLIKELY(users == NULL))
    {
        LOGE("AuthenticationClient: failed to create local users table");
        authenticationclientTunnelDestroy(t);
        return NULL;
    }

    if (UNLIKELY(! usersCreate(users)))
    {
        LOGE("AuthenticationClient: failed to create local users table");
        memoryFree(users);
        authenticationclientTunnelDestroy(t);
        return NULL;
    }
    ts->users = users;

    return t;
}
