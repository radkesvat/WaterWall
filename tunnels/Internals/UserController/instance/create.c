#include "structure.h"

#include "loggers/network_logger.h"

static hash_t usercontrollerAuthenticationClientTypeHash(void)
{
    const char *type_name = "AuthenticationClient";
    return calcHashBytes(type_name, stringLength(type_name));
}

static bool parseAuthClientNode(usercontroller_tstate_t *ts, node_t *node, const char *auth_client_node_name)
{
    node_t *auth_client_node = nodemanagerGetConfigNodeByName(node->node_manager_config, auth_client_node_name);
    if (auth_client_node == NULL)
    {
        LOGF("UserController: auth-client-node-name \"%s\" was not found", auth_client_node_name);
        return false;
    }

    if (auth_client_node == node)
    {
        LOGF("UserController: auth-client-node-name must not point back to UserController itself");
        return false;
    }

    if (auth_client_node->hash_type != usercontrollerAuthenticationClientTypeHash())
    {
        LOGF("UserController: auth-client-node-name \"%s\" must point to an AuthenticationClient node",
             auth_client_node_name);
        return false;
    }

    ts->auth_client_node = auth_client_node;
    return true;
}

static bool parseSettings(usercontroller_tstate_t *ts, node_t *node, const cJSON *settings)
{
    const cJSON *auth_node_json = cJSON_GetObjectItemCaseSensitive(settings, "auth-client-node-name");
    int          sweep_interval_ms = kUserControllerDefaultSweepIntervalMs;

    if (! cJSON_IsString(auth_node_json) || auth_node_json->valuestring == NULL ||
        auth_node_json->valuestring[0] == '\0')
    {
        LOGF("JSON Error: UserController->settings->auth-client-node-name (string field) must be a non-empty string");
        return false;
    }

    getBoolFromJsonObjectOrDefault(&ts->verbose, settings, "verbose", false);
    getIntFromJsonObjectOrDefault(
        &sweep_interval_ms, settings, "sweep-interval-ms", kUserControllerDefaultSweepIntervalMs);
    if (sweep_interval_ms < 1)
    {
        LOGF("JSON Error: UserController->settings->sweep-interval-ms (int field) must be >= 1");
        return false;
    }
    ts->sweep_interval_ms = (uint32_t) sweep_interval_ms;

    return parseAuthClientNode(ts, node, auth_node_json->valuestring);
}

tunnel_t *usercontrollerTunnelCreate(node_t *node)
{
    tunnel_t                *t  = tunnelCreate(node, sizeof(usercontroller_tstate_t), sizeof(usercontroller_lstate_t));
    usercontroller_tstate_t *ts = tunnelGetState(t);
    const cJSON             *settings = node->node_settings_json;

    t->fnInitU    = &usercontrollerTunnelUpStreamInit;
    t->fnEstU     = &usercontrollerTunnelUpStreamEst;
    t->fnFinU     = &usercontrollerTunnelUpStreamFinish;
    t->fnPayloadU = &usercontrollerTunnelUpStreamPayload;
    t->fnPauseU   = &usercontrollerTunnelUpStreamPause;
    t->fnResumeU  = &usercontrollerTunnelUpStreamResume;

    t->fnInitD    = &usercontrollerTunnelDownStreamInit;
    t->fnEstD     = &usercontrollerTunnelDownStreamEst;
    t->fnFinD     = &usercontrollerTunnelDownStreamFinish;
    t->fnPayloadD = &usercontrollerTunnelDownStreamPayload;
    t->fnPauseD   = &usercontrollerTunnelDownStreamPause;
    t->fnResumeD  = &usercontrollerTunnelDownStreamResume;

    t->onPrepare    = &usercontrollerTunnelOnPrepair;
    t->onStart      = &usercontrollerTunnelOnStart;
    t->onStop       = &usercontrollerTunnelOnStop;
    t->onWorkerStop = &usercontrollerTunnelOnWorkerStop;
    t->onDestroy    = &usercontrollerTunnelDestroy;

    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: UserController->settings (object field) : The object was empty or invalid");
        tunnelDestroy(t);
        return NULL;
    }

    ts->verbose           = false;
    ts->sweep_interval_ms = kUserControllerDefaultSweepIntervalMs;
    ts->worker_count      = getWorkersCount();
    ts->worker_states     = memoryAllocateZero(sizeof(*ts->worker_states) * ts->worker_count);
    if (UNLIKELY(ts->worker_states == NULL))
    {
        LOGF("UserController: failed to allocate worker state");
        tunnelDestroy(t);
        return NULL;
    }

    if (! parseSettings(ts, node, settings))
    {
        usercontrollerTunnelstateDestroy(ts);
        tunnelDestroy(t);
        return NULL;
    }

    return t;
}
