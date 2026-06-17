#include "structure.h"

#include "UserController/interface.h"

#include "loggers/network_logger.h"
#include "managers/node_manager.h"

static hash_t trojanserverAuthenticationClientTypeHash(void)
{
    const char *type_name = "AuthenticationClient";
    return calcHashBytes(type_name, stringLength(type_name));
}

static bool parseAuthClientNode(trojanserver_tstate_t *ts, node_t *node, const char *auth_client_node_name)
{
    node_t *auth_client_node = nodemanagerGetConfigNodeByName(node->node_manager_config, auth_client_node_name);
    if (auth_client_node == NULL)
    {
        LOGF("TrojanServer: auth-client-node-name \"%s\" was not found", auth_client_node_name);
        return false;
    }

    if (auth_client_node == node)
    {
        LOGF("TrojanServer: auth-client-node-name must not point back to TrojanServer itself");
        return false;
    }

    if (auth_client_node->hash_type != trojanserverAuthenticationClientTypeHash())
    {
        LOGF("TrojanServer: auth-client-node-name \"%s\" must point to an AuthenticationClient node",
             auth_client_node_name);
        return false;
    }

    ts->auth_client_node = auth_client_node;
    return true;
}

static const cJSON *getSettingsItemByKeys(const cJSON *settings, const char *key1, const char *key2, const char *key3)
{
    const char *keys[3] = {key1, key2, key3};

    for (size_t i = 0; i < ARRAY_SIZE(keys); ++i)
    {
        if (keys[i] == NULL)
        {
            continue;
        }

        const cJSON *item = cJSON_GetObjectItemCaseSensitive(settings, keys[i]);
        if (item != NULL)
        {
            return item;
        }
    }

    return NULL;
}

static bool parseFallbackNode(trojanserver_tstate_t *ts, node_t *node, const cJSON *settings)
{
    const cJSON *fallback_json = getSettingsItemByKeys(settings, "fallback-node-name", "fallback-node", "fallback");

    if (fallback_json == NULL)
    {
        ts->fallback_node = NULL;
        return true;
    }

    if (! cJSON_IsString(fallback_json) || fallback_json->valuestring == NULL || fallback_json->valuestring[0] == '\0')
    {
        LOGF("JSON Error: TrojanServer->settings->fallback-node-name (string field) must be a non-empty string");
        return false;
    }

    node_t *fallback_node = nodemanagerGetConfigNodeByName(node->node_manager_config, fallback_json->valuestring);
    if (fallback_node == NULL)
    {
        LOGF("TrojanServer: fallback node \"%s\" was not found", fallback_json->valuestring);
        return false;
    }

    if (fallback_node == node)
    {
        LOGF("TrojanServer: fallback node must not point back to TrojanServer itself");
        return false;
    }

    ts->fallback_node = fallback_node;
    return true;
}

static char *trojanserverMakeChildName(const node_t *node, const char *suffix)
{
    const char *base = node->name != NULL ? node->name : "TrojanServer";
    return stringConcat(base, suffix);
}

static void trojanserverConfigureUserControllerNode(node_t *child, node_t template_node, const node_t *owner)
{
    *child = template_node;

    child->name      = trojanserverMakeChildName(owner, ".user-controller");
    child->hash_name = calcHashBytes(child->name, stringLength(child->name));
    child->next      = owner->next != NULL ? stringDuplicate(owner->next) : NULL;
    child->hash_next = owner->hash_next;
    child->version   = owner->version;

    child->node_json           = owner->node_json;
    child->node_settings_json  = owner->node_settings_json;
    child->node_manager_config = owner->node_manager_config;
    child->instance            = NULL;
}

static bool trojanserverCreateUserControllerTunnel(tunnel_t *t, node_t *node)
{
    trojanserver_tstate_t *ts = tunnelGetState(t);

    trojanserverConfigureUserControllerNode(&ts->user_controller_node, nodeUserControllerGet(), node);

    ts->user_controller_tunnel = ts->user_controller_node.createHandle(&ts->user_controller_node);
    if (ts->user_controller_tunnel == NULL)
    {
        LOGF("TrojanServer: failed to create internal UserController");
        return false;
    }

    ts->user_controller_node.instance = ts->user_controller_tunnel;
    return true;
}

tunnel_t *trojanserverTunnelCreate(node_t *node)
{
    tunnel_t              *t        = tunnelCreate(node, sizeof(trojanserver_tstate_t), sizeof(trojanserver_lstate_t));
    trojanserver_tstate_t *ts       = tunnelGetState(t);
    const cJSON           *settings = node->node_settings_json;

    t->fnInitU    = &trojanserverTunnelUpStreamInit;
    t->fnEstU     = &trojanserverTunnelUpStreamEst;
    t->fnFinU     = &trojanserverTunnelUpStreamFinish;
    t->fnPayloadU = &trojanserverTunnelUpStreamPayload;
    t->fnPauseU   = &trojanserverTunnelUpStreamPause;
    t->fnResumeU  = &trojanserverTunnelUpStreamResume;

    t->fnInitD    = &trojanserverTunnelDownStreamInit;
    t->fnEstD     = &trojanserverTunnelDownStreamEst;
    t->fnFinD     = &trojanserverTunnelDownStreamFinish;
    t->fnPayloadD = &trojanserverTunnelDownStreamPayload;
    t->fnPauseD   = &trojanserverTunnelDownStreamPause;
    t->fnResumeD  = &trojanserverTunnelDownStreamResume;

    t->onPrepare = &trojanserverTunnelOnPrepair;
    t->onChain   = &trojanserverTunnelOnChain;
    t->onStart   = &trojanserverTunnelOnStart;
    t->onStop    = &trojanserverTunnelOnStop;
    t->onDestroy = &trojanserverTunnelDestroy;

    if (! nodeHasNext(node))
    {
        LOGF("TrojanServer: a next node is required for authenticated Trojan traffic");
        trojanserverTunnelDestroy(t);
        return NULL;
    }

    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: TrojanServer->settings (object field) : The object was empty or invalid");
        trojanserverTunnelDestroy(t);
        return NULL;
    }

    const cJSON *auth_node_json = cJSON_GetObjectItemCaseSensitive(settings, "auth-client-node-name");
    if (! cJSON_IsString(auth_node_json) || auth_node_json->valuestring == NULL ||
        auth_node_json->valuestring[0] == '\0')
    {
        LOGF("JSON Error: TrojanServer->settings->auth-client-node-name (string field) must be a non-empty string");
        trojanserverTunnelDestroy(t);
        return NULL;
    }

    ts->allow_connect = true;
    ts->allow_udp     = true;
    getBoolFromJsonObjectOrDefault(&ts->allow_connect, settings, "connect", true);
    getBoolFromJsonObjectOrDefault(&ts->allow_udp, settings, "udp", true);
    getBoolFromJsonObjectOrDefault(&ts->verbose, settings, "verbose", false);

    if (! ts->allow_connect && ! ts->allow_udp)
    {
        LOGF("JSON Error: TrojanServer must enable at least one of connect/udp");
        trojanserverTunnelDestroy(t);
        return NULL;
    }

    if (! parseAuthClientNode(ts, node, auth_node_json->valuestring) || ! parseFallbackNode(ts, node, settings) ||
        ! trojanserverCreateUserControllerTunnel(t, node))
    {
        trojanserverTunnelDestroy(t);
        return NULL;
    }

    return t;
}
