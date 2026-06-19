#include "structure.h"

#include "UserController/interface.h"

#include "loggers/network_logger.h"
#include "managers/node_manager.h"

enum
{
    kTrojanServerDefaultFallbackIntentionalDelayMs       = 7,
    kTrojanServerDefaultFallbackIntentionalDelayJitterMs = 1
};

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

static bool trojanserverAppendPassword(trojanserver_tstate_t *ts, const char *username, const char *password,
                                       const char *path)
{
    sha224_hash_t digest = {0};
    if (UNLIKELY(wCryptoSHA224(&digest, (const unsigned char *) password, stringLength(password)) != 0))
    {
        wCryptoZero(&digest, sizeof(digest));
        LOGF("TrojanServer: failed to calculate SHA224 password digest");
        return false;
    }

    for (uint32_t i = 0; i < ts->user_count; ++i)
    {
        if (wCryptoEqual(ts->users[i].sha224, digest.bytes, SHA224_DIGEST_SIZE))
        {
            wCryptoZero(&digest, sizeof(digest));
            LOGF("JSON Error: TrojanServer->settings->%s duplicates a configured local password", path);
            return false;
        }
    }

    size_t new_count = (size_t) ts->user_count + 1U;
    if (UNLIKELY(new_count > UINT32_MAX))
    {
        wCryptoZero(&digest, sizeof(digest));
        LOGF("TrojanServer: too many configured users");
        return false;
    }

    trojanserver_user_t *users = memoryReAllocate(ts->users, sizeof(*users) * new_count);
    if (UNLIKELY(users == NULL))
    {
        wCryptoZero(&digest, sizeof(digest));
        LOGF("TrojanServer: failed to allocate password allowlist");
        return false;
    }

    ts->users = users;
    memoryCopy(ts->users[ts->user_count].sha224, digest.bytes, SHA224_DIGEST_SIZE);
    ts->users[ts->user_count].username = username != NULL ? stringDuplicate(username) : NULL;
    ts->users[ts->user_count].password = stringDuplicate(password);
    ts->user_count                     = (uint32_t) new_count;

    wCryptoZero(&digest, sizeof(digest));
    return true;
}

static bool trojanserverParsePasswordValue(trojanserver_tstate_t *ts, const cJSON *item, const char *path,
                                           const char *username)
{
    if (! cJSON_IsString(item) || item->valuestring == NULL || item->valuestring[0] == '\0')
    {
        LOGF("JSON Error: TrojanServer->settings->%s must be a non-empty password string", path);
        return false;
    }

    return trojanserverAppendPassword(ts, username, item->valuestring, path);
}

static const cJSON *trojanserverGetObjectPasswordField(const cJSON *item, const char *path, bool *invalid)
{
    *invalid             = false;
    const cJSON *password = cJSON_GetObjectItemCaseSensitive(item, "password");
    const cJSON *pass     = cJSON_GetObjectItemCaseSensitive(item, "pass");
    if (password != NULL && pass != NULL)
    {
        LOGF("JSON Error: TrojanServer->settings->%s object must use either password or pass, not both", path);
        *invalid = true;
        return NULL;
    }

    if (password != NULL)
    {
        return password;
    }

    return pass;
}

static bool trojanserverParseUserEntry(trojanserver_tstate_t *ts, const cJSON *item, const char *path)
{
    if (cJSON_IsString(item))
    {
        return trojanserverParsePasswordValue(ts, item, path, NULL);
    }

    if (! cJSON_IsObject(item))
    {
        LOGF("JSON Error: TrojanServer->settings->%s must be a password string or object", path);
        return false;
    }

    bool         password_invalid = false;
    const cJSON *password         = trojanserverGetObjectPasswordField(item, path, &password_invalid);
    if (password_invalid)
    {
        return false;
    }
    if (password == NULL)
    {
        LOGF("JSON Error: TrojanServer->settings->%s object must contain password or pass", path);
        return false;
    }

    const cJSON *username      = cJSON_GetObjectItemCaseSensitive(item, "username");
    const char  *username_text = NULL;
    if (username != NULL)
    {
        if (! cJSON_IsString(username) || username->valuestring == NULL || username->valuestring[0] == '\0')
        {
            LOGF("JSON Error: TrojanServer->settings->%s->username must be a non-empty string when provided", path);
            return false;
        }
        username_text = username->valuestring;
    }

    return trojanserverParsePasswordValue(ts, password, path, username_text);
}

static bool trojanserverParsePasswordArray(trojanserver_tstate_t *ts, const cJSON *array, const char *path)
{
    if (! cJSON_IsArray(array) || cJSON_GetArraySize(array) <= 0)
    {
        LOGF("JSON Error: TrojanServer->settings->%s must be a non-empty array", path);
        return false;
    }

    int    index = 0;
    cJSON *item  = NULL;
    cJSON_ArrayForEach(item, array)
    {
        char item_path[64] = {0};
        snprintf(item_path, sizeof(item_path), "%s[%d]", path, index);
        if (! trojanserverParseUserEntry(ts, item, item_path))
        {
            return false;
        }
        ++index;
    }

    return true;
}

static bool trojanserverParseUsers(trojanserver_tstate_t *ts, const cJSON *settings)
{
    const cJSON *password = cJSON_GetObjectItemCaseSensitive(settings, "password");
    const cJSON *pass     = cJSON_GetObjectItemCaseSensitive(settings, "pass");
    if (password != NULL && pass != NULL)
    {
        LOGF("JSON Error: TrojanServer->settings must use either password or pass, not both");
        return false;
    }
    if (password == NULL)
    {
        password = pass;
    }

    if (password != NULL && ! trojanserverParsePasswordValue(
                                ts, password, password->string != NULL ? password->string : "password", NULL))
    {
        return false;
    }

    const cJSON *passwords = cJSON_GetObjectItemCaseSensitive(settings, "passwords");
    if (passwords != NULL && ! trojanserverParsePasswordArray(ts, passwords, "passwords"))
    {
        return false;
    }

    const cJSON *users   = cJSON_GetObjectItemCaseSensitive(settings, "users");
    const cJSON *clients = cJSON_GetObjectItemCaseSensitive(settings, "clients");
    if (users != NULL && clients != NULL)
    {
        LOGF("JSON Error: TrojanServer->settings must use either users or clients, not both");
        return false;
    }

    if (users != NULL && ! trojanserverParsePasswordArray(ts, users, "users"))
    {
        return false;
    }

    if (clients != NULL && ! trojanserverParsePasswordArray(ts, clients, "clients"))
    {
        return false;
    }

    if (ts->user_count == 0)
    {
        LOGF("JSON Error: TrojanServer->settings requires at least one password, passwords, users, or clients entry");
        return false;
    }

    return true;
}

static bool trojanserverHasLocalUserSettings(const cJSON *settings)
{
    return cJSON_GetObjectItemCaseSensitive(settings, "password") != NULL ||
           cJSON_GetObjectItemCaseSensitive(settings, "pass") != NULL ||
           cJSON_GetObjectItemCaseSensitive(settings, "passwords") != NULL ||
           cJSON_GetObjectItemCaseSensitive(settings, "users") != NULL ||
           cJSON_GetObjectItemCaseSensitive(settings, "clients") != NULL;
}

static bool trojanserverParseAuthMode(trojanserver_tstate_t *ts, tunnel_t *t, node_t *node, const cJSON *settings)
{
    const cJSON *auth_node_json = cJSON_GetObjectItemCaseSensitive(settings, "auth-client-node-name");

    if (auth_node_json == NULL)
    {
        return trojanserverParseUsers(ts, settings);
    }

    if (! cJSON_IsString(auth_node_json) || auth_node_json->valuestring == NULL ||
        auth_node_json->valuestring[0] == '\0')
    {
        LOGF("JSON Error: TrojanServer->settings->auth-client-node-name (string field) must be a non-empty string");
        return false;
    }

    if (trojanserverHasLocalUserSettings(settings))
    {
        LOGF("JSON Error: TrojanServer auth-client mode uses the AuthenticationClient users database; remove local "
             "password/passwords/users/clients settings");
        return false;
    }

    return parseAuthClientNode(ts, node, auth_node_json->valuestring) && trojanserverCreateUserControllerTunnel(t, node);
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

    ts->allow_connect = true;
    ts->allow_udp     = true;
    int fallback_intentional_delay_ms        = kTrojanServerDefaultFallbackIntentionalDelayMs;
    int fallback_intentional_delay_jitter_ms = kTrojanServerDefaultFallbackIntentionalDelayJitterMs;
    getBoolFromJsonObjectOrDefault(&ts->allow_connect, settings, "connect", true);
    getBoolFromJsonObjectOrDefault(&ts->allow_udp, settings, "udp", true);
    getBoolFromJsonObjectOrDefault(&ts->verbose, settings, "verbose", false);
    getIntFromJsonObjectOrDefault(&fallback_intentional_delay_ms,
                                  settings,
                                  "fallback-intentional-delay-ms",
                                  kTrojanServerDefaultFallbackIntentionalDelayMs);
    getIntFromJsonObjectOrDefault(&fallback_intentional_delay_jitter_ms,
                                  settings,
                                  "fallback-intentional-delay-jitter-ms",
                                  kTrojanServerDefaultFallbackIntentionalDelayJitterMs);

    if (! ts->allow_connect && ! ts->allow_udp)
    {
        LOGF("JSON Error: TrojanServer must enable at least one of connect/udp");
        trojanserverTunnelDestroy(t);
        return NULL;
    }

    if (fallback_intentional_delay_ms < 0)
    {
        LOGF(
            "JSON Error: TrojanServer->settings->fallback-intentional-delay-ms (number field) : The value was invalid");
        trojanserverTunnelDestroy(t);
        return NULL;
    }
    ts->fallback_intentional_delay_ms = (uint32_t) fallback_intentional_delay_ms;

    if (fallback_intentional_delay_jitter_ms < 0)
    {
        LOGF(
            "JSON Error: TrojanServer->settings->fallback-intentional-delay-jitter-ms (number field) : The value was invalid");
        trojanserverTunnelDestroy(t);
        return NULL;
    }
    ts->fallback_intentional_delay_jitter_ms = (uint32_t) fallback_intentional_delay_jitter_ms;

    if (ts->fallback_intentional_delay_ms == 0 && ts->fallback_intentional_delay_jitter_ms > 0)
    {
        LOGD("TrojanServer: fallback-intentional-delay-jitter-ms is ignored because fallback-intentional-delay-ms is 0");
    }

    if (! trojanserverParseAuthMode(ts, t, node, settings) || ! parseFallbackNode(ts, node, settings))
    {
        trojanserverTunnelDestroy(t);
        return NULL;
    }

    if (ts->auth_client_node != NULL || ts->fallback_node != NULL)
    {
        t->onChain = &trojanserverTunnelOnChain;
    }

    return t;
}
