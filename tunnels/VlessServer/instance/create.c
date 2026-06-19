#include "structure.h"

#include "UserController/interface.h"

#include "loggers/network_logger.h"
#include "managers/node_manager.h"

static hash_t vlessserverAuthenticationClientTypeHash(void)
{
    const char *type_name = "AuthenticationClient";
    return calcHashBytes(type_name, stringLength(type_name));
}

static bool vlessserverParseAuthClientNode(vlessserver_tstate_t *ts, node_t *node, const char *auth_client_node_name)
{
    node_t *auth_client_node = nodemanagerGetConfigNodeByName(node->node_manager_config, auth_client_node_name);
    if (auth_client_node == NULL)
    {
        LOGF("VlessServer: auth-client-node-name \"%s\" was not found", auth_client_node_name);
        return false;
    }

    if (auth_client_node == node)
    {
        LOGF("VlessServer: auth-client-node-name must not point back to VlessServer itself");
        return false;
    }

    if (auth_client_node->hash_type != vlessserverAuthenticationClientTypeHash())
    {
        LOGF("VlessServer: auth-client-node-name \"%s\" must point to an AuthenticationClient node",
             auth_client_node_name);
        return false;
    }

    ts->auth_client_node = auth_client_node;
    return true;
}

static const cJSON *vlessserverGetSettingsItemByKeys(const cJSON *settings, const char *key1, const char *key2,
                                                     const char *key3)
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

static bool vlessserverParseFallbackNode(vlessserver_tstate_t *ts, node_t *node, const cJSON *settings)
{
    const cJSON *fallback_json =
        vlessserverGetSettingsItemByKeys(settings, "fallback-node-name", "fallback-node", "fallback");

    if (fallback_json == NULL)
    {
        ts->fallback_node = NULL;
        return true;
    }

    if (! cJSON_IsString(fallback_json) || fallback_json->valuestring == NULL || fallback_json->valuestring[0] == '\0')
    {
        LOGF("JSON Error: VlessServer->settings->fallback-node-name (string field) must be a non-empty string");
        return false;
    }

    node_t *fallback_node = nodemanagerGetConfigNodeByName(node->node_manager_config, fallback_json->valuestring);
    if (fallback_node == NULL)
    {
        LOGF("VlessServer: fallback node \"%s\" was not found", fallback_json->valuestring);
        return false;
    }

    if (fallback_node == node)
    {
        LOGF("VlessServer: fallback node must not point back to VlessServer itself");
        return false;
    }

    ts->fallback_node = fallback_node;
    return true;
}

static char *vlessserverMakeChildName(const node_t *node, const char *suffix)
{
    const char *base = node->name != NULL ? node->name : "VlessServer";
    return stringConcat(base, suffix);
}

static void vlessserverConfigureUserControllerNode(node_t *child, node_t template_node, const node_t *owner)
{
    *child = template_node;

    child->name      = vlessserverMakeChildName(owner, ".user-controller");
    child->hash_name = calcHashBytes(child->name, stringLength(child->name));
    child->next      = owner->next != NULL ? stringDuplicate(owner->next) : NULL;
    child->hash_next = owner->hash_next;
    child->version   = owner->version;

    child->node_json           = owner->node_json;
    child->node_settings_json  = owner->node_settings_json;
    child->node_manager_config = owner->node_manager_config;
    child->instance            = NULL;
}

static bool vlessserverCreateUserControllerTunnel(tunnel_t *t, node_t *node)
{
    vlessserver_tstate_t *ts = tunnelGetState(t);

    vlessserverConfigureUserControllerNode(&ts->user_controller_node, nodeUserControllerGet(), node);

    ts->user_controller_tunnel = ts->user_controller_node.createHandle(&ts->user_controller_node);
    if (ts->user_controller_tunnel == NULL)
    {
        LOGF("VlessServer: failed to create internal UserController");
        return false;
    }

    ts->user_controller_node.instance = ts->user_controller_tunnel;
    return true;
}

static int vlessserverHexValue(uint8_t c)
{
    if (c >= '0' && c <= '9')
    {
        return (int) (c - '0');
    }

    if (c >= 'a' && c <= 'f')
    {
        return (int) (c - 'a' + 10);
    }

    if (c >= 'A' && c <= 'F')
    {
        return (int) (c - 'A' + 10);
    }

    return -1;
}

static bool vlessserverParseUuidString(const char *text, uint8_t out[kVlessServerUuidLen])
{
    size_t len    = stringLength(text);
    bool   dashed = len == 36;

    if (len != 32 && len != 36)
    {
        return false;
    }

    memoryZero(out, kVlessServerUuidLen);

    size_t hex_index = 0;
    for (size_t i = 0; i < len; ++i)
    {
        if (dashed && (i == 8 || i == 13 || i == 18 || i == 23))
        {
            if (text[i] != '-')
            {
                return false;
            }
            continue;
        }

        if (text[i] == '-')
        {
            return false;
        }

        int value = vlessserverHexValue((uint8_t) text[i]);
        if (value < 0 || hex_index >= 32)
        {
            return false;
        }

        if ((hex_index & 1U) == 0)
        {
            out[hex_index / 2U] = (uint8_t) (value << 4);
        }
        else
        {
            out[hex_index / 2U] |= (uint8_t) value;
        }
        ++hex_index;
    }

    return hex_index == 32;
}

static bool vlessserverAppendUuid(vlessserver_tstate_t *ts, const uint8_t uuid[kVlessServerUuidLen],
                                  const char *username, const char *path)
{
    for (uint32_t i = 0; i < ts->user_count; ++i)
    {
        if (wCryptoEqual(ts->users[i].uuid, uuid, kVlessServerUuidLen))
        {
            LOGF("JSON Error: VlessServer->settings->%s duplicates a configured local UUID", path);
            return false;
        }
    }

    size_t new_count = (size_t) ts->user_count + 1U;
    if (UNLIKELY(new_count > UINT32_MAX))
    {
        LOGF("VlessServer: too many configured users");
        return false;
    }

    vlessserver_user_t *users = memoryReAllocate(ts->users, sizeof(*users) * new_count);
    if (UNLIKELY(users == NULL))
    {
        LOGF("VlessServer: failed to allocate UUID allowlist");
        return false;
    }

    ts->users = users;
    memoryCopy(ts->users[ts->user_count].uuid, uuid, kVlessServerUuidLen);
    ts->users[ts->user_count].username = username != NULL ? stringDuplicate(username) : NULL;
    ts->user_count = (uint32_t) new_count;
    return true;
}

static bool vlessserverParseUuidValue(vlessserver_tstate_t *ts, const cJSON *item, const char *path,
                                      const char *username)
{
    if (! cJSON_IsString(item) || item->valuestring == NULL || item->valuestring[0] == '\0')
    {
        LOGF("JSON Error: VlessServer->settings->%s must be a non-empty UUID string", path);
        return false;
    }

    uint8_t uuid[kVlessServerUuidLen] = {0};
    if (! vlessserverParseUuidString(item->valuestring, uuid))
    {
        LOGF("JSON Error: VlessServer->settings->%s must be an RFC4122 UUID string", path);
        return false;
    }

    return vlessserverAppendUuid(ts, uuid, username, path);
}

static const cJSON *vlessserverGetObjectUuidField(const cJSON *item, const char *path, bool *invalid)
{
    *invalid             = false;
    const cJSON *uuid    = cJSON_GetObjectItemCaseSensitive(item, "uuid");
    const cJSON *id      = cJSON_GetObjectItemCaseSensitive(item, "id");
    const cJSON *user_id = cJSON_GetObjectItemCaseSensitive(item, "user-id");
    uint32_t field_count = (uuid != NULL ? 1U : 0U) + (id != NULL ? 1U : 0U) + (user_id != NULL ? 1U : 0U);
    if (field_count > 1U)
    {
        LOGF("JSON Error: VlessServer->settings->%s object must use only one of uuid, id, or user-id", path);
        *invalid = true;
        return NULL;
    }

    if (uuid != NULL)
    {
        return uuid;
    }

    if (id != NULL)
    {
        return id;
    }

    return user_id;
}

static bool vlessserverParseUserEntry(vlessserver_tstate_t *ts, const cJSON *item, const char *path)
{
    if (cJSON_IsString(item))
    {
        return vlessserverParseUuidValue(ts, item, path, NULL);
    }

    if (! cJSON_IsObject(item))
    {
        LOGF("JSON Error: VlessServer->settings->%s must be a UUID string or object", path);
        return false;
    }

    bool         uuid_invalid = false;
    const cJSON *uuid         = vlessserverGetObjectUuidField(item, path, &uuid_invalid);
    if (uuid_invalid)
    {
        return false;
    }
    if (uuid == NULL)
    {
        LOGF("JSON Error: VlessServer->settings->%s object must contain uuid, id, or user-id", path);
        return false;
    }

    const cJSON *username      = cJSON_GetObjectItemCaseSensitive(item, "username");
    const char  *username_text = NULL;
    if (username != NULL)
    {
        if (! cJSON_IsString(username) || username->valuestring == NULL || username->valuestring[0] == '\0')
        {
            LOGF("JSON Error: VlessServer->settings->%s->username must be a non-empty string when provided", path);
            return false;
        }
        username_text = username->valuestring;
    }

    return vlessserverParseUuidValue(ts, uuid, path, username_text);
}

static bool vlessserverParseUuidArray(vlessserver_tstate_t *ts, const cJSON *array, const char *path)
{
    if (! cJSON_IsArray(array) || cJSON_GetArraySize(array) <= 0)
    {
        LOGF("JSON Error: VlessServer->settings->%s must be a non-empty array", path);
        return false;
    }

    int    index = 0;
    cJSON *item  = NULL;
    cJSON_ArrayForEach(item, array)
    {
        char item_path[64] = {0};
        snprintf(item_path, sizeof(item_path), "%s[%d]", path, index);
        if (! vlessserverParseUserEntry(ts, item, item_path))
        {
            return false;
        }
        ++index;
    }

    return true;
}

static bool vlessserverParseUsers(vlessserver_tstate_t *ts, const cJSON *settings)
{
    const cJSON *uuid = cJSON_GetObjectItemCaseSensitive(settings, "uuid");
    const cJSON *id   = cJSON_GetObjectItemCaseSensitive(settings, "id");
    if (uuid != NULL && id != NULL)
    {
        LOGF("JSON Error: VlessServer->settings must use either uuid or id, not both");
        return false;
    }
    if (uuid == NULL)
    {
        uuid = id;
    }

    if (uuid != NULL && ! vlessserverParseUuidValue(ts, uuid, uuid->string != NULL ? uuid->string : "uuid", NULL))
    {
        return false;
    }

    const cJSON *uuids = cJSON_GetObjectItemCaseSensitive(settings, "uuids");
    if (uuids != NULL && ! vlessserverParseUuidArray(ts, uuids, "uuids"))
    {
        return false;
    }

    const cJSON *users   = cJSON_GetObjectItemCaseSensitive(settings, "users");
    const cJSON *clients = cJSON_GetObjectItemCaseSensitive(settings, "clients");
    if (users != NULL && clients != NULL)
    {
        LOGF("JSON Error: VlessServer->settings must use either users or clients, not both");
        return false;
    }

    if (users != NULL && ! vlessserverParseUuidArray(ts, users, "users"))
    {
        return false;
    }

    if (clients != NULL && ! vlessserverParseUuidArray(ts, clients, "clients"))
    {
        return false;
    }

    if (ts->user_count == 0)
    {
        LOGF("JSON Error: VlessServer->settings requires at least one uuid, uuids, users, or clients entry");
        return false;
    }

    return true;
}

static bool vlessserverHasLocalUserSettings(const cJSON *settings)
{
    return cJSON_GetObjectItemCaseSensitive(settings, "uuid") != NULL ||
           cJSON_GetObjectItemCaseSensitive(settings, "id") != NULL ||
           cJSON_GetObjectItemCaseSensitive(settings, "uuids") != NULL ||
           cJSON_GetObjectItemCaseSensitive(settings, "users") != NULL ||
           cJSON_GetObjectItemCaseSensitive(settings, "clients") != NULL;
}

static bool vlessserverParseAuthMode(vlessserver_tstate_t *ts, tunnel_t *t, node_t *node, const cJSON *settings)
{
    const cJSON *auth_node_json = cJSON_GetObjectItemCaseSensitive(settings, "auth-client-node-name");

    if (auth_node_json == NULL)
    {
        return vlessserverParseUsers(ts, settings);
    }

    if (! cJSON_IsString(auth_node_json) || auth_node_json->valuestring == NULL ||
        auth_node_json->valuestring[0] == '\0')
    {
        LOGF("JSON Error: VlessServer->settings->auth-client-node-name (string field) must be a non-empty string");
        return false;
    }

    if (vlessserverHasLocalUserSettings(settings))
    {
        LOGF("JSON Error: VlessServer auth-client mode uses the AuthenticationClient users database; remove local "
             "uuid/uuids/users/clients settings");
        return false;
    }

    if (! vlessserverParseAuthClientNode(ts, node, auth_node_json->valuestring))
    {
        return false;
    }

    return vlessserverCreateUserControllerTunnel(t, node);
}

tunnel_t *vlessserverTunnelCreate(node_t *node)
{
    tunnel_t             *t        = tunnelCreate(node, sizeof(vlessserver_tstate_t), sizeof(vlessserver_lstate_t));
    vlessserver_tstate_t *ts       = tunnelGetState(t);
    const cJSON          *settings = node->node_settings_json;

    t->fnInitU    = &vlessserverTunnelUpStreamInit;
    t->fnEstU     = &vlessserverTunnelUpStreamEst;
    t->fnFinU     = &vlessserverTunnelUpStreamFinish;
    t->fnPayloadU = &vlessserverTunnelUpStreamPayload;
    t->fnPauseU   = &vlessserverTunnelUpStreamPause;
    t->fnResumeU  = &vlessserverTunnelUpStreamResume;

    t->fnInitD    = &vlessserverTunnelDownStreamInit;
    t->fnEstD     = &vlessserverTunnelDownStreamEst;
    t->fnFinD     = &vlessserverTunnelDownStreamFinish;
    t->fnPayloadD = &vlessserverTunnelDownStreamPayload;
    t->fnPauseD   = &vlessserverTunnelDownStreamPause;
    t->fnResumeD  = &vlessserverTunnelDownStreamResume;

    t->onPrepare = &vlessserverTunnelOnPrepair;
    t->onStart   = &vlessserverTunnelOnStart;
    t->onStop    = &vlessserverTunnelOnStop;
    t->onDestroy = &vlessserverTunnelDestroy;

    if (! nodeHasNext(node))
    {
        LOGF("VlessServer: a next node is required for accepted VLESS traffic");
        vlessserverTunnelDestroy(t);
        return NULL;
    }

    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: VlessServer->settings (object field) : The object was empty or invalid");
        vlessserverTunnelDestroy(t);
        return NULL;
    }

    ts->allow_connect = true;
    ts->allow_udp     = true;
    getBoolFromJsonObjectOrDefault(&ts->allow_connect, settings, "connect", true);
    getBoolFromJsonObjectOrDefault(&ts->allow_udp, settings, "udp", true);
    getBoolFromJsonObjectOrDefault(&ts->verbose, settings, "verbose", false);

    if (! ts->allow_connect && ! ts->allow_udp)
    {
        LOGF("JSON Error: VlessServer must enable at least one of connect/udp");
        vlessserverTunnelDestroy(t);
        return NULL;
    }

    if (! vlessserverParseAuthMode(ts, t, node, settings) || ! vlessserverParseFallbackNode(ts, node, settings))
    {
        vlessserverTunnelDestroy(t);
        return NULL;
    }

    if (ts->auth_client_node != NULL || ts->fallback_node != NULL)
    {
        t->onChain = &vlessserverTunnelOnChain;
    }

    return t;
}
