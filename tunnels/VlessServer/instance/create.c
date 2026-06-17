#include "structure.h"

#include "loggers/network_logger.h"

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

static bool vlessserverAppendUuid(vlessserver_tstate_t *ts, const uint8_t uuid[kVlessServerUuidLen])
{
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
    ts->user_count = (uint32_t) new_count;
    return true;
}

static bool vlessserverParseUuidValue(vlessserver_tstate_t *ts, const cJSON *item, const char *path)
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

    return vlessserverAppendUuid(ts, uuid);
}

static const cJSON *vlessserverGetObjectUuidField(const cJSON *item)
{
    const cJSON *uuid = cJSON_GetObjectItemCaseSensitive(item, "uuid");
    if (uuid != NULL)
    {
        return uuid;
    }

    uuid = cJSON_GetObjectItemCaseSensitive(item, "id");
    if (uuid != NULL)
    {
        return uuid;
    }

    return cJSON_GetObjectItemCaseSensitive(item, "user-id");
}

static bool vlessserverParseUserEntry(vlessserver_tstate_t *ts, const cJSON *item, const char *path)
{
    if (cJSON_IsString(item))
    {
        return vlessserverParseUuidValue(ts, item, path);
    }

    if (! cJSON_IsObject(item))
    {
        LOGF("JSON Error: VlessServer->settings->%s must be a UUID string or object", path);
        return false;
    }

    const cJSON *uuid = vlessserverGetObjectUuidField(item);
    if (uuid == NULL)
    {
        LOGF("JSON Error: VlessServer->settings->%s object must contain uuid or id", path);
        return false;
    }

    return vlessserverParseUuidValue(ts, uuid, path);
}

static bool vlessserverParseUuidArray(vlessserver_tstate_t *ts, const cJSON *array, const char *path)
{
    if (! cJSON_IsArray(array) || cJSON_GetArraySize(array) <= 0)
    {
        LOGF("JSON Error: VlessServer->settings->%s must be a non-empty array", path);
        return false;
    }

    int index = 0;
    cJSON *item = NULL;
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
    if (uuid == NULL)
    {
        uuid = cJSON_GetObjectItemCaseSensitive(settings, "id");
    }

    if (uuid != NULL && ! vlessserverParseUuidValue(ts, uuid, uuid->string != NULL ? uuid->string : "uuid"))
    {
        return false;
    }

    const cJSON *uuids = cJSON_GetObjectItemCaseSensitive(settings, "uuids");
    if (uuids != NULL && ! vlessserverParseUuidArray(ts, uuids, "uuids"))
    {
        return false;
    }

    const cJSON *users = cJSON_GetObjectItemCaseSensitive(settings, "users");
    if (users != NULL && ! vlessserverParseUuidArray(ts, users, "users"))
    {
        return false;
    }

    const cJSON *clients = cJSON_GetObjectItemCaseSensitive(settings, "clients");
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

tunnel_t *vlessserverTunnelCreate(node_t *node)
{
    tunnel_t              *t        = tunnelCreate(node, sizeof(vlessserver_tstate_t), sizeof(vlessserver_lstate_t));
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

    if (! vlessserverParseUsers(ts, settings))
    {
        vlessserverTunnelDestroy(t);
        return NULL;
    }

    return t;
}
