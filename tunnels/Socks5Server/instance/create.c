#include "structure.h"

#include "loggers/network_logger.h"

static const cJSON *getSettingsItemByKeys(const cJSON *settings, const char *key1, const char *key2)
{
    const char *keys[2] = {key1, key2};

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

static void cleanupUsersArray(socks5server_user_t *users, size_t count)
{
    if (users == NULL)
    {
        return;
    }

    for (size_t i = 0; i < count; ++i)
    {
        memoryFree(users[i].username);
        if (users[i].password != NULL)
        {
            memorySet(users[i].password, 0, users[i].password_len);
            memoryFree(users[i].password);
        }
    }

    memoryFree(users);
}

static bool parseUsers(socks5server_tstate_t *ts, const cJSON *settings)
{
    char *single_user = NULL;
    char *single_pass = NULL;

    getStringFromJsonObject(&single_user, settings, "username");
    getStringFromJsonObject(&single_pass, settings, "password");

    if (single_user == NULL && single_pass != NULL)
    {
        memoryFree(single_user);
        memoryFree(single_pass);
        LOGF("JSON Error: Socks5Server password cannot be provided without username");
        return false;
    }

    if (single_user != NULL)
    {
        size_t username_len = stringLength(single_user);
        size_t password_len = single_pass != NULL ? stringLength(single_pass) : 0;
        if (username_len == 0 || username_len > UINT8_MAX || password_len > UINT8_MAX)
        {
            if (single_pass != NULL)
            {
                memorySet(single_pass, 0, password_len);
            }
            memoryFree(single_user);
            memoryFree(single_pass);
            LOGF("JSON Error: Socks5Server username must be non-empty and credentials must be <= %u bytes",
                 (unsigned int) UINT8_MAX);
            return false;
        }

        if (single_pass == NULL)
        {
            single_pass = stringDuplicate("");
        }

        ts->users      = memoryAllocate(sizeof(*ts->users));
        ts->users[0]   = (socks5server_user_t) {.username     = single_user,
                                                .password     = single_pass,
                                                .username_len = (uint8_t) username_len,
                                                .password_len = (uint8_t) password_len};
        ts->user_count = 1;
    }

    const cJSON *users_json = getSettingsItemByKeys(settings, "users", "accounts");
    if (users_json == NULL)
    {
        return true;
    }

    if (! cJSON_IsArray(users_json))
    {
        LOGF("JSON Error: Socks5Server->settings->users must be an array");
        return false;
    }

    if (ts->user_count > 0)
    {
        LOGF("JSON Error: Socks5Server uses either username/password or users[], not both");
        return false;
    }

    size_t count = (size_t) cJSON_GetArraySize(users_json);
    if (count == 0)
    {
        return true;
    }

    socks5server_user_t *users = memoryAllocate(sizeof(*users) * count);
    memorySet(users, 0, sizeof(*users) * count);

    size_t index = 0;
    cJSON *entry = NULL;
    cJSON_ArrayForEach(entry, users_json)
    {
        if (! cJSON_IsObject(entry))
        {
            LOGF("JSON Error: Socks5Server->settings->users[%u] must be an object", (unsigned int) index);
            cleanupUsersArray(users, index);
            return false;
        }

        cJSON *username_json = cJSON_GetObjectItemCaseSensitive(entry, "username");
        cJSON *password_json = cJSON_GetObjectItemCaseSensitive(entry, "password");
        if (! cJSON_IsString(username_json) || username_json->valuestring == NULL)
        {
            LOGF("JSON Error: Socks5Server->settings->users[%u] needs a string username", (unsigned int) index);
            cleanupUsersArray(users, index);
            return false;
        }

        size_t      username_len   = stringLength(username_json->valuestring);
        size_t      password_len   = 0;
        const char *password_value = "";
        if (password_json != NULL)
        {
            if (! cJSON_IsString(password_json) || password_json->valuestring == NULL)
            {
                LOGF("JSON Error: Socks5Server->settings->users[%u].password must be a string when present",
                     (unsigned int) index);
                cleanupUsersArray(users, index);
                return false;
            }

            password_value = password_json->valuestring;
            password_len   = stringLength(password_value);
        }

        if (username_len == 0 || username_len > UINT8_MAX || password_len > UINT8_MAX)
        {
            LOGF("JSON Error: Socks5Server username must be non-empty and credentials must be <= %u bytes",
                 (unsigned int) UINT8_MAX);
            cleanupUsersArray(users, index);
            return false;
        }

        users[index].username     = stringDuplicate(username_json->valuestring);
        users[index].password     = stringDuplicate(password_value);
        users[index].username_len = (uint8_t) username_len;
        users[index].password_len = (uint8_t) password_len;
        ++index;
    }

    ts->users      = users;
    ts->user_count = (uint32_t) index;
    return true;
}

static bool parseUdpReplyAddress(socks5server_tstate_t *ts, const cJSON *settings)
{
    const cJSON *ipv4_json = getSettingsItemByKeys(settings, "ipv4", "udp-ipv4");

    if (! ts->allow_udp)
    {
        return true;
    }

    if (! cJSON_IsString(ipv4_json) || ipv4_json->valuestring == NULL)
    {
        LOGF("JSON Error: Socks5Server->settings->ipv4 is required when udp is enabled");
        return false;
    }

    if (! ip4addr_aton(ipv4_json->valuestring, ip_2_ip4(&ts->udp_reply_ip)))
    {
        LOGF("JSON Error: Socks5Server->settings->ipv4 must be a valid IPv4 address");
        return false;
    }

    ts->udp_reply_ip.type = IPADDR_TYPE_V4;
    ts->udp_reply_ipv4    = stringDuplicate(ipv4_json->valuestring);
    return true;
}

tunnel_t *socks5serverTunnelCreate(node_t *node)
{
    tunnel_t              *t        = tunnelCreate(node, sizeof(socks5server_tstate_t), sizeof(socks5server_lstate_t));
    socks5server_tstate_t *ts       = tunnelGetState(t);
    const cJSON           *settings = node->node_settings_json;

    t->fnInitU    = &socks5serverTunnelUpStreamInit;
    t->fnEstU     = &socks5serverTunnelUpStreamEst;
    t->fnFinU     = &socks5serverTunnelUpStreamFinish;
    t->fnPayloadU = &socks5serverTunnelUpStreamPayload;
    t->fnPauseU   = &socks5serverTunnelUpStreamPause;
    t->fnResumeU  = &socks5serverTunnelUpStreamResume;

    t->fnInitD    = &socks5serverTunnelDownStreamInit;
    t->fnEstD     = &socks5serverTunnelDownStreamEst;
    t->fnFinD     = &socks5serverTunnelDownStreamFinish;
    t->fnPayloadD = &socks5serverTunnelDownStreamPayload;
    t->fnPauseD   = &socks5serverTunnelDownStreamPause;
    t->fnResumeD  = &socks5serverTunnelDownStreamResume;

    t->onPrepare = &socks5serverTunnelOnPrepair;
    t->onStart   = &socks5serverTunnelOnStart;
    t->onStop    = &socks5serverTunnelOnStop;
    t->onDestroy = &socks5serverTunnelDestroy;

    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: Socks5Server->settings (object field) : The object was empty or invalid");
        tunnelDestroy(t);
        return NULL;
    }

    ts->allow_connect = true;
    ts->allow_udp     = false;
    getBoolFromJsonObjectOrDefault(&ts->allow_connect, settings, "connect", true);
    getBoolFromJsonObjectOrDefault(&ts->allow_udp, settings, "udp", false);
    getBoolFromJsonObjectOrDefault(&ts->verbose, settings, "verbose", false);

    if (! parseUsers(ts, settings) || ! parseUdpReplyAddress(ts, settings))
    {
        socks5serverTunnelstateDestroy(ts);
        tunnelDestroy(t);
        return NULL;
    }

    if (! ts->allow_connect && ! ts->allow_udp)
    {
        LOGF("JSON Error: Socks5Server must enable at least one of connect/udp");
        socks5serverTunnelstateDestroy(ts);
        tunnelDestroy(t);
        return NULL;
    }

    return t;
}
