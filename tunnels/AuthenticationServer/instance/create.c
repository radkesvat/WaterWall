#include "structure.h"

#include "loggers/network_logger.h"

static void authenticationserverTrimTrailingPathSeparators(char *path)
{
    size_t len = stringLength(path);

    while (len > 1U && filePathIsSeparator(path[len - 1U]))
    {
#ifdef OS_WIN
        if (len == 3U && path[1] == ':')
        {
            break;
        }
#endif
        path[--len] = '\0';
    }
}

static bool authenticationserverParseNormalBackupsMode(const char                                 *mode,
                                                       authenticationserver_normal_backups_mode_t *out)
{
    if (stringCompare(mode, "hourly") == 0)
    {
        *out = kAuthenticationServerNormalBackupsHourly;
        return true;
    }
    if (stringCompare(mode, "daily") == 0)
    {
        *out = kAuthenticationServerNormalBackupsDaily;
        return true;
    }
    if (stringCompare(mode, "weekly") == 0)
    {
        *out = kAuthenticationServerNormalBackupsWeekly;
        return true;
    }
    return false;
}

static bool authenticationserverParseNormalBackups(authenticationserver_tstate_t *ts, const cJSON *settings)
{
    const cJSON *mode_json  = cJSON_GetObjectItemCaseSensitive(settings, "normal-backups");
    const cJSON *path_json  = cJSON_GetObjectItemCaseSensitive(settings, "normal-backups-path");
    const cJSON *limit_json = cJSON_GetObjectItemCaseSensitive(settings, "normal-backups-count-limit");

    if (UNLIKELY((mode_json == NULL) != (path_json == NULL)))
    {
        LOGF("JSON Error: AuthenticationServer->settings->normal-backups and normal-backups-path must be specified "
             "together");
        return false;
    }

    if (mode_json == NULL)
    {
        if (UNLIKELY(limit_json != NULL))
        {
            LOGF("JSON Error: AuthenticationServer->settings->normal-backups-count-limit requires normal-backups and "
                 "normal-backups-path");
            return false;
        }
        ts->normal_backups_mode        = kAuthenticationServerNormalBackupsDisabled;
        ts->normal_backups_count_limit = kAuthenticationServerDefaultNormalBackupsCountLimit;
        return true;
    }

    if (UNLIKELY(! cJSON_IsString(mode_json) || mode_json->valuestring == NULL ||
                 ! authenticationserverParseNormalBackupsMode(mode_json->valuestring, &ts->normal_backups_mode)))
    {
        LOGF("JSON Error: AuthenticationServer->settings->normal-backups (string field) : expected hourly, daily, or "
             "weekly");
        return false;
    }

    if (UNLIKELY(! cJSON_IsString(path_json) || path_json->valuestring == NULL || path_json->valuestring[0] == '\0'))
    {
        LOGF("JSON Error: AuthenticationServer->settings->normal-backups-path (string field) : The data was empty or "
             "invalid");
        return false;
    }

    ts->normal_backups_path = stringDuplicate(path_json->valuestring);
    if (UNLIKELY(ts->normal_backups_path == NULL))
    {
        LOGE("AuthenticationServer: failed to allocate normal-backups-path");
        return false;
    }
    authenticationserverTrimTrailingPathSeparators(ts->normal_backups_path);

    if (UNLIKELY(ts->normal_backups_path[0] == '\0'))
    {
        LOGF("JSON Error: AuthenticationServer->settings->normal-backups-path (string field) : The data was empty or "
             "invalid");
        return false;
    }
    if (UNLIKELY(stringLength(ts->normal_backups_path) >= MAX_PATH))
    {
        LOGF("AuthenticationServer: normal-backups-path \"%s\" is too long", ts->normal_backups_path);
        return false;
    }

    int count_limit = (int) kAuthenticationServerDefaultNormalBackupsCountLimit;
    if (limit_json != NULL)
    {
        if (UNLIKELY(! cJSON_IsNumber(limit_json) || limit_json->valueint <= 0))
        {
            LOGF("JSON Error: AuthenticationServer->settings->normal-backups-count-limit (positive integer field) : "
                 "The data was invalid");
            return false;
        }
        count_limit = limit_json->valueint;
    }
    ts->normal_backups_count_limit = (uint32_t) count_limit;

    int create_result = createDirIfNotExists(ts->normal_backups_path);
    if (UNLIKELY(create_result != 0 && create_result != EEXIST))
    {
        LOGF("AuthenticationServer: failed to create normal-backups-path \"%s\"", ts->normal_backups_path);
        return false;
    }
    if (UNLIKELY(! isDir(ts->normal_backups_path)))
    {
        LOGF("AuthenticationServer: normal-backups-path \"%s\" is not a directory", ts->normal_backups_path);
        return false;
    }

    return true;
}

static void authenticationserverInitializeCallbacks(tunnel_t *t)
{
    t->fnInitU    = &authenticationserverTunnelUpStreamInit;
    t->fnEstU     = &authenticationserverTunnelUpStreamEst;
    t->fnFinU     = &authenticationserverTunnelUpStreamFinish;
    t->fnPayloadU = &authenticationserverTunnelUpStreamPayload;
    t->fnPauseU   = &authenticationserverTunnelUpStreamPause;
    t->fnResumeU  = &authenticationserverTunnelUpStreamResume;

    t->fnInitD    = &authenticationserverTunnelDownStreamInit;
    t->fnEstD     = &authenticationserverTunnelDownStreamEst;
    t->fnFinD     = &authenticationserverTunnelDownStreamFinish;
    t->fnPayloadD = &authenticationserverTunnelDownStreamPayload;
    t->fnPauseD   = &authenticationserverTunnelDownStreamPause;
    t->fnResumeD  = &authenticationserverTunnelDownStreamResume;

    t->onPrepare    = &authenticationserverTunnelOnPrepair;
    t->onStart      = &authenticationserverTunnelOnStart;
    t->onStop       = &authenticationserverTunnelOnStop;
    t->onWorkerStop = &authenticationserverTunnelOnWorkerStop;
    t->onDestroy    = &authenticationserverTunnelDestroy;
}

static bool authenticationserverParseSettings(authenticationserver_tstate_t *ts, node_t *node)
{
    const cJSON *settings = node->node_settings_json;

    if (UNLIKELY(nodeHasNext(node)))
    {
        LOGF("AuthenticationServer: this node is a chain end and must not have a next node");
        return false;
    }

    if (UNLIKELY(! checkJsonIsObjectAndHasChild(settings)))
    {
        LOGF("JSON Error: AuthenticationServer->settings (object field) : The object was empty or invalid");
        return false;
    }

    if (UNLIKELY(! getStringFromJsonObject(&ts->db_path, settings, "db-path")))
    {
        LOGF("JSON Error: AuthenticationServer->settings->db-path (string field) : The data was empty or invalid");
        return false;
    }

    getBoolFromJsonObjectOrDefault(&ts->verbose, settings, "verbose", false);

    int file_save_rate_ms = 0;
    if (UNLIKELY(! getIntFromJsonObject(&file_save_rate_ms, settings, "file-save-rate-ms") || file_save_rate_ms <= 0))
    {
        LOGF("JSON Error: AuthenticationServer->settings->file-save-rate-ms (positive integer field) : The data was "
             "empty or invalid");
        return false;
    }

    ts->file_save_rate_ms = (uint32_t) file_save_rate_ms;

    int session_idle_timeout_ms = 0;
    getIntFromJsonObjectOrDefault(&session_idle_timeout_ms,
                                  settings,
                                  "session-idle-timeout-ms",
                                  kAuthenticationServerDefaultSessionIdleTimeoutMs);
    if (UNLIKELY(session_idle_timeout_ms <= 0))
    {
        LOGF("JSON Error: AuthenticationServer->settings->session-idle-timeout-ms (positive integer field) : The data "
             "was invalid");
        return false;
    }
    ts->session_idle_timeout_ms = (uint32_t) session_idle_timeout_ms;

    if (UNLIKELY(! authenticationserverParseNormalBackups(ts, settings)))
    {
        return false;
    }

    const cJSON *auth_clients = cJSON_GetObjectItemCaseSensitive(settings, "auth-clients");
    if (UNLIKELY(! cJSON_IsArray(auth_clients) || cJSON_GetArraySize(auth_clients) <= 0))
    {
        LOGF("JSON Error: AuthenticationServer->settings->auth-clients (non-empty array field) : The data was empty "
             "or invalid");
        return false;
    }

    int auth_clients_count = cJSON_GetArraySize(auth_clients);
    ts->auth_clients       = memoryAllocateZero(sizeof(*ts->auth_clients) * (size_t) auth_clients_count);
    if (UNLIKELY(ts->auth_clients == NULL))
    {
        LOGE("AuthenticationServer: failed to allocate auth-clients array");
        return false;
    }
    ts->auth_clients_count = (uint32_t) auth_clients_count;

    const cJSON *client_json = NULL;
    uint32_t     index       = 0;
    cJSON_ArrayForEach(client_json, auth_clients)
    {
        authenticationserver_auth_client_t *client = &ts->auth_clients[index];

        if (UNLIKELY(! checkJsonIsObjectAndHasChild(client_json)))
        {
            LOGF("JSON Error: AuthenticationServer->settings->auth-clients[%u] (object field) : invalid object",
                 (unsigned int) index);
            return false;
        }

        if (UNLIKELY(! getStringFromJsonObject(&client->name, client_json, "name") || client->name[0] == '\0'))
        {
            LOGF("JSON Error: AuthenticationServer->settings->auth-clients[%u]->name (string field) : invalid value",
                 (unsigned int) index);
            return false;
        }

        if (UNLIKELY(! getStringFromJsonObject(&client->secret, client_json, "secret") || client->secret[0] == '\0'))
        {
            LOGF("JSON Error: AuthenticationServer->settings->auth-clients[%u]->secret (string field) : invalid value",
                 (unsigned int) index);
            return false;
        }

        getBoolFromJsonObjectOrDefault(&client->allow_stats_push, client_json, "allow-stats-push", false);
        getBoolFromJsonObjectOrDefault(&client->allow_user_pull, client_json, "allow-user-pull", false);
        getBoolFromJsonObjectOrDefault(&client->allow_user_write, client_json, "allow-user-write", false);

        int client_session_idle_timeout_ms = 0;
        getIntFromJsonObjectOrDefault(
            &client_session_idle_timeout_ms, client_json, "session-idle-timeout-ms", (int) ts->session_idle_timeout_ms);
        if (UNLIKELY(client_session_idle_timeout_ms <= 0))
        {
            LOGF("JSON Error: AuthenticationServer->settings->auth-clients[%u]->session-idle-timeout-ms (positive "
                 "integer field) : invalid value",
                 (unsigned int) index);
            return false;
        }
        client->session_idle_timeout_ms = (uint32_t) client_session_idle_timeout_ms;
        ++index;
    }

    return true;
}

tunnel_t *authenticationserverTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(authenticationserver_tstate_t), sizeof(authenticationserver_lstate_t));
    if (UNLIKELY(t == NULL))
    {
        return NULL;
    }

    authenticationserverInitializeCallbacks(t);

    authenticationserver_tstate_t *ts = tunnelGetState(t);
    recursivemutexInit(&ts->database_mutex);
    ts->store.config_revision = 1U;
    ts->store.stats_revision  = 1U;

    if (UNLIKELY(! usersCreate(&ts->store.users)))
    {
        LOGE("AuthenticationServer: failed to create in-memory users database");
        recursivemutexDestroy(&ts->database_mutex);
        tunnelDestroy(t);
        return NULL;
    }

    if (UNLIKELY(! authenticationserverParseSettings(ts, node)))
    {
        authenticationserverTunnelDestroy(t);
        return NULL;
    }

    if (ts->verbose)
    {
        LOGD("AuthenticationServer: verbose flow logging is enabled");
    }

    if (UNLIKELY(! authenticationserverLoadDatabase(ts)))
    {
        LOGE("AuthenticationServer: failed to load users database");
        authenticationserverTunnelDestroy(t);
        return NULL;
    }
    ts->database_loaded = true;

    return t;
}
