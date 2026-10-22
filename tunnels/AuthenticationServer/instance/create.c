#include "../../Internals/AuthenticationCommon/credentials.h"
#include "AuthenticationServer/api.h"
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

    int64_t count_limit = kAuthenticationServerDefaultNormalBackupsCountLimit;
    if (UNLIKELY(jsonGetObjectIntegerInRange(settings, "normal-backups-count-limit", 1, INT_MAX, &count_limit) ==
                 kJsonValueInvalid))
    {
        LOGF("JSON Error: AuthenticationServer->settings->normal-backups-count-limit must be an integer from 1 "
             "through %d",
             INT_MAX);
        return false;
    }
    ts->normal_backups_count_limit = (uint32_t) count_limit;

    int create_result = createDirIfNotExists(ts->normal_backups_path);
    if (UNLIKELY(create_result != 0))
    {
        if (create_result == ENOTDIR)
        {
            LOGF("AuthenticationServer: normal-backups-path \"%s\" exists but is not a directory",
                 ts->normal_backups_path);
        }
        else
        {
            LOGF("AuthenticationServer: failed to create normal-backups-path \"%s\"", ts->normal_backups_path);
        }
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
    t->fnFinU     = &authenticationserverTunnelUpStreamFinish;
    t->fnPayloadU = &authenticationserverTunnelUpStreamPayload;
    t->fnPauseU   = &authenticationserverTunnelUpStreamPause;
    t->fnResumeU  = &authenticationserverTunnelUpStreamResume;
    t->fnEstD     = &authenticationserverTunnelDownStreamEst;
    t->fnFinD     = &authenticationserverTunnelDownStreamFinish;
    t->fnPayloadD = &authenticationserverTunnelDownStreamPayload;
    t->fnPauseD   = &authenticationserverTunnelDownStreamPause;
    t->fnResumeD  = &authenticationserverTunnelDownStreamResume;

    t->onStart         = &authenticationserverTunnelOnStart;
    t->onWorkerQuiesce = &authenticationserverTunnelOnWorkerQuiesce;
    t->onDestroy       = &authenticationserverTunnelDestroy;
}

static bool authenticationserverSettingUnique(const cJSON *settings, const char *name)
{
    bool seen = false;
    for (const cJSON *item = settings->child; item != NULL; item = item->next)
        if (item->string != NULL && strcmp(item->string, name) == 0)
        {
            if (seen)
                return false;
            seen = true;
        }
    return true;
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

    int64_t file_save_rate_ms = 0;
    if (UNLIKELY(jsonGetObjectIntegerInRange(settings, "file-save-rate-ms", 1, INT_MAX, &file_save_rate_ms) !=
                 kJsonValuePresent))
    {
        LOGF("JSON Error: AuthenticationServer->settings->file-save-rate-ms requires an integer from 1 through %d",
             INT_MAX);
        return false;
    }

    ts->file_save_rate_ms = (uint32_t) file_save_rate_ms;

    int64_t session_idle_timeout_ms = kAuthenticationServerDefaultSessionIdleTimeoutMs;
    if (UNLIKELY(jsonGetObjectIntegerInRange(
                     settings, "session-idle-timeout-ms", 1, INT_MAX, &session_idle_timeout_ms) == kJsonValueInvalid))
    {
        LOGF("JSON Error: AuthenticationServer->settings->session-idle-timeout-ms must be an integer from 1 through %d",
             INT_MAX);
        return false;
    }
    ts->session_idle_timeout_ms = (uint32_t) session_idle_timeout_ms;

    int64_t snapshot_max_bytes = kAuthenticationServerDefaultSnapshotMaxBytes;
    int64_t snapshot_idle_ms   = kAuthenticationServerDefaultSnapshotIdleTimeoutMs;
    if (! authenticationserverSettingUnique(settings, "snapshot-max-bytes") ||
        ! authenticationserverSettingUnique(settings, "snapshot-idle-timeout-ms") ||
        jsonGetObjectIntegerInRange(settings,
                                    "snapshot-max-bytes",
                                    1,
                                    (int64_t) min((uint64_t) SIZE_MAX, (uint64_t) INT64_MAX),
                                    &snapshot_max_bytes) == kJsonValueInvalid ||
        jsonGetObjectIntegerInRange(settings, "snapshot-idle-timeout-ms", 1, INT_MAX, &snapshot_idle_ms) ==
            kJsonValueInvalid)
    {
        LOGF("JSON Error: AuthenticationServer snapshot limits must be unique positive host-representable integers; "
             "snapshot-idle-timeout-ms must not exceed %d",
             INT_MAX);
        return false;
    }
    ts->snapshot_max_bytes       = (size_t) snapshot_max_bytes;
    ts->snapshot_idle_timeout_ms = (uint32_t) snapshot_idle_ms;

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

    int    auth_clients_count = cJSON_GetArraySize(auth_clients);
    size_t bytes;
    if (UNLIKELY(! memoryTryComputeArraySize((size_t) auth_clients_count, sizeof(*ts->auth_clients), &bytes)))
    {
        LOGE("AuthenticationServer: auth-clients array is too large");
        return false;
    }
    ts->auth_clients       = memoryAllocateZero(bytes);
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
        for (uint32_t previous = 0; previous < index; ++previous)
        {
            if (stringCompare(ts->auth_clients[previous].name, client->name) == 0)
            {
                LOGF("AuthenticationServer: auth-client names must be unique");
                return false;
            }
        }

        if (UNLIKELY(! getStringFromJsonObject(&client->secret, client_json, "secret") || client->secret[0] == '\0'))
        {
            LOGF("JSON Error: AuthenticationServer->settings->auth-clients[%u]->secret (string field) : invalid value",
                 (unsigned int) index);
            return false;
        }

        if (! authenticationCredentialsFit(client->name, client->secret))
        {
            LOGE("AuthenticationServer: configured credentials exceed the authentication handshake limit");
            return false;
        }

        getBoolFromJsonObjectOrDefault(&client->allow_stats_push, client_json, "allow-stats-push", false);
        getBoolFromJsonObjectOrDefault(&client->allow_user_pull, client_json, "allow-user-pull", false);
        getBoolFromJsonObjectOrDefault(&client->allow_user_write, client_json, "allow-user-write", false);

        int64_t client_session_idle_timeout_ms = ts->session_idle_timeout_ms;
        if (UNLIKELY(jsonGetObjectIntegerInRange(
                         client_json, "session-idle-timeout-ms", 1, INT_MAX, &client_session_idle_timeout_ms) ==
                     kJsonValueInvalid))
        {
            LOGF("JSON Error: AuthenticationServer->settings->auth-clients[%u]->session-idle-timeout-ms must be an "
                 "integer from 1 through %d",
                 (unsigned int) index,
                 INT_MAX);
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
    if (! t)
    {
        return NULL;
    }

    authenticationserver_tstate_t *ts = tunnelGetState(t);
    if (UNLIKELY(! rwlockTryInit(&ts->state_lock)))
    {
        LOGF("AuthenticationServer: failed to initialize state lock");
        tunnelDestroy(t);
        return NULL;
    }

    authenticationserverInitializeCallbacks(t);

    ts->store.config_revision = 1U;
    ts->store.stats_revision  = 1U;
    authenticationserverInitializeAccountingClock(ts);
    authenticationserverInitializeExportLimit(ts);

    if (UNLIKELY(! usersCreate(&ts->store.users)))
    {
        LOGE("AuthenticationServer: failed to create in-memory users database");
        rwlockDestroy(&ts->state_lock);
        tunnelDestroy(t);
        return NULL;
    }

    if (UNLIKELY(! authenticationserverParseSettings(ts, node)))
    {
        authenticationserverTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    if (ts->verbose)
    {
        LOGD("AuthenticationServer: verbose flow logging is enabled");
    }

    if (UNLIKELY(! authenticationserverLoadDatabase(ts)))
    {
        LOGE("AuthenticationServer: failed to load users database");
        authenticationserverTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }
    ts->database_loaded = true;

    if (! secureRandomBytes(ts->api_instance_id, sizeof(ts->api_instance_id)) || ! authenticationserverRegisterApi(t))
    {
        LOGE("AuthenticationServer: failed to initialize registered API");
        authenticationserverTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    if (! authenticationserverAuditConfigure(t, node))
    {
        authenticationserverTunnelDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }

    return t;
}
