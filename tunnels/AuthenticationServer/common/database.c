#include "structure.h"

#include "loggers/network_logger.h"

static char *authenticationserverCreateBackupPath(const char *db_path)
{
    static const char suffix[] = ".backup";

    size_t db_path_len = stringLength(db_path);
    size_t suffix_len  = sizeof(suffix) - 1U;
    char  *backup_path = memoryAllocate(db_path_len + suffix_len + 1U);

    if (backup_path == NULL)
    {
        return NULL;
    }

    memoryCopy(backup_path, db_path, db_path_len);
    memoryCopy(backup_path + db_path_len, suffix, suffix_len + 1U);
    return backup_path;
}

static bool authenticationserverBuildUsersJson(authenticationserver_tstate_t *ts, char **out, size_t *out_len)
{
    cJSON *json = usersToJson(&ts->store.users);
    if (json == NULL)
    {
        LOGE("AuthenticationServer: failed to build users JSON from in-memory database");
        return false;
    }

    char *json_text = cJSON_PrintBuffered(json, 4096, true);
    cJSON_Delete(json);

    if (json_text == NULL)
    {
        LOGE("AuthenticationServer: failed to serialize users JSON");
        return false;
    }

    *out     = json_text;
    *out_len = stringLength(json_text);
    return true;
}

static bool authenticationserverWriteJsonFile(const char *path, const char *json_text, size_t json_len)
{
    if (! writeFile(path, json_text, json_len))
    {
        LOGE("AuthenticationServer: failed to write users database file \"%s\"", path);
        return false;
    }
    return true;
}

static bool authenticationserverLoadUsersFromPath(authenticationserver_tstate_t *ts, const char *path)
{
    char *json_text = readFile(path);
    if (json_text == NULL)
    {
        LOGW("AuthenticationServer: could not read users database \"%s\"", path);
        return false;
    }

    cJSON *json = cJSON_ParseWithLength(json_text, stringLength(json_text));
    if (json == NULL)
    {
        LOGW("AuthenticationServer: could not parse users database \"%s\"", path);
        memoryFree(json_text);
        return false;
    }

    usersClear(&ts->store.users);
    bool ok = usersFeedJson(&ts->store.users, json);
    if (! ok)
    {
        LOGW("AuthenticationServer: users database \"%s\" has an invalid users layout", path);
        usersClear(&ts->store.users);
    }
    else if (! usersValidate(&ts->store.users))
    {
        LOGW("AuthenticationServer: users database \"%s\" failed validation", path);
        usersClear(&ts->store.users);
        ok = false;
    }

    if (ok)
    {
        LOGI("AuthenticationServer: loaded %zu users from \"%s\"", usersCount(&ts->store.users), path);
    }

    cJSON_Delete(json);
    memoryFree(json_text);
    return ok;
}

static bool authenticationserverRewritePrimaryFromMemory(authenticationserver_tstate_t *ts)
{
    char  *json_text = NULL;
    size_t json_len  = 0;

    if (! authenticationserverBuildUsersJson(ts, &json_text, &json_len))
    {
        return false;
    }

    bool ok = authenticationserverWriteJsonFile(ts->db_path, json_text, json_len);
    memoryFree(json_text);
    return ok;
}

static bool authenticationserverSaveDatabaseUnlocked(authenticationserver_tstate_t *ts)
{
    char  *json_text = NULL;
    size_t json_len  = 0;

    if (! ts->database_loaded)
    {
        return false;
    }

    if (! authenticationserverBuildUsersJson(ts, &json_text, &json_len))
    {
        return false;
    }

    if (! authenticationserverWriteJsonFile(ts->backup_path, json_text, json_len))
    {
        memoryFree(json_text);
        return false;
    }

    if (! authenticationserverWriteJsonFile(ts->db_path, json_text, json_len))
    {
        memoryFree(json_text);
        return false;
    }

    LOGD("AuthenticationServer: saved %zu users to \"%s\" using backup \"%s\"",
         usersCount(&ts->store.users),
         ts->db_path,
         ts->backup_path);
    memoryFree(json_text);
    return true;
}

bool authenticationserverSaveDatabase(authenticationserver_tstate_t *ts)
{
    /*
     * Runtime modules can temporarily mutate users_t and then roll back on file
     * failure. The database mutex keeps periodic/final saves from persisting
     * those in-flight states or interleaving writes to db-path and backup.
     */
    recursivemutexLock(&ts->database_mutex);
    bool ok = authenticationserverSaveDatabaseUnlocked(ts);
    recursivemutexUnlock(&ts->database_mutex);
    return ok;
}

bool authenticationserverLoadDatabase(authenticationserver_tstate_t *ts)
{
    ts->backup_path = authenticationserverCreateBackupPath(ts->db_path);
    if (ts->backup_path == NULL)
    {
        LOGE("AuthenticationServer: failed to allocate backup path for \"%s\"", ts->db_path);
        return false;
    }

    LOGI("AuthenticationServer: loading users database from \"%s\"", ts->db_path);
    if (authenticationserverLoadUsersFromPath(ts, ts->db_path))
    {
        return true;
    }

    LOGW("AuthenticationServer: primary users database \"%s\" could not be loaded; attempting recovery from \"%s\"",
         ts->db_path,
         ts->backup_path);

    if (! isFile(ts->backup_path))
    {
        LOGE("AuthenticationServer: recovery failed because backup file \"%s\" does not exist", ts->backup_path);
        return false;
    }

    if (! authenticationserverLoadUsersFromPath(ts, ts->backup_path))
    {
        LOGE("AuthenticationServer: recovery failed because backup file \"%s\" is not valid", ts->backup_path);
        return false;
    }

    if (! authenticationserverRewritePrimaryFromMemory(ts))
    {
        LOGE("AuthenticationServer: recovery failed because recovered data could not be written to \"%s\"",
             ts->db_path);
        return false;
    }

    LOGI("AuthenticationServer: recovered users database from backup \"%s\"", ts->backup_path);

    if (remove(ts->backup_path) != 0)
    {
        LOGW("AuthenticationServer: could not remove recovered backup \"%s\": %s", ts->backup_path, strerror(errno));
    }
    else
    {
        LOGI("AuthenticationServer: removed recovered backup \"%s\"", ts->backup_path);
    }

    LOGI("AuthenticationServer: recovery complete; rewrote primary users database \"%s\"", ts->db_path);
    return true;
}

void authenticationserverSaveTimerCallback(wtimer_t *timer)
{
    tunnel_t *t = weventGetUserdata(timer);
    if (t == NULL || isApplicationTerminating())
    {
        return;
    }

    authenticationserver_tstate_t *ts = tunnelGetState(t);
    if (! authenticationserverSaveDatabase(ts))
    {
        LOGW("AuthenticationServer: periodic users database save failed");
    }
}
