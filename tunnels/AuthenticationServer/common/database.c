#include "structure.h"

#include "loggers/network_logger.h"

#include <inttypes.h>

typedef struct authenticationserver_backup_path_list_s
{
    char **items;
    size_t count;
    size_t capacity;
} authenticationserver_backup_path_list_t;

typedef struct authenticationserver_user_id_list_s
{
    uint64_t *items;
    size_t    count;
    size_t    capacity;
} authenticationserver_user_id_list_t;

static char *authenticationserverCreateBackupPath(const char *db_path)
{
    static const char suffix[] = ".backup";

    size_t db_path_len = stringLength(db_path);
    size_t suffix_len  = sizeof(suffix) - 1U;
    char  *backup_path = memoryAllocate(db_path_len + suffix_len + 1U);

    if (UNLIKELY(backup_path == NULL))
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
    if (UNLIKELY(json == NULL))
    {
        LOGE("AuthenticationServer: failed to build users JSON from in-memory database");
        return false;
    }

    char *json_text = cJSON_PrintBuffered(json, 4096, true);
    cJSON_Delete(json);

    if (UNLIKELY(json_text == NULL))
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
    if (UNLIKELY(! writeFile(path, json_text, json_len)))
    {
        LOGE("AuthenticationServer: failed to write users database file \"%s\"", path);
        return false;
    }
    return true;
}

static const char *authenticationserverNormalBackupsModeName(authenticationserver_normal_backups_mode_t mode)
{
    switch (mode)
    {
    case kAuthenticationServerNormalBackupsHourly:
        return "hourly";
    case kAuthenticationServerNormalBackupsDaily:
        return "daily";
    case kAuthenticationServerNormalBackupsWeekly:
        return "weekly";
    default:
        return "disabled";
    }
}

static bool authenticationserverJoinPath(const char *dir, const char *name, char *out, size_t out_len)
{
    size_t      dir_len   = stringLength(dir);
    const char *separator = "";

    if (dir_len > 0U && ! filePathIsSeparator(dir[dir_len - 1U]))
    {
#ifdef OS_WIN
        separator = "\\";
#else
        separator = "/";
#endif
    }

    int written = snprintf(out, out_len, "%s%s%s", dir, separator, name);
    return written > 0 && (size_t) written < out_len;
}

static bool authenticationserverLocalTime(const time_t *now, struct tm *out)
{
#ifdef OS_UNIX
    return localtime_r(now, out) != NULL;
#else
    return localtime_s(out, now) == 0;
#endif
}

static bool authenticationserverNormalBackupPeriod(authenticationserver_normal_backups_mode_t mode, time_t now,
                                                   uint64_t *slot, char *period, size_t period_len)
{
    struct tm local_tm;
    if (UNLIKELY(! authenticationserverLocalTime(&now, &local_tm)))
    {
        return false;
    }

    int year  = local_tm.tm_year + 1900;
    int month = local_tm.tm_mon + 1;
    int day   = local_tm.tm_mday;

    switch (mode)
    {
    case kAuthenticationServerNormalBackupsHourly: {
        *slot = ((uint64_t) year * 1000000ULL) + ((uint64_t) month * 10000ULL) + ((uint64_t) day * 100ULL) +
                (uint64_t) local_tm.tm_hour;
        int written = snprintf(period, period_len, "%04d%02d%02d%02d", year, month, day, local_tm.tm_hour);
        return written > 0 && (size_t) written < period_len;
    }

    case kAuthenticationServerNormalBackupsDaily: {
        *slot       = ((uint64_t) year * 10000ULL) + ((uint64_t) month * 100ULL) + (uint64_t) day;
        int written = snprintf(period, period_len, "%04d%02d%02d", year, month, day);
        return written > 0 && (size_t) written < period_len;
    }

    case kAuthenticationServerNormalBackupsWeekly: {
        struct tm week_start_tm     = local_tm;
        int       days_since_monday = local_tm.tm_wday == 0 ? 6 : local_tm.tm_wday - 1;

        week_start_tm.tm_hour  = 0;
        week_start_tm.tm_min   = 0;
        week_start_tm.tm_sec   = 0;
        week_start_tm.tm_isdst = -1;

        time_t week_start_ts = mktime(&week_start_tm);
        if (UNLIKELY(week_start_ts == (time_t) -1))
        {
            return false;
        }
        week_start_ts -= (time_t) days_since_monday * SECONDS_PER_DAY;

        if (UNLIKELY(! authenticationserverLocalTime(&week_start_ts, &week_start_tm)))
        {
            return false;
        }

        year        = week_start_tm.tm_year + 1900;
        month       = week_start_tm.tm_mon + 1;
        day         = week_start_tm.tm_mday;
        *slot       = ((uint64_t) year * 10000ULL) + ((uint64_t) month * 100ULL) + (uint64_t) day;
        int written = snprintf(period, period_len, "%04d%02d%02d", year, month, day);
        return written > 0 && (size_t) written < period_len;
    }

    default:
        return false;
    }
}

static bool authenticationserverBuildNormalBackupPrefix(authenticationserver_tstate_t *ts, char *prefix,
                                                        size_t prefix_len)
{
    hash_t      db_path_hash = calcHashBytes(ts->db_path, stringLength(ts->db_path));
    const char *mode_name    = authenticationserverNormalBackupsModeName(ts->normal_backups_mode);
    const char *db_name      = filePathBaseName(ts->db_path);

    int written = snprintf(prefix,
                           prefix_len,
                           "authenticationserver-%s-%016llx-%s-",
                           db_name,
                           (unsigned long long) db_path_hash,
                           mode_name);
    if (written > 0 && (size_t) written < prefix_len)
    {
        return true;
    }

    written =
        snprintf(prefix, prefix_len, "authenticationserver-%016llx-%s-", (unsigned long long) db_path_hash, mode_name);
    return written > 0 && (size_t) written < prefix_len;
}

static bool authenticationserverBackupPathListAppend(authenticationserver_backup_path_list_t *list, const char *path)
{
    if (list->count == list->capacity)
    {
        size_t new_capacity = list->capacity == 0U ? 16U : list->capacity * 2U;
        char **new_items    = memoryReAllocate(list->items, sizeof(*new_items) * new_capacity);
        if (UNLIKELY(new_items == NULL))
        {
            return false;
        }
        list->items    = new_items;
        list->capacity = new_capacity;
    }

    list->items[list->count] = stringDuplicate(path);
    if (UNLIKELY(list->items[list->count] == NULL))
    {
        return false;
    }
    ++list->count;
    return true;
}

static void authenticationserverBackupPathListDestroy(authenticationserver_backup_path_list_t *list)
{
    for (size_t i = 0; i < list->count; ++i)
    {
        memoryFree(list->items[i]);
    }
    memoryFree(list->items);
}

static void authenticationserverUserIdListDestroy(authenticationserver_user_id_list_t *list)
{
    memoryFree(list->items);
}

static bool authenticationserverUserIdListAppend(authenticationserver_user_id_list_t *list, uint64_t id)
{
    for (size_t i = 0; i < list->count; ++i)
    {
        if (UNLIKELY(list->items[i] == id))
        {
            LOGW("AuthenticationServer: users database contains duplicate required user id %" PRIu64, id);
            return false;
        }
    }

    if (list->count == list->capacity)
    {
        size_t new_capacity = list->capacity == 0U ? 16U : list->capacity * 2U;
        if (UNLIKELY(new_capacity < list->count))
        {
            LOGE("AuthenticationServer: user id validation capacity overflow");
            return false;
        }

        uint64_t *new_items = memoryReAllocate(list->items, sizeof(*new_items) * new_capacity);
        if (UNLIKELY(new_items == NULL))
        {
            LOGE("AuthenticationServer: failed to allocate user id validation list");
            return false;
        }
        list->items    = new_items;
        list->capacity = new_capacity;
    }

    list->items[list->count] = id;
    ++list->count;
    return true;
}

static bool authenticationserverJsonLooksLikeSingleUser(const cJSON *json)
{
    return cJSON_GetObjectItemCaseSensitive(json, "password") != NULL ||
           cJSON_GetObjectItemCaseSensitive(json, "pass") != NULL;
}

static const cJSON *authenticationserverUserJsonIdItem(const cJSON *user_json)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(user_json, "id");
    return item != NULL ? item : cJSON_GetObjectItemCaseSensitive(user_json, "user-id");
}

static bool authenticationserverReadRequiredUserJsonId(const cJSON *user_json, uint64_t *id)
{
    const cJSON *item = authenticationserverUserJsonIdItem(user_json);
    if (UNLIKELY(item == NULL || cJSON_IsNull(item)))
    {
        return false;
    }
    if (UNLIKELY(cJSON_IsString(item) && (item->valuestring == NULL || item->valuestring[0] == '\0')))
    {
        return false;
    }
    if (UNLIKELY(! getUint64FromJson(id, item)))
    {
        return false;
    }

    return *id != 0;
}

static bool authenticationserverValidateUserJsonRequiredId(authenticationserver_user_id_list_t *ids,
                                                           const cJSON                         *user_json,
                                                           const char                          *path)
{
    const size_t index = ids->count;
    uint64_t     id    = 0;

    if (UNLIKELY(! cJSON_IsObject(user_json)))
    {
        LOGW("AuthenticationServer: users database \"%s\" has a non-object user entry at index %zu", path, index);
        return false;
    }
    if (UNLIKELY(! authenticationserverReadRequiredUserJsonId(user_json, &id)))
    {
        LOGW("AuthenticationServer: users database \"%s\" has a user at index %zu without a required non-zero id",
             path,
             index);
        return false;
    }

    return authenticationserverUserIdListAppend(ids, id);
}

static bool authenticationserverValidateUsersJsonRequiredIds(authenticationserver_user_id_list_t *ids,
                                                            const cJSON                         *json,
                                                            const char                          *path);

static bool authenticationserverValidateUsersJsonArrayRequiredIds(authenticationserver_user_id_list_t *ids,
                                                                 const cJSON                         *array,
                                                                 const char                          *path)
{
    const cJSON *entry = NULL;

    cJSON_ArrayForEach(entry, array)
    {
        if (UNLIKELY(! authenticationserverValidateUserJsonRequiredId(ids, entry, path)))
        {
            return false;
        }
    }

    return true;
}

static bool authenticationserverValidateUsersJsonObjectMapRequiredIds(authenticationserver_user_id_list_t *ids,
                                                                     const cJSON                         *object,
                                                                     const char                          *path)
{
    const cJSON *entry = NULL;

    cJSON_ArrayForEach(entry, object)
    {
        if (UNLIKELY(! authenticationserverValidateUserJsonRequiredId(ids, entry, path)))
        {
            return false;
        }
    }

    return true;
}

static bool authenticationserverValidateUsersJsonRequiredIds(authenticationserver_user_id_list_t *ids,
                                                            const cJSON                         *json,
                                                            const char                          *path)
{
    if (UNLIKELY(json == NULL || cJSON_IsNull(json)))
    {
        return true;
    }
    if (cJSON_IsArray(json))
    {
        return authenticationserverValidateUsersJsonArrayRequiredIds(ids, json, path);
    }
    if (UNLIKELY(! cJSON_IsObject(json)))
    {
        LOGW("AuthenticationServer: users database \"%s\" must be an object, array, or null", path);
        return false;
    }
    if (json->child == NULL)
    {
        return true;
    }

    const cJSON *users_array = cJSON_GetObjectItemCaseSensitive(json, "users");
    if (users_array != NULL)
    {
        if (UNLIKELY(cJSON_IsNull(users_array)))
        {
            return true;
        }
        if (UNLIKELY(! cJSON_IsArray(users_array)))
        {
            LOGW("AuthenticationServer: users database \"%s\" field \"users\" must be an array", path);
            return false;
        }
        return authenticationserverValidateUsersJsonArrayRequiredIds(ids, users_array, path);
    }
    if (authenticationserverJsonLooksLikeSingleUser(json))
    {
        return authenticationserverValidateUserJsonRequiredId(ids, json, path);
    }

    return authenticationserverValidateUsersJsonObjectMapRequiredIds(ids, json, path);
}

static bool authenticationserverValidateDatabaseJsonRequiredIds(const cJSON *json, const char *path)
{
    authenticationserver_user_id_list_t ids = {0};
    bool                               ok  = authenticationserverValidateUsersJsonRequiredIds(&ids, json, path);

    authenticationserverUserIdListDestroy(&ids);
    return ok;
}

static int authenticationserverCompareBackupPaths(const void *left, const void *right)
{
    const char *const *left_path  = left;
    const char *const *right_path = right;
    return stringCompare(*left_path, *right_path);
}

static bool authenticationserverMaybeCollectNormalBackupFile(authenticationserver_backup_path_list_t *list,
                                                             authenticationserver_tstate_t *ts, const char *prefix,
                                                             const char *name)
{
    if (! stringStartsWith(name, prefix) || ! stringEndsWith(name, ".json"))
    {
        return true;
    }

    char path[MAX_PATH];
    if (UNLIKELY(! authenticationserverJoinPath(ts->normal_backups_path, name, path, sizeof(path))))
    {
        LOGW("AuthenticationServer: normal backup path is too long for \"%s\"", name);
        return true;
    }

    if (! isFile(path))
    {
        return true;
    }

    return authenticationserverBackupPathListAppend(list, path);
}

static bool authenticationserverCollectNormalBackupFiles(authenticationserver_tstate_t *ts, const char *prefix,
                                                         authenticationserver_backup_path_list_t *list)
{
#ifdef OS_WIN
    char search_path[MAX_PATH];
    if (UNLIKELY(! authenticationserverJoinPath(ts->normal_backups_path, "*", search_path, sizeof(search_path))))
    {
        LOGW("AuthenticationServer: normal-backups-path \"%s\" is too long to prune", ts->normal_backups_path);
        return false;
    }

    WIN32_FIND_DATAA find_data;
    HANDLE           find_handle = FindFirstFileA(search_path, &find_data);
    if (find_handle == INVALID_HANDLE_VALUE)
    {
        if (GetLastError() == ERROR_FILE_NOT_FOUND)
        {
            return true;
        }
        LOGW("AuthenticationServer: failed to scan normal-backups-path \"%s\"", ts->normal_backups_path);
        return false;
    }

    do
    {
        if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
        {
            if (UNLIKELY(! authenticationserverMaybeCollectNormalBackupFile(list, ts, prefix, find_data.cFileName)))
            {
                FindClose(find_handle);
                return false;
            }
        }
    } while (FindNextFileA(find_handle, &find_data));

    FindClose(find_handle);
    return true;
#else
    DIR *dir = opendir(ts->normal_backups_path);
    if (UNLIKELY(dir == NULL))
    {
        LOGW("AuthenticationServer: failed to scan normal-backups-path \"%s\": %s",
             ts->normal_backups_path,
             strerror(errno));
        return false;
    }

    struct dirent *entry = NULL;
    while ((entry = readdir(dir)) != NULL)
    {
        if (UNLIKELY(! authenticationserverMaybeCollectNormalBackupFile(list, ts, prefix, entry->d_name)))
        {
            closedir(dir);
            return false;
        }
    }

    closedir(dir);
    return true;
#endif
}

static bool authenticationserverPruneNormalBackups(authenticationserver_tstate_t *ts, const char *prefix)
{
    authenticationserver_backup_path_list_t list = {0};

    if (UNLIKELY(! authenticationserverCollectNormalBackupFiles(ts, prefix, &list)))
    {
        authenticationserverBackupPathListDestroy(&list);
        return false;
    }

    if (list.count <= ts->normal_backups_count_limit)
    {
        authenticationserverBackupPathListDestroy(&list);
        return true;
    }

    qsort(list.items, list.count, sizeof(*list.items), authenticationserverCompareBackupPaths);

    size_t remove_count = list.count - (size_t) ts->normal_backups_count_limit;
    for (size_t i = 0; i < remove_count; ++i)
    {
        if (UNLIKELY(remove(list.items[i]) != 0))
        {
            LOGW("AuthenticationServer: failed to remove expired normal backup \"%s\": %s",
                 list.items[i],
                 strerror(errno));
        }
        else
        {
            LOGD("AuthenticationServer: removed expired normal backup \"%s\"", list.items[i]);
        }
    }

    authenticationserverBackupPathListDestroy(&list);
    return true;
}

static bool authenticationserverMaybeWriteNormalBackup(authenticationserver_tstate_t *ts, const char *json_text,
                                                       size_t json_len)
{
    if (ts->normal_backups_mode == kAuthenticationServerNormalBackupsDisabled)
    {
        return true;
    }

    time_t now = time(NULL);
    if (UNLIKELY(now == (time_t) -1))
    {
        LOGW("AuthenticationServer: failed to read wall-clock time for normal backup");
        return false;
    }

    uint64_t slot = 0;
    char     period[32];
    if (UNLIKELY(! authenticationserverNormalBackupPeriod(ts->normal_backups_mode, now, &slot, period, sizeof(period))))
    {
        LOGW("AuthenticationServer: failed to calculate normal backup period");
        return false;
    }

    if (ts->normal_backups_last_slot == slot)
    {
        return true;
    }

    char prefix[512];
    if (UNLIKELY(! authenticationserverBuildNormalBackupPrefix(ts, prefix, sizeof(prefix))))
    {
        LOGW("AuthenticationServer: failed to build normal backup filename prefix");
        return false;
    }

    char filename[640];
    int  written = snprintf(filename, sizeof(filename), "%s%s.json", prefix, period);
    if (UNLIKELY(written <= 0 || (size_t) written >= sizeof(filename)))
    {
        LOGW("AuthenticationServer: normal backup filename is too long");
        return false;
    }

    char path[MAX_PATH];
    if (UNLIKELY(! authenticationserverJoinPath(ts->normal_backups_path, filename, path, sizeof(path))))
    {
        LOGW("AuthenticationServer: normal backup path is too long for \"%s\"", filename);
        return false;
    }

    if (UNLIKELY(! authenticationserverWriteJsonFile(path, json_text, json_len)))
    {
        return false;
    }

#ifdef OS_UNIX
    if (UNLIKELY(chmod(path, S_IRUSR | S_IWUSR) != 0))
    {
        LOGW(
            "AuthenticationServer: failed to restrict normal backup permissions for \"%s\": %s", path, strerror(errno));
    }
#endif

    if (UNLIKELY(! authenticationserverPruneNormalBackups(ts, prefix)))
    {
        return false;
    }

    ts->normal_backups_last_slot = slot;

    LOGD("AuthenticationServer: wrote normal %s backup \"%s\"",
         authenticationserverNormalBackupsModeName(ts->normal_backups_mode),
         path);
    return true;
}

static bool authenticationserverValidateUsersHaveRequiredIds(authenticationserver_tstate_t *ts, const char *path);

static bool authenticationserverLoadUsersFromPath(authenticationserver_tstate_t *ts, const char *path)
{
    char *json_text = readFile(path);
    if (UNLIKELY(json_text == NULL))
    {
        LOGW("AuthenticationServer: could not read users database \"%s\"", path);
        return false;
    }

    cJSON *json = cJSON_ParseWithLength(json_text, stringLength(json_text));
    if (UNLIKELY(json == NULL))
    {
        LOGW("AuthenticationServer: could not parse users database \"%s\"", path);
        memoryFree(json_text);
        return false;
    }

    bool ok = authenticationserverValidateDatabaseJsonRequiredIds(json, path);
    usersClear(&ts->store.users);
    if (UNLIKELY(! ok))
    {
        LOGW("AuthenticationServer: users database \"%s\" failed required user id validation", path);
    }
    else if (UNLIKELY(! usersFeedJson(&ts->store.users, json)))
    {
        usersClear(&ts->store.users);
        LOGW("AuthenticationServer: users database \"%s\" has an invalid users layout", path);
        ok = false;
    }
    else if (UNLIKELY(! usersValidate(&ts->store.users)))
    {
        LOGW("AuthenticationServer: users database \"%s\" failed validation", path);
        usersClear(&ts->store.users);
        ok = false;
    }
    else if (UNLIKELY(! authenticationserverValidateUsersHaveRequiredIds(ts, path)))
    {
        LOGW("AuthenticationServer: users database \"%s\" failed required user id validation", path);
        usersClear(&ts->store.users);
        ok = false;
    }

    if (LIKELY(ok))
    {
        LOGI("AuthenticationServer: loaded %zu users from \"%s\"", usersCount(&ts->store.users), path);
    }

    cJSON_Delete(json);
    memoryFree(json_text);
    return ok;
}

static bool authenticationserverValidateUsersHaveRequiredIds(authenticationserver_tstate_t *ts, const char *path)
{
    const size_t count = usersCount(&ts->store.users);

    for (size_t i = 0; i < count; ++i)
    {
        const user_t *user = usersGetAtConst(&ts->store.users, i);
        if (UNLIKELY(user == NULL))
        {
            LOGW("AuthenticationServer: users database \"%s\" could not inspect user at index %zu", path, i);
            return false;
        }
        if (UNLIKELY(! authenticationserverUserHasRequiredId(user)))
        {
            LOGW("AuthenticationServer: users database \"%s\" has a user at index %zu without a required non-zero id",
                 path,
                 i);
            return false;
        }
    }

    return true;
}

static bool authenticationserverRewritePrimaryFromMemory(authenticationserver_tstate_t *ts)
{
    char  *json_text = NULL;
    size_t json_len  = 0;

    if (UNLIKELY(! authenticationserverBuildUsersJson(ts, &json_text, &json_len)))
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

    if (UNLIKELY(! ts->database_loaded))
    {
        return false;
    }

    if (UNLIKELY(! authenticationserverBuildUsersJson(ts, &json_text, &json_len)))
    {
        return false;
    }

    if (UNLIKELY(! authenticationserverWriteJsonFile(ts->backup_path, json_text, json_len)))
    {
        memoryFree(json_text);
        return false;
    }

    if (UNLIKELY(! authenticationserverWriteJsonFile(ts->db_path, json_text, json_len)))
    {
        memoryFree(json_text);
        return false;
    }

    if (UNLIKELY(! authenticationserverMaybeWriteNormalBackup(ts, json_text, json_len)))
    {
        LOGW("AuthenticationServer: normal backup save failed");
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
    if (UNLIKELY(ts->backup_path == NULL))
    {
        LOGE("AuthenticationServer: failed to allocate backup path for \"%s\"", ts->db_path);
        return false;
    }

    LOGI("AuthenticationServer: loading users database from \"%s\"", ts->db_path);
    if (LIKELY(authenticationserverLoadUsersFromPath(ts, ts->db_path)))
    {
        return true;
    }

    LOGW("AuthenticationServer: primary users database \"%s\" could not be loaded; attempting recovery from \"%s\"",
         ts->db_path,
         ts->backup_path);

    if (UNLIKELY(! isFile(ts->backup_path)))
    {
        LOGE("AuthenticationServer: recovery failed because backup file \"%s\" does not exist", ts->backup_path);
        return false;
    }

    if (UNLIKELY(! authenticationserverLoadUsersFromPath(ts, ts->backup_path)))
    {
        LOGE("AuthenticationServer: recovery failed because backup file \"%s\" is not valid", ts->backup_path);
        return false;
    }

    if (UNLIKELY(! authenticationserverRewritePrimaryFromMemory(ts)))
    {
        LOGE("AuthenticationServer: recovery failed because recovered data could not be written to \"%s\"",
             ts->db_path);
        return false;
    }

    LOGI("AuthenticationServer: recovered users database from backup \"%s\"", ts->backup_path);

    if (UNLIKELY(remove(ts->backup_path) != 0))
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
    if (UNLIKELY(t == NULL || isApplicationTerminating()))
    {
        return;
    }

    authenticationserver_tstate_t *ts = tunnelGetState(t);
    if (UNLIKELY(! authenticationserverSaveDatabase(ts)))
    {
        LOGW("AuthenticationServer: periodic users database save failed");
    }
}
