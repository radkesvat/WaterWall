/*
 * User object lifecycle, JSON persistence, and usage accounting helpers.
 */

#include "objects/user.h"

#include "utils/json_helpers.h"

static bool userStringIsEmpty(const char *value)
{
    return value == NULL || value[0] == '\0';
}

static bool userObjectIsInitialized(const User *user)
{
    return user != NULL && user->initialized;
}

static bool userStringDuplicate(char **dest, const char *value)
{
    char *copy = stringDuplicate(value != NULL ? value : "");
    if (UNLIKELY(copy == NULL))
    {
        return false;
    }

    *dest = copy;
    return true;
}

static bool userReplaceString(char **dest, const char *value)
{
    char *copy = stringDuplicate(value != NULL ? value : "");
    if (UNLIKELY(copy == NULL))
    {
        return false;
    }

    memoryFree(*dest);
    *dest = copy;
    return true;
}

static void userFreePassword(char *password)
{
    if (UNLIKELY(password == NULL))
    {
        return;
    }

    wCryptoZero(password, stringLength(password));
    memoryFree(password);
}

static void userDestroyStrings(User *user)
{
    memoryFree(user->name);
    userFreePassword(user->password);
    memoryFree(user->email);
    memoryFree(user->notes);

    user->name     = NULL;
    user->password = NULL;
    user->email    = NULL;
    user->notes    = NULL;
}

typedef struct user_snapshot_s
{
    char *name;
    char *password;
    char *email;
    char *notes;

    hash_t gid;
    bool   enabled;

    user_limit_t     limit;
    user_time_info_t timeinfo;
    int              record_stat_interval_ms;

    user_stat_t stats;

    hash_t        hash_pass;
    sha224_hash_t sha224_pass;
    sha256_hash_t sha256_pass;
    sha384_hash_t sha384_pass;
    sha512_hash_t sha512_pass;

    bool sha224_pass_valid;
    bool sha256_pass_valid;
    bool sha384_pass_valid;
    bool sha512_pass_valid;
} user_snapshot_t;

static void userSnapshotDestroy(user_snapshot_t *snapshot)
{
    if (UNLIKELY(snapshot == NULL))
    {
        return;
    }

    memoryFree(snapshot->name);
    userFreePassword(snapshot->password);
    memoryFree(snapshot->email);
    memoryFree(snapshot->notes);
    wCryptoZero(&snapshot->sha224_pass, sizeof(snapshot->sha224_pass));
    wCryptoZero(&snapshot->sha256_pass, sizeof(snapshot->sha256_pass));
    wCryptoZero(&snapshot->sha384_pass, sizeof(snapshot->sha384_pass));
    wCryptoZero(&snapshot->sha512_pass, sizeof(snapshot->sha512_pass));
    memoryZero(snapshot, sizeof(*snapshot));
}

static bool userSnapshotCreate(user_snapshot_t *snapshot, const User *src)
{
    User *mutable_src = (User *) src;

    if (UNLIKELY(snapshot == NULL || ! userObjectIsInitialized(src)))
    {
        return false;
    }

    memoryZero(snapshot, sizeof(*snapshot));

    rwlockReadLock(&mutable_src->lock);
    rwlockReadLock(&mutable_src->stats_lock);

    if (UNLIKELY(! userStringDuplicate(&snapshot->name, src->name) ||
                 ! userStringDuplicate(&snapshot->password, src->password) ||
                 ! userStringDuplicate(&snapshot->email, src->email) ||
                 ! userStringDuplicate(&snapshot->notes, src->notes)))
    {
        rwlockReadUnlock(&mutable_src->stats_lock);
        rwlockReadUnlock(&mutable_src->lock);
        userSnapshotDestroy(snapshot);
        return false;
    }

    snapshot->gid                     = src->gid;
    snapshot->enabled                 = src->enabled;
    snapshot->limit                   = src->limit;
    snapshot->timeinfo                = src->timeinfo;
    snapshot->record_stat_interval_ms = src->record_stat_interval_ms;
    snapshot->stats                   = src->stats;
    snapshot->hash_pass               = src->hash_pass;
    snapshot->sha224_pass             = src->sha224_pass;
    snapshot->sha256_pass             = src->sha256_pass;
    snapshot->sha384_pass             = src->sha384_pass;
    snapshot->sha512_pass             = src->sha512_pass;
    snapshot->sha224_pass_valid       = src->sha224_pass_valid;
    snapshot->sha256_pass_valid       = src->sha256_pass_valid;
    snapshot->sha384_pass_valid       = src->sha384_pass_valid;
    snapshot->sha512_pass_valid       = src->sha512_pass_valid;

    rwlockReadUnlock(&mutable_src->stats_lock);
    rwlockReadUnlock(&mutable_src->lock);
    return true;
}

static bool userPasswordHashesCreate(User *user, const char *password)
{
    const size_t password_len = stringLength(password);

    user->hash_pass = calcHashBytes(password, password_len);

    user->sha224_pass_valid = false;
    user->sha256_pass_valid = false;
    user->sha384_pass_valid = false;
    user->sha512_pass_valid = false;

    memoryZero(&user->sha224_pass, sizeof(user->sha224_pass));
    memoryZero(&user->sha256_pass, sizeof(user->sha256_pass));
    memoryZero(&user->sha384_pass, sizeof(user->sha384_pass));
    memoryZero(&user->sha512_pass, sizeof(user->sha512_pass));

#if defined(WCRYPTO_BACKEND_OPENSSL)
    if (UNLIKELY(wCryptoSHA224(&user->sha224_pass, (const unsigned char *) password, password_len) != 0))
    {
        return false;
    }
    user->sha224_pass_valid = true;
#endif

#if defined(WCRYPTO_BACKEND_OPENSSL) || defined(WCRYPTO_BACKEND_SODIUM)
    if (UNLIKELY(wCryptoSHA256(&user->sha256_pass, (const unsigned char *) password, password_len) != 0))
    {
        return false;
    }
    if (UNLIKELY(wCryptoSHA512(&user->sha512_pass, (const unsigned char *) password, password_len) != 0))
    {
        return false;
    }
    user->sha256_pass_valid = true;
    user->sha512_pass_valid = true;
#endif

#if defined(WCRYPTO_BACKEND_OPENSSL)
    if (UNLIKELY(wCryptoSHA384(&user->sha384_pass, (const unsigned char *) password, password_len) != 0))
    {
        return false;
    }
    user->sha384_pass_valid = true;
#endif

    return true;
}

static const cJSON *userJsonGetItem(const cJSON *json_obj, const char *key)
{
    if (! cJSON_IsObject(json_obj))
    {
        return NULL;
    }
    return cJSON_GetObjectItemCaseSensitive(json_obj, key);
}

static const cJSON *userJsonGetItemAliased(const cJSON *json_obj, const char *primary, const char *fallback)
{
    const cJSON *item = userJsonGetItem(json_obj, primary);
    if (item != NULL)
    {
        return item;
    }
    return userJsonGetItem(json_obj, fallback);
}

static bool userJsonGetRequiredStringAliased(const cJSON *json_obj, const char *primary, const char *fallback,
                                             const char **value)
{
    const cJSON *item = userJsonGetItemAliased(json_obj, primary, fallback);
    if (UNLIKELY(! cJSON_IsString(item) || userStringIsEmpty(item->valuestring)))
    {
        return false;
    }

    *value = item->valuestring;
    return true;
}

static bool userJsonReadOptionalString(const cJSON *json_obj, const char *key, const char **value)
{
    const cJSON *item = userJsonGetItem(json_obj, key);
    if (item == NULL || cJSON_IsNull(item))
    {
        *value = NULL;
        return true;
    }
    if (UNLIKELY(! cJSON_IsString(item) || item->valuestring == NULL))
    {
        return false;
    }

    *value = item->valuestring;
    return true;
}

static bool userJsonReadOptionalBoolAliased(const cJSON *json_obj, const char *primary, const char *fallback,
                                            bool *value)
{
    const cJSON *item = userJsonGetItemAliased(json_obj, primary, fallback);
    if (item == NULL || cJSON_IsNull(item))
    {
        return true;
    }
    if (cJSON_IsString(item) && userStringIsEmpty(item->valuestring))
    {
        return true;
    }
    if (UNLIKELY(! cJSON_IsBool(item)))
    {
        return false;
    }

    *value = cJSON_IsTrue(item);
    return true;
}

static bool userJsonReadOptionalUint64(const cJSON *json_obj, const char *key, uint64_t *value)
{
    const cJSON *item = userJsonGetItem(json_obj, key);

    /* Absent, null, or an empty-string placeholder all mean "keep the current value". */
    if (item == NULL || cJSON_IsNull(item) || (cJSON_IsString(item) && userStringIsEmpty(item->valuestring)))
    {
        return true;
    }

    return getUint64FromJson(value, item);
}

static bool userJsonReadOptionalUint64Aliased(const cJSON *json_obj, const char *primary, const char *alias,
                                              uint64_t *value)
{
    const char *key = userJsonGetItem(json_obj, primary) != NULL ? primary : alias;
    return userJsonReadOptionalUint64(json_obj, key, value);
}

static bool userJsonReadOptionalInt(const cJSON *json_obj, const char *key, int *value)
{
    uint64_t parsed = (uint64_t) *value;

    if (UNLIKELY(! userJsonReadOptionalUint64(json_obj, key, &parsed)))
    {
        return false;
    }
    if (UNLIKELY(parsed > (uint64_t) INT_MAX))
    {
        return false;
    }

    *value = (int) parsed;
    return true;
}

static bool userJsonReadUd(const cJSON *json_obj, user_ud_t *value)
{
    if (json_obj == NULL || cJSON_IsNull(json_obj) ||
        (cJSON_IsString(json_obj) && userStringIsEmpty(json_obj->valuestring)))
    {
        return true;
    }
    if (UNLIKELY(! cJSON_IsObject(json_obj)))
    {
        return false;
    }

    return userJsonReadOptionalUint64Aliased(json_obj, "u", "up", &value->u) &&
           userJsonReadOptionalUint64Aliased(json_obj, "d", "down", &value->d);
}

static bool userJsonReadLimit(const cJSON *json_obj, user_limit_t *limit)
{
    if (json_obj == NULL || cJSON_IsNull(json_obj) ||
        (cJSON_IsString(json_obj) && userStringIsEmpty(json_obj->valuestring)))
    {
        return true;
    }
    if (UNLIKELY(! cJSON_IsObject(json_obj)))
    {
        return false;
    }

    const cJSON *traffic   = userJsonGetItem(json_obj, "traffic");
    const cJSON *bandwidth = userJsonGetItem(json_obj, "bandwidth");

    if (traffic != NULL && ! cJSON_IsNull(traffic) &&
        (! cJSON_IsString(traffic) || ! userStringIsEmpty(traffic->valuestring)))
    {
        if (UNLIKELY(! cJSON_IsObject(traffic) ||
                     ! userJsonReadOptionalUint64Aliased(traffic, "u", "up", &limit->traffic.u) ||
                     ! userJsonReadOptionalUint64Aliased(traffic, "d", "down", &limit->traffic.d) ||
                     ! userJsonReadOptionalUint64(traffic, "total", &limit->traffic.total)))
        {
            return false;
        }
    }

    if (UNLIKELY(! userJsonReadUd(bandwidth, &limit->bandwidth)))
    {
        return false;
    }

    return userJsonReadOptionalUint64Aliased(json_obj, "ip", "ips", &limit->ips) &&
           userJsonReadOptionalUint64(json_obj, "devices", &limit->devices) &&
           userJsonReadOptionalUint64Aliased(json_obj, "cons-in", "connections-in", &limit->cons_in) &&
           userJsonReadOptionalUint64Aliased(json_obj, "cons-out", "connections-out", &limit->cons_out);
}

static bool userJsonReadTimeInfo(const cJSON *json_obj, user_time_info_t *timeinfo)
{
    if (json_obj == NULL || cJSON_IsNull(json_obj) ||
        (cJSON_IsString(json_obj) && userStringIsEmpty(json_obj->valuestring)))
    {
        return true;
    }
    if (UNLIKELY(! cJSON_IsObject(json_obj)))
    {
        return false;
    }

    return userJsonReadOptionalUint64Aliased(json_obj, "created-at-ms", "created_at_ms", &timeinfo->created_at_ms) &&
           userJsonReadOptionalUint64Aliased(
               json_obj, "first-usage-at-ms", "first_usage_at_ms", &timeinfo->first_usage_at_ms) &&
           userJsonReadOptionalUint64Aliased(json_obj, "expire-at-ms", "expires-at-ms", &timeinfo->expire_at_ms) &&
           userJsonReadOptionalUint64Aliased(json_obj,
                                       "expire-after-first-usage-ms",
                                       "expire-after-first-use-ms",
                                       &timeinfo->expire_after_first_usage_ms);
}

static bool userJsonReadStats(const cJSON *json_obj, user_stat_t *stats)
{
    const cJSON *speed   = userJsonGetItem(json_obj, "speed");
    const cJSON *traffic = userJsonGetItem(json_obj, "traffic");

    if (json_obj == NULL || cJSON_IsNull(json_obj) ||
        (cJSON_IsString(json_obj) && userStringIsEmpty(json_obj->valuestring)))
    {
        return true;
    }
    if (UNLIKELY(! cJSON_IsObject(json_obj)))
    {
        return false;
    }

    return userJsonReadOptionalUint64Aliased(json_obj, "ip", "ips", &stats->ips) &&
           userJsonReadOptionalUint64(json_obj, "devices", &stats->devices) &&
           userJsonReadOptionalUint64Aliased(json_obj, "cons-in", "connections-in", &stats->cons_in) &&
           userJsonReadOptionalUint64Aliased(json_obj, "cons-out", "connections-out", &stats->cons_out) &&
           userJsonReadUd(speed, &stats->speed) && userJsonReadUd(traffic, &stats->traffic);
}

static bool userJsonAddStringIfNotEmpty(cJSON *json_obj, const char *key, const char *value)
{
    if (userStringIsEmpty(value))
    {
        return true;
    }

    return cJSON_AddStringToObject(json_obj, key, value) != NULL;
}

static bool userJsonAddUdIfNotZero(cJSON *json_obj, const char *key, user_ud_t value)
{
    cJSON *ud_json = NULL;

    if (value.u == 0 && value.d == 0)
    {
        return true;
    }

    ud_json = cJSON_CreateObject();
    if (UNLIKELY(ud_json == NULL))
    {
        return false;
    }

    if (UNLIKELY((value.u != 0 && ! jsonAddUint64ToObject(ud_json, "up", value.u)) ||
                 (value.d != 0 && ! jsonAddUint64ToObject(ud_json, "down", value.d))))
    {
        cJSON_Delete(ud_json);
        return false;
    }

    if (UNLIKELY(! cJSON_AddItemToObject(json_obj, key, ud_json)))
    {
        cJSON_Delete(ud_json);
        return false;
    }
    return true;
}

static bool userJsonAddLimitIfNotZero(cJSON *root, const user_limit_t *limit)
{
    cJSON *limit_json   = NULL;
    cJSON *traffic_json = NULL;

    if (limit->traffic.u == 0 && limit->traffic.d == 0 && limit->traffic.total == 0 && limit->bandwidth.u == 0 &&
        limit->bandwidth.d == 0 && limit->ips == 0 && limit->devices == 0 && limit->cons_in == 0 &&
        limit->cons_out == 0)
    {
        return true;
    }

    limit_json = cJSON_CreateObject();
    if (UNLIKELY(limit_json == NULL))
    {
        return false;
    }

    if (limit->traffic.u != 0 || limit->traffic.d != 0 || limit->traffic.total != 0)
    {
        traffic_json = cJSON_CreateObject();
        if (UNLIKELY(traffic_json == NULL))
        {
            cJSON_Delete(limit_json);
            return false;
        }

        if (UNLIKELY((limit->traffic.u != 0 && ! jsonAddUint64ToObject(traffic_json, "up", limit->traffic.u)) ||
                     (limit->traffic.d != 0 && ! jsonAddUint64ToObject(traffic_json, "down", limit->traffic.d)) ||
                     (limit->traffic.total != 0 &&
                      ! jsonAddUint64ToObject(traffic_json, "total", limit->traffic.total))))
        {
            cJSON_Delete(traffic_json);
            cJSON_Delete(limit_json);
            return false;
        }
        if (UNLIKELY(! cJSON_AddItemToObject(limit_json, "traffic", traffic_json)))
        {
            cJSON_Delete(traffic_json);
            cJSON_Delete(limit_json);
            return false;
        }
    }

    if (UNLIKELY(! userJsonAddUdIfNotZero(limit_json, "bandwidth", limit->bandwidth) ||
                 (limit->ips != 0 && ! jsonAddUint64ToObject(limit_json, "ips", limit->ips)) ||
                 (limit->devices != 0 && ! jsonAddUint64ToObject(limit_json, "devices", limit->devices)) ||
                 (limit->cons_in != 0 && ! jsonAddUint64ToObject(limit_json, "connections-in", limit->cons_in)) ||
                 (limit->cons_out != 0 && ! jsonAddUint64ToObject(limit_json, "connections-out", limit->cons_out))))
    {
        cJSON_Delete(limit_json);
        return false;
    }

    if (UNLIKELY(! cJSON_AddItemToObject(root, "limit", limit_json)))
    {
        cJSON_Delete(limit_json);
        return false;
    }
    return true;
}

static bool userJsonAddTimeInfo(cJSON *root, const user_time_info_t *timeinfo)
{
    cJSON *time_json = cJSON_CreateObject();
    if (UNLIKELY(time_json == NULL))
    {
        return false;
    }

    if (UNLIKELY(
            (timeinfo->created_at_ms != 0 &&
             ! jsonAddUint64ToObject(time_json, "created-at-ms", timeinfo->created_at_ms)) ||
            (timeinfo->first_usage_at_ms != 0 &&
             ! jsonAddUint64ToObject(time_json, "first-usage-at-ms", timeinfo->first_usage_at_ms)) ||
            (timeinfo->expire_at_ms != 0 &&
             ! jsonAddUint64ToObject(time_json, "expire-at-ms", timeinfo->expire_at_ms)) ||
            (timeinfo->expire_after_first_usage_ms != 0 &&
             ! jsonAddUint64ToObject(time_json, "expire-after-first-usage-ms", timeinfo->expire_after_first_usage_ms))))
    {
        cJSON_Delete(time_json);
        return false;
    }

    if (time_json->child == NULL)
    {
        cJSON_Delete(time_json);
        return true;
    }

    if (UNLIKELY(! cJSON_AddItemToObject(root, "time", time_json)))
    {
        cJSON_Delete(time_json);
        return false;
    }
    return true;
}

static bool userJsonAddStatsIfNotZero(cJSON *root, const user_stat_t *stats)
{
    cJSON *stats_json = NULL;

    if (stats->ips == 0 && stats->devices == 0 && stats->cons_in == 0 && stats->cons_out == 0 &&
        stats->traffic.u == 0 && stats->traffic.d == 0)
    {
        return true;
    }

    stats_json = cJSON_CreateObject();
    if (UNLIKELY(stats_json == NULL))
    {
        return false;
    }

    if (UNLIKELY((stats->ips != 0 && ! jsonAddUint64ToObject(stats_json, "ips", stats->ips)) ||
                 (stats->devices != 0 && ! jsonAddUint64ToObject(stats_json, "devices", stats->devices)) ||
                 (stats->cons_in != 0 && ! jsonAddUint64ToObject(stats_json, "connections-in", stats->cons_in)) ||
                 (stats->cons_out != 0 && ! jsonAddUint64ToObject(stats_json, "connections-out", stats->cons_out)) ||
                 ! userJsonAddUdIfNotZero(stats_json, "traffic", stats->traffic)))
    {
        cJSON_Delete(stats_json);
        return false;
    }

    if (UNLIKELY(! cJSON_AddItemToObject(root, "stats", stats_json)))
    {
        cJSON_Delete(stats_json);
        return false;
    }
    return true;
}

static uint64_t userSaturatingAdd(uint64_t a, uint64_t b)
{
    if (UNLIKELY(UINT64_MAX - a < b))
    {
        return UINT64_MAX;
    }
    return a + b;
}

static uint64_t userSaturatingSub(uint64_t a, uint64_t b)
{
    return a > b ? a - b : 0;
}

static bool userLimitReached(uint64_t limit, uint64_t value)
{
    return limit != USER_NO_LIMIT && value >= limit;
}

bool userCreate(User *user, const char *password)
{
    if (UNLIKELY(user == NULL || userStringIsEmpty(password)))
    {
        return false;
    }

    memoryZero(user, sizeof(*user));
    rwlockinit(&user->lock);
    rwlockinit(&user->stats_lock);

    user->initialized = true;

    user->enabled                 = true;
    user->record_stat_interval_ms = USER_DEFAULT_RECORD_STAT_INTERVAL_MS;
    user->timeinfo.created_at_ms  = getTimeOfDayMS();

    if (UNLIKELY(! userStringDuplicate(&user->name, "") || ! userStringDuplicate(&user->email, "") ||
                 ! userStringDuplicate(&user->notes, "") || ! userChangePassword(user, password)))
    {
        userDestroy(user);
        return false;
    }

    return true;
}

bool userCopy(User *dest, const User *src)
{
    user_snapshot_t snapshot;

    if (UNLIKELY(dest == NULL || src == NULL))
    {
        return false;
    }
    if (UNLIKELY(! userSnapshotCreate(&snapshot, src)))
    {
        return false;
    }

    memoryZero(dest, sizeof(*dest));
    rwlockinit(&dest->lock);
    rwlockinit(&dest->stats_lock);

    dest->initialized = true;

    dest->name     = snapshot.name;
    dest->password = snapshot.password;
    dest->email    = snapshot.email;
    dest->notes    = snapshot.notes;

    dest->gid                     = snapshot.gid;
    dest->enabled                 = snapshot.enabled;
    dest->limit                   = snapshot.limit;
    dest->timeinfo                = snapshot.timeinfo;
    dest->record_stat_interval_ms = snapshot.record_stat_interval_ms;
    dest->stats                   = snapshot.stats;
    dest->hash_pass               = snapshot.hash_pass;
    dest->sha224_pass             = snapshot.sha224_pass;
    dest->sha256_pass             = snapshot.sha256_pass;
    dest->sha384_pass             = snapshot.sha384_pass;
    dest->sha512_pass             = snapshot.sha512_pass;
    dest->sha224_pass_valid       = snapshot.sha224_pass_valid;
    dest->sha256_pass_valid       = snapshot.sha256_pass_valid;
    dest->sha384_pass_valid       = snapshot.sha384_pass_valid;
    dest->sha512_pass_valid       = snapshot.sha512_pass_valid;

    snapshot.name     = NULL;
    snapshot.password = NULL;
    snapshot.email    = NULL;
    snapshot.notes    = NULL;
    memoryZero(&snapshot.sha224_pass, sizeof(snapshot.sha224_pass));
    memoryZero(&snapshot.sha256_pass, sizeof(snapshot.sha256_pass));
    memoryZero(&snapshot.sha384_pass, sizeof(snapshot.sha384_pass));
    memoryZero(&snapshot.sha512_pass, sizeof(snapshot.sha512_pass));
    userSnapshotDestroy(&snapshot);
    return true;
}

void userDestroy(User *user)
{
    if (UNLIKELY(user == NULL || ! user->initialized))
    {
        return;
    }

    userDestroyStrings(user);
    wCryptoZero(&user->sha224_pass, sizeof(user->sha224_pass));
    wCryptoZero(&user->sha256_pass, sizeof(user->sha256_pass));
    wCryptoZero(&user->sha384_pass, sizeof(user->sha384_pass));
    wCryptoZero(&user->sha512_pass, sizeof(user->sha512_pass));
    memoryZero(&user->limit, sizeof(user->limit));
    memoryZero(&user->timeinfo, sizeof(user->timeinfo));
    memoryZero(&user->stats, sizeof(user->stats));
    user->hash_pass = 0;
    user->enabled   = false;

    rwlockDestroy(&user->stats_lock);
    rwlockDestroy(&user->lock);
    memoryZero(user, sizeof(*user));
}

bool userChangePassword(User *user, const char *password)
{
    User  staged_hashes = {0};
    char *copy          = NULL;

    if (UNLIKELY(! userObjectIsInitialized(user) || userStringIsEmpty(password)))
    {
        return false;
    }

    if (UNLIKELY(! userPasswordHashesCreate(&staged_hashes, password)))
    {
        wCryptoZero(&staged_hashes.sha224_pass, sizeof(staged_hashes.sha224_pass));
        wCryptoZero(&staged_hashes.sha256_pass, sizeof(staged_hashes.sha256_pass));
        wCryptoZero(&staged_hashes.sha384_pass, sizeof(staged_hashes.sha384_pass));
        wCryptoZero(&staged_hashes.sha512_pass, sizeof(staged_hashes.sha512_pass));
        return false;
    }

    copy = stringDuplicate(password);
    if (UNLIKELY(copy == NULL))
    {
        wCryptoZero(&staged_hashes.sha224_pass, sizeof(staged_hashes.sha224_pass));
        wCryptoZero(&staged_hashes.sha256_pass, sizeof(staged_hashes.sha256_pass));
        wCryptoZero(&staged_hashes.sha384_pass, sizeof(staged_hashes.sha384_pass));
        wCryptoZero(&staged_hashes.sha512_pass, sizeof(staged_hashes.sha512_pass));
        return false;
    }

    rwlockWriteLock(&user->lock);

    wCryptoZero(&user->sha224_pass, sizeof(user->sha224_pass));
    wCryptoZero(&user->sha256_pass, sizeof(user->sha256_pass));
    wCryptoZero(&user->sha384_pass, sizeof(user->sha384_pass));
    wCryptoZero(&user->sha512_pass, sizeof(user->sha512_pass));
    user->hash_pass         = staged_hashes.hash_pass;
    user->sha224_pass       = staged_hashes.sha224_pass;
    user->sha256_pass       = staged_hashes.sha256_pass;
    user->sha384_pass       = staged_hashes.sha384_pass;
    user->sha512_pass       = staged_hashes.sha512_pass;
    user->sha224_pass_valid = staged_hashes.sha224_pass_valid;
    user->sha256_pass_valid = staged_hashes.sha256_pass_valid;
    user->sha384_pass_valid = staged_hashes.sha384_pass_valid;
    user->sha512_pass_valid = staged_hashes.sha512_pass_valid;

    userFreePassword(user->password);
    user->password = copy;
    rwlockWriteUnlock(&user->lock);
    wCryptoZero(&staged_hashes.sha224_pass, sizeof(staged_hashes.sha224_pass));
    wCryptoZero(&staged_hashes.sha256_pass, sizeof(staged_hashes.sha256_pass));
    wCryptoZero(&staged_hashes.sha384_pass, sizeof(staged_hashes.sha384_pass));
    wCryptoZero(&staged_hashes.sha512_pass, sizeof(staged_hashes.sha512_pass));
    return true;
}

bool userSetPassword(User *user, const char *password)
{
    return userChangePassword(user, password);
}

bool userCreateFromJson(User *user, const cJSON *user_json)
{
    const char  *password = NULL;
    const char  *value    = NULL;
    const cJSON *limit    = NULL;
    const cJSON *timeinfo = NULL;
    const cJSON *stats    = NULL;

    if (UNLIKELY(user == NULL || ! cJSON_IsObject(user_json)))
    {
        return false;
    }
    if (UNLIKELY(! userJsonGetRequiredStringAliased(user_json, "password", "pass", &password)))
    {
        return false;
    }
    if (UNLIKELY(! userCreate(user, password)))
    {
        return false;
    }

    if (UNLIKELY(! userJsonReadOptionalString(user_json, "name", &value) ||
                 (value != NULL && ! userReplaceString(&user->name, value)) ||
                 ! userJsonReadOptionalString(user_json, "email", &value) ||
                 (value != NULL && ! userReplaceString(&user->email, value)) ||
                 ! userJsonReadOptionalString(user_json, "notes", &value) ||
                 (value != NULL && ! userReplaceString(&user->notes, value)) ||
                 ! userJsonReadOptionalUint64Aliased(user_json, "gid", "group-id", &user->gid) ||
                 ! userJsonReadOptionalBoolAliased(user_json, "enabled", "enable", &user->enabled) ||
                 ! userJsonReadOptionalInt(user_json, "record-stat-interval-ms", &user->record_stat_interval_ms)))
    {
        userDestroy(user);
        return false;
    }

    limit    = cJSON_GetObjectItemCaseSensitive(user_json, "limit");
    timeinfo = cJSON_GetObjectItemCaseSensitive(user_json, "time");
    stats    = cJSON_GetObjectItemCaseSensitive(user_json, "stats");

    if (UNLIKELY(! userJsonReadLimit(limit, &user->limit) || ! userJsonReadTimeInfo(timeinfo, &user->timeinfo) ||
                 ! userJsonReadStats(stats, &user->stats)))
    {
        userDestroy(user);
        return false;
    }

    if (UNLIKELY(! userJsonReadOptionalUint64Aliased(
                     user_json, "created-at-ms", "created_at_ms", &user->timeinfo.created_at_ms) ||
                 ! userJsonReadOptionalUint64Aliased(
                     user_json, "first-usage-at-ms", "first_usage_at_ms", &user->timeinfo.first_usage_at_ms) ||
                 ! userJsonReadOptionalUint64Aliased(
                     user_json, "expire-at-ms", "expires-at-ms", &user->timeinfo.expire_at_ms) ||
                 ! userJsonReadOptionalUint64Aliased(
                     user_json, "expire-after-first-usage-ms", "expire-after-first-use-ms",
                     &user->timeinfo.expire_after_first_usage_ms)))
    {
        userDestroy(user);
        return false;
    }

    return true;
}

cJSON *userToJson(User *user)
{
    cJSON      *json  = NULL;
    user_stat_t stats = {0};

    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return NULL;
    }

    json = cJSON_CreateObject();
    if (UNLIKELY(json == NULL))
    {
        return NULL;
    }

    rwlockReadLock(&user->lock);
    rwlockReadLock(&user->stats_lock);
    stats = user->stats;
    rwlockReadUnlock(&user->stats_lock);

    if (UNLIKELY(! userJsonAddStringIfNotEmpty(json, "name", user->name) ||
                 ! cJSON_AddStringToObject(json, "password", user->password) ||
                 ! userJsonAddStringIfNotEmpty(json, "email", user->email) ||
                 ! userJsonAddStringIfNotEmpty(json, "notes", user->notes) ||
                 (user->gid != 0 && ! jsonAddUint64ToObject(json, "gid", user->gid)) ||
                 (! user->enabled && cJSON_AddFalseToObject(json, "enabled") == NULL) ||
                 (user->record_stat_interval_ms != USER_DEFAULT_RECORD_STAT_INTERVAL_MS &&
                  ! jsonAddUint64ToObject(json, "record-stat-interval-ms", (uint64_t) user->record_stat_interval_ms)) ||
                 ! userJsonAddTimeInfo(json, &user->timeinfo) || ! userJsonAddLimitIfNotZero(json, &user->limit) ||
                 ! userJsonAddStatsIfNotZero(json, &stats)))
    {
        rwlockReadUnlock(&user->lock);
        cJSON_Delete(json);
        return NULL;
    }

    rwlockReadUnlock(&user->lock);
    return json;
}

bool userPasswordMatches(User *user, const char *password)
{
    sha256_hash_t sha256 = {0};
    sha512_hash_t sha512 = {0};
    bool          result = false;

    if (UNLIKELY(! userObjectIsInitialized(user) || userStringIsEmpty(password)))
    {
        return false;
    }

    rwlockReadLock(&user->lock);
    if (UNLIKELY(userStringIsEmpty(user->password)))
    {
        rwlockReadUnlock(&user->lock);
        return false;
    }
    if (calcHashBytes(password, stringLength(password)) != user->hash_pass)
    {
        rwlockReadUnlock(&user->lock);
        return false;
    }

    result = stringLength(user->password) == stringLength(password) &&
             wCryptoEqual(user->password, password, stringLength(password));

#if defined(WCRYPTO_BACKEND_OPENSSL) || defined(WCRYPTO_BACKEND_SODIUM)
    if (user->sha256_pass_valid && user->sha512_pass_valid &&
        wCryptoSHA256(&sha256, (const unsigned char *) password, stringLength(password)) == 0 &&
        wCryptoSHA512(&sha512, (const unsigned char *) password, stringLength(password)) == 0)
    {
        result = wCryptoEqual(&sha256, &user->sha256_pass, sizeof(sha256)) &&
                 wCryptoEqual(&sha512, &user->sha512_pass, sizeof(sha512));
    }
#endif

    rwlockReadUnlock(&user->lock);
    wCryptoZero(&sha256, sizeof(sha256));
    wCryptoZero(&sha512, sizeof(sha512));
    return result;
}

bool userPasswordDataValid(User *user)
{
    sha256_hash_t sha256 = {0};
    sha512_hash_t sha512 = {0};
    bool          result = false;

    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return false;
    }

    rwlockReadLock(&user->lock);
    if (! userStringIsEmpty(user->password) &&
        calcHashBytes(user->password, stringLength(user->password)) == user->hash_pass)
    {
        result = true;

#if defined(WCRYPTO_BACKEND_OPENSSL) || defined(WCRYPTO_BACKEND_SODIUM)
        if (user->sha256_pass_valid && user->sha512_pass_valid &&
            wCryptoSHA256(&sha256, (const unsigned char *) user->password, stringLength(user->password)) == 0 &&
            wCryptoSHA512(&sha512, (const unsigned char *) user->password, stringLength(user->password)) == 0)
        {
            result = wCryptoEqual(&sha256, &user->sha256_pass, sizeof(sha256)) &&
                     wCryptoEqual(&sha512, &user->sha512_pass, sizeof(sha512));
        }
#endif
    }
    rwlockReadUnlock(&user->lock);

    wCryptoZero(&sha256, sizeof(sha256));
    wCryptoZero(&sha512, sizeof(sha512));
    return result;
}

void userSetEnabled(User *user, bool enabled)
{
    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return;
    }

    rwlockWriteLock(&user->lock);
    user->enabled = enabled;
    rwlockWriteUnlock(&user->lock);
}

bool userIsEnabled(User *user)
{
    bool enabled = false;

    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return false;
    }

    rwlockReadLock(&user->lock);
    enabled = user->enabled;
    rwlockReadUnlock(&user->lock);
    return enabled;
}

bool userIsDisabled(User *user)
{
    return ! userIsEnabled(user);
}

bool userIsExpired(User *user, uint64_t now_ms)
{
    bool expired = false;

    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return true;
    }

    rwlockReadLock(&user->lock);
    expired = userLimitReached(user->timeinfo.expire_at_ms, now_ms);
    if (! expired && user->timeinfo.expire_after_first_usage_ms != USER_NO_EXPIRY &&
        user->timeinfo.first_usage_at_ms != 0)
    {
        expired =
            now_ms >= userSaturatingAdd(user->timeinfo.first_usage_at_ms, user->timeinfo.expire_after_first_usage_ms);
    }
    rwlockReadUnlock(&user->lock);
    return expired;
}

bool userIsActive(User *user, uint64_t now_ms)
{
    return userIsEnabled(user) && ! userIsExpired(user, now_ms) && ! userHasReachedLimit(user);
}

bool userIsTrafficLimited(User *user)
{
    bool limited = false;

    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return false;
    }

    rwlockReadLock(&user->lock);
    limited = user->limit.traffic.u != USER_NO_LIMIT || user->limit.traffic.d != USER_NO_LIMIT ||
              user->limit.traffic.total != USER_NO_LIMIT;
    rwlockReadUnlock(&user->lock);
    return limited;
}

bool userHasReachedTrafficLimit(User *user)
{
    bool reached = false;

    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return true;
    }

    rwlockReadLock(&user->lock);
    rwlockReadLock(&user->stats_lock);
    reached =
        userLimitReached(user->limit.traffic.u, user->stats.traffic.u) ||
        userLimitReached(user->limit.traffic.d, user->stats.traffic.d) ||
        userLimitReached(user->limit.traffic.total, userSaturatingAdd(user->stats.traffic.u, user->stats.traffic.d));
    rwlockReadUnlock(&user->stats_lock);
    rwlockReadUnlock(&user->lock);
    return reached;
}

bool userHasReachedBandwidthLimit(User *user)
{
    bool reached = false;

    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return true;
    }

    rwlockReadLock(&user->lock);
    rwlockReadLock(&user->stats_lock);
    reached = userLimitReached(user->limit.bandwidth.u, user->stats.speed.u) ||
              userLimitReached(user->limit.bandwidth.d, user->stats.speed.d);
    rwlockReadUnlock(&user->stats_lock);
    rwlockReadUnlock(&user->lock);
    return reached;
}

bool userHasReachedLimit(User *user)
{
    bool reached = false;

    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return true;
    }

    rwlockReadLock(&user->lock);
    rwlockReadLock(&user->stats_lock);
    reached =
        userLimitReached(user->limit.ips, user->stats.ips) ||
        userLimitReached(user->limit.devices, user->stats.devices) ||
        userLimitReached(user->limit.cons_in, user->stats.cons_in) ||
        userLimitReached(user->limit.cons_out, user->stats.cons_out) ||
        userLimitReached(user->limit.traffic.u, user->stats.traffic.u) ||
        userLimitReached(user->limit.traffic.d, user->stats.traffic.d) ||
        userLimitReached(user->limit.traffic.total, userSaturatingAdd(user->stats.traffic.u, user->stats.traffic.d)) ||
        userLimitReached(user->limit.bandwidth.u, user->stats.speed.u) ||
        userLimitReached(user->limit.bandwidth.d, user->stats.speed.d);
    rwlockReadUnlock(&user->stats_lock);
    rwlockReadUnlock(&user->lock);
    return reached;
}

void userMarkFirstUsage(User *user, uint64_t now_ms)
{
    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return;
    }

    rwlockWriteLock(&user->lock);
    if (user->timeinfo.first_usage_at_ms == 0)
    {
        user->timeinfo.first_usage_at_ms = now_ms;
    }
    rwlockWriteUnlock(&user->lock);
}

void userAddTraffic(User *user, uint64_t upload_bytes, uint64_t download_bytes)
{
    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return;
    }

    rwlockWriteLock(&user->stats_lock);
    user->stats.traffic.u = userSaturatingAdd(user->stats.traffic.u, upload_bytes);
    user->stats.traffic.d = userSaturatingAdd(user->stats.traffic.d, download_bytes);
    rwlockWriteUnlock(&user->stats_lock);
}

void userAddSpeed(User *user, uint64_t upload_bytes_per_sec, uint64_t download_bytes_per_sec)
{
    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return;
    }

    rwlockWriteLock(&user->stats_lock);
    user->stats.speed.u = upload_bytes_per_sec;
    user->stats.speed.d = download_bytes_per_sec;
    rwlockWriteUnlock(&user->stats_lock);
}

void userAddConnection(User *user, bool inbound)
{
    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return;
    }

    rwlockWriteLock(&user->stats_lock);
    if (inbound)
    {
        user->stats.cons_in = userSaturatingAdd(user->stats.cons_in, 1);
    }
    else
    {
        user->stats.cons_out = userSaturatingAdd(user->stats.cons_out, 1);
    }
    rwlockWriteUnlock(&user->stats_lock);
}

void userRemoveConnection(User *user, bool inbound)
{
    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return;
    }

    rwlockWriteLock(&user->stats_lock);
    if (inbound)
    {
        user->stats.cons_in = userSaturatingSub(user->stats.cons_in, 1);
    }
    else
    {
        user->stats.cons_out = userSaturatingSub(user->stats.cons_out, 1);
    }
    rwlockWriteUnlock(&user->stats_lock);
}

void userSetIpCount(User *user, uint64_t ips)
{
    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return;
    }

    rwlockWriteLock(&user->stats_lock);
    user->stats.ips = ips;
    rwlockWriteUnlock(&user->stats_lock);
}

void userSetDeviceCount(User *user, uint64_t devices)
{
    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return;
    }

    rwlockWriteLock(&user->stats_lock);
    user->stats.devices = devices;
    rwlockWriteUnlock(&user->stats_lock);
}

void userGetStats(User *user, user_stat_t *stats)
{
    if (UNLIKELY(! userObjectIsInitialized(user) || stats == NULL))
    {
        return;
    }

    rwlockReadLock(&user->stats_lock);
    *stats = user->stats;
    rwlockReadUnlock(&user->stats_lock);
}

user_stat_t userStatsDiff(User *base, User *current)
{
    user_stat_t base_stats    = {0};
    user_stat_t current_stats = {0};
    user_stat_t diff          = {0};

    if (UNLIKELY(! userObjectIsInitialized(base) || ! userObjectIsInitialized(current)))
    {
        return diff;
    }

    userGetStats(base, &base_stats);
    userGetStats(current, &current_stats);

    diff.ips       = userSaturatingSub(current_stats.ips, base_stats.ips);
    diff.devices   = userSaturatingSub(current_stats.devices, base_stats.devices);
    diff.cons_in   = userSaturatingSub(current_stats.cons_in, base_stats.cons_in);
    diff.cons_out  = userSaturatingSub(current_stats.cons_out, base_stats.cons_out);
    diff.speed.u   = userSaturatingSub(current_stats.speed.u, base_stats.speed.u);
    diff.speed.d   = userSaturatingSub(current_stats.speed.d, base_stats.speed.d);
    diff.traffic.u = userSaturatingSub(current_stats.traffic.u, base_stats.traffic.u);
    diff.traffic.d = userSaturatingSub(current_stats.traffic.d, base_stats.traffic.d);

    return diff;
}
