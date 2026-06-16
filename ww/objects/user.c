/*
 * User object lifecycle, JSON persistence, and usage accounting helpers.
 */

#include "objects/user.h"

#include "utils/json_helpers.h"

#include <stddef.h>

_Static_assert(offsetof(user_t, sha224_pass) % 32U == 0, "user_t.sha224_pass must be 32-byte aligned");
_Static_assert(offsetof(user_t, sha256_pass) % 32U == 0, "user_t.sha256_pass must be 32-byte aligned");
_Static_assert(_Alignof(user_t) >= 32U, "user_t storage must be at least 32-byte aligned");
_Static_assert(sizeof(user_t) % 32U == 0, "user_t storage size must be a 32-byte multiple");

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

    uint64_t id;
    hash_t gid;
    bool   enabled;

    user_limit_t     limit;
    user_time_info_t timeinfo;
    int              record_stat_interval_ms;

    user_stat_t stats;

    hash_t        hash_pass;
    uint8_t       sha_alignment_padding[8];
    MSVC_ATTR_ALIGNED_32 sha224_hash_t sha224_pass GNU_ATTR_ALIGNED_32;
    uint8_t       sha224_pass_padding[SHA256_DIGEST_SIZE - SHA224_DIGEST_SIZE];
    MSVC_ATTR_ALIGNED_32 sha256_hash_t sha256_pass GNU_ATTR_ALIGNED_32;

    bool sha224_pass_valid;
    bool sha256_pass_valid;
} user_snapshot_t;

_Static_assert(offsetof(user_snapshot_t, sha224_pass) % 32U == 0,
               "user_snapshot_t.sha224_pass must be 32-byte aligned");
_Static_assert(offsetof(user_snapshot_t, sha256_pass) % 32U == 0,
               "user_snapshot_t.sha256_pass must be 32-byte aligned");
_Static_assert(_Alignof(user_snapshot_t) >= 32U, "user_snapshot_t storage must be at least 32-byte aligned");
_Static_assert(sizeof(user_snapshot_t) % 32U == 0, "user_snapshot_t storage size must be a 32-byte multiple");

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

    snapshot->id                      = src->id;
    snapshot->gid                     = src->gid;
    snapshot->enabled                 = src->enabled;
    snapshot->limit                   = src->limit;
    snapshot->timeinfo                = src->timeinfo;
    snapshot->record_stat_interval_ms = src->record_stat_interval_ms;
    snapshot->stats                   = src->stats;
    snapshot->hash_pass               = src->hash_pass;
    snapshot->sha224_pass             = src->sha224_pass;
    snapshot->sha256_pass             = src->sha256_pass;
    snapshot->sha224_pass_valid       = src->sha224_pass_valid;
    snapshot->sha256_pass_valid       = src->sha256_pass_valid;

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

    memoryZero(&user->sha224_pass, sizeof(user->sha224_pass));
    memoryZero(&user->sha256_pass, sizeof(user->sha256_pass));

    if (UNLIKELY(wCryptoSHA224(&user->sha224_pass, (const unsigned char *) password, password_len) != 0))
    {
        return false;
    }
    user->sha224_pass_valid = true;

    if (UNLIKELY(wCryptoSHA256(&user->sha256_pass, (const unsigned char *) password, password_len) != 0))
    {
        return false;
    }
    user->sha256_pass_valid = true;

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

/* Expiry computation. Caller must hold at least a read lock on user->lock. */
static bool userExpiredLocked(const User *user, uint64_t now_ms)
{
    if (user->client_view_expiry_valid)
    {
        return user->client_view_expires_at_ms != 0 && now_ms >= user->client_view_expires_at_ms;
    }

    bool expired = userLimitReached(user->timeinfo.expire_at_ms, now_ms);
    if (! expired && user->timeinfo.expire_after_first_usage_ms != USER_NO_EXPIRY &&
        user->timeinfo.first_usage_at_ms != 0)
    {
        expired =
            now_ms >= userSaturatingAdd(user->timeinfo.first_usage_at_ms, user->timeinfo.expire_after_first_usage_ms);
    }
    return expired;
}

/* Traffic-quota computation. Caller must hold read locks on user->lock and user->stats_lock. */
static bool userTrafficReachedLocked(const User *user)
{
    return userLimitReached(user->limit.traffic.u, user->stats.traffic.u) ||
           userLimitReached(user->limit.traffic.d, user->stats.traffic.d) ||
           userLimitReached(user->limit.traffic.total,
                            userSaturatingAdd(user->stats.traffic.u, user->stats.traffic.d));
}

static bool userIpKeyValid(const user_ip_key_t *ip_key)
{
    return ip_key != NULL && ip_key->type != 0;
}

static bool userIpKeyEqual(const user_ip_key_t *a, const user_ip_key_t *b)
{
    return a->type == b->type && memoryCompare(a->bytes, b->bytes, sizeof(a->bytes)) == 0;
}

/* Returns the index of ip_key in the runtime tracker, or runtime->ip_usage_count when absent. */
static size_t userRuntimeFindIpLocked(const user_runtime_stat_t *runtime, const user_ip_key_t *ip_key)
{
    for (size_t i = 0; i < runtime->ip_usage_count; ++i)
    {
        if (userIpKeyEqual(&runtime->ip_usages[i].key, ip_key))
        {
            return i;
        }
    }
    return runtime->ip_usage_count;
}

/* Ensures room for at least one more IP usage entry. Caller holds user->stats_lock. */
static bool userRuntimeReserveIpLocked(user_runtime_stat_t *runtime)
{
    if (runtime->ip_usage_count < runtime->ip_usage_capacity)
    {
        return true;
    }

    size_t           new_capacity = runtime->ip_usage_capacity == 0 ? 4 : runtime->ip_usage_capacity * 2;
    user_ip_usage_t *grown        = memoryReAllocate(runtime->ip_usages, new_capacity * sizeof(*grown));
    if (UNLIKELY(grown == NULL))
    {
        return false;
    }

    runtime->ip_usages         = grown;
    runtime->ip_usage_capacity = new_capacity;
    return true;
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

    dest->id                      = snapshot.id;
    dest->gid                     = snapshot.gid;
    dest->enabled                 = snapshot.enabled;
    dest->limit                   = snapshot.limit;
    dest->timeinfo                = snapshot.timeinfo;
    dest->record_stat_interval_ms = snapshot.record_stat_interval_ms;
    dest->stats                   = snapshot.stats;
    dest->hash_pass               = snapshot.hash_pass;
    dest->sha224_pass             = snapshot.sha224_pass;
    dest->sha256_pass             = snapshot.sha256_pass;
    dest->sha224_pass_valid       = snapshot.sha224_pass_valid;
    dest->sha256_pass_valid       = snapshot.sha256_pass_valid;

    snapshot.name     = NULL;
    snapshot.password = NULL;
    snapshot.email    = NULL;
    snapshot.notes    = NULL;
    memoryZero(&snapshot.sha224_pass, sizeof(snapshot.sha224_pass));
    memoryZero(&snapshot.sha256_pass, sizeof(snapshot.sha256_pass));
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
    if (user->runtime.ip_usages != NULL)
    {
        memoryFree(user->runtime.ip_usages);
    }
    memoryZero(&user->runtime, sizeof(user->runtime));
    wCryptoZero(&user->sha224_pass, sizeof(user->sha224_pass));
    wCryptoZero(&user->sha256_pass, sizeof(user->sha256_pass));
    memoryZero(&user->limit, sizeof(user->limit));
    memoryZero(&user->timeinfo, sizeof(user->timeinfo));
    memoryZero(&user->stats, sizeof(user->stats));
    user->id        = 0;
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
        return false;
    }

    copy = stringDuplicate(password);
    if (UNLIKELY(copy == NULL))
    {
        wCryptoZero(&staged_hashes.sha224_pass, sizeof(staged_hashes.sha224_pass));
        wCryptoZero(&staged_hashes.sha256_pass, sizeof(staged_hashes.sha256_pass));
        return false;
    }

    rwlockWriteLock(&user->lock);

    wCryptoZero(&user->sha224_pass, sizeof(user->sha224_pass));
    wCryptoZero(&user->sha256_pass, sizeof(user->sha256_pass));
    user->hash_pass         = staged_hashes.hash_pass;
    user->sha224_pass       = staged_hashes.sha224_pass;
    user->sha256_pass       = staged_hashes.sha256_pass;
    user->sha224_pass_valid = staged_hashes.sha224_pass_valid;
    user->sha256_pass_valid = staged_hashes.sha256_pass_valid;

    userFreePassword(user->password);
    user->password = copy;
    rwlockWriteUnlock(&user->lock);
    wCryptoZero(&staged_hashes.sha224_pass, sizeof(staged_hashes.sha224_pass));
    wCryptoZero(&staged_hashes.sha256_pass, sizeof(staged_hashes.sha256_pass));
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
                 ! userJsonReadOptionalUint64Aliased(user_json, "id", "user-id", &user->id) ||
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
                 (user->id != 0 && ! jsonAddUint64ToObject(json, "id", user->id)) ||
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
    sha224_hash_t sha224 = {0};
    sha256_hash_t sha256 = {0};
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

    if (user->sha224_pass_valid && user->sha256_pass_valid &&
        wCryptoSHA224(&sha224, (const unsigned char *) password, stringLength(password)) == 0 &&
        wCryptoSHA256(&sha256, (const unsigned char *) password, stringLength(password)) == 0)
    {
        result = wCryptoEqual(&sha256, &user->sha256_pass, sizeof(sha256)) &&
                 wCryptoEqual(&sha224, &user->sha224_pass, sizeof(sha224));
    }

    rwlockReadUnlock(&user->lock);
    wCryptoZero(&sha224, sizeof(sha224));
    wCryptoZero(&sha256, sizeof(sha256));
    return result;
}

bool userPasswordDataValid(User *user)
{
    sha224_hash_t sha224 = {0};
    sha256_hash_t sha256 = {0};
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

        if (user->sha224_pass_valid && user->sha256_pass_valid &&
            wCryptoSHA224(&sha224, (const unsigned char *) user->password, stringLength(user->password)) == 0 &&
            wCryptoSHA256(&sha256, (const unsigned char *) user->password, stringLength(user->password)) == 0)
        {
            result = wCryptoEqual(&sha256, &user->sha256_pass, sizeof(sha256)) &&
                     wCryptoEqual(&sha224, &user->sha224_pass, sizeof(sha224));
        }
    }
    rwlockReadUnlock(&user->lock);

    wCryptoZero(&sha224, sizeof(sha224));
    wCryptoZero(&sha256, sizeof(sha256));
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

uint64_t userGetId(User *user)
{
    uint64_t id = 0;

    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return 0;
    }

    rwlockReadLock(&user->lock);
    id = user->id;
    rwlockReadUnlock(&user->lock);
    return id;
}

void userSetId(User *user, uint64_t id)
{
    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return;
    }

    rwlockWriteLock(&user->lock);
    user->id = id;
    rwlockWriteUnlock(&user->lock);
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
    expired = userExpiredLocked(user, now_ms);
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
    reached = userTrafficReachedLocked(user);
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

user_admission_result_t userTryAdmitConnection(User *user, const user_ip_key_t *ip_key, uint64_t now_ms)
{
    user_admission_result_t result = kUserAdmissionOk;

    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return kUserAdmissionInvalid;
    }

    /* Lock order matches userSnapshotCreate(): user->lock then user->stats_lock. */
    rwlockWriteLock(&user->lock);
    rwlockWriteLock(&user->stats_lock);

    if (! user->enabled)
    {
        result = kUserAdmissionDisabled;
    }
    else if (userExpiredLocked(user, now_ms))
    {
        result = kUserAdmissionExpired;
    }
    else if (userTrafficReachedLocked(user))
    {
        result = kUserAdmissionTrafficLimited;
    }
    else if (userLimitReached(user->limit.cons_out, user->runtime.active_cons_out))
    {
        result = kUserAdmissionConnectionLimited;
    }
    else
    {
        user_runtime_stat_t *runtime  = &user->runtime;
        bool                 track_ip = userIpKeyValid(ip_key);
        size_t               ip_index = runtime->ip_usage_count;

        if (track_ip)
        {
            ip_index = userRuntimeFindIpLocked(runtime, ip_key);

            // A previously unseen IP would push the distinct-IP set past the configured limit.
            if (ip_index == runtime->ip_usage_count && userLimitReached(user->limit.ips, runtime->ip_usage_count))
            {
                result = kUserAdmissionIpLimited;
            }
        }

        if (result == kUserAdmissionOk && track_ip)
        {
            if (ip_index < runtime->ip_usage_count)
            {
                runtime->ip_usages[ip_index].refs = userSaturatingAdd(runtime->ip_usages[ip_index].refs, 1);
            }
            else if (userRuntimeReserveIpLocked(runtime))
            {
                runtime->ip_usages[runtime->ip_usage_count].key  = *ip_key;
                runtime->ip_usages[runtime->ip_usage_count].refs = 1;
                runtime->ip_usage_count += 1;
            }
            else
            {
                // Refuse rather than admit a connection we could not account for.
                result = kUserAdmissionInvalid;
            }
        }

        if (result == kUserAdmissionOk)
        {
            runtime->active_cons_out = userSaturatingAdd(runtime->active_cons_out, 1);
        }
    }

    rwlockWriteUnlock(&user->stats_lock);
    rwlockWriteUnlock(&user->lock);
    return result;
}

void userReleaseConnection(User *user, const user_ip_key_t *ip_key)
{
    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return;
    }

    rwlockWriteLock(&user->stats_lock);
    user->runtime.active_cons_out = userSaturatingSub(user->runtime.active_cons_out, 1);

    if (userIpKeyValid(ip_key))
    {
        user_runtime_stat_t *runtime  = &user->runtime;
        size_t               ip_index = userRuntimeFindIpLocked(runtime, ip_key);
        if (ip_index < runtime->ip_usage_count)
        {
            if (runtime->ip_usages[ip_index].refs > 1)
            {
                runtime->ip_usages[ip_index].refs -= 1;
            }
            else
            {
                // Last connection from this IP: drop the slot (swap-with-last keeps the array dense).
                runtime->ip_usages[ip_index] = runtime->ip_usages[runtime->ip_usage_count - 1];
                runtime->ip_usage_count -= 1;
            }
        }
    }
    rwlockWriteUnlock(&user->stats_lock);
}

bool userAccountTraffic(User *user, uint64_t upload_bytes, uint64_t download_bytes, uint64_t now_ms,
                        bool *first_usage_push_needed)
{
    bool should_close = false;

    if (first_usage_push_needed != NULL)
    {
        *first_usage_push_needed = false;
    }

    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return true;
    }

    rwlockReadLock(&user->lock);
    rwlockWriteLock(&user->stats_lock);
    user->stats.traffic.u = userSaturatingAdd(user->stats.traffic.u, upload_bytes);
    user->stats.traffic.d = userSaturatingAdd(user->stats.traffic.d, download_bytes);
    if (first_usage_push_needed != NULL && (upload_bytes != 0 || download_bytes != 0) &&
        user->timeinfo.first_usage_at_ms == 0 && ! user->runtime.first_usage_push_requested)
    {
        user->runtime.first_usage_push_requested = true;
        *first_usage_push_needed                 = true;
    }
    should_close = (! user->enabled) || userExpiredLocked(user, now_ms) || userTrafficReachedLocked(user);
    rwlockWriteUnlock(&user->stats_lock);
    rwlockReadUnlock(&user->lock);
    return should_close;
}

bool userRuntimeShouldClose(User *user, uint64_t now_ms)
{
    bool should_close = false;

    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return true;
    }

    rwlockReadLock(&user->lock);
    rwlockReadLock(&user->stats_lock);
    should_close = (! user->enabled) || userExpiredLocked(user, now_ms) || userTrafficReachedLocked(user);
    rwlockReadUnlock(&user->stats_lock);
    rwlockReadUnlock(&user->lock);
    return should_close;
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

void userSetClientViewExpiry(User *user, uint64_t expires_at_ms, bool valid)
{
    if (UNLIKELY(! userObjectIsInitialized(user)))
    {
        return;
    }

    rwlockWriteLock(&user->lock);
    user->client_view_expires_at_ms = valid ? expires_at_ms : 0;
    user->client_view_expiry_valid  = valid;
    rwlockWriteUnlock(&user->lock);
}

void userGetTimeInfo(User *user, user_time_info_t *timeinfo)
{
    if (UNLIKELY(! userObjectIsInitialized(user) || timeinfo == NULL))
    {
        return;
    }

    rwlockReadLock(&user->lock);
    *timeinfo = user->timeinfo;
    rwlockReadUnlock(&user->lock);
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
