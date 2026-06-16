#pragma once
#ifndef WW_OBJECTS_USERS_H
#define WW_OBJECTS_USERS_H

/*
 * User database manager.
 *
 * Ownership:
 * - users_t owns every user_t it returns.
 * - Returned user_t pointers point into users_t-owned storage and remain valid
 *   until that specific user is removed, usersClear(), or usersDestroy().
 *   Other users keep stable object addresses across add/remove operations, but
 *   index ordering may change after removal.
 * - Removed user pointers become invalid immediately. Removed storage is not
 *   reused until usersClear()/usersDestroy(), so stale pointers do not silently
 *   become another active user during normal removal.
 * - usersAddUser() copies the supplied user into users_t-owned storage.
 *
 * Thread safety:
 * - Public functions acquire the database lock internally.
 * - Lookup/export/count helpers take the database read lock.
 * - Modification helpers take the database write lock, or the read lock plus
 *   the target user's own lock for counter-only updates.
 * - Lookup/get helpers do not pin the returned user after they release the
 *   database lock. If other threads may remove users concurrently, callers must
 *   serialize that lifetime externally or perform the full operation through a
 *   users_t helper.
 * - Destroy must be called only after other threads have stopped using the database.
 * - No public function requires the caller to already hold users_t.lock.
 *
 * Fatal behavior:
 * - The legacy usersAddUser()/usersFeedJson() insertion path terminates on a
 *   duplicate SHA-256 lookup key, which protects startup database consistency.
 * - usersAddUserChecked()/usersAddUserFromJsonChecked() report duplicate keys
 *   to the caller instead, for runtime request handling.
 * - Calling generic-hash lookup after collision disabled that lookup terminates
 *   the program.
 *
 * API safety:
 * - The struct is visible so users_t can live on the stack or inside other
 *   objects, but its fields are implementation details. Do not read or write
 *   blocks, count, capacity, lookup tables, flags, or locks directly. Use the
 *   helper functions below so locking and lookup-table consistency are kept.
 * - If a user is owned by users_t, change its password with
 *   usersChangePassword(), not userChangePassword(), because password hashes are
 *   lookup keys in this database.
 */

#include "wlibc.h"

#include "objects/user.h"

typedef struct users_hash_table_s   users_hash_table_t;
typedef struct users_sha256_table_s users_sha256_table_t;

typedef struct user_update_s
{
    uint32_t mask;

    const char *password;
    const char *name;
    const char *email;
    const char *notes;

    hash_t gid;
    bool   enabled;

    user_limit_t     limit;
    user_time_info_t timeinfo;
    user_stat_t      stats;
    int              record_stat_interval_ms;
} user_update_t;

typedef enum users_add_result_e
{
    kUsersAddResultOk = 0,
    kUsersAddResultInvalidArgument,
    kUsersAddResultInvalidJson,
    kUsersAddResultInvalidUser,
    kUsersAddResultDuplicateName,
    kUsersAddResultDuplicateSHA256,
    kUsersAddResultHashConflict,
    kUsersAddResultAllocationFailed,
    kUsersAddResultCommitFailed
} users_add_result_t;

typedef enum users_update_result_e
{
    kUsersUpdateResultOk = 0,
    kUsersUpdateResultInvalidArgument,
    kUsersUpdateResultUnknownFields,
    kUsersUpdateResultInvalidRecordStatInterval,
    kUsersUpdateResultAllocationFailed,
    kUsersUpdateResultUserNotFound,
    kUsersUpdateResultDuplicateName,
    kUsersUpdateResultPasswordUpdateFailed
} users_update_result_t;

enum
{
    kUserUpdatePassword           = 1U << 0U,
    kUserUpdateName               = 1U << 1U,
    kUserUpdateEmail              = 1U << 2U,
    kUserUpdateNotes              = 1U << 3U,
    kUserUpdateGid                = 1U << 4U,
    kUserUpdateEnabled            = 1U << 5U,
    kUserUpdateLimit              = 1U << 6U,
    kUserUpdateTimeInfo           = 1U << 7U,
    kUserUpdateStats              = 1U << 8U,
    kUserUpdateRecordStatInterval = 1U << 9U
};

typedef struct users_s
{
    /* Internal fields. Callers must not access or mutate them directly. */
    wrwlock_t lock;

    user_t **blocks;
    user_t **items;
    size_t   count;
    size_t   capacity;
    size_t   slot_count;
    size_t   slot_capacity;
    size_t   block_count;
    size_t   block_capacity;

    users_hash_table_t   *generic_hash_table;
    users_sha256_table_t *sha256_table;

    bool generic_hash_lookup_available;
    bool generic_hash_collision_seen;
} users_t;

bool usersCreate(users_t *users);
void usersDestroy(users_t *users);

bool               usersAddUser(users_t *users, const user_t *user);
users_add_result_t usersAddUserChecked(users_t *users, const user_t *user);
bool               usersAddUserFromJson(users_t *users, const cJSON *json);
users_add_result_t usersAddUserFromJsonChecked(users_t *users, const cJSON *json);
bool               usersFeedJson(users_t *users, const cJSON *json);
cJSON             *usersToJson(const users_t *users);
bool               usersClear(users_t *users);

bool usersGenericHashLookupAvailable(const users_t *users);

user_t       *usersLookupByHash(users_t *users, hash_t hash);
const user_t *usersLookupByHashConst(const users_t *users, hash_t hash);

user_t       *usersLookupBySHA256(users_t *users, const uint8_t sha256[SHA256_DIGEST_SIZE]);
const user_t *usersLookupBySHA256Const(const users_t *users, const uint8_t sha256[SHA256_DIGEST_SIZE]);
cJSON        *usersUserToJsonBySHA256(const users_t *users, const uint8_t sha256[SHA256_DIGEST_SIZE]);
cJSON        *usersUserToJsonByPassword(const users_t *users, const char *password);

/*
 * Looks up by plaintext password. The helper tries generic hash lookup when it
 * is available, falls back to SHA-256 lookup, and verifies candidates with
 * userPasswordMatches(). It does not terminate merely because generic lookup
 * was disabled by a collision.
 */
user_t       *usersLookupByPassword(users_t *users, const char *password);
const user_t *usersLookupByPasswordConst(const users_t *users, const char *password);

bool usersRemoveUser(users_t *users, user_t *user);
bool usersRemoveUserBySHA256(users_t *users, const uint8_t sha256[SHA256_DIGEST_SIZE]);
bool usersRemoveUserByHash(users_t *users, hash_t hash);

bool                  usersChangePassword(users_t *users, user_t *user, const char *password);
bool                  usersUpdateUser(users_t *users, user_t *user, const user_update_t *update);
users_update_result_t usersUpdateUserBySHA256(users_t *users, const uint8_t sha256[SHA256_DIGEST_SIZE],
                                              const user_update_t *update);
bool                  usersSetUserName(users_t *users, user_t *user, const char *name);
bool                  usersSetUserEmail(users_t *users, user_t *user, const char *email);
bool                  usersSetUserNotes(users_t *users, user_t *user, const char *notes);
bool                  usersSetUserGid(users_t *users, user_t *user, hash_t gid);
bool                  usersSetUserEnabled(users_t *users, user_t *user, bool enabled);
bool                  usersSetUserLimit(users_t *users, user_t *user, const user_limit_t *limit);
bool                  usersSetUserTimeInfo(users_t *users, user_t *user, const user_time_info_t *timeinfo);
bool                  usersSetUserStats(users_t *users, user_t *user, const user_stat_t *stats);
bool                  usersSetUserRecordStatInterval(users_t *users, user_t *user, int interval_ms);
bool                  usersAddTraffic(users_t *users, user_t *user, uint64_t upload_bytes, uint64_t download_bytes);
users_update_result_t usersAddTrafficBySHA256(users_t *users, const uint8_t sha256[SHA256_DIGEST_SIZE],
                                              uint64_t upload_bytes, uint64_t download_bytes);
/*
 * Moves process-local runtime enforcement state from matching users in src to
 * dest, keyed by SHA-256.
 */
bool                  usersMigrateRuntimeStateBySHA256(users_t *dest, users_t *src);
users_update_result_t usersSetFirstUsageIfMissingBySHA256(users_t *users,
                                                          const uint8_t sha256[SHA256_DIGEST_SIZE],
                                                          uint64_t first_usage_at_ms,
                                                          bool    *changed);
bool                  usersAddUserUsage(users_t *users, user_t *user, uint64_t upload_bytes, uint64_t download_bytes);

/*
 * Live connection-admission helpers keyed by SHA-256 password digest. They take
 * the database read lock, locate the user, and run the matching user_t runtime
 * helper. They operate on the process-local runtime state, not the synced stats.
 */
user_admission_result_t usersTryAdmitConnectionBySHA256(users_t *users, const uint8_t sha256[SHA256_DIGEST_SIZE],
                                                        const user_ip_key_t *ip_key, uint64_t now_ms);
void usersReleaseConnectionBySHA256(users_t *users, const uint8_t sha256[SHA256_DIGEST_SIZE],
                                    const user_ip_key_t *ip_key);
/* Adds traffic and returns whether the user must now be cut off; *found reports if the user existed. */
bool usersAccountTrafficBySHA256(users_t *users, const uint8_t sha256[SHA256_DIGEST_SIZE], uint64_t upload_bytes,
                                 uint64_t download_bytes, uint64_t now_ms, bool *found,
                                 bool *first_usage_push_needed);
void usersResetFirstUsagePushRequests(users_t *users);
void usersResetFirstUsagePushRequestBySHA256(users_t *users, const uint8_t sha256[SHA256_DIGEST_SIZE]);
/* True when the user no longer exists or may no longer carry traffic. */
bool usersRuntimeShouldCloseBySHA256(users_t *users, const uint8_t sha256[SHA256_DIGEST_SIZE], uint64_t now_ms);
bool usersAddSpeed(users_t *users, user_t *user, uint64_t upload_bytes_per_sec, uint64_t download_bytes_per_sec);
bool usersAddConnection(users_t *users, user_t *user, bool inbound);
bool usersRemoveConnection(users_t *users, user_t *user, bool inbound);
bool usersSetIpCount(users_t *users, user_t *user, uint64_t ips);
bool usersSetDeviceCount(users_t *users, user_t *user, uint64_t devices);
bool usersMarkFirstUsage(users_t *users, user_t *user, uint64_t now_ms);
bool usersResetUsage(users_t *users, user_t *user);
bool usersResetUserUsage(users_t *users, user_t *user);
bool usersResetStats(users_t *users, user_t *user);
bool usersUserLimitReached(users_t *users, const user_t *user);
bool usersUserEnabled(users_t *users, const user_t *user);
bool usersUserDisabled(users_t *users, const user_t *user);
bool usersUserExpired(users_t *users, const user_t *user, uint64_t now_ms);
bool usersUserActive(users_t *users, const user_t *user, uint64_t now_ms);

size_t        usersCount(const users_t *users);
bool          usersIsEmpty(const users_t *users);
bool          usersReserve(users_t *users, size_t capacity);
user_t       *usersGetAt(users_t *users, size_t index);
const user_t *usersGetAtConst(const users_t *users, size_t index);
bool          usersContainsUser(const users_t *users, const user_t *user);

bool usersRebuildLookups(users_t *users);
bool usersValidate(const users_t *users);

user_t       *usersFindFirstExpired(users_t *users, uint64_t now_ms);
const user_t *usersFindFirstExpiredConst(const users_t *users, uint64_t now_ms);
user_t       *usersFindFirstDisabled(users_t *users);
const user_t *usersFindFirstDisabledConst(const users_t *users);
user_t       *usersFindFirstLimited(users_t *users);
const user_t *usersFindFirstLimitedConst(const users_t *users);

user_stat_t usersUsageDiff(users_t *users, user_t *base, user_t *current);

#endif // WW_OBJECTS_USERS_H
