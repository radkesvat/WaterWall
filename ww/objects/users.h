#pragma once
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
 * Collision behavior:
 * - Duplicate durable ids and lookup keys reject the current insertion, update,
 *   load, or validation operation. AuthenticationServer startup treats a failed
 *   database load as a startup failure, while runtime callers can roll back or
 *   report the rejected action without terminating the process.
 * - usersAddUserChecked()/usersAddUserFromJsonChecked() report duplicate keys
 *   with a more specific result code for runtime request handling.
 *
 * API safety:
 * - The struct is visible so users_t can live on the stack or inside other
 *   objects, but its fields are implementation details. Do not read or write
 *   blocks, count, capacity, lookup tables, flags, or locks directly. Use the
 *   helper functions below so locking and lookup-table consistency are kept.
 * - If a user is owned by users_t, change its password with
 *   usersChangePassword(), not userChangePassword(), because the SHA-224 and
 *   SHA-256 password hashes are lookup keys in this database.
 */

#include "wlibc.h"

#include "objects/user.h"

typedef struct users_sha224_table_s users_sha224_table_t;
typedef struct users_sha256_table_s users_sha256_table_t;
typedef struct users_uuid_table_s   users_uuid_table_t;
typedef struct users_wireguard_publickey_table_s users_wireguard_publickey_table_t;
typedef struct users_id_table_s     users_id_table_t;

typedef struct user_update_s
{
    uint32_t mask;

    const char *password;
    const char *name;
    const char *email;
    const char *notes;
    const char *wireguard_allowed_ips;

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
    kUsersAddResultInvalidWireGuardAllowedIps,
    kUsersAddResultDuplicateName,
    kUsersAddResultDuplicateId,
    kUsersAddResultDuplicateSHA224,
    kUsersAddResultDuplicateSHA256,
    kUsersAddResultDuplicateUUID,
    kUsersAddResultDuplicateWireGuardPublicKey,
    kUsersAddResultDuplicateWireGuardAllowedIps,
    kUsersAddResultAllocationFailed,
    kUsersAddResultCommitFailed
} users_add_result_t;

typedef enum users_update_result_e
{
    kUsersUpdateResultOk = 0,
    kUsersUpdateResultInvalidArgument,
    kUsersUpdateResultUnknownFields,
    kUsersUpdateResultInvalidRecordStatInterval,
    kUsersUpdateResultInvalidWireGuardAllowedIps,
    kUsersUpdateResultAllocationFailed,
    kUsersUpdateResultUserNotFound,
    kUsersUpdateResultDuplicateName,
    kUsersUpdateResultDuplicateUUID,
    kUsersUpdateResultDuplicateWireGuardPublicKey,
    kUsersUpdateResultDuplicateWireGuardAllowedIps,
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
    kUserUpdateRecordStatInterval = 1U << 9U,
    kUserUpdateWireGuardAllowedIps = 1U << 10U
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

    users_sha224_table_t *sha224_table;
    users_sha256_table_t *sha256_table;
    users_uuid_table_t   *uuid_table;
    users_wireguard_publickey_table_t *wireguard_publickey_table;
    users_id_table_t     *id_table;
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

user_t       *usersLookupBySHA224(users_t *users, const uint8_t sha224[SHA224_DIGEST_SIZE]);
const user_t *usersLookupBySHA224Const(const users_t *users, const uint8_t sha224[SHA224_DIGEST_SIZE]);
user_t       *usersLookupBySHA256(users_t *users, const uint8_t sha256[SHA256_DIGEST_SIZE]);
const user_t *usersLookupBySHA256Const(const users_t *users, const uint8_t sha256[SHA256_DIGEST_SIZE]);
user_t       *usersLookupByUUID(users_t *users, const uint8_t uuid[kWwUuidBytesLen]);
const user_t *usersLookupByUUIDConst(const users_t *users, const uint8_t uuid[kWwUuidBytesLen]);
user_t       *usersLookupByWireGuardPublicKey(users_t *users,
                                              const uint8_t publickey[USER_WIREGUARD_PUBLICKEY_SIZE]);
const user_t *usersLookupByWireGuardPublicKeyConst(const users_t *users,
                                                   const uint8_t publickey[USER_WIREGUARD_PUBLICKEY_SIZE]);
user_t       *usersLookupByWireGuardAllowedIp(users_t *users, const ip_addr_t *ip);
const user_t *usersLookupByWireGuardAllowedIpConst(const users_t *users, const ip_addr_t *ip);
user_t       *usersLookupByIdentifier(users_t *users, uint64_t id);
const user_t *usersLookupByIdentifierConst(const users_t *users, uint64_t id);
cJSON        *usersUserToJsonBySHA224(const users_t *users, const uint8_t sha224[SHA224_DIGEST_SIZE]);
cJSON        *usersUserToJsonBySHA256(const users_t *users, const uint8_t sha256[SHA256_DIGEST_SIZE]);
cJSON        *usersUserToJsonByIdentifier(const users_t *users, uint64_t id);
cJSON        *usersUserToJsonByPassword(const users_t *users, const char *password);

/*
 * Looks up by plaintext password through the SHA-256 lookup table and verifies
 * candidates with userPasswordMatches().
 */
user_t       *usersLookupByPassword(users_t *users, const char *password);
const user_t *usersLookupByPasswordConst(const users_t *users, const char *password);

bool usersRemoveUser(users_t *users, user_t *user);
bool usersRemoveUserBySHA256(users_t *users, const uint8_t sha256[SHA256_DIGEST_SIZE]);
bool usersRemoveUserByIdentifier(users_t *users, uint64_t id);

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
users_update_result_t usersAddTrafficByIdentifier(users_t *users, uint64_t id, uint64_t upload_bytes,
                                                  uint64_t download_bytes);
/*
 * Moves process-local runtime enforcement state from matching users in src to
 * dest, keyed by durable id.
 */
bool usersMigrateRuntimeStateByIdentifier(users_t *dest, users_t *src);
users_update_result_t usersSetFirstUsageIfMissingBySHA256(users_t *users,
                                                          const uint8_t sha256[SHA256_DIGEST_SIZE],
                                                          uint64_t first_usage_at_ms,
                                                          bool    *changed);
users_update_result_t usersSetFirstUsageIfMissingByIdentifier(users_t *users,
                                                              uint64_t id,
                                                              uint64_t first_usage_at_ms,
                                                              bool    *changed);
bool                  usersAddUserUsage(users_t *users, user_t *user, uint64_t upload_bytes, uint64_t download_bytes);

/*
 * Live connection-admission helpers keyed by durable user id. They take the
 * database read lock, locate the user, and run the matching user_t runtime
 * helper. They operate on the process-local runtime state, not the synced stats.
 */
user_admission_result_t usersTryAdmitConnectionByIdentifier(users_t *users, uint64_t id,
                                                            const user_ip_key_t *ip_key, uint64_t now_ms);
void usersReleaseConnectionByIdentifier(users_t *users, uint64_t id, const user_ip_key_t *ip_key);
/* Adds traffic and returns whether the user must now be cut off; *found reports if the user existed. */
bool usersAccountTrafficByIdentifier(users_t *users, uint64_t id, uint64_t upload_bytes, uint64_t download_bytes,
                                     uint64_t now_ms, bool *found, bool *first_usage_push_needed);
void usersResetFirstUsagePushRequests(users_t *users);
void usersResetFirstUsagePushRequestByIdentifier(users_t *users, uint64_t id);
/* True when the user no longer exists or may no longer carry traffic. */
bool usersRuntimeShouldCloseByIdentifier(users_t *users, uint64_t id, uint64_t now_ms);
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
