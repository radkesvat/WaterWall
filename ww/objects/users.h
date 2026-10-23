#pragma once
/*
 * User database manager.
 *
 * Ownership:
 * - users_t owns every user_t it returns.
 * - Returned user_t pointers point into users_t-owned storage and remain valid
 *   until that specific user is removed, usersClear(), usersDestroy(), or a
 *   successful non-self usersCopy() or usersPublishCandidate() replaces this
 *   destination. Replacement invalidates
 *   every old destination user/string pointer; failure preserves the destination.
 *   Other users keep stable object addresses across add/remove operations, but
 *   index ordering may change after removal.
 * - Removed user pointers become invalid immediately. Removed storage is not
 *   reused until usersClear()/usersDestroy(), so stale pointers do not silently
 *   become another active user during normal removal. The explicitly unpublished
 *   last-addition rollback helper is the sole exception and requires continuous
 *   external exclusive ownership with no pointer publication.
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
 *   Mutating an indexed field directly (id, name, password-derived keys, or
 *   Allowed-IP range) desynchronizes the lookup indexes; usersValidate() is
 *   designed to detect exactly that kind of corruption.
 * - If a user is owned by users_t, change its password with
 *   usersChangePassword(), not userChangePassword(), because the SHA-224 and
 *   SHA-256 password hashes are lookup keys in this database.
 *
 * Lookup indexes and complexity:
 * - Keyed lookups (SHA-224, SHA-256, plaintext password, UUID, WireGuard public
 *   key, durable id, and non-empty name) are average O(1) hash-map lookups.
 * - WireGuard Allowed-IP address lookup and range-overlap detection use an
 *   ordered interval index and are O(log M) in the number of configured ranges.
 * - Add, load, password change, name change, Allowed-IP change, and removal
 *   update the affected indexes incrementally; they do not rebuild every index.
 * - Full validation is O(N) (plus O(N log M) for Allowed-IP overlap checks); it
 *   performs no pairwise user comparison.
 * - Predicate scans (usersFindFirstExpired/Disabled/Limited), JSON export,
 *   clear/destroy, and native copy inspect every user and remain O(N) by design.
 *
 * Removal ordering and failure atomicity:
 * - Removal erases the victim's index entries, then swaps the last active user
 *   into the freed slot, so items[] ordering may change but every remaining
 *   user keeps a stable object address. The victim's stable storage slot is not
 *   reused until usersClear()/usersDestroy(), except for an unpublished last
 *   addition reclaimed by its exclusively owning transaction.
 * - Add/update/remove are failure-atomic: a failure before the commit point
 *   leaves the table and every index unchanged. An impossible failure after an
 *   irreversible commit emits a fixed fatal diagnostic and terminates directly;
 *   corrupt removal never allocates or rebuilds indexes.
 */

#include "wlibc.h"

#include "objects/user.h"

typedef struct users_sha224_table_s              users_sha224_table_t;
typedef struct users_sha256_table_s              users_sha256_table_t;
typedef struct users_uuid_table_s                users_uuid_table_t;
typedef struct users_wireguard_publickey_table_s users_wireguard_publickey_table_t;
typedef struct users_id_table_s                  users_id_table_t;
typedef struct users_name_table_s                users_name_table_t;
typedef struct users_pointer_table_s             users_pointer_table_t;
typedef struct users_allowed_ip_table_s          users_allowed_ip_table_t;

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

/* Configuration-only leaves. Omitted bits preserve stored values. Selected
 * strings must be non-NULL; an empty string clears the field. This type cannot
 * carry credentials, usage, runtime state or creation/first-use timestamps. */
typedef struct user_config_patch_s
{
    uint32_t     mask;
    const char  *name, *email, *notes, *wireguard_allowed_ips;
    uint64_t     gid;
    bool         enabled;
    int          record_stat_interval_ms;
    user_limit_t limit;
    uint64_t     expire_at_ms, expire_after_first_usage_ms;
} user_config_patch_t;

enum
{
    kUserConfigName                  = 1U << 0U,
    kUserConfigEmail                 = 1U << 1U,
    kUserConfigNotes                 = 1U << 2U,
    kUserConfigWireGuardAllowedIps   = 1U << 3U,
    kUserConfigGid                   = 1U << 4U,
    kUserConfigEnabled               = 1U << 5U,
    kUserConfigRecordStatInterval    = 1U << 6U,
    kUserConfigTrafficUp             = 1U << 7U,
    kUserConfigTrafficDown           = 1U << 8U,
    kUserConfigTrafficTotal          = 1U << 9U,
    kUserConfigBandwidthUp           = 1U << 10U,
    kUserConfigBandwidthDown         = 1U << 11U,
    kUserConfigIps                   = 1U << 12U,
    kUserConfigDevices               = 1U << 13U,
    kUserConfigConnectionsIn         = 1U << 14U,
    kUserConfigConnectionsOut        = 1U << 15U,
    kUserConfigExpireAt              = 1U << 16U,
    kUserConfigExpireAfterFirstUsage = 1U << 17U,
    kKnownUserConfigMask             = (1U << 18U) - 1U
};

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
    /* Rejected storage/index geometry or failed native lock initialization;
     * memory-manager heap exhaustion terminates instead of returning. */
    kUsersAddResultStorageUnavailable,
    kUsersAddResultBusy,
    kUsersAddResultResourceLimit,
    kUsersAddResultTimeout,
    kUsersAddResultPrecommitRejected,
    kUsersAddResultCreationFailed,
    kUsersAddResultTooLarge
} users_add_result_t;

typedef enum users_update_result_e
{
    kUsersUpdateResultOk = 0,
    kUsersUpdateResultInvalidArgument,
    kUsersUpdateResultUnknownFields,
    kUsersUpdateResultInvalidRecordStatInterval,
    kUsersUpdateResultInvalidWireGuardAllowedIps,
    /* Rejected index-capacity geometry; heap exhaustion does not return. */
    kUsersUpdateResultCapacityRejected,
    kUsersUpdateResultUserNotFound,
    kUsersUpdateResultDuplicateName,
    kUsersUpdateResultDuplicateUUID,
    kUsersUpdateResultDuplicateWireGuardPublicKey,
    kUsersUpdateResultDuplicateWireGuardAllowedIps,
    kUsersUpdateResultPasswordUpdateFailed,
    kUsersUpdateResultBusy,
    kUsersUpdateResultResourceLimit,
    kUsersUpdateResultTimeout,
    kUsersUpdateResultPrecommitRejected,
    kUsersUpdateResultRevisionExhausted,
    kUsersUpdateResultTooLarge
} users_update_result_t;

enum
{
    kUserUpdatePassword            = 1U << 0U,
    kUserUpdateName                = 1U << 1U,
    kUserUpdateEmail               = 1U << 2U,
    kUserUpdateNotes               = 1U << 3U,
    kUserUpdateGid                 = 1U << 4U,
    kUserUpdateEnabled             = 1U << 5U,
    kUserUpdateLimit               = 1U << 6U,
    kUserUpdateTimeInfo            = 1U << 7U,
    kUserUpdateStats               = 1U << 8U,
    kUserUpdateRecordStatInterval  = 1U << 9U,
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

    users_sha224_table_t              *sha224_table;
    users_sha256_table_t              *sha256_table;
    users_uuid_table_t                *uuid_table;
    users_wireguard_publickey_table_t *wireguard_publickey_table;
    users_id_table_t                  *id_table;
    /*
     * name_table indexes users by non-empty name for average-O(1) duplicate
     * checks; pointer_table maps each stored user_t* to its current active
     * items[] index so pointer membership/index lookups are average-O(1). Both
     * are implementation details; see users.c for ownership and key rules.
     */
    users_name_table_t    *name_table;
    users_pointer_table_t *pointer_table;
    /*
     * allowed_ip_table is an ordered interval index over configured WireGuard
     * Allowed-IP ranges, giving O(log M) address lookup and overlap detection.
     */
    users_allowed_ip_table_t *allowed_ip_table;
} users_t;

bool usersCreate(users_t *users);
void usersDestroy(users_t *users);

bool               usersAddUser(users_t *users, const user_t *user);
users_add_result_t usersAddUserChecked(users_t *users, const user_t *user);
bool               usersAddUserFromJson(users_t *users, const cJSON *json);
users_add_result_t usersAddUserFromJsonChecked(users_t *users, const cJSON *json);
bool               usersFeedJson(users_t *users, const cJSON *json);
/* Trusted, credential-bearing full-table export. Caller owns the returned JSON
 * tree. Allocates for every account while holding the collection read lock;
 * public status callers should use the existing redacted projections. */
cJSON             *usersToJson(const users_t *users);
bool               usersClear(users_t *users);

user_t       *usersLookupBySHA224(users_t *users, const uint8_t sha224[SHA224_DIGEST_SIZE]);
const user_t *usersLookupBySHA224Const(const users_t *users, const uint8_t sha224[SHA224_DIGEST_SIZE]);
user_t       *usersLookupBySHA256(users_t *users, const uint8_t sha256[SHA256_DIGEST_SIZE]);
const user_t *usersLookupBySHA256Const(const users_t *users, const uint8_t sha256[SHA256_DIGEST_SIZE]);
user_t       *usersLookupByUUID(users_t *users, const uint8_t uuid[kWwUuidBytesLen]);
const user_t *usersLookupByUUIDConst(const users_t *users, const uint8_t uuid[kWwUuidBytesLen]);
user_t       *usersLookupByWireGuardPublicKey(users_t *users, const uint8_t publickey[USER_WIREGUARD_PUBLICKEY_SIZE]);
const user_t *usersLookupByWireGuardPublicKeyConst(const users_t *users,
                                                   const uint8_t  publickey[USER_WIREGUARD_PUBLICKEY_SIZE]);
user_t       *usersLookupByWireGuardAllowedIp(users_t *users, const ip_addr_t *ip);
const user_t *usersLookupByWireGuardAllowedIpConst(const users_t *users, const ip_addr_t *ip);
user_t       *usersLookupByIdentifier(users_t *users, uint64_t id);
const user_t *usersLookupByIdentifierConst(const users_t *users, uint64_t id);
/* Trusted credential-bearing account exports; caller owns each returned JSON
 * tree. Public status callers should use the existing redacted projections. */
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

/* Reclaim only the most recent addition, before its enclosing transaction
 * commits or exposes any pointer to it. Caller must continuously hold external
 * exclusive transaction ownership from successful insertion through rollback.
 * Acquires the collection write lock internally; caller must not hold that lock.
 * A missing ID or mismatch with either the last active item or last allocated
 * slot is a fatal invariant violation. Erases indexes and destroys the account
 * without allocating, retaining capacity for reuse. Never use for normal removal. */
void usersRollbackUnpublishedLastUserByIdentifier(users_t *users, uint64_t id);

bool                  usersChangePassword(users_t *users, user_t *user, const char *password);
bool                  usersUpdateUser(users_t *users, user_t *user, const user_update_t *update);
users_update_result_t usersUpdateUserBySHA256(users_t *users, const uint8_t sha256[SHA256_DIGEST_SIZE],
                                              const user_update_t *update);
/* Failure-atomic, ID-addressed configuration edit. Holds collection ownership
 * through commit and applies selected leaves under the user's lock. */
users_update_result_t usersPatchConfigByIdentifier(users_t *users, uint64_t id, const user_config_patch_t *patch);
users_update_result_t usersPatchConfigByIdentifierWithExportLimit(users_t *users, uint64_t id,
                                                                  const user_config_patch_t *patch,
                                                                  size_t                     max_export_bytes);
typedef struct user_config_prepared_patch_s user_config_prepared_patch_t;
/* Preparation owns selected strings and normalized routing data. The allowance
 * covers its allocation and peak transient normalization storage/scratch. A zero
 * deadline has no time limit. Every failure clears *out. */
/* Successful config ownership transfer consumes the preparation. It may only be
 * destroyed afterward. Busy/timeout/precommit refusals leave it reusable.
 * Prepared fresh-account creation intentionally has different reusable semantics. */
users_update_result_t usersPrepareConfigPatch(const user_config_patch_t *patch, size_t max_owned_bytes,
                                              uint64_t deadline_ms, user_config_prepared_patch_t **out);
void                  usersFreePreparedConfigPatch(user_config_prepared_patch_t *prepared);
size_t                usersPreparedConfigPatchOwnedBytes(const user_config_prepared_patch_t *prepared);
size_t                usersPreparedConfigPatchPeakBytes(const user_config_prepared_patch_t *prepared);
/* Called with collection and target configuration write locks held, after all
 * fallible index preparation. It must not call back into users/user helpers.
 * False refuses before logical mutation; the caller retains its precise reason.
 * An accepted patch transfers its selected strings; free prepared afterward on
 * every result. Bandwidth patches additionally hold the target statistics lock;
 * other configuration edits do not acquire it. Private capacity may survive a
 * refusal. The callback may be NULL. */
typedef bool (*users_config_precommit_fn)(void *context);
/* Credential-only preparation and failure-atomic bounded replacement. Neither
 * the opaque preparation nor this path owns/copies a user or native lock.
 * Preparation caps its password at 32 KiB; the try transaction admits the old
 * password's cached length under the existing locks, retaining its 32 KiB limit
 * and bounded cleanup of that allocation including its terminator. Deadline
 * checks bracket precommit. No index grows,
 * no statistics lock is acquired, and only the target's configuration is locked.
 * Free the preparation on every result, including success. */
typedef struct user_prepared_password_change_s user_prepared_password_change_t;
typedef enum users_password_result_e
{
    kUsersPasswordOk = 0,
    kUsersPasswordInvalidArgument,
    kUsersPasswordBusy,
    kUsersPasswordNotFound,
    kUsersPasswordResourceLimit,
    kUsersPasswordTimeout,
    kUsersPasswordCredentialsExist,
    kUsersPasswordPreparationFailed,
    kUsersPasswordPrecommitRejected,
    kUsersPasswordTooLarge
} users_password_result_t;
users_password_result_t usersPreparePasswordChange(const char *password, size_t max_owned_bytes, uint64_t deadline_ms,
                                                   user_prepared_password_change_t **out);
void                    usersFreePreparedPasswordChange(user_prepared_password_change_t *prepared);
size_t                  usersPreparedPasswordChangeOwnedBytes(const user_prepared_password_change_t *prepared);
size_t                  usersPreparedPasswordChangePeakBytes(const user_prepared_password_change_t *prepared);
size_t                  usersPreparedPasswordChangeCommitBytes(const user_prepared_password_change_t *prepared);
/* max_working_bytes covers fixed commit scratch, excluding retained preparation
 * already charged by its owner. Callback runs with collection/target write
 * locks held, cannot reenter user/collection helpers, and can refuse before any
 * mutation. Deadline is checked once more immediately after the callback. */
users_password_result_t usersTryChangePreparedPasswordByIdentifier(users_t *users, uint64_t id,
                                                                   user_prepared_password_change_t *prepared,
                                                                   size_t max_working_bytes, uint64_t deadline_ms,
                                                                   users_config_precommit_fn precommit, void *context);
/* Finite allowance includes the complete row and maximum future scalar growth.
 * SIZE_MAX explicitly disables policy; zero permits no row. */
users_password_result_t usersTryChangePreparedPasswordByIdentifierWithExportLimit(
    users_t *users, uint64_t id, user_prepared_password_change_t *prepared, size_t max_working_bytes,
    size_t max_export_bytes, uint64_t deadline_ms, users_config_precommit_fn precommit, void *context);
users_update_result_t usersTryApplyPreparedConfigByIdentifier(users_t *users, uint64_t id,
                                                              user_config_prepared_patch_t *prepared,
                                                              size_t max_growth_bytes, uint64_t deadline_ms,
                                                              users_config_precommit_fn precommit, void *context);
/* Finite allowance includes the complete row and maximum future scalar growth.
 * SIZE_MAX explicitly disables policy; zero permits no row. */
users_update_result_t usersTryApplyPreparedConfigByIdentifierWithExportLimit(
    users_t *users, uint64_t id, user_config_prepared_patch_t *prepared, size_t max_growth_bytes,
    size_t max_export_bytes, uint64_t deadline_ms, users_config_precommit_fn precommit, void *context);
/* Fresh private accounts only: preparation derives credentials and owns all
 * selected input before any shared lock. NULL/empty config uses userCreate()
 * defaults. The retained/peak accounting includes aligned private storage,
 * normalization scratch and all secret/string copies. A zero deadline is unlimited. */
typedef struct user_prepared_creation_s user_prepared_creation_t;
users_add_result_t usersPrepareNewUser(uint64_t id, const char *password, const user_config_patch_t *config,
                                       size_t max_owned_bytes, uint64_t deadline_ms, user_prepared_creation_t **out);
void               usersFreePreparedNewUser(user_prepared_creation_t *prepared);
size_t             usersPreparedNewUserOwnedBytes(const user_prepared_creation_t *prepared);
size_t             usersPreparedNewUserPeakBytes(const user_prepared_creation_t *prepared);
/* ID-first duplicate classification; try-lock collection ownership only. Growth
 * admits full new extents and unpublished-slot copy/snapshot storage together.
 * The callback runs after slot/capacity preparation, before the final deadline
 * check and publication, and
 * must not call user/collection helpers. Private capacity can survive refusal.
 * Caller frees the prepared account on every result, including success. */
users_add_result_t usersTryAddPreparedUser(users_t *users, user_prepared_creation_t *prepared, size_t max_growth_bytes,
                                           uint64_t deadline_ms, users_config_precommit_fn precommit, void *context);
/* Finite allowance includes the complete row and maximum future scalar growth.
 * SIZE_MAX explicitly disables policy; zero permits no row. */
users_add_result_t    usersTryAddPreparedUserWithExportLimit(users_t *users, user_prepared_creation_t *prepared,
                                                             size_t max_growth_bytes, size_t max_export_bytes,
                                                             uint64_t deadline_ms, users_config_precommit_fn precommit,
                                                             void *context);
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
users_update_result_t usersAddTrafficByIdentifier(users_t *users, uint64_t id, uint64_t upload_bytes,
                                                  uint64_t download_bytes);
/*
 * Moves process-local runtime enforcement state from matching users in src to
 * dest, keyed by durable id. The function acquires both database write locks
 * and each matched pair's user locks, then stats locks, in address order; callers
 * must not hold any of those locks.
 * Destination runtime reservations and client-clock evidence are replaced;
 * use a fresh/unpublished destination without independently live reservations.
 */
bool usersMigrateRuntimeStateByIdentifier(users_t *dest, users_t *src);
/* Owned accounting values, captured under collection -> user -> stats locks.
 * False on unrepresentable array geometry; heap OOM is fatal. Free with memoryFree(). */
bool usersSnapshotAccounting(const users_t *users, user_accounting_snapshot_t **entries_out, size_t *count_out);
users_update_result_t usersSetFirstUsageIfMissingBySHA256(users_t *users, const uint8_t sha256[SHA256_DIGEST_SIZE],
                                                          uint64_t first_usage_at_ms, bool *changed);
users_update_result_t usersSetFirstUsageIfMissingByIdentifier(users_t *users, uint64_t id, uint64_t first_usage_at_ms,
                                                              bool *changed);
bool                  usersAddUserUsage(users_t *users, user_t *user, uint64_t upload_bytes, uint64_t download_bytes);

/*
 * Live connection-admission helpers keyed by durable user id. They take the
 * database read lock, locate the user, and run the matching user_t runtime
 * helper. They operate on the process-local runtime state, not the synced stats.
 */
user_admission_result_t usersTryAdmitConnectionByIdentifier(users_t *users, uint64_t id, const user_ip_key_t *ip_key,
                                                            uint64_t now_ms);
void                    usersReleaseConnectionByIdentifier(users_t *users, uint64_t id, const user_ip_key_t *ip_key);
/* Adds traffic and returns whether the user must now be cut off; *found reports if the user existed. */
bool usersAccountTrafficByIdentifier(users_t *users, uint64_t id, uint64_t upload_bytes, uint64_t download_bytes,
                                     uint64_t now_ms, bool *found, bool *first_usage_push_needed);
/* Raw-byte variant using userAccountTrafficScaled() under the same collection lock. */
bool usersAccountTrafficScaledByIdentifier(users_t *users, uint64_t id, uint64_t upload_bytes, uint64_t download_bytes,
                                           uint32_t multiplier, uint64_t now_ms, bool *found,
                                           bool *first_usage_push_needed);
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

size_t usersCount(const users_t *users);
/* Bounded, owned public projections. No collection/user pointer escapes the
 * protected copy. Caller supplies room for limit summaries (1..100); positions
 * at count return an empty terminal page. Error outputs are always cleared.
 * Detail allowance counts all string allocations, including terminating NULs. */
user_public_result_t usersTryCount(const users_t *users, uint64_t deadline_ms, size_t *count_out);
user_public_result_t usersCopyPublicDetailByIdentifier(const users_t *users, uint64_t id, size_t max_string_bytes,
                                                       uint64_t deadline_ms, user_public_detail_t *out);
user_public_result_t usersCopyPublicPage(const users_t *users, size_t position, size_t limit, uint64_t deadline_ms,
                                         user_public_summary_t *entries_out, size_t *count_out, size_t *total_out);
bool                 usersIsEmpty(const users_t *users);
bool                 usersReserve(users_t *users, size_t capacity);
user_t              *usersGetAt(users_t *users, size_t index);
const user_t        *usersGetAtConst(const users_t *users, size_t index);
bool                 usersContainsUser(const users_t *users, const user_t *user);

bool usersRebuildLookups(users_t *users);
bool usersValidate(const users_t *users);

/*
 * Native O(N) deep copy of src into dest. Both tables must already be
 * initialized (usersCreate()). dest == src succeeds without work. On failure
 * dest is left unchanged. Success invalidates every old destination user/string
 * pointer. Serialized configuration and stat fields are copied
 * and lookup indexes are rebuilt directly from the copied users; process-local
 * runtime connection/IP state and the AuthenticationClient projected local
 * expiry are NOT copied (use usersMigrateRuntimeStateByIdentifier() for runtime
 * state). This never serializes through JSON.
 */
bool usersCopy(users_t *dest, const users_t *src);

user_t       *usersFindFirstExpired(users_t *users, uint64_t now_ms);
const user_t *usersFindFirstExpiredConst(const users_t *users, uint64_t now_ms);
user_t       *usersFindFirstDisabled(users_t *users);
const user_t *usersFindFirstDisabledConst(const users_t *users);
user_t       *usersFindFirstLimited(users_t *users);
const user_t *usersFindFirstLimitedConst(const users_t *users);

user_stat_t usersUsageDiff(users_t *users, user_t *base, user_t *current);

bool usersObserveTrafficByIdentifier(users_t *users, uint64_t id, uint64_t upload_bytes, uint64_t download_bytes,
                                     uint64_t now_ms, bool *first_usage_push_needed);
bool usersBandwidthRegisterByIdentifier(users_t *users, uint64_t id, user_bandwidth_direction_t direction,
                                        uint64_t ticket);
void usersBandwidthSetEligibleByIdentifier(users_t *users, uint64_t id, user_bandwidth_direction_t direction,
                                           uint64_t ticket, bool eligible);
void usersBandwidthCancelByIdentifier(users_t *users, uint64_t id, user_bandwidth_direction_t direction,
                                      uint64_t ticket);
bool usersBandwidthReserveByIdentifier(users_t *users, uint64_t id, user_bandwidth_direction_t direction,
                                       uint64_t ticket, buffer_budget_cost_t cost);
void usersBandwidthReleaseByIdentifier(users_t *users, uint64_t id, user_bandwidth_direction_t direction,
                                       uint64_t ticket, buffer_budget_cost_t cost);
user_bandwidth_result_t  usersBandwidthPreviewByIdentifier(users_t *users, uint64_t id,
                                                           user_bandwidth_direction_t direction, uint64_t ticket,
                                                           uint64_t bytes, bool datagram);
user_delivery_decision_t usersCommitDeliveryByIdentifier(users_t *users, uint64_t id,
                                                         user_bandwidth_direction_t direction, uint64_t ticket,
                                                         uint64_t bytes, bool datagram, bool more, uint32_t multiplier);

/* Null input or {"users":null} imports no records. A `users` member takes
 * precedence over other container fields; a single user or name-keyed map is
 * accepted only without that member.
 * Incremental fresh import with lexical, required nonzero IDs. Failure rolls back
 * this append only; existing records/handles remain. Credentials derive once. */
bool usersFeedJsonRequiredIds(users_t *users, const cJSON *json);
/* Preserve native/construction refusals for startup recovery decisions. */
typedef enum users_json_result_e
{
    kUsersJsonOk,
    kUsersJsonInvalid,
    kUsersJsonResourceFailure
} users_json_result_t;
users_json_result_t usersFeedJsonRequiredIdsResult(users_t *users, const cJSON *json);
/* Failure details contain no names or credentials. entry_index is zero-based,
 * or SIZE_MAX for a container failure; id is zero when unavailable. reason is
 * a static diagnostic class string, NULL on success. */
typedef struct users_json_diagnostic_s
{
    size_t      entry_index;
    uint64_t    id;
    const char *reason;
} users_json_diagnostic_t;
users_json_result_t usersFeedJsonRequiredIdsResultDetailed(users_t *users, const cJSON *json,
                                                           users_json_diagnostic_t *diagnostic);
/* Candidate must be an initialized, exclusively owned unpublished table. Swaps
 * complete contents under dest's lock; candidate receives the old destination.
 * No allocation or native construction can fail during publication. Old
 * destination pointers now belong to candidate and expire when it is destroyed;
 * runtime state is not migrated between the old and new users. */
void usersPublishCandidate(users_t *dest, users_t *candidate);
/* Index/structural check for trusted fresh imports/copies. usersValidate remains
 * the full derived-credential diagnostic in every build configuration. */
bool usersValidateStructure(const users_t *users);
/* Owned full credential-bearing row, admitted before arbitrary strings are
 * copied. Exact compact JSON size is returned; failure clears both outputs. */
user_public_result_t usersCopyFullUserJsonAt(const users_t *users, size_t position, size_t max_encoded, cJSON **out,
                                             size_t *encoded_size);
/* Indexed point lookups with the same full-row size admission. Hold collection
 * ownership through copying so concurrent removal cannot invalidate the match.
 * Missing credentials return NotFound; all failures clear both outputs. */
user_public_result_t usersCopyFullUserJsonBySHA224(const users_t *users, const uint8_t sha224[SHA224_DIGEST_SIZE],
                                                   size_t max_encoded, cJSON **out, size_t *encoded_size);
user_public_result_t usersCopyFullUserJsonBySHA256(const users_t *users, const uint8_t sha256[SHA256_DIGEST_SIZE],
                                                   size_t max_encoded, cJSON **out, size_t *encoded_size);
user_public_result_t usersCopyFullUserJsonByPassword(const users_t *users, const char *password, size_t max_encoded,
                                                     cJSON **out, size_t *encoded_size);
