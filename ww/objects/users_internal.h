#pragma once

/* Private collection types and explicitly locked helpers. */

#include "objects/user_index_geometry.h"
#include "objects/user_internal.h"
#include "objects/users.h"

#include "loggers/internal_logger.h"

enum
{
    kUsersBlockSize            = 64,
    kUsersInitialTableCapacity = 16,
    kKnownUserUpdateMask       = kUserUpdatePassword | kUserUpdateName | kUserUpdateEmail | kUserUpdateNotes |
                           kUserUpdateGid | kUserUpdateEnabled | kUserUpdateLimit | kUserUpdateTimeInfo |
                           kUserUpdateStats | kUserUpdateRecordStatInterval | kUserUpdateWireGuardAllowedIps
};

_Static_assert(_Alignof(user_t) >= 32U, "user_t storage must be at least 32-byte aligned");
_Static_assert(sizeof(user_t) % 32U == 0, "user_t storage size must be a 32-byte multiple");

typedef struct users_sha224_key_s
{
    uint8_t bytes[SHA224_DIGEST_SIZE];
    uint8_t sha224_padding[SHA256_DIGEST_SIZE - SHA224_DIGEST_SIZE];
} users_sha224_key_t;

typedef struct users_sha256_key_s
{
    uint8_t bytes[SHA256_DIGEST_SIZE];
} users_sha256_key_t;

typedef struct users_uuid_key_s
{
    uint8_t bytes[kWwUuidBytesLen];
} users_uuid_key_t;

typedef struct users_wireguard_publickey_key_s
{
    uint8_t bytes[USER_WIREGUARD_PUBLICKEY_SIZE];
} users_wireguard_publickey_key_t;

typedef struct users_wireguard_allowed_ips_update_s
{
    char     *copy;
    ip_addr_t ip;
    ip_addr_t mask;
    uint64_t  count;
    uint8_t   family;
    uint8_t   prefix;
    bool      valid;
} users_wireguard_allowed_ips_update_t;

struct user_config_prepared_patch_s
{
    bool                                 consumed;
    user_config_patch_t                  patch;
    user_update_t                        update;
    char                                *name, *email, *notes;
    users_wireguard_allowed_ips_update_t allowed_ips;
    size_t                               owned_bytes, peak_bytes;
};

enum
{
    kUsersConfigOldNameLimit     = 32U * 1024U,
    kUsersConfigRangeGrowthLimit = 1024U * 1024U,
    /* CIDR normalization's bounded local text/address scratch. */
    kUsersConfigPreparationScratchBytes = 512U
};

static size_t usersSHA224KeyHash(const users_sha224_key_t *key)
{
    return (size_t) calcHashBytes(key->bytes, SHA224_DIGEST_SIZE);
}

static size_t usersSHA256KeyHash(const users_sha256_key_t *key)
{
    return (size_t) calcHashBytes(key->bytes, SHA256_DIGEST_SIZE);
}

static size_t usersUUIDKeyHash(const users_uuid_key_t *key)
{
    return (size_t) calcHashBytes(key->bytes, kWwUuidBytesLen);
}

static size_t usersWireGuardPublicKeyHash(const users_wireguard_publickey_key_t *key)
{
    return (size_t) calcHashBytes(key->bytes, USER_WIREGUARD_PUBLICKEY_SIZE);
}

static bool usersSHA224KeyEq(const users_sha224_key_t *a, const users_sha224_key_t *b)
{
    /*
     * STC owns hash-map key storage and allocates it through its normal allocator,
     * so the key address is not guaranteed to be 32-byte aligned. Do not use
     * memoryEqualAligned32() here; compare only the meaningful digest bytes.
     */
    return memoryCompare(a->bytes, b->bytes, SHA224_DIGEST_SIZE) == 0;
}

static bool usersSHA256KeyEq(const users_sha256_key_t *a, const users_sha256_key_t *b)
{
    /*
     * Same rule as SHA-224: STC table keys are not part of users_t's aligned
     * user_t storage invariant, so strict aligned helpers are intentionally not
     * used in hash-map callbacks.
     */
    return memoryCompare(a->bytes, b->bytes, SHA256_DIGEST_SIZE) == 0;
}

static bool usersUUIDKeyEq(const users_uuid_key_t *a, const users_uuid_key_t *b)
{
    return memoryCompare(a->bytes, b->bytes, kWwUuidBytesLen) == 0;
}

static bool usersWireGuardPublicKeyEq(const users_wireguard_publickey_key_t *a,
                                      const users_wireguard_publickey_key_t *b)
{
    return memoryCompare(a->bytes, b->bytes, USER_WIREGUARD_PUBLICKEY_SIZE) == 0;
}

#define i_type users_sha224_map_t // NOLINT
#define i_key  users_sha224_key_t // NOLINT
#define i_val  user_t *           // NOLINT
#define i_hash usersSHA224KeyHash // NOLINT
#define i_eq   usersSHA224KeyEq   // NOLINT
#include "stc/hmap.h"
#undef i_eq
#undef i_hash
#undef i_val
#undef i_key
#undef i_type

#define i_type users_sha256_map_t // NOLINT
#define i_key  users_sha256_key_t // NOLINT
#define i_val  user_t *           // NOLINT
#define i_hash usersSHA256KeyHash // NOLINT
#define i_eq   usersSHA256KeyEq   // NOLINT
#include "stc/hmap.h"
#undef i_eq
#undef i_hash
#undef i_val
#undef i_key
#undef i_type

#define i_type users_uuid_map_t // NOLINT
#define i_key  users_uuid_key_t // NOLINT
#define i_val  user_t *         // NOLINT
#define i_hash usersUUIDKeyHash // NOLINT
#define i_eq   usersUUIDKeyEq   // NOLINT
#include "stc/hmap.h"
#undef i_eq
#undef i_hash
#undef i_val
#undef i_key
#undef i_type

#define i_type users_wireguard_publickey_map_t // NOLINT
#define i_key  users_wireguard_publickey_key_t // NOLINT
#define i_val  user_t *                        // NOLINT
#define i_hash usersWireGuardPublicKeyHash     // NOLINT
#define i_eq   usersWireGuardPublicKeyEq       // NOLINT
#include "stc/hmap.h"
#undef i_eq
#undef i_hash
#undef i_val
#undef i_key
#undef i_type

#define i_type users_id_map_t // NOLINT
#define i_key  uint64_t       // NOLINT
#define i_val  user_t *       // NOLINT
#include "stc/hmap.h"
#undef i_val
#undef i_key
#undef i_type

/*
 * The name key stores a borrowed pointer to a user-owned name string. The map
 * neither owns nor duplicates the string: it hashes and compares by string
 * contents, so the owning user must keep the string alive and unchanged while
 * its entry exists (erase before rename, insert the replacement before the
 * users_t write lock is released).
 */
typedef struct users_name_key_s
{
    const char *name;
} users_name_key_t;

static size_t usersNameKeyHash(const users_name_key_t *key)
{
    return (size_t) calcHashBytes(key->name, stringLength(key->name));
}

static bool usersNameKeyEq(const users_name_key_t *a, const users_name_key_t *b)
{
    return stringCompare(a->name, b->name) == 0;
}

#define i_type users_name_map_t // NOLINT
#define i_key  users_name_key_t // NOLINT
#define i_val  user_t *         // NOLINT
#define i_hash usersNameKeyHash // NOLINT
#define i_eq   usersNameKeyEq   // NOLINT
#include "stc/hmap.h"
#undef i_eq
#undef i_hash
#undef i_val
#undef i_key
#undef i_type

/* Maps a stored user_t address (as uintptr_t) to its active items[] index. */
#define i_type users_pointer_map_t // NOLINT
#define i_key  uintptr_t           // NOLINT
#define i_val  size_t              // NOLINT
#include "stc/hmap.h"
#undef i_val
#undef i_key
#undef i_type

/*
 * Ordered interval index for WireGuard Allowed-IP ranges. A looked-up address
 * may fall inside a CIDR without equaling its network address, so a plain hash
 * map is insufficient; this ordered map is keyed by (address family, inclusive
 * range end) in network-byte lexicographic order. Because configured ranges may
 * not overlap, a single lower_bound() probe answers both address containment and
 * new-range overlap in O(log M). IPv4 uses the first four end/start bytes and
 * leaves the rest zero; IPv6 uses all sixteen. Family is compared before bytes.
 */
typedef struct users_allowed_ip_key_s
{
    uint8_t family;
    uint8_t end[16];
} users_allowed_ip_key_t;

typedef struct users_allowed_ip_value_s
{
    uint8_t start[16];
    user_t *user;
} users_allowed_ip_value_t;

static int usersAllowedIpKeyCmp(const users_allowed_ip_key_t *a, const users_allowed_ip_key_t *b)
{
    if (a->family != b->family)
    {
        return a->family < b->family ? -1 : 1;
    }
    int c = memoryCompare(a->end, b->end, sizeof(a->end));
    return (c > 0) - (c < 0);
}

#define i_type users_allowed_ip_map_t   // NOLINT
#define i_key  users_allowed_ip_key_t   // NOLINT
#define i_val  users_allowed_ip_value_t // NOLINT
#define i_cmp  usersAllowedIpKeyCmp     // NOLINT
#include "stc/smap.h"
#undef i_cmp
#undef i_val
#undef i_key
#undef i_type

struct users_sha224_table_s
{
    users_sha224_map_t map;
};

struct users_sha256_table_s
{
    users_sha256_map_t map;
};

struct users_uuid_table_s
{
    users_uuid_map_t map;
};

struct users_wireguard_publickey_table_s
{
    users_wireguard_publickey_map_t map;
};

struct users_id_table_s
{
    users_id_map_t map;
};

struct users_name_table_s
{
    users_name_map_t map;
};

struct users_pointer_table_s
{
    users_pointer_map_t map;
};

struct users_allowed_ip_table_s
{
    users_allowed_ip_map_t map;
};

typedef struct users_duplicate_result_s
{
    users_add_result_t result;
    size_t             index;
    uint8_t            priority;
    bool               found;
} users_duplicate_result_t;

struct user_prepared_password_change_s
{
    user_prepared_password_t material;
    size_t                   owned_bytes, peak_bytes;
};

struct user_prepared_creation_s
{
    user_t user;
    size_t owned_bytes, peak_bytes, string_bytes;
};

void *usersAllocateAlignedZero32(size_t size);

user_t *usersStorageAtLocked(const users_t *users, size_t index);

user_t *usersGetAtLocked(const users_t *users, size_t index);

const char *usersUserNameForLog(const user_t *user);

void usersStringDuplicate(char **dest, const char *value);

void usersReplaceStringOwned(char **dest, char **owned_value);

bool usersWireGuardAllowedIpContainsFields(bool valid, const ip_addr_t *network, const ip_addr_t *mask, uint8_t family,
                                           const ip_addr_t *ip);

bool usersWireGuardAllowedIpContainsUser(const user_t *user, const ip_addr_t *ip);

bool usersAllowedIpExtractBytes(const ip_addr_t *addr, uint8_t family, uint8_t out[16]);

bool usersAllowedIpRangeFromFields(const ip_addr_t *network, const ip_addr_t *mask, uint8_t family, uint8_t start16[16],
                                   uint8_t end16[16]);

bool usersAllowedIpEntryFromUser(const user_t *user, users_allowed_ip_key_t *key, users_allowed_ip_value_t *value);

bool usersAllowedIpUserFieldsIndexable(const user_t *user);

void usersAllowedIpTableCreateIfNeeded(users_t *users);

size_t usersAllowedIpTableSize(const users_allowed_ip_table_t *table);

bool usersAllowedIpTableGrowthGeometry(const users_allowed_ip_table_t *table, size_t min_capacity, size_t *capacity_out,
                                       size_t *extent_out);

bool usersAllowedIpTableReserve(users_allowed_ip_table_t *table, size_t min_capacity);

bool usersAllowedIpTableEnsureCapacity(users_t *users, size_t count);

bool usersAllowedIpTableEnsureOneMoreRange(users_t *users);

void usersAllowedIpTableClear(users_allowed_ip_table_t *table);

void usersAllowedIpTableDestroy(users_allowed_ip_table_t *table);

bool usersAllowedIpTableInsertLocked(users_t *users, user_t *user);

bool usersAllowedIpTableEraseLocked(users_t *users, const user_t *user);

user_t *usersAllowedIpTableFindContainingLocked(const users_t *users, uint8_t family, const uint8_t addr16[16]);

user_t *usersAllowedIpTableFindOverlapLocked(const users_t *users, uint8_t family, const uint8_t start16[16],
                                             const uint8_t end16[16], const user_t *ignore);

user_t *usersFindWireGuardAllowedIpsOverlapLocked(const users_t *users, bool valid, const ip_addr_t *network,
                                                  const ip_addr_t *mask, uint8_t family, const user_t *ignore,
                                                  bool *range_ok);

users_sha224_key_t usersSHA224KeyFromBytes(const uint8_t bytes[SHA224_DIGEST_SIZE]);

users_sha256_key_t usersSHA256KeyFromBytes(const uint8_t bytes[SHA256_DIGEST_SIZE]);

users_uuid_key_t usersUUIDKeyFromBytes(const uint8_t bytes[kWwUuidBytesLen]);

users_wireguard_publickey_key_t usersWireGuardPublicKeyFromBytes(const uint8_t bytes[USER_WIREGUARD_PUBLICKEY_SIZE]);

void usersWipeCredentialSnapshot(sha224_hash_t *old_sha224, sha256_hash_t *old_sha256,
                                 uint8_t old_uuid[kWwUuidBytesLen],
                                 uint8_t old_wireguard_publickey[USER_WIREGUARD_PUBLICKEY_SIZE]);

bool usersPasswordLookupKeyCreate(sha256_hash_t *sha256, const char *password);

bool usersSHA224TableReserve(users_sha224_table_t *table, size_t count);

bool usersSHA256TableReserve(users_sha256_table_t *table, size_t count);

bool usersUUIDTableReserve(users_uuid_table_t *table, size_t count);

bool usersWireGuardPublicKeyTableReserve(users_wireguard_publickey_table_t *table, size_t count);

bool usersIDTableReserve(users_id_table_t *table, size_t count);

void usersSHA224TableCreateIfNeeded(users_t *users);

void usersSHA256TableCreateIfNeeded(users_t *users);

void usersUUIDTableCreateIfNeeded(users_t *users);

void usersWireGuardPublicKeyTableCreateIfNeeded(users_t *users);

void usersIDTableCreateIfNeeded(users_t *users);

bool usersSHA256TableEnsureCapacity(users_t *users, size_t count);

bool usersSHA224TableEnsureCapacity(users_t *users, size_t count);

bool usersUUIDTableEnsureCapacity(users_t *users, size_t count);

bool usersWireGuardPublicKeyTableEnsureCapacity(users_t *users, size_t count);

bool usersIDTableEnsureCapacity(users_t *users, size_t count);

void usersSHA224TableClear(users_sha224_table_t *table);

void usersSHA256TableClear(users_sha256_table_t *table);

void usersUUIDTableClear(users_uuid_table_t *table);

void usersWireGuardPublicKeyTableClear(users_wireguard_publickey_table_t *table);

void usersIDTableClear(users_id_table_t *table);

void usersSHA224TableDestroy(users_sha224_table_t *table);

void usersSHA256TableDestroy(users_sha256_table_t *table);

void usersUUIDTableDestroy(users_uuid_table_t *table);

void usersWireGuardPublicKeyTableDestroy(users_wireguard_publickey_table_t *table);

void usersIDTableDestroy(users_id_table_t *table);

user_t *usersSHA224TableLookupLocked(const users_t *users, const uint8_t key_bytes[SHA224_DIGEST_SIZE]);

user_t *usersSHA256TableLookupLocked(const users_t *users, const uint8_t key_bytes[SHA256_DIGEST_SIZE]);

user_t *usersUUIDTableLookupLocked(const users_t *users, const uint8_t key_bytes[kWwUuidBytesLen]);

user_t *usersWireGuardPublicKeyTableLookupLocked(const users_t *users,
                                                 const uint8_t  key_bytes[USER_WIREGUARD_PUBLICKEY_SIZE]);

user_t *usersIDTableLookupLocked(const users_t *users, uint64_t id);

bool usersSHA224TableInsertEntryLocked(users_t *users, user_t *user);

bool usersSHA224TableInsertLocked(users_t *users, user_t *user);

bool usersSHA256TableInsertEntryLocked(users_t *users, user_t *user);

bool usersSHA256TableInsertLocked(users_t *users, user_t *user);

bool usersUUIDTableInsertEntryLocked(users_t *users, user_t *user);

bool usersUUIDTableInsertLocked(users_t *users, user_t *user);

bool usersWireGuardPublicKeyTableInsertEntryLocked(users_t *users, user_t *user);

bool usersWireGuardPublicKeyTableInsertLocked(users_t *users, user_t *user);

bool usersIDTableInsertLocked(users_t *users, user_t *user);

bool usersSHA224TableEraseLocked(users_t *users, const user_t *user, const uint8_t bytes[SHA224_DIGEST_SIZE]);

bool usersSHA256TableEraseLocked(users_t *users, const user_t *user, const uint8_t bytes[SHA256_DIGEST_SIZE]);

bool usersUUIDTableEraseLocked(users_t *users, const user_t *user, const uint8_t bytes[kWwUuidBytesLen]);

bool usersWireGuardPublicKeyTableEraseLocked(users_t *users, const user_t *user,
                                             const uint8_t bytes[USER_WIREGUARD_PUBLICKEY_SIZE]);

bool usersIDTableEraseLocked(users_t *users, const user_t *user, uint64_t id);

bool usersNameTableReserve(users_name_table_t *table, size_t count);

void usersNameTableCreateIfNeeded(users_t *users);

bool usersNameTableEnsureCapacity(users_t *users, size_t count);

void usersNameTableClear(users_name_table_t *table);

void usersNameTableDestroy(users_name_table_t *table);

user_t *usersNameTableLookupLocked(const users_t *users, const char *name);

bool usersNameTableInsertLocked(users_t *users, user_t *user);

bool usersNameTableEraseLocked(users_t *users, const user_t *user, const char *name);

bool usersNameTableInsertReservedLocked(users_t *users, user_t *user);

bool usersPointerTableReserve(users_pointer_table_t *table, size_t count);

void usersPointerTableCreateIfNeeded(users_t *users);

bool usersPointerTableEnsureCapacity(users_t *users, size_t count);

void usersPointerTableClear(users_pointer_table_t *table);

void usersPointerTableDestroy(users_pointer_table_t *table);

bool usersPointerTableLookupLocked(const users_t *users, const user_t *user, size_t *index_out);

bool usersPointerTableSetLocked(users_t *users, user_t *user, size_t index);

bool usersPointerTableUpdateExistingLocked(users_t *users, const user_t *user, size_t index);

void usersPointerTableEraseLocked(users_t *users, const user_t *user);

bool usersEnsureLookupCapacityLocked(users_t *users, size_t count);

void usersLookupTablesCreateIfNeededLocked(users_t *users);

void usersLookupTablesDestroy(users_t *users);

void usersLookupTablesSwapLocked(users_t *a, users_t *b);

bool usersBuildLookupTablesForItemsLocked(users_t *lookup_users, user_t **items, size_t count);

bool usersRebuildLookupTablesLocked(users_t *users);

bool usersEraseAllIndexEntriesLocked(users_t *users, user_t *user);

bool usersReserveItemsLocked(users_t *users, size_t capacity);

bool usersReserveStorageLocked(users_t *users, size_t slot_capacity);

bool usersReserveLocked(users_t *users, size_t capacity);

bool usersIndexOfLocked(const users_t *users, const user_t *user, size_t *index_out);

user_t *usersFindByNameLocked(const users_t *users, const char *name, const user_t *exclude);

void usersCommitReservedCredentialsLocked(users_t *users, user_t *slot);

void usersCommitReservedUserLocked(users_t *users, user_t *slot);

bool usersCommitNewUserLocked(users_t *users, user_t *slot, bool prevalidated);

void usersDuplicateResultConsider(const users_t *users, users_duplicate_result_t *best, user_t *owner,
                                  users_add_result_t result, uint8_t priority);

users_add_result_t usersValidateNewUserIndexesLocked(const users_t *users, const user_t *user);

users_add_result_t usersValidateNewUserNoFatalLocked(const users_t *users, const user_t *user);

users_update_result_t usersPasswordPreflightLocked(users_t *users, user_t *user,
                                                   const user_prepared_password_t *prepared);

void usersCommitPasswordLocked(users_t *users, user_t *user, user_prepared_password_t *prepared,
                               size_t old_password_length);

users_update_result_t usersChangePasswordLocked(users_t *users, user_t *user, const char *password);

user_t *usersLookupByPasswordLocked(users_t *users, const sha256_hash_t *sha256_key, const char *password);

bool usersRemoveUserLocked(users_t *users, user_t *user);

void usersClearLocked(users_t *users);

void usersRollbackFeedLocked(users_t *users, size_t old_count, size_t old_slot_count);

void usersApplyNameHint(user_t *user, const char *name_hint);

bool usersAppendJsonUserLocked(users_t *users, const cJSON *user_json, const char *name_hint, bool required_ids);

bool usersReserveForFeedLocked(users_t *users, const cJSON *container);

bool usersFeedJsonArrayLocked(users_t *users, const cJSON *array, bool required_ids);

bool usersFeedJsonObjectMapLocked(users_t *users, const cJSON *object, bool required_ids);

bool usersJsonObjectLooksLikeSingleUser(const cJSON *json);

bool usersFeedJsonLocked(users_t *users, const cJSON *json, bool required_ids);

bool usersValidateUserLookupKeysLocked(const users_t *users, bool credentials);

users_update_result_t usersValidateUpdateRequest(const user_update_t *update);

void usersFreeUpdateStringCopies(char *name_copy, char *email_copy, char *notes_copy,
                                 users_wireguard_allowed_ips_update_t *wireguard_allowed_ips);

users_update_result_t usersCopyUpdateStrings(const user_update_t *update, char **name_copy, char **email_copy,
                                             char                                **notes_copy,
                                             users_wireguard_allowed_ips_update_t *wireguard_allowed_ips);

users_update_result_t usersPrepareUpdate(const user_update_t *update, char **name_copy, char **email_copy,
                                         char                                **notes_copy,
                                         users_wireguard_allowed_ips_update_t *wireguard_allowed_ips);

users_update_result_t usersPreflightConfigIndexesLocked(users_t *users, user_t *user, const user_update_t *update,
                                                        const char                                 *name_copy,
                                                        const users_wireguard_allowed_ips_update_t *allowed_ips,
                                                        bool bounded, size_t max_growth_bytes, uint64_t deadline_ms);

void usersApplyConfigValues(user_t *user, const user_update_t *update, char **name_copy, char **email_copy,
                            char **notes_copy, users_wireguard_allowed_ips_update_t *wireguard_allowed_ips,
                            const user_config_patch_t *patch);

bool usersUpdateTouchesBandwidth(const user_update_t *update, const user_config_patch_t *patch);

void usersCommitConfigUpdateLocked(users_t *users, user_t *user, const user_update_t *update, char **name_copy,
                                   char **email_copy, char **notes_copy,
                                   users_wireguard_allowed_ips_update_t *wireguard_allowed_ips,
                                   const user_config_patch_t            *patch);

users_update_result_t usersApplyUpdateToExistingUserLocked(users_t *users, user_t *user, const user_update_t *update,
                                                           char **name_copy, char **email_copy, char **notes_copy,
                                                           users_wireguard_allowed_ips_update_t *wireguard_allowed_ips);

users_update_result_t usersConfigPatchToUpdate(const user_config_patch_t *patch, user_update_t *out);

bool usersConfigStringBytes(const char *value, size_t allowance, size_t *bytes);

users_password_result_t usersPasswordAdmitLength(const char *password, size_t limit, uint64_t deadline_ms,
                                                 size_t *length_out);

bool usersCreationCharge(size_t *charge, size_t extent, size_t allowance);

bool usersCreationGrowthGeometry(const users_t *users, const user_prepared_creation_t *prepared, size_t allowance,
                                 bool *name_growth);

users_add_result_t usersCreationInspectNames(const users_t *users, size_t allowance, uint64_t deadline_ms);

users_update_result_t usersApplyPreparedConfigByIdentifier(users_t *users, uint64_t id,
                                                           user_config_prepared_patch_t *prepared, bool bounded,
                                                           size_t max_growth_bytes, uint64_t deadline_ms,
                                                           users_config_precommit_fn precommit, void *context);

void usersMoveRuntimeStateWithLocks(user_t *dest, user_t *src);

void usersSwapContentsLocked(users_t *a, users_t *b);

bool usersCommitCopiedUserLocked(users_t *dest, user_t *slot);

bool usersCopy(users_t *dest, const users_t *src);

enum
{
    kUsersPasswordTextLimit           = 32U * 1024U,
    kUsersPasswordPrepareScratchBytes = 256U,
    kUsersPasswordCommitScratchBytes  = 1024U
};
