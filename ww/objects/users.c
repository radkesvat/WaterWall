/*
 * User database manager implementation.
 */

#include "objects/users.h"

#include "loggers/internal_logger.h"

#include <inttypes.h>
#include <stdint.h>

enum
{
    kUsersBlockSize            = 64,
    kUsersInitialTableCapacity = 16,
    kKnownUserUpdateMask       = kUserUpdatePassword | kUserUpdateName | kUserUpdateEmail | kUserUpdateNotes |
                                  kUserUpdateGid | kUserUpdateEnabled | kUserUpdateLimit | kUserUpdateTimeInfo |
                                  kUserUpdateStats | kUserUpdateRecordStatInterval
};

typedef struct users_sha256_key_s
{
    uint8_t bytes[SHA256_DIGEST_SIZE];
} users_sha256_key_t;

typedef struct users_password_probe_s
{
    hash_t        hash_pass;
    sha256_hash_t sha256_pass;
    bool          sha256_pass_valid;
} users_password_probe_t;

static uint64_t usersSHA256KeyHash(const users_sha256_key_t *key)
{
    return calcHashBytes(key->bytes, SHA256_DIGEST_SIZE);
}

static bool usersSHA256KeyEq(const users_sha256_key_t *a, const users_sha256_key_t *b)
{
    return memoryCompare(a->bytes, b->bytes, SHA256_DIGEST_SIZE) == 0;
}

#define i_type users_hash_map_t // NOLINT
#define i_key  hash_t           // NOLINT
#define i_val  user_t *         // NOLINT
#include "stc/hmap.h"
#undef i_val
#undef i_key
#undef i_type

#define i_type users_sha256_map_t  // NOLINT
#define i_key  users_sha256_key_t  // NOLINT
#define i_val  user_t *            // NOLINT
#define i_hash usersSHA256KeyHash  // NOLINT
#define i_eq   usersSHA256KeyEq    // NOLINT
#include "stc/hmap.h"
#undef i_eq
#undef i_hash
#undef i_val
#undef i_key
#undef i_type

struct users_hash_table_s
{
    users_hash_map_t map;
};

struct users_sha256_table_s
{
    users_sha256_map_t map;
};

static user_t *usersStorageAtLocked(const users_t *users, size_t index)
{
    return &users->blocks[index / kUsersBlockSize][index % kUsersBlockSize];
}

static user_t *usersGetAtLocked(const users_t *users, size_t index)
{
    return users->items[index];
}

static const char *usersUserNameForLog(const user_t *user)
{
    if (user == NULL || user->name == NULL || user->name[0] == '\0')
    {
        return "<unnamed>";
    }
    return user->name;
}

static bool usersStringDuplicate(char **dest, const char *value)
{
    char *copy = stringDuplicate(value != NULL ? value : "");
    if (copy == NULL)
    {
        return false;
    }

    *dest = copy;
    return true;
}

static void usersReplaceStringOwned(char **dest, char **owned_value)
{
    memoryFree(*dest);
    *dest        = *owned_value;
    *owned_value = NULL;
}

static bool usersSha256Equal(const uint8_t a[SHA256_DIGEST_SIZE], const uint8_t b[SHA256_DIGEST_SIZE])
{
    return wCryptoEqual(a, b, SHA256_DIGEST_SIZE);
}

static void usersSha256ToHex(const uint8_t sha256[SHA256_DIGEST_SIZE], char out[SHA256_DIGEST_SIZE * 2U + 1U])
{
    static const char hex[] = "0123456789abcdef";

    for (size_t i = 0; i < SHA256_DIGEST_SIZE; ++i)
    {
        out[i * 2U]      = hex[(sha256[i] >> 4U) & 0x0FU];
        out[i * 2U + 1U] = hex[sha256[i] & 0x0FU];
    }
    out[SHA256_DIGEST_SIZE * 2U] = '\0';
}

static users_sha256_key_t usersSHA256KeyFromBytes(const uint8_t bytes[SHA256_DIGEST_SIZE])
{
    users_sha256_key_t key = {0};

    memoryCopy(key.bytes, bytes, SHA256_DIGEST_SIZE);
    return key;
}

static bool usersPasswordProbeCreate(users_password_probe_t *probe, const char *password)
{
    const size_t password_len = password != NULL ? stringLength(password) : 0;

    if (probe == NULL || password == NULL || password[0] == '\0')
    {
        return false;
    }

    memoryZero(probe, sizeof(*probe));
    probe->hash_pass = calcHashBytes(password, password_len);

#if defined(WCRYPTO_BACKEND_OPENSSL) || defined(WCRYPTO_BACKEND_SODIUM)
    if (wCryptoSHA256(&probe->sha256_pass, (const unsigned char *) password, password_len) != 0)
    {
        wCryptoZero(&probe->sha256_pass, sizeof(probe->sha256_pass));
        return false;
    }
    probe->sha256_pass_valid = true;
#endif

    return true;
}

static void usersPasswordProbeDestroy(users_password_probe_t *probe)
{
    if (probe == NULL)
    {
        return;
    }

    wCryptoZero(&probe->sha256_pass, sizeof(probe->sha256_pass));
    memoryZero(probe, sizeof(*probe));
}

static bool usersHashTableReserve(users_hash_table_t *table, size_t count)
{
    size_t capacity = count < kUsersInitialTableCapacity ? kUsersInitialTableCapacity : count;

    if (capacity > (size_t) PTRDIFF_MAX)
    {
        LOGE("Users: generic hash lookup table capacity overflow");
        return false;
    }
    if (! users_hash_map_t_reserve(&table->map, (isize) capacity))
    {
        LOGE("Users: failed to reserve generic hash lookup table");
        return false;
    }

    return true;
}

static bool usersSHA256TableReserve(users_sha256_table_t *table, size_t count)
{
    size_t capacity = count < kUsersInitialTableCapacity ? kUsersInitialTableCapacity : count;

    if (capacity > (size_t) PTRDIFF_MAX)
    {
        LOGE("Users: SHA-256 lookup table capacity overflow");
        return false;
    }
    if (! users_sha256_map_t_reserve(&table->map, (isize) capacity))
    {
        LOGE("Users: failed to reserve SHA-256 lookup table");
        return false;
    }

    return true;
}

static bool usersHashTableCreateIfNeeded(users_t *users)
{
    users_hash_table_t *table;

    if (users->generic_hash_table != NULL)
    {
        return true;
    }

    table = memoryAllocate(sizeof(*table));
    if (table == NULL)
    {
        LOGE("Users: failed to allocate generic hash lookup table");
        return false;
    }
    memoryZero(table, sizeof(*table));

    if (! usersHashTableReserve(table, kUsersInitialTableCapacity))
    {
        users_hash_map_t_drop(&table->map);
        memoryFree(table);
        return false;
    }

    users->generic_hash_table = table;
    return true;
}

static bool usersSHA256TableCreateIfNeeded(users_t *users)
{
    users_sha256_table_t *table;

    if (users->sha256_table != NULL)
    {
        return true;
    }

    table = memoryAllocate(sizeof(*table));
    if (table == NULL)
    {
        LOGE("Users: failed to allocate SHA-256 lookup table");
        return false;
    }
    memoryZero(table, sizeof(*table));

    if (! usersSHA256TableReserve(table, kUsersInitialTableCapacity))
    {
        users_sha256_map_t_drop(&table->map);
        memoryFree(table);
        return false;
    }

    users->sha256_table = table;
    return true;
}

static bool usersHashTableEnsureCapacity(users_t *users, size_t count)
{
    return usersHashTableCreateIfNeeded(users) && usersHashTableReserve(users->generic_hash_table, count);
}

static bool usersSHA256TableEnsureCapacity(users_t *users, size_t count)
{
    return usersSHA256TableCreateIfNeeded(users) && usersSHA256TableReserve(users->sha256_table, count);
}

static void usersHashTableClear(users_hash_table_t *table)
{
    if (table == NULL)
    {
        return;
    }

    users_hash_map_t_clear(&table->map);
}

static void usersSHA256TableClear(users_sha256_table_t *table)
{
    if (table == NULL)
    {
        return;
    }

    users_sha256_map_t_clear(&table->map);
}

static void usersHashTableDestroy(users_hash_table_t *table)
{
    if (table == NULL)
    {
        return;
    }

    users_hash_map_t_drop(&table->map);
    memoryFree(table);
}

static void usersSHA256TableDestroy(users_sha256_table_t *table)
{
    if (table == NULL)
    {
        return;
    }

    users_sha256_map_t_drop(&table->map);
    memoryFree(table);
}

static user_t *usersHashTableLookupLocked(const users_t *users, hash_t key)
{
    users_hash_table_t *table = users->generic_hash_table;

    if (table == NULL)
    {
        return NULL;
    }

    users_hash_map_t_iter it = users_hash_map_t_find(&table->map, key);
    return it.ref != NULL ? it.ref->second : NULL;
}

static user_t *usersSHA256TableLookupLocked(const users_t *users, const uint8_t key_bytes[SHA256_DIGEST_SIZE])
{
    users_sha256_table_t *table = users->sha256_table;

    if (table == NULL || key_bytes == NULL)
    {
        return NULL;
    }

    users_sha256_key_t       key = usersSHA256KeyFromBytes(key_bytes);
    users_sha256_map_t_iter it  = users_sha256_map_t_find(&table->map, key);
    return it.ref != NULL ? it.ref->second : NULL;
}

static void usersDisableGenericHashLookupLocked(users_t *users, const user_t *first, const user_t *second,
                                                hash_t hash)
{
    if (! users->generic_hash_lookup_available)
    {
        return;
    }

    LOGW("Users: generic hash collision for hash=%" PRIu64 " between users \"%s\" and \"%s\"; "
         "generic hash lookup is now disabled",
         (uint64_t) hash, usersUserNameForLog(first), usersUserNameForLog(second));
    users->generic_hash_lookup_available = false;
    users->generic_hash_collision_seen   = true;
    usersHashTableClear(users->generic_hash_table);
}

static bool usersHashTableInsertLocked(users_t *users, user_t *user)
{
    users_hash_map_t_result result;
    hash_t                  key = user->hash_pass;

    if (! users->generic_hash_lookup_available)
    {
        return true;
    }
    if (! usersHashTableEnsureCapacity(users, users->count + 1U))
    {
        return false;
    }

    result = users_hash_map_t_insert(&users->generic_hash_table->map, key, user);
    if (result.ref == NULL)
    {
        LOGE("Users: failed to insert generic hash lookup entry");
        return false;
    }
    if (! result.inserted && result.ref->second != user)
    {
        usersDisableGenericHashLookupLocked(users, result.ref->second, user, key);
    }

    return true;
}

static bool usersSHA256TableInsertLocked(users_t *users, user_t *user)
{
    users_sha256_key_t        key;
    users_sha256_map_t_result result;

    if (! user->sha256_pass_valid)
    {
        LOGE("Users: user \"%s\" does not have a usable SHA-256 password hash", usersUserNameForLog(user));
        return false;
    }
    if (! usersSHA256TableEnsureCapacity(users, users->count + 1U))
    {
        return false;
    }

    key    = usersSHA256KeyFromBytes(user->sha256_pass.bytes);
    result = users_sha256_map_t_insert(&users->sha256_table->map, key, user);
    if (result.ref == NULL)
    {
        LOGE("Users: failed to insert SHA-256 lookup entry");
        return false;
    }
    if (! result.inserted && result.ref->second != user)
    {
        char key_hex[SHA256_DIGEST_SIZE * 2U + 1U];
        usersSha256ToHex(user->sha256_pass.bytes, key_hex);
        LOGF("Users: fatal SHA-256 lookup collision for key %s between users \"%s\" and \"%s\"", key_hex,
             usersUserNameForLog(result.ref->second), usersUserNameForLog(user));
        terminateProgram(1);
    }

    return true;
}

static bool usersEnsureLookupCapacityLocked(users_t *users, size_t count)
{
    if (! usersSHA256TableEnsureCapacity(users, count))
    {
        return false;
    }
    if (users->generic_hash_lookup_available && ! usersHashTableEnsureCapacity(users, count))
    {
        return false;
    }

    return true;
}

static bool usersRebuildLookupTablesLocked(users_t *users)
{
    if (! usersEnsureLookupCapacityLocked(users, users->count))
    {
        return false;
    }

    usersSHA256TableClear(users->sha256_table);
    usersHashTableClear(users->generic_hash_table);

    for (size_t i = 0; i < users->count; ++i)
    {
        user_t *user = usersGetAtLocked(users, i);
        if (! usersSHA256TableInsertLocked(users, user))
        {
            return false;
        }
        if (! usersHashTableInsertLocked(users, user))
        {
            return false;
        }
    }

    return true;
}

static bool usersReserveItemsLocked(users_t *users, size_t capacity)
{
    if (capacity <= users->capacity)
    {
        return true;
    }

    size_t new_capacity = users->capacity == 0 ? kUsersBlockSize : users->capacity;
    while (new_capacity < capacity)
    {
        if (new_capacity > SIZE_MAX / 2U)
        {
            LOGE("Users: active user pointer capacity overflow");
            return false;
        }
        new_capacity *= 2U;
    }
    if (new_capacity > SIZE_MAX / sizeof(*users->items))
    {
        LOGE("Users: active user pointer capacity overflow");
        return false;
    }

    user_t **new_items = memoryReAllocate(users->items, new_capacity * sizeof(*new_items));
    if (new_items == NULL)
    {
        LOGE("Users: failed to grow active user pointer array");
        return false;
    }
    memoryZero(new_items + users->capacity, (new_capacity - users->capacity) * sizeof(*new_items));

    users->items    = new_items;
    users->capacity = new_capacity;
    return true;
}

static bool usersReserveStorageLocked(users_t *users, size_t slot_capacity)
{
    if (slot_capacity <= users->slot_capacity)
    {
        return true;
    }

    while (users->slot_capacity < slot_capacity)
    {
        user_t *block = NULL;

        if (users->block_count == users->block_capacity)
        {
            size_t new_block_capacity = users->block_capacity == 0 ? 4U : users->block_capacity * 2U;
            if (new_block_capacity < users->block_capacity || new_block_capacity > SIZE_MAX / sizeof(*users->blocks))
            {
                LOGE("Users: user block pointer capacity overflow");
                return false;
            }

            user_t **new_blocks = memoryReAllocate(users->blocks, new_block_capacity * sizeof(*new_blocks));
            if (new_blocks == NULL)
            {
                LOGE("Users: failed to grow user block pointer array");
                return false;
            }

            users->blocks         = new_blocks;
            users->block_capacity = new_block_capacity;
        }

        block = memoryCalloc(kUsersBlockSize, sizeof(*block));
        if (block == NULL)
        {
            LOGE("Users: failed to allocate user storage block");
            return false;
        }

        users->blocks[users->block_count] = block;
        users->block_count += 1U;
        users->slot_capacity += kUsersBlockSize;
    }

    return true;
}

static bool usersReserveLocked(users_t *users, size_t capacity)
{
    size_t new_slots_needed;

    if (! usersReserveItemsLocked(users, capacity))
    {
        return false;
    }

    new_slots_needed = capacity > users->count ? capacity - users->count : 0;
    if (users->slot_count > SIZE_MAX - new_slots_needed)
    {
        LOGE("Users: user storage capacity overflow");
        return false;
    }

    return usersReserveStorageLocked(users, users->slot_count + new_slots_needed);
}

static bool usersIndexOfLocked(const users_t *users, const user_t *user, size_t *index_out)
{
    if (user == NULL)
    {
        return false;
    }

    for (size_t i = 0; i < users->count; ++i)
    {
        if (usersGetAtLocked(users, i) == user)
        {
            if (index_out != NULL)
            {
                *index_out = i;
            }
            return true;
        }
    }

    return false;
}

static user_t *usersFindByNameLocked(const users_t *users, const char *name, const user_t *exclude)
{
    if (name == NULL || name[0] == '\0')
    {
        return NULL;
    }

    for (size_t i = 0; i < users->count; ++i)
    {
        user_t *user = usersGetAtLocked(users, i);
        if (user != exclude && user->name != NULL && stringCompare(user->name, name) == 0)
        {
            return user;
        }
    }

    return NULL;
}

static bool usersCommitNewUserLocked(users_t *users, user_t *slot)
{
    user_t *duplicate_name;

    if (! slot->sha256_pass_valid)
    {
        LOGE("Users: user \"%s\" does not have a usable SHA-256 password hash", usersUserNameForLog(slot));
        return false;
    }
    if (! userPasswordDataValid(slot))
    {
        LOGE("Users: user \"%s\" has inconsistent password lookup data", usersUserNameForLog(slot));
        return false;
    }

    duplicate_name = usersFindByNameLocked(users, slot->name, NULL);
    if (duplicate_name != NULL)
    {
        LOGE("Users: duplicate username \"%s\" in user database", slot->name);
        return false;
    }
    if (! usersEnsureLookupCapacityLocked(users, users->count + 1U))
    {
        return false;
    }
    if (usersSHA256TableLookupLocked(users, slot->sha256_pass.bytes) != NULL)
    {
        char key_hex[SHA256_DIGEST_SIZE * 2U + 1U];
        usersSha256ToHex(slot->sha256_pass.bytes, key_hex);
        LOGF("Users: fatal duplicate SHA-256 lookup key %s while loading user \"%s\"", key_hex,
             usersUserNameForLog(slot));
        terminateProgram(1);
    }

    if (! usersSHA256TableInsertLocked(users, slot))
    {
        return false;
    }
    if (! usersHashTableInsertLocked(users, slot))
    {
        if (! usersRebuildLookupTablesLocked(users))
        {
            LOGF("Users: failed to restore lookup tables after an insertion failure");
            terminateProgram(1);
        }
        return false;
    }

    users->items[users->count] = slot;
    users->count += 1U;
    users->slot_count += 1U;
    return true;
}

static bool usersHashBytesConflict(bool a_valid, const void *a, bool b_valid, const void *b, size_t len)
{
    return a_valid && b_valid && wCryptoEqual(a, b, len);
}

static users_add_result_t usersValidateNewUserNoFatalLocked(const users_t *users, const user_t *user)
{
    if (user == NULL || ! user->initialized || ! user->sha256_pass_valid || ! userPasswordDataValid((user_t *) user))
    {
        return kUsersAddResultInvalidUser;
    }
    if (usersFindByNameLocked(users, user->name, NULL) != NULL)
    {
        return kUsersAddResultDuplicateName;
    }

    for (size_t i = 0; i < users->count; ++i)
    {
        user_t *existing = usersGetAtLocked(users, i);

        if (existing->sha256_pass_valid && usersSha256Equal(existing->sha256_pass.bytes, user->sha256_pass.bytes))
        {
            return kUsersAddResultDuplicateSHA256;
        }
        if (existing->hash_pass == user->hash_pass)
        {
            return kUsersAddResultHashConflict;
        }
        if (usersHashBytesConflict(existing->sha224_pass_valid, existing->sha224_pass.bytes, user->sha224_pass_valid,
                                   user->sha224_pass.bytes, SHA224_DIGEST_SIZE) ||
            usersHashBytesConflict(existing->sha384_pass_valid, existing->sha384_pass.bytes, user->sha384_pass_valid,
                                   user->sha384_pass.bytes, SHA384_DIGEST_SIZE) ||
            usersHashBytesConflict(existing->sha512_pass_valid, existing->sha512_pass.bytes, user->sha512_pass_valid,
                                   user->sha512_pass.bytes, SHA512_DIGEST_SIZE))
        {
            return kUsersAddResultHashConflict;
        }
    }

    return kUsersAddResultOk;
}

users_add_result_t usersAddUserChecked(users_t *users, const user_t *user)
{
    user_t            *slot;
    users_add_result_t result;

    if (users == NULL || user == NULL)
    {
        return kUsersAddResultInvalidArgument;
    }

    rwlockWriteLock(&users->lock);

    result = usersValidateNewUserNoFatalLocked(users, user);
    if (result != kUsersAddResultOk)
    {
        rwlockWriteUnlock(&users->lock);
        return result;
    }
    if (! usersReserveLocked(users, users->count + 1U))
    {
        rwlockWriteUnlock(&users->lock);
        return kUsersAddResultAllocationFailed;
    }

    slot = usersStorageAtLocked(users, users->slot_count);
    if (! userCopy(slot, user))
    {
        rwlockWriteUnlock(&users->lock);
        return kUsersAddResultAllocationFailed;
    }
    if (! usersCommitNewUserLocked(users, slot))
    {
        userDestroy(slot);
        rwlockWriteUnlock(&users->lock);
        return kUsersAddResultCommitFailed;
    }

    rwlockWriteUnlock(&users->lock);
    return kUsersAddResultOk;
}

static bool usersChangePasswordLocked(users_t *users, user_t *user, const char *password)
{
    user_t                 *generic_collision_user = NULL;
    user_t                 *sha_duplicate;
    users_password_probe_t  password_probe;
    bool                    disable_generic_after_password_update = false;

    if (! usersIndexOfLocked(users, user, NULL))
    {
        return false;
    }

    memoryZero(&password_probe, sizeof(password_probe));
    if (! usersPasswordProbeCreate(&password_probe, password))
    {
        return false;
    }
    if (! password_probe.sha256_pass_valid)
    {
        LOGE("Users: updated password for user \"%s\" does not produce a usable SHA-256 hash",
             usersUserNameForLog(user));
        usersPasswordProbeDestroy(&password_probe);
        return false;
    }

    sha_duplicate = usersSHA256TableLookupLocked(users, password_probe.sha256_pass.bytes);
    if (sha_duplicate != NULL && sha_duplicate != user)
    {
        char key_hex[SHA256_DIGEST_SIZE * 2U + 1U];
        usersSha256ToHex(password_probe.sha256_pass.bytes, key_hex);
        LOGF("Users: fatal SHA-256 lookup collision for key %s while updating user \"%s\"", key_hex,
             usersUserNameForLog(user));
        usersPasswordProbeDestroy(&password_probe);
        terminateProgram(1);
    }
    if (users->generic_hash_lookup_available)
    {
        user_t *hash_duplicate = usersHashTableLookupLocked(users, password_probe.hash_pass);
        if (hash_duplicate != NULL && hash_duplicate != user)
        {
            disable_generic_after_password_update = true;
            generic_collision_user                = hash_duplicate;
        }
    }
    if (! usersEnsureLookupCapacityLocked(users, users->count))
    {
        usersPasswordProbeDestroy(&password_probe);
        return false;
    }
    if (! userChangePassword(user, password))
    {
        usersPasswordProbeDestroy(&password_probe);
        return false;
    }
    if (disable_generic_after_password_update)
    {
        usersDisableGenericHashLookupLocked(users, generic_collision_user, user, password_probe.hash_pass);
    }
    if (! usersRebuildLookupTablesLocked(users))
    {
        LOGF("Users: failed to rebuild lookup tables after updating user \"%s\"", usersUserNameForLog(user));
        usersPasswordProbeDestroy(&password_probe);
        terminateProgram(1);
    }

    usersPasswordProbeDestroy(&password_probe);
    return true;
}

static user_t *usersLookupByPasswordLocked(users_t *users, const users_password_probe_t *password_probe,
                                           const char *password)
{
    user_t *candidate = NULL;

    if (users->generic_hash_lookup_available)
    {
        candidate = usersHashTableLookupLocked(users, password_probe->hash_pass);
        if (candidate != NULL && userPasswordMatches(candidate, password))
        {
            return candidate;
        }
    }
    if (password_probe->sha256_pass_valid)
    {
        candidate = usersSHA256TableLookupLocked(users, password_probe->sha256_pass.bytes);
        if (candidate != NULL && userPasswordMatches(candidate, password))
        {
            return candidate;
        }
    }

    for (size_t i = 0; i < users->count; ++i)
    {
        candidate = usersGetAtLocked(users, i);
        if (userPasswordMatches(candidate, password))
        {
            return candidate;
        }
    }

    return NULL;
}

static bool usersRemoveUserLocked(users_t *users, user_t *user)
{
    size_t index;

    if (! usersIndexOfLocked(users, user, &index))
    {
        return false;
    }

    user_t *victim = usersGetAtLocked(users, index);
    userDestroy(victim);

    if (index + 1U < users->count)
    {
        memoryMove(&users->items[index], &users->items[index + 1U],
                   (users->count - index - 1U) * sizeof(*users->items));
    }
    users->count -= 1U;
    users->items[users->count] = NULL;
    if (! usersRebuildLookupTablesLocked(users))
    {
        LOGF("Users: failed to rebuild lookup tables after removing a user");
        terminateProgram(1);
    }

    return true;
}

static void usersClearLocked(users_t *users)
{
    for (size_t i = 0; i < users->count; ++i)
    {
        userDestroy(usersGetAtLocked(users, i));
        users->items[i] = NULL;
    }

    users->count      = 0;
    users->slot_count = 0;
    usersHashTableClear(users->generic_hash_table);
    usersSHA256TableClear(users->sha256_table);
}

static void usersRollbackFeedLocked(users_t *users, size_t old_count, size_t old_slot_count,
                                    bool old_generic_available, bool old_generic_collision_seen)
{
    for (size_t i = old_count; i < users->count; ++i)
    {
        userDestroy(usersGetAtLocked(users, i));
        users->items[i] = NULL;
    }

    users->count                         = old_count;
    users->slot_count                    = old_slot_count;
    users->generic_hash_lookup_available = old_generic_available;
    users->generic_hash_collision_seen   = old_generic_collision_seen;

    if (! usersRebuildLookupTablesLocked(users))
    {
        LOGF("Users: failed to rebuild lookup tables while rolling back a failed JSON load");
        terminateProgram(1);
    }
}

static bool usersApplyNameHint(user_t *user, const char *name_hint)
{
    char *name = NULL;

    if (name_hint == NULL || name_hint[0] == '\0' || (user->name != NULL && user->name[0] != '\0'))
    {
        return true;
    }
    if (! usersStringDuplicate(&name, name_hint))
    {
        LOGE("Users: failed to allocate object-key username hint");
        return false;
    }

    memoryFree(user->name);
    user->name = name;
    return true;
}

static bool usersAppendJsonUserLocked(users_t *users, const cJSON *user_json, const char *name_hint)
{
    user_t *slot;

    if (! cJSON_IsObject(user_json))
    {
        LOGE("Users: user entry must be a JSON object");
        return false;
    }
    if (! usersReserveLocked(users, users->count + 1U))
    {
        return false;
    }

    slot = usersStorageAtLocked(users, users->slot_count);
    if (! userCreateFromJson(slot, user_json))
    {
        LOGE("Users: failed to create user from JSON entry at index %zu", users->count);
        return false;
    }
    if (! usersApplyNameHint(slot, name_hint))
    {
        userDestroy(slot);
        return false;
    }
    if (usersCommitNewUserLocked(users, slot))
    {
        return true;
    }

    userDestroy(slot);
    return false;
}

static bool usersFeedJsonArrayLocked(users_t *users, const cJSON *array)
{
    const cJSON *entry = NULL;

    cJSON_ArrayForEach(entry, array)
    {
        if (! usersAppendJsonUserLocked(users, entry, NULL))
        {
            return false;
        }
    }

    return true;
}

static bool usersFeedJsonObjectMapLocked(users_t *users, const cJSON *object)
{
    const cJSON *entry = NULL;

    cJSON_ArrayForEach(entry, object)
    {
        if (! usersAppendJsonUserLocked(users, entry, entry->string))
        {
            return false;
        }
    }

    return true;
}

static bool usersJsonObjectLooksLikeSingleUser(const cJSON *json)
{
    return cJSON_GetObjectItemCaseSensitive(json, "password") != NULL ||
           cJSON_GetObjectItemCaseSensitive(json, "pass") != NULL;
}

/*
 * Accepted layouts:
 * - null, an empty array, or an empty object: no-op success.
 * - [user, ...]
 * - {"users": [user, ...]}
 * - {"name": user, ...}, where the object key is used as a username hint.
 * - A single user object when it contains "password" or "pass".
 */
static bool usersFeedJsonLocked(users_t *users, const cJSON *json)
{
    if (json == NULL || cJSON_IsNull(json))
    {
        return true;
    }
    if (cJSON_IsArray(json))
    {
        return usersFeedJsonArrayLocked(users, json);
    }
    if (! cJSON_IsObject(json))
    {
        LOGE("Users: JSON input must be an object, array, or null");
        return false;
    }
    if (json->child == NULL)
    {
        return true;
    }

    const cJSON *users_array = cJSON_GetObjectItemCaseSensitive(json, "users");
    if (users_array != NULL)
    {
        if (cJSON_IsNull(users_array))
        {
            return true;
        }
        if (! cJSON_IsArray(users_array))
        {
            LOGE("Users: JSON field \"users\" must be an array");
            return false;
        }
        return usersFeedJsonArrayLocked(users, users_array);
    }
    if (usersJsonObjectLooksLikeSingleUser(json))
    {
        return usersAppendJsonUserLocked(users, json, NULL);
    }

    return usersFeedJsonObjectMapLocked(users, json);
}

static bool usersValidateUserLookupKeysLocked(const users_t *users)
{
    for (size_t i = 0; i < users->count; ++i)
    {
        const user_t *a = usersGetAtLocked(users, i);
        if (! a->sha256_pass_valid)
        {
            LOGE("Users: user \"%s\" has no SHA-256 lookup key", usersUserNameForLog(a));
            return false;
        }
        if (! userPasswordDataValid((user_t *) a))
        {
            LOGE("Users: user \"%s\" has inconsistent password lookup data", usersUserNameForLog(a));
            return false;
        }
        if (usersSHA256TableLookupLocked(users, a->sha256_pass.bytes) != a)
        {
            LOGE("Users: SHA-256 lookup table does not point back to user \"%s\"", usersUserNameForLog(a));
            return false;
        }
        if (users->generic_hash_lookup_available && usersHashTableLookupLocked(users, a->hash_pass) != a)
        {
            LOGE("Users: generic hash lookup table does not point back to user \"%s\"", usersUserNameForLog(a));
            return false;
        }

        for (size_t j = i + 1U; j < users->count; ++j)
        {
            const user_t *b = usersGetAtLocked(users, j);
            if (usersSha256Equal(a->sha256_pass.bytes, b->sha256_pass.bytes))
            {
                char key_hex[SHA256_DIGEST_SIZE * 2U + 1U];
                usersSha256ToHex(a->sha256_pass.bytes, key_hex);
                LOGF("Users: fatal SHA-256 lookup collision for key %s between users \"%s\" and \"%s\"", key_hex,
                     usersUserNameForLog(a), usersUserNameForLog(b));
                terminateProgram(1);
            }
            if (users->generic_hash_lookup_available && a->hash_pass == b->hash_pass)
            {
                LOGE("Users: generic hash collision exists while generic lookup is marked available");
                return false;
            }
            if (a->name != NULL && a->name[0] != '\0' && b->name != NULL && stringCompare(a->name, b->name) == 0)
            {
                LOGE("Users: duplicate username \"%s\"", a->name);
                return false;
            }
        }
    }

    return true;
}

bool usersCreate(users_t *users)
{
    if (users == NULL)
    {
        return false;
    }

    memoryZero(users, sizeof(*users));
    rwlockinit(&users->lock);
    users->generic_hash_lookup_available = true;
    if (! usersHashTableCreateIfNeeded(users) || ! usersSHA256TableCreateIfNeeded(users))
    {
        usersHashTableDestroy(users->generic_hash_table);
        usersSHA256TableDestroy(users->sha256_table);
        rwlockDestroy(&users->lock);
        memoryZero(users, sizeof(*users));
        return false;
    }

    return true;
}

void usersDestroy(users_t *users)
{
    if (users == NULL)
    {
        return;
    }

    usersClearLocked(users);
    for (size_t i = 0; i < users->block_count; ++i)
    {
        memoryFree(users->blocks[i]);
    }

    memoryFree(users->blocks);
    memoryFree(users->items);
    usersHashTableDestroy(users->generic_hash_table);
    usersSHA256TableDestroy(users->sha256_table);

    rwlockDestroy(&users->lock);
    memoryZero(users, sizeof(*users));
}

bool usersAddUser(users_t *users, const user_t *user)
{
    user_t *slot;
    user_t  user_copy;
    bool    result = false;

    if (users == NULL || user == NULL)
    {
        return false;
    }

    memoryZero(&user_copy, sizeof(user_copy));
    if (! userCopy(&user_copy, user))
    {
        return false;
    }

    rwlockWriteLock(&users->lock);
    if (usersReserveLocked(users, users->count + 1U))
    {
        slot = usersStorageAtLocked(users, users->slot_count);
        if (userCopy(slot, &user_copy))
        {
            result = usersCommitNewUserLocked(users, slot);
            if (! result)
            {
                userDestroy(slot);
            }
        }
    }
    rwlockWriteUnlock(&users->lock);
    userDestroy(&user_copy);
    return result;
}

bool usersAddUserFromJson(users_t *users, const cJSON *json)
{
    user_t user;
    bool   result;

    if (users == NULL || ! cJSON_IsObject(json))
    {
        return false;
    }

    memoryZero(&user, sizeof(user));
    if (! userCreateFromJson(&user, json))
    {
        LOGE("Users: failed to create user from JSON entry");
        return false;
    }

    result = usersAddUser(users, &user);
    userDestroy(&user);
    return result;
}

users_add_result_t usersAddUserFromJsonChecked(users_t *users, const cJSON *json)
{
    user_t             user;
    users_add_result_t result;

    if (users == NULL)
    {
        return kUsersAddResultInvalidArgument;
    }
    if (! cJSON_IsObject(json))
    {
        return kUsersAddResultInvalidJson;
    }

    memoryZero(&user, sizeof(user));
    if (! userCreateFromJson(&user, json))
    {
        LOGE("Users: failed to create user from JSON entry");
        return kUsersAddResultInvalidUser;
    }

    result = usersAddUserChecked(users, &user);
    userDestroy(&user);
    return result;
}

bool usersFeedJson(users_t *users, const cJSON *json)
{
    size_t old_count;
    size_t old_slot_count;
    bool   old_generic_available;
    bool   old_generic_collision_seen;
    bool   result;

    if (users == NULL)
    {
        return false;
    }

    rwlockWriteLock(&users->lock);
    old_count                  = users->count;
    old_slot_count             = users->slot_count;
    old_generic_available      = users->generic_hash_lookup_available;
    old_generic_collision_seen = users->generic_hash_collision_seen;

    result = usersFeedJsonLocked(users, json);
    if (! result)
    {
        usersRollbackFeedLocked(users, old_count, old_slot_count, old_generic_available, old_generic_collision_seen);
    }

    rwlockWriteUnlock(&users->lock);
    return result;
}

bool usersClear(users_t *users)
{
    if (users == NULL)
    {
        return false;
    }

    rwlockWriteLock(&users->lock);
    usersClearLocked(users);
    rwlockWriteUnlock(&users->lock);
    return true;
}

cJSON *usersToJson(const users_t *users)
{
    cJSON   *root  = NULL;
    cJSON   *array = NULL;
    users_t *self  = (users_t *) users;

    if (users == NULL)
    {
        return NULL;
    }

    root = cJSON_CreateObject();
    if (root == NULL)
    {
        return NULL;
    }
    array = cJSON_CreateArray();
    if (array == NULL)
    {
        cJSON_Delete(root);
        return NULL;
    }
    if (! cJSON_AddItemToObject(root, "users", array))
    {
        cJSON_Delete(array);
        cJSON_Delete(root);
        return NULL;
    }

    rwlockReadLock(&self->lock);
    for (size_t i = 0; i < users->count; ++i)
    {
        cJSON *user_json = userToJson(usersGetAtLocked(users, i));
        if (user_json == NULL)
        {
            rwlockReadUnlock(&self->lock);
            cJSON_Delete(root);
            return NULL;
        }
        if (! cJSON_AddItemToArray(array, user_json))
        {
            rwlockReadUnlock(&self->lock);
            cJSON_Delete(user_json);
            cJSON_Delete(root);
            return NULL;
        }
    }
    rwlockReadUnlock(&self->lock);

    return root;
}

bool usersGenericHashLookupAvailable(const users_t *users)
{
    bool result;

    if (users == NULL)
    {
        return false;
    }

    rwlockReadLock(&((users_t *) users)->lock);
    result = users->generic_hash_lookup_available;
    rwlockReadUnlock(&((users_t *) users)->lock);
    return result;
}

user_t *usersLookupByHash(users_t *users, hash_t hash)
{
    user_t *result;

    if (users == NULL)
    {
        return NULL;
    }

    rwlockReadLock(&users->lock);
    if (! users->generic_hash_lookup_available)
    {
        rwlockReadUnlock(&users->lock);
        LOGF("Users: generic hash lookup is disabled because collisions were detected during user database creation");
        terminateProgram(1);
    }
    result = usersHashTableLookupLocked(users, hash);
    rwlockReadUnlock(&users->lock);
    return result;
}

const user_t *usersLookupByHashConst(const users_t *users, hash_t hash)
{
    return usersLookupByHash((users_t *) users, hash);
}

user_t *usersLookupBySHA256(users_t *users, const uint8_t sha256[SHA256_DIGEST_SIZE])
{
    user_t *result;

    if (users == NULL || sha256 == NULL)
    {
        return NULL;
    }

    rwlockReadLock(&users->lock);
    result = usersSHA256TableLookupLocked(users, sha256);
    rwlockReadUnlock(&users->lock);
    return result;
}

const user_t *usersLookupBySHA256Const(const users_t *users, const uint8_t sha256[SHA256_DIGEST_SIZE])
{
    return usersLookupBySHA256((users_t *) users, sha256);
}

cJSON *usersUserToJsonBySHA256(const users_t *users, const uint8_t sha256[SHA256_DIGEST_SIZE])
{
    users_t *self = (users_t *) users;
    user_t  *user = NULL;
    cJSON   *json = NULL;

    if (users == NULL || sha256 == NULL)
    {
        return NULL;
    }

    rwlockReadLock(&self->lock);
    user = usersSHA256TableLookupLocked(self, sha256);
    if (user != NULL)
    {
        json = userToJson(user);
    }
    rwlockReadUnlock(&self->lock);
    return json;
}

cJSON *usersUserToJsonByPassword(const users_t *users, const char *password)
{
    users_password_probe_t password_probe;
    users_t               *self = (users_t *) users;
    user_t                *user = NULL;
    cJSON                 *json = NULL;

    if (users == NULL || password == NULL)
    {
        return NULL;
    }

    memoryZero(&password_probe, sizeof(password_probe));
    if (! usersPasswordProbeCreate(&password_probe, password))
    {
        return NULL;
    }

    rwlockReadLock(&self->lock);
    user = usersLookupByPasswordLocked(self, &password_probe, password);
    if (user != NULL)
    {
        json = userToJson(user);
    }
    rwlockReadUnlock(&self->lock);

    usersPasswordProbeDestroy(&password_probe);
    return json;
}

user_t *usersLookupByPassword(users_t *users, const char *password)
{
    users_password_probe_t password_probe;
    user_t                *result;

    if (users == NULL || password == NULL)
    {
        return NULL;
    }

    memoryZero(&password_probe, sizeof(password_probe));
    if (! usersPasswordProbeCreate(&password_probe, password))
    {
        return NULL;
    }

    rwlockReadLock(&users->lock);
    result = usersLookupByPasswordLocked(users, &password_probe, password);
    rwlockReadUnlock(&users->lock);

    usersPasswordProbeDestroy(&password_probe);
    return result;
}

const user_t *usersLookupByPasswordConst(const users_t *users, const char *password)
{
    return usersLookupByPassword((users_t *) users, password);
}

bool usersRemoveUser(users_t *users, user_t *user)
{
    bool result;

    if (users == NULL || user == NULL)
    {
        return false;
    }

    rwlockWriteLock(&users->lock);
    result = usersRemoveUserLocked(users, user);
    rwlockWriteUnlock(&users->lock);
    return result;
}

bool usersRemoveUserBySHA256(users_t *users, const uint8_t sha256[SHA256_DIGEST_SIZE])
{
    user_t *user;
    bool    result = false;

    if (users == NULL || sha256 == NULL)
    {
        return false;
    }

    rwlockWriteLock(&users->lock);
    user = usersSHA256TableLookupLocked(users, sha256);
    if (user != NULL)
    {
        result = usersRemoveUserLocked(users, user);
    }
    rwlockWriteUnlock(&users->lock);
    return result;
}

bool usersRemoveUserByHash(users_t *users, hash_t hash)
{
    user_t *user;
    bool    result = false;

    if (users == NULL)
    {
        return false;
    }

    rwlockWriteLock(&users->lock);
    if (! users->generic_hash_lookup_available)
    {
        rwlockWriteUnlock(&users->lock);
        LOGF("Users: generic hash lookup is disabled because collisions were detected during user database creation");
        terminateProgram(1);
    }
    user = usersHashTableLookupLocked(users, hash);
    if (user != NULL)
    {
        result = usersRemoveUserLocked(users, user);
    }
    rwlockWriteUnlock(&users->lock);
    return result;
}

bool usersChangePassword(users_t *users, user_t *user, const char *password)
{
    bool result;

    if (users == NULL || user == NULL)
    {
        return false;
    }

    rwlockWriteLock(&users->lock);
    result = usersChangePasswordLocked(users, user, password);
    rwlockWriteUnlock(&users->lock);
    return result;
}

bool usersUpdateUser(users_t *users, user_t *user, const user_update_t *update)
{
    char   *name_copy  = NULL;
    char   *email_copy = NULL;
    char   *notes_copy = NULL;
    user_t *duplicate_name;

    if (users == NULL || user == NULL || update == NULL)
    {
        return false;
    }
    if ((update->mask & ~((uint32_t) kKnownUserUpdateMask)) != 0U)
    {
        LOGE("Users: update request contains unknown fields");
        return false;
    }
    if ((update->mask & kUserUpdateRecordStatInterval) != 0U && update->record_stat_interval_ms < 0)
    {
        LOGE("Users: record stat interval must not be negative");
        return false;
    }

    if ((update->mask & kUserUpdateName) != 0U && ! usersStringDuplicate(&name_copy, update->name))
    {
        return false;
    }
    if ((update->mask & kUserUpdateEmail) != 0U && ! usersStringDuplicate(&email_copy, update->email))
    {
        memoryFree(name_copy);
        return false;
    }
    if ((update->mask & kUserUpdateNotes) != 0U && ! usersStringDuplicate(&notes_copy, update->notes))
    {
        memoryFree(name_copy);
        memoryFree(email_copy);
        return false;
    }

    rwlockWriteLock(&users->lock);
    if (! usersIndexOfLocked(users, user, NULL))
    {
        rwlockWriteUnlock(&users->lock);
        memoryFree(name_copy);
        memoryFree(email_copy);
        memoryFree(notes_copy);
        return false;
    }

    if ((update->mask & kUserUpdateName) != 0U)
    {
        duplicate_name = usersFindByNameLocked(users, name_copy, user);
        if (duplicate_name != NULL)
        {
            LOGE("Users: duplicate username \"%s\" in update", name_copy);
            rwlockWriteUnlock(&users->lock);
            memoryFree(name_copy);
            memoryFree(email_copy);
            memoryFree(notes_copy);
            return false;
        }
    }
    if ((update->mask & kUserUpdatePassword) != 0U && ! usersChangePasswordLocked(users, user, update->password))
    {
        rwlockWriteUnlock(&users->lock);
        memoryFree(name_copy);
        memoryFree(email_copy);
        memoryFree(notes_copy);
        return false;
    }

    rwlockWriteLock(&user->lock);
    if ((update->mask & kUserUpdateName) != 0U)
    {
        usersReplaceStringOwned(&user->name, &name_copy);
    }
    if ((update->mask & kUserUpdateEmail) != 0U)
    {
        usersReplaceStringOwned(&user->email, &email_copy);
    }
    if ((update->mask & kUserUpdateNotes) != 0U)
    {
        usersReplaceStringOwned(&user->notes, &notes_copy);
    }
    if ((update->mask & kUserUpdateGid) != 0U)
    {
        user->gid = update->gid;
    }
    if ((update->mask & kUserUpdateEnabled) != 0U)
    {
        user->enabled = update->enabled;
    }
    if ((update->mask & kUserUpdateLimit) != 0U)
    {
        user->limit = update->limit;
    }
    if ((update->mask & kUserUpdateTimeInfo) != 0U)
    {
        user->timeinfo = update->timeinfo;
    }
    if ((update->mask & kUserUpdateRecordStatInterval) != 0U)
    {
        user->record_stat_interval_ms = update->record_stat_interval_ms;
    }
    rwlockWriteUnlock(&user->lock);

    if ((update->mask & kUserUpdateStats) != 0U)
    {
        rwlockWriteLock(&user->stats_lock);
        user->stats = update->stats;
        rwlockWriteUnlock(&user->stats_lock);
    }

    rwlockWriteUnlock(&users->lock);

    memoryFree(name_copy);
    memoryFree(email_copy);
    memoryFree(notes_copy);
    return true;
}

bool usersSetUserName(users_t *users, user_t *user, const char *name)
{
    user_update_t update = {.mask = kUserUpdateName, .name = name};
    return usersUpdateUser(users, user, &update);
}

bool usersSetUserEmail(users_t *users, user_t *user, const char *email)
{
    user_update_t update = {.mask = kUserUpdateEmail, .email = email};
    return usersUpdateUser(users, user, &update);
}

bool usersSetUserNotes(users_t *users, user_t *user, const char *notes)
{
    user_update_t update = {.mask = kUserUpdateNotes, .notes = notes};
    return usersUpdateUser(users, user, &update);
}

bool usersSetUserGid(users_t *users, user_t *user, hash_t gid)
{
    user_update_t update = {.mask = kUserUpdateGid, .gid = gid};
    return usersUpdateUser(users, user, &update);
}

bool usersSetUserEnabled(users_t *users, user_t *user, bool enabled)
{
    user_update_t update = {.mask = kUserUpdateEnabled, .enabled = enabled};
    return usersUpdateUser(users, user, &update);
}

bool usersSetUserLimit(users_t *users, user_t *user, const user_limit_t *limit)
{
    user_update_t update = {.mask = kUserUpdateLimit};

    if (limit == NULL)
    {
        return false;
    }

    update.limit = *limit;
    return usersUpdateUser(users, user, &update);
}

bool usersSetUserTimeInfo(users_t *users, user_t *user, const user_time_info_t *timeinfo)
{
    user_update_t update = {.mask = kUserUpdateTimeInfo};

    if (timeinfo == NULL)
    {
        return false;
    }

    update.timeinfo = *timeinfo;
    return usersUpdateUser(users, user, &update);
}

bool usersSetUserStats(users_t *users, user_t *user, const user_stat_t *stats)
{
    user_update_t update = {.mask = kUserUpdateStats};

    if (stats == NULL)
    {
        return false;
    }

    update.stats = *stats;
    return usersUpdateUser(users, user, &update);
}

bool usersSetUserRecordStatInterval(users_t *users, user_t *user, int interval_ms)
{
    user_update_t update = {.mask = kUserUpdateRecordStatInterval, .record_stat_interval_ms = interval_ms};
    return usersUpdateUser(users, user, &update);
}

bool usersAddTraffic(users_t *users, user_t *user, uint64_t upload_bytes, uint64_t download_bytes)
{
    bool result;

    if (users == NULL || user == NULL)
    {
        return false;
    }

    rwlockReadLock(&users->lock);
    result = usersIndexOfLocked(users, user, NULL);
    if (result)
    {
        userAddTraffic(user, upload_bytes, download_bytes);
    }
    rwlockReadUnlock(&users->lock);
    return result;
}

bool usersAddUserUsage(users_t *users, user_t *user, uint64_t upload_bytes, uint64_t download_bytes)
{
    return usersAddTraffic(users, user, upload_bytes, download_bytes);
}

bool usersAddSpeed(users_t *users, user_t *user, uint64_t upload_bytes_per_sec, uint64_t download_bytes_per_sec)
{
    bool result;

    if (users == NULL || user == NULL)
    {
        return false;
    }

    rwlockReadLock(&users->lock);
    result = usersIndexOfLocked(users, user, NULL);
    if (result)
    {
        userAddSpeed(user, upload_bytes_per_sec, download_bytes_per_sec);
    }
    rwlockReadUnlock(&users->lock);
    return result;
}

bool usersAddConnection(users_t *users, user_t *user, bool inbound)
{
    bool result;

    if (users == NULL || user == NULL)
    {
        return false;
    }

    rwlockReadLock(&users->lock);
    result = usersIndexOfLocked(users, user, NULL);
    if (result)
    {
        userAddConnection(user, inbound);
    }
    rwlockReadUnlock(&users->lock);
    return result;
}

bool usersRemoveConnection(users_t *users, user_t *user, bool inbound)
{
    bool result;

    if (users == NULL || user == NULL)
    {
        return false;
    }

    rwlockReadLock(&users->lock);
    result = usersIndexOfLocked(users, user, NULL);
    if (result)
    {
        userRemoveConnection(user, inbound);
    }
    rwlockReadUnlock(&users->lock);
    return result;
}

bool usersSetIpCount(users_t *users, user_t *user, uint64_t ips)
{
    bool result;

    if (users == NULL || user == NULL)
    {
        return false;
    }

    rwlockReadLock(&users->lock);
    result = usersIndexOfLocked(users, user, NULL);
    if (result)
    {
        userSetIpCount(user, ips);
    }
    rwlockReadUnlock(&users->lock);
    return result;
}

bool usersSetDeviceCount(users_t *users, user_t *user, uint64_t devices)
{
    bool result;

    if (users == NULL || user == NULL)
    {
        return false;
    }

    rwlockReadLock(&users->lock);
    result = usersIndexOfLocked(users, user, NULL);
    if (result)
    {
        userSetDeviceCount(user, devices);
    }
    rwlockReadUnlock(&users->lock);
    return result;
}

bool usersMarkFirstUsage(users_t *users, user_t *user, uint64_t now_ms)
{
    bool result;

    if (users == NULL || user == NULL)
    {
        return false;
    }

    rwlockReadLock(&users->lock);
    result = usersIndexOfLocked(users, user, NULL);
    if (result)
    {
        userMarkFirstUsage(user, now_ms);
    }
    rwlockReadUnlock(&users->lock);
    return result;
}

bool usersResetUsage(users_t *users, user_t *user)
{
    bool result;

    if (users == NULL || user == NULL)
    {
        return false;
    }

    rwlockReadLock(&users->lock);
    result = usersIndexOfLocked(users, user, NULL);
    if (result)
    {
        rwlockWriteLock(&user->stats_lock);
        memoryZero(&user->stats.speed, sizeof(user->stats.speed));
        memoryZero(&user->stats.traffic, sizeof(user->stats.traffic));
        rwlockWriteUnlock(&user->stats_lock);
    }
    rwlockReadUnlock(&users->lock);
    return result;
}

bool usersResetUserUsage(users_t *users, user_t *user)
{
    return usersResetUsage(users, user);
}

bool usersResetStats(users_t *users, user_t *user)
{
    bool result;

    if (users == NULL || user == NULL)
    {
        return false;
    }

    rwlockReadLock(&users->lock);
    result = usersIndexOfLocked(users, user, NULL);
    if (result)
    {
        rwlockWriteLock(&user->stats_lock);
        memoryZero(&user->stats, sizeof(user->stats));
        rwlockWriteUnlock(&user->stats_lock);
    }
    rwlockReadUnlock(&users->lock);
    return result;
}

bool usersUserLimitReached(users_t *users, const user_t *user)
{
    bool result = false;

    if (users == NULL || user == NULL)
    {
        return false;
    }

    rwlockReadLock(&users->lock);
    if (usersIndexOfLocked(users, user, NULL))
    {
        result = userHasReachedLimit((user_t *) user);
    }
    rwlockReadUnlock(&users->lock);
    return result;
}

bool usersUserEnabled(users_t *users, const user_t *user)
{
    bool result = false;

    if (users == NULL || user == NULL)
    {
        return false;
    }

    rwlockReadLock(&users->lock);
    if (usersIndexOfLocked(users, user, NULL))
    {
        result = userIsEnabled((user_t *) user);
    }
    rwlockReadUnlock(&users->lock);
    return result;
}

bool usersUserDisabled(users_t *users, const user_t *user)
{
    bool result = false;

    if (users == NULL || user == NULL)
    {
        return false;
    }

    rwlockReadLock(&users->lock);
    if (usersIndexOfLocked(users, user, NULL))
    {
        result = userIsDisabled((user_t *) user);
    }
    rwlockReadUnlock(&users->lock);
    return result;
}

bool usersUserExpired(users_t *users, const user_t *user, uint64_t now_ms)
{
    bool result = false;

    if (users == NULL || user == NULL)
    {
        return false;
    }

    rwlockReadLock(&users->lock);
    if (usersIndexOfLocked(users, user, NULL))
    {
        result = userIsExpired((user_t *) user, now_ms);
    }
    rwlockReadUnlock(&users->lock);
    return result;
}

bool usersUserActive(users_t *users, const user_t *user, uint64_t now_ms)
{
    bool result = false;

    if (users == NULL || user == NULL)
    {
        return false;
    }

    rwlockReadLock(&users->lock);
    if (usersIndexOfLocked(users, user, NULL))
    {
        result = userIsActive((user_t *) user, now_ms);
    }
    rwlockReadUnlock(&users->lock);
    return result;
}

size_t usersCount(const users_t *users)
{
    size_t result;

    if (users == NULL)
    {
        return 0;
    }

    rwlockReadLock(&((users_t *) users)->lock);
    result = users->count;
    rwlockReadUnlock(&((users_t *) users)->lock);
    return result;
}

bool usersIsEmpty(const users_t *users)
{
    return usersCount(users) == 0;
}

bool usersReserve(users_t *users, size_t capacity)
{
    bool result;

    if (users == NULL)
    {
        return false;
    }

    rwlockWriteLock(&users->lock);
    result = usersReserveLocked(users, capacity);
    rwlockWriteUnlock(&users->lock);
    return result;
}

user_t *usersGetAt(users_t *users, size_t index)
{
    user_t *result = NULL;

    if (users == NULL)
    {
        return NULL;
    }

    rwlockReadLock(&users->lock);
    if (index < users->count)
    {
        result = usersGetAtLocked(users, index);
    }
    rwlockReadUnlock(&users->lock);
    return result;
}

const user_t *usersGetAtConst(const users_t *users, size_t index)
{
    return usersGetAt((users_t *) users, index);
}

bool usersContainsUser(const users_t *users, const user_t *user)
{
    bool result;

    if (users == NULL)
    {
        return false;
    }

    rwlockReadLock(&((users_t *) users)->lock);
    result = usersIndexOfLocked(users, user, NULL);
    rwlockReadUnlock(&((users_t *) users)->lock);
    return result;
}

bool usersRebuildLookups(users_t *users)
{
    bool result;

    if (users == NULL)
    {
        return false;
    }

    rwlockWriteLock(&users->lock);
    result = usersRebuildLookupTablesLocked(users);
    rwlockWriteUnlock(&users->lock);
    return result;
}

bool usersValidate(const users_t *users)
{
    bool     result;
    users_t *self = (users_t *) users;

    if (users == NULL)
    {
        return false;
    }

    rwlockReadLock(&self->lock);
    result = usersValidateUserLookupKeysLocked(users);
    rwlockReadUnlock(&self->lock);
    return result;
}

user_stat_t usersUsageDiff(users_t *users, user_t *base, user_t *current)
{
    user_stat_t diff = {0};

    if (users == NULL || base == NULL || current == NULL)
    {
        return diff;
    }

    rwlockReadLock(&users->lock);
    if (usersIndexOfLocked(users, base, NULL) && usersIndexOfLocked(users, current, NULL))
    {
        diff = userStatsDiff(base, current);
    }
    rwlockReadUnlock(&users->lock);
    return diff;
}

user_t *usersFindFirstExpired(users_t *users, uint64_t now_ms)
{
    user_t *result = NULL;

    if (users == NULL)
    {
        return NULL;
    }

    rwlockReadLock(&users->lock);
    for (size_t i = 0; i < users->count; ++i)
    {
        user_t *user = usersGetAtLocked(users, i);
        if (userIsExpired(user, now_ms))
        {
            result = user;
            break;
        }
    }
    rwlockReadUnlock(&users->lock);
    return result;
}

const user_t *usersFindFirstExpiredConst(const users_t *users, uint64_t now_ms)
{
    return usersFindFirstExpired((users_t *) users, now_ms);
}

user_t *usersFindFirstDisabled(users_t *users)
{
    user_t *result = NULL;

    if (users == NULL)
    {
        return NULL;
    }

    rwlockReadLock(&users->lock);
    for (size_t i = 0; i < users->count; ++i)
    {
        user_t *user = usersGetAtLocked(users, i);
        if (userIsDisabled(user))
        {
            result = user;
            break;
        }
    }
    rwlockReadUnlock(&users->lock);
    return result;
}

const user_t *usersFindFirstDisabledConst(const users_t *users)
{
    return usersFindFirstDisabled((users_t *) users);
}

user_t *usersFindFirstLimited(users_t *users)
{
    user_t *result = NULL;

    if (users == NULL)
    {
        return NULL;
    }

    rwlockReadLock(&users->lock);
    for (size_t i = 0; i < users->count; ++i)
    {
        user_t *user = usersGetAtLocked(users, i);
        if (userHasReachedLimit(user))
        {
            result = user;
            break;
        }
    }
    rwlockReadUnlock(&users->lock);
    return result;
}

const user_t *usersFindFirstLimitedConst(const users_t *users)
{
    return usersFindFirstLimited((users_t *) users);
}
