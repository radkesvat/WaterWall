/*
 * User database manager implementation.
 */

#include "objects/users.h"

#include "loggers/internal_logger.h"

#include <stddef.h>

enum
{
    kUsersBlockSize            = 64,
    kUsersInitialTableCapacity = 16,
    kKnownUserUpdateMask       = kUserUpdatePassword | kUserUpdateName | kUserUpdateEmail | kUserUpdateNotes |
                                 kUserUpdateGid | kUserUpdateEnabled | kUserUpdateLimit | kUserUpdateTimeInfo |
                                 kUserUpdateStats | kUserUpdateRecordStatInterval
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

typedef struct users_password_probe_s
{
    MSVC_ATTR_ALIGNED_32 sha224_hash_t sha224_pass GNU_ATTR_ALIGNED_32;
    uint8_t       sha224_pass_padding[SHA256_DIGEST_SIZE - SHA224_DIGEST_SIZE];
    MSVC_ATTR_ALIGNED_32 sha256_hash_t sha256_pass GNU_ATTR_ALIGNED_32;
    uint8_t uuid_pass[kWwUuidBytesLen];
    uint8_t wireguard_publickey[USER_WIREGUARD_PUBLICKEY_SIZE];
    bool sha224_pass_valid;
    bool sha256_pass_valid;
    bool uuid_pass_valid;
    bool wireguard_publickey_valid;
} users_password_probe_t;

_Static_assert(offsetof(users_password_probe_t, sha224_pass) % 32U == 0,
               "users_password_probe_t.sha224_pass must be 32-byte aligned");
_Static_assert(offsetof(users_password_probe_t, sha256_pass) % 32U == 0,
               "users_password_probe_t.sha256_pass must be 32-byte aligned");
_Static_assert(_Alignof(users_password_probe_t) >= 32U,
               "users_password_probe_t storage must be at least 32-byte aligned");
_Static_assert(sizeof(users_password_probe_t) % 32U == 0,
               "users_password_probe_t storage size must be a 32-byte multiple");

static uint64_t usersSHA224KeyHash(const users_sha224_key_t *key)
{
    return calcHashBytes(key->bytes, SHA224_DIGEST_SIZE);
}

static uint64_t usersSHA256KeyHash(const users_sha256_key_t *key)
{
    return calcHashBytes(key->bytes, SHA256_DIGEST_SIZE);
}

static uint64_t usersUUIDKeyHash(const users_uuid_key_t *key)
{
    return calcHashBytes(key->bytes, kWwUuidBytesLen);
}

static uint64_t usersWireGuardPublicKeyHash(const users_wireguard_publickey_key_t *key)
{
    return calcHashBytes(key->bytes, USER_WIREGUARD_PUBLICKEY_SIZE);
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
#define i_val  user_t  *          // NOLINT
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
#define i_val  user_t  *        // NOLINT
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
#define i_val  user_t  *                       // NOLINT
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

static void *usersAllocateAlignedZero32(size_t size)
{
    assert((size & 31U) == 0);

    /*
     * users_t-owned user_t objects rely on real 32-byte base alignment so their
     * SHA fields are actually 32-byte aligned at runtime. Keep this as aligned
     * allocation plus strict zeroing; do not replace it with memoryAllocateZero().
     */
    void *ptr = memoryAllocateAligned(size, 32);
    if (LIKELY(ptr != NULL))
    {
        memoryZeroAligned32(ptr, size);
    }
    return ptr;
}

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
    if (UNLIKELY(user == NULL || user->name == NULL || user->name[0] == '\0'))
    {
        return "<unnamed>";
    }
    return user->name;
}

static bool usersStringDuplicate(char **dest, const char *value)
{
    char *copy = stringDuplicate(value != NULL ? value : "");
    if (UNLIKELY(copy == NULL))
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

static bool usersSha224Equal(const uint8_t a[SHA224_DIGEST_SIZE], const uint8_t b[SHA224_DIGEST_SIZE])
{
    return wCryptoEqual(a, b, SHA224_DIGEST_SIZE);
}

static bool usersSha256Equal(const uint8_t a[SHA256_DIGEST_SIZE], const uint8_t b[SHA256_DIGEST_SIZE])
{
    return wCryptoEqual(a, b, SHA256_DIGEST_SIZE);
}

static bool usersUUIDEqual(const uint8_t a[kWwUuidBytesLen], const uint8_t b[kWwUuidBytesLen])
{
    return wCryptoEqual(a, b, kWwUuidBytesLen);
}

static bool usersWireGuardPublicKeyEqual(const uint8_t a[USER_WIREGUARD_PUBLICKEY_SIZE],
                                         const uint8_t b[USER_WIREGUARD_PUBLICKEY_SIZE])
{
    return wCryptoEqual(a, b, USER_WIREGUARD_PUBLICKEY_SIZE);
}

static void usersSha224ToHex(const uint8_t sha224[SHA224_DIGEST_SIZE], char out[SHA224_DIGEST_SIZE * 2U + 1U])
{
    static const char hex[] = "0123456789abcdef";

    for (size_t i = 0; i < SHA224_DIGEST_SIZE; ++i)
    {
        out[i * 2U]      = hex[(sha224[i] >> 4U) & 0x0FU];
        out[i * 2U + 1U] = hex[sha224[i] & 0x0FU];
    }
    out[SHA224_DIGEST_SIZE * 2U] = '\0';
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

static users_sha224_key_t usersSHA224KeyFromBytes(const uint8_t bytes[SHA224_DIGEST_SIZE])
{
    users_sha224_key_t key = {0};

    memoryCopy(key.bytes, bytes, SHA224_DIGEST_SIZE);
    return key;
}

static users_sha256_key_t usersSHA256KeyFromBytes(const uint8_t bytes[SHA256_DIGEST_SIZE])
{
    users_sha256_key_t key = {0};

    memoryCopy(key.bytes, bytes, SHA256_DIGEST_SIZE);
    return key;
}

static users_uuid_key_t usersUUIDKeyFromBytes(const uint8_t bytes[kWwUuidBytesLen])
{
    users_uuid_key_t key = {0};

    memoryCopy(key.bytes, bytes, kWwUuidBytesLen);
    return key;
}

static users_wireguard_publickey_key_t usersWireGuardPublicKeyFromBytes(
    const uint8_t bytes[USER_WIREGUARD_PUBLICKEY_SIZE])
{
    users_wireguard_publickey_key_t key = {0};

    memoryCopy(key.bytes, bytes, USER_WIREGUARD_PUBLICKEY_SIZE);
    return key;
}

static bool usersPasswordProbeCreate(users_password_probe_t *probe, const char *password,
                                     bool derive_wireguard_publickey)
{
    static const uint8_t wireguard_basepoint[USER_WIREGUARD_PUBLICKEY_SIZE] = {9};

    if (UNLIKELY(probe == NULL || password == NULL || password[0] == '\0'))
    {
        return false;
    }

    memoryZero(probe, sizeof(*probe));

    const size_t password_len = stringLength(password);
    if (UNLIKELY(wCryptoSHA224(&probe->sha224_pass, (const unsigned char *) password, password_len) != 0))
    {
        wCryptoZero(&probe->sha224_pass, sizeof(probe->sha224_pass));
        return false;
    }
    if (UNLIKELY(wCryptoSHA256(&probe->sha256_pass, (const unsigned char *) password, password_len) != 0))
    {
        wCryptoZero(&probe->sha224_pass, sizeof(probe->sha224_pass));
        wCryptoZero(&probe->sha256_pass, sizeof(probe->sha256_pass));
        return false;
    }
    probe->sha224_pass_valid = true;
    probe->sha256_pass_valid = true;
    if (derive_wireguard_publickey)
    {
        if (UNLIKELY(performX25519(probe->wireguard_publickey, probe->sha256_pass.bytes, wireguard_basepoint) != 0))
        {
            wCryptoZero(&probe->sha224_pass, sizeof(probe->sha224_pass));
            wCryptoZero(&probe->sha256_pass, sizeof(probe->sha256_pass));
            memoryZero(probe->wireguard_publickey, sizeof(probe->wireguard_publickey));
            return false;
        }
        probe->wireguard_publickey_valid = true;
    }
    if (wwUuidParseString(password, probe->uuid_pass))
    {
        probe->uuid_pass_valid = true;
    }

    return true;
}

static void usersPasswordProbeDestroy(users_password_probe_t *probe)
{
    if (UNLIKELY(probe == NULL))
    {
        return;
    }

    wCryptoZero(&probe->sha224_pass, sizeof(probe->sha224_pass));
    wCryptoZero(&probe->sha256_pass, sizeof(probe->sha256_pass));
    memoryZero(probe->uuid_pass, sizeof(probe->uuid_pass));
    memoryZero(probe->wireguard_publickey, sizeof(probe->wireguard_publickey));
    memoryZero(probe, sizeof(*probe));
}

static bool usersSHA224TableReserve(users_sha224_table_t *table, size_t count)
{
    size_t capacity = count < kUsersInitialTableCapacity ? kUsersInitialTableCapacity : count;

    if (UNLIKELY(capacity > (size_t) PTRDIFF_MAX))
    {
        LOGE("Users: SHA-224 lookup table capacity overflow");
        return false;
    }
    if (UNLIKELY(! users_sha224_map_t_reserve(&table->map, (isize) capacity)))
    {
        LOGE("Users: failed to reserve SHA-224 lookup table");
        return false;
    }

    return true;
}

static bool usersSHA256TableReserve(users_sha256_table_t *table, size_t count)
{
    size_t capacity = count < kUsersInitialTableCapacity ? kUsersInitialTableCapacity : count;

    if (UNLIKELY(capacity > (size_t) PTRDIFF_MAX))
    {
        LOGE("Users: SHA-256 lookup table capacity overflow");
        return false;
    }
    if (UNLIKELY(! users_sha256_map_t_reserve(&table->map, (isize) capacity)))
    {
        LOGE("Users: failed to reserve SHA-256 lookup table");
        return false;
    }

    return true;
}

static bool usersUUIDTableReserve(users_uuid_table_t *table, size_t count)
{
    size_t capacity = count < kUsersInitialTableCapacity ? kUsersInitialTableCapacity : count;

    if (UNLIKELY(capacity > (size_t) PTRDIFF_MAX))
    {
        LOGE("Users: UUID lookup table capacity overflow");
        return false;
    }
    if (UNLIKELY(! users_uuid_map_t_reserve(&table->map, (isize) capacity)))
    {
        LOGE("Users: failed to reserve UUID lookup table");
        return false;
    }

    return true;
}

static bool usersWireGuardPublicKeyTableReserve(users_wireguard_publickey_table_t *table, size_t count)
{
    size_t capacity = count < kUsersInitialTableCapacity ? kUsersInitialTableCapacity : count;

    if (UNLIKELY(capacity > (size_t) PTRDIFF_MAX))
    {
        LOGE("Users: WireGuard public key lookup table capacity overflow");
        return false;
    }
    if (UNLIKELY(! users_wireguard_publickey_map_t_reserve(&table->map, (isize) capacity)))
    {
        LOGE("Users: failed to reserve WireGuard public key lookup table");
        return false;
    }

    return true;
}

static bool usersIDTableReserve(users_id_table_t *table, size_t count)
{
    size_t capacity = count < kUsersInitialTableCapacity ? kUsersInitialTableCapacity : count;

    if (UNLIKELY(capacity > (size_t) PTRDIFF_MAX))
    {
        LOGE("Users: id lookup table capacity overflow");
        return false;
    }
    if (UNLIKELY(! users_id_map_t_reserve(&table->map, (isize) capacity)))
    {
        LOGE("Users: failed to reserve id lookup table");
        return false;
    }

    return true;
}

static bool usersSHA224TableCreateIfNeeded(users_t *users)
{
    users_sha224_table_t *table;

    if (LIKELY(users->sha224_table != NULL))
    {
        return true;
    }

    table = memoryAllocate(sizeof(*table));
    if (UNLIKELY(table == NULL))
    {
        LOGE("Users: failed to allocate SHA-224 lookup table");
        return false;
    }
    memoryZero(table, sizeof(*table));

    if (UNLIKELY(! usersSHA224TableReserve(table, kUsersInitialTableCapacity)))
    {
        users_sha224_map_t_drop(&table->map);
        memoryFree(table);
        return false;
    }

    users->sha224_table = table;
    return true;
}

static bool usersSHA256TableCreateIfNeeded(users_t *users)
{
    users_sha256_table_t *table;

    if (LIKELY(users->sha256_table != NULL))
    {
        return true;
    }

    table = memoryAllocate(sizeof(*table));
    if (UNLIKELY(table == NULL))
    {
        LOGE("Users: failed to allocate SHA-256 lookup table");
        return false;
    }
    memoryZero(table, sizeof(*table));

    if (UNLIKELY(! usersSHA256TableReserve(table, kUsersInitialTableCapacity)))
    {
        users_sha256_map_t_drop(&table->map);
        memoryFree(table);
        return false;
    }

    users->sha256_table = table;
    return true;
}

static bool usersUUIDTableCreateIfNeeded(users_t *users)
{
    users_uuid_table_t *table;

    if (LIKELY(users->uuid_table != NULL))
    {
        return true;
    }

    table = memoryAllocate(sizeof(*table));
    if (UNLIKELY(table == NULL))
    {
        LOGE("Users: failed to allocate UUID lookup table");
        return false;
    }
    memoryZero(table, sizeof(*table));

    if (UNLIKELY(! usersUUIDTableReserve(table, kUsersInitialTableCapacity)))
    {
        users_uuid_map_t_drop(&table->map);
        memoryFree(table);
        return false;
    }

    users->uuid_table = table;
    return true;
}

static bool usersWireGuardPublicKeyTableCreateIfNeeded(users_t *users)
{
    users_wireguard_publickey_table_t *table;

    if (LIKELY(users->wireguard_publickey_table != NULL))
    {
        return true;
    }

    table = memoryAllocate(sizeof(*table));
    if (UNLIKELY(table == NULL))
    {
        LOGE("Users: failed to allocate WireGuard public key lookup table");
        return false;
    }
    memoryZero(table, sizeof(*table));

    if (UNLIKELY(! usersWireGuardPublicKeyTableReserve(table, kUsersInitialTableCapacity)))
    {
        users_wireguard_publickey_map_t_drop(&table->map);
        memoryFree(table);
        return false;
    }

    users->wireguard_publickey_table = table;
    return true;
}

static bool usersIDTableCreateIfNeeded(users_t *users)
{
    users_id_table_t *table;

    if (LIKELY(users->id_table != NULL))
    {
        return true;
    }

    table = memoryAllocate(sizeof(*table));
    if (UNLIKELY(table == NULL))
    {
        LOGE("Users: failed to allocate id lookup table");
        return false;
    }
    memoryZero(table, sizeof(*table));

    if (UNLIKELY(! usersIDTableReserve(table, kUsersInitialTableCapacity)))
    {
        users_id_map_t_drop(&table->map);
        memoryFree(table);
        return false;
    }

    users->id_table = table;
    return true;
}

static bool usersSHA256TableEnsureCapacity(users_t *users, size_t count)
{
    return usersSHA256TableCreateIfNeeded(users) && usersSHA256TableReserve(users->sha256_table, count);
}

static bool usersSHA224TableEnsureCapacity(users_t *users, size_t count)
{
    return usersSHA224TableCreateIfNeeded(users) && usersSHA224TableReserve(users->sha224_table, count);
}

static bool usersUUIDTableEnsureCapacity(users_t *users, size_t count)
{
    return usersUUIDTableCreateIfNeeded(users) && usersUUIDTableReserve(users->uuid_table, count);
}

static bool usersWireGuardPublicKeyTableEnsureCapacity(users_t *users, size_t count)
{
    return usersWireGuardPublicKeyTableCreateIfNeeded(users) &&
           usersWireGuardPublicKeyTableReserve(users->wireguard_publickey_table, count);
}

static bool usersIDTableEnsureCapacity(users_t *users, size_t count)
{
    return usersIDTableCreateIfNeeded(users) && usersIDTableReserve(users->id_table, count);
}

static void usersSHA224TableClear(users_sha224_table_t *table)
{
    if (UNLIKELY(table == NULL))
    {
        return;
    }

    users_sha224_map_t_clear(&table->map);
}

static void usersSHA256TableClear(users_sha256_table_t *table)
{
    if (UNLIKELY(table == NULL))
    {
        return;
    }

    users_sha256_map_t_clear(&table->map);
}

static void usersUUIDTableClear(users_uuid_table_t *table)
{
    if (UNLIKELY(table == NULL))
    {
        return;
    }

    users_uuid_map_t_clear(&table->map);
}

static void usersWireGuardPublicKeyTableClear(users_wireguard_publickey_table_t *table)
{
    if (UNLIKELY(table == NULL))
    {
        return;
    }

    users_wireguard_publickey_map_t_clear(&table->map);
}

static void usersIDTableClear(users_id_table_t *table)
{
    if (UNLIKELY(table == NULL))
    {
        return;
    }

    users_id_map_t_clear(&table->map);
}

static void usersSHA224TableDestroy(users_sha224_table_t *table)
{
    if (UNLIKELY(table == NULL))
    {
        return;
    }

    users_sha224_map_t_drop(&table->map);
    memoryFree(table);
}

static void usersSHA256TableDestroy(users_sha256_table_t *table)
{
    if (UNLIKELY(table == NULL))
    {
        return;
    }

    users_sha256_map_t_drop(&table->map);
    memoryFree(table);
}

static void usersUUIDTableDestroy(users_uuid_table_t *table)
{
    if (UNLIKELY(table == NULL))
    {
        return;
    }

    users_uuid_map_t_drop(&table->map);
    memoryFree(table);
}

static void usersWireGuardPublicKeyTableDestroy(users_wireguard_publickey_table_t *table)
{
    if (UNLIKELY(table == NULL))
    {
        return;
    }

    users_wireguard_publickey_map_t_drop(&table->map);
    memoryFree(table);
}

static void usersIDTableDestroy(users_id_table_t *table)
{
    if (UNLIKELY(table == NULL))
    {
        return;
    }

    users_id_map_t_drop(&table->map);
    memoryFree(table);
}

static user_t *usersSHA224TableLookupLocked(const users_t *users, const uint8_t key_bytes[SHA224_DIGEST_SIZE])
{
    users_sha224_table_t *table = users->sha224_table;

    if (UNLIKELY(table == NULL || key_bytes == NULL))
    {
        return NULL;
    }

    users_sha224_key_t      key = usersSHA224KeyFromBytes(key_bytes);
    users_sha224_map_t_iter it  = users_sha224_map_t_find(&table->map, key);
    return it.ref != NULL ? it.ref->second : NULL;
}

static user_t *usersSHA256TableLookupLocked(const users_t *users, const uint8_t key_bytes[SHA256_DIGEST_SIZE])
{
    users_sha256_table_t *table = users->sha256_table;

    if (UNLIKELY(table == NULL || key_bytes == NULL))
    {
        return NULL;
    }

    users_sha256_key_t      key = usersSHA256KeyFromBytes(key_bytes);
    users_sha256_map_t_iter it  = users_sha256_map_t_find(&table->map, key);
    return it.ref != NULL ? it.ref->second : NULL;
}

static user_t *usersUUIDTableLookupLocked(const users_t *users, const uint8_t key_bytes[kWwUuidBytesLen])
{
    users_uuid_table_t *table = users->uuid_table;

    if (UNLIKELY(table == NULL || key_bytes == NULL))
    {
        return NULL;
    }

    users_uuid_key_t      key = usersUUIDKeyFromBytes(key_bytes);
    users_uuid_map_t_iter it  = users_uuid_map_t_find(&table->map, key);
    return it.ref != NULL ? it.ref->second : NULL;
}

static user_t *usersWireGuardPublicKeyTableLookupLocked(
    const users_t *users, const uint8_t key_bytes[USER_WIREGUARD_PUBLICKEY_SIZE])
{
    users_wireguard_publickey_table_t *table = users->wireguard_publickey_table;

    if (UNLIKELY(table == NULL || key_bytes == NULL))
    {
        return NULL;
    }

    users_wireguard_publickey_key_t      key = usersWireGuardPublicKeyFromBytes(key_bytes);
    users_wireguard_publickey_map_t_iter it  = users_wireguard_publickey_map_t_find(&table->map, key);
    return it.ref != NULL ? it.ref->second : NULL;
}

static user_t *usersIDTableLookupLocked(const users_t *users, uint64_t id)
{
    users_id_table_t *table = users->id_table;

    if (UNLIKELY(table == NULL || id == 0))
    {
        return NULL;
    }

    users_id_map_t_iter it = users_id_map_t_find(&table->map, id);
    return it.ref != NULL ? it.ref->second : NULL;
}

static bool usersSHA224TableInsertLocked(users_t *users, user_t *user)
{
    users_sha224_key_t        key;
    users_sha224_map_t_result result;

    if (UNLIKELY(! user->sha224_pass_valid))
    {
        LOGE("Users: user \"%s\" does not have a usable SHA-224 password hash", usersUserNameForLog(user));
        return false;
    }
    if (UNLIKELY(! usersSHA224TableEnsureCapacity(users, users->count + 1U)))
    {
        return false;
    }

    key    = usersSHA224KeyFromBytes(user->sha224_pass.bytes);
    result = users_sha224_map_t_insert(&users->sha224_table->map, key, user);
    if (UNLIKELY(result.ref == NULL))
    {
        LOGE("Users: failed to insert SHA-224 lookup entry");
        return false;
    }
    if (UNLIKELY(! result.inserted && result.ref->second != user))
    {
        char key_hex[SHA224_DIGEST_SIZE * 2U + 1U];
        usersSha224ToHex(user->sha224_pass.bytes, key_hex);
        LOGE("Users: duplicate SHA-224 lookup key %s between users \"%s\" and \"%s\"",
             key_hex,
             usersUserNameForLog(result.ref->second),
             usersUserNameForLog(user));
        return false;
    }

    return true;
}

static bool usersSHA256TableInsertLocked(users_t *users, user_t *user)
{
    users_sha256_key_t        key;
    users_sha256_map_t_result result;

    if (UNLIKELY(! user->sha256_pass_valid))
    {
        LOGE("Users: user \"%s\" does not have a usable SHA-256 password hash", usersUserNameForLog(user));
        return false;
    }
    if (UNLIKELY(! usersSHA256TableEnsureCapacity(users, users->count + 1U)))
    {
        return false;
    }

    key    = usersSHA256KeyFromBytes(user->sha256_pass.bytes);
    result = users_sha256_map_t_insert(&users->sha256_table->map, key, user);
    if (UNLIKELY(result.ref == NULL))
    {
        LOGE("Users: failed to insert SHA-256 lookup entry");
        return false;
    }
    if (UNLIKELY(! result.inserted && result.ref->second != user))
    {
        char key_hex[SHA256_DIGEST_SIZE * 2U + 1U];
        usersSha256ToHex(user->sha256_pass.bytes, key_hex);
        LOGE("Users: duplicate SHA-256 lookup key %s between users \"%s\" and \"%s\"",
             key_hex,
             usersUserNameForLog(result.ref->second),
             usersUserNameForLog(user));
        return false;
    }

    return true;
}

static bool usersUUIDTableInsertLocked(users_t *users, user_t *user)
{
    users_uuid_key_t        key;
    users_uuid_map_t_result result;

    if (! user->uuid_pass_valid)
    {
        return true;
    }
    if (UNLIKELY(! usersUUIDTableEnsureCapacity(users, users->count + 1U)))
    {
        return false;
    }

    key    = usersUUIDKeyFromBytes(user->uuid_pass);
    result = users_uuid_map_t_insert(&users->uuid_table->map, key, user);
    if (UNLIKELY(result.ref == NULL))
    {
        LOGE("Users: failed to insert UUID lookup entry");
        return false;
    }
    if (UNLIKELY(! result.inserted && result.ref->second != user))
    {
        char key_text[kWwUuidCanonicalStringLen + 1U];
        wwUuidToCanonicalString(user->uuid_pass, key_text);
        LOGE("Users: duplicate UUID credential %s between users \"%s\" and \"%s\"",
             key_text,
             usersUserNameForLog(result.ref->second),
             usersUserNameForLog(user));
        return false;
    }

    return true;
}

static bool usersWireGuardPublicKeyTableInsertLocked(users_t *users, user_t *user)
{
    users_wireguard_publickey_key_t        key;
    users_wireguard_publickey_map_t_result result;

    if (UNLIKELY(! user->wireguard_publickey_valid))
    {
        LOGE("Users: user \"%s\" does not have a usable WireGuard public key", usersUserNameForLog(user));
        return false;
    }
    if (UNLIKELY(! usersWireGuardPublicKeyTableEnsureCapacity(users, users->count + 1U)))
    {
        return false;
    }

    key    = usersWireGuardPublicKeyFromBytes(user->wireguard_publickey);
    result = users_wireguard_publickey_map_t_insert(&users->wireguard_publickey_table->map, key, user);
    if (UNLIKELY(result.ref == NULL))
    {
        LOGE("Users: failed to insert WireGuard public key lookup entry");
        return false;
    }
    if (UNLIKELY(! result.inserted && result.ref->second != user))
    {
        LOGE("Users: duplicate WireGuard public key between users \"%s\" and \"%s\"",
             usersUserNameForLog(result.ref->second),
             usersUserNameForLog(user));
        return false;
    }

    return true;
}

static bool usersIDTableInsertLocked(users_t *users, user_t *user)
{
    users_id_map_t_result result;
    uint64_t              id = user->id;

    if (id == 0)
    {
        return true;
    }
    if (UNLIKELY(! usersIDTableEnsureCapacity(users, users->count + 1U)))
    {
        return false;
    }

    result = users_id_map_t_insert(&users->id_table->map, id, user);
    if (UNLIKELY(result.ref == NULL))
    {
        LOGE("Users: failed to insert id lookup entry");
        return false;
    }
    if (UNLIKELY(! result.inserted && result.ref->second != user))
    {
        LOGE("Users: duplicate id %" PRIu64 " between users \"%s\" and \"%s\"",
             id,
             usersUserNameForLog(result.ref->second),
             usersUserNameForLog(user));
        return false;
    }

    return true;
}

static bool usersEnsureLookupCapacityLocked(users_t *users, size_t count)
{
    if (UNLIKELY(! usersSHA224TableEnsureCapacity(users, count)))
    {
        return false;
    }
    if (UNLIKELY(! usersSHA256TableEnsureCapacity(users, count)))
    {
        return false;
    }
    if (UNLIKELY(! usersUUIDTableEnsureCapacity(users, count)))
    {
        return false;
    }
    if (UNLIKELY(! usersWireGuardPublicKeyTableEnsureCapacity(users, count)))
    {
        return false;
    }
    if (UNLIKELY(! usersIDTableEnsureCapacity(users, count)))
    {
        return false;
    }

    return true;
}

static bool usersRebuildLookupTablesLocked(users_t *users)
{
    if (UNLIKELY(! usersEnsureLookupCapacityLocked(users, users->count)))
    {
        return false;
    }

    usersSHA224TableClear(users->sha224_table);
    usersSHA256TableClear(users->sha256_table);
    usersUUIDTableClear(users->uuid_table);
    usersWireGuardPublicKeyTableClear(users->wireguard_publickey_table);
    usersIDTableClear(users->id_table);

    for (size_t i = 0; i < users->count; ++i)
    {
        user_t *user = usersGetAtLocked(users, i);
        if (UNLIKELY(! usersSHA224TableInsertLocked(users, user)))
        {
            return false;
        }
        if (UNLIKELY(! usersSHA256TableInsertLocked(users, user)))
        {
            return false;
        }
        if (UNLIKELY(! usersUUIDTableInsertLocked(users, user)))
        {
            return false;
        }
        if (UNLIKELY(! usersWireGuardPublicKeyTableInsertLocked(users, user)))
        {
            return false;
        }
        if (UNLIKELY(! usersIDTableInsertLocked(users, user)))
        {
            return false;
        }
    }

    return true;
}

static bool usersReserveItemsLocked(users_t *users, size_t capacity)
{
    if (LIKELY(capacity <= users->capacity))
    {
        return true;
    }

    size_t new_capacity = users->capacity == 0 ? kUsersBlockSize : users->capacity;
    while (new_capacity < capacity)
    {
        if (UNLIKELY(new_capacity > SIZE_MAX / 2U))
        {
            LOGE("Users: active user pointer capacity overflow");
            return false;
        }
        new_capacity *= 2U;
    }
    if (UNLIKELY(new_capacity > SIZE_MAX / sizeof(*users->items)))
    {
        LOGE("Users: active user pointer capacity overflow");
        return false;
    }

    /* This array is aligned-allocated, so grow it manually; memoryReAllocate() cannot preserve that contract. */
    user_t **new_items = usersAllocateAlignedZero32(new_capacity * sizeof(*new_items));
    if (UNLIKELY(new_items == NULL))
    {
        LOGE("Users: failed to grow active user pointer array");
        return false;
    }
    if (LIKELY(users->items != NULL))
    {
        memoryCopy(new_items, users->items, users->capacity * sizeof(*new_items));
        memoryFreeAligned(users->items);
    }

    users->items    = new_items;
    users->capacity = new_capacity;
    return true;
}

static bool usersReserveStorageLocked(users_t *users, size_t slot_capacity)
{
    if (LIKELY(slot_capacity <= users->slot_capacity))
    {
        return true;
    }

    while (users->slot_capacity < slot_capacity)
    {
        user_t *block = NULL;

        if (UNLIKELY(users->block_count == users->block_capacity))
        {
            size_t new_block_capacity = users->block_capacity == 0
                                            ? (32U + sizeof(*users->blocks) - 1U) / sizeof(*users->blocks)
                                            : users->block_capacity * 2U;
            if (UNLIKELY(new_block_capacity < users->block_capacity ||
                         new_block_capacity > SIZE_MAX / sizeof(*users->blocks)))
            {
                LOGE("Users: user block pointer capacity overflow");
                return false;
            }

            /* Keep this manual grow in sync with memoryFreeAligned() in usersDestroy(). */
            user_t **new_blocks = usersAllocateAlignedZero32(new_block_capacity * sizeof(*new_blocks));
            if (UNLIKELY(new_blocks == NULL))
            {
                LOGE("Users: failed to grow user block pointer array");
                return false;
            }
            if (LIKELY(users->blocks != NULL))
            {
                memoryCopy(new_blocks, users->blocks, users->block_capacity * sizeof(*new_blocks));
                memoryFreeAligned(users->blocks);
            }

            users->blocks         = new_blocks;
            users->block_capacity = new_block_capacity;
        }

        block = usersAllocateAlignedZero32(kUsersBlockSize * sizeof(*block));
        if (UNLIKELY(block == NULL))
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

    if (UNLIKELY(! usersReserveItemsLocked(users, capacity)))
    {
        return false;
    }

    new_slots_needed = capacity > users->count ? capacity - users->count : 0;
    if (UNLIKELY(users->slot_count > SIZE_MAX - new_slots_needed))
    {
        LOGE("Users: user storage capacity overflow");
        return false;
    }

    return usersReserveStorageLocked(users, users->slot_count + new_slots_needed);
}

static bool usersIndexOfLocked(const users_t *users, const user_t *user, size_t *index_out)
{
    if (UNLIKELY(user == NULL))
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
    if (UNLIKELY(name == NULL || name[0] == '\0'))
    {
        return NULL;
    }

    for (size_t i = 0; i < users->count; ++i)
    {
        user_t *user = usersGetAtLocked(users, i);
        if (user != exclude && LIKELY(user->name != NULL) && stringCompare(user->name, name) == 0)
        {
            return user;
        }
    }

    return NULL;
}

static bool usersCommitNewUserLocked(users_t *users, user_t *slot)
{
    user_t *duplicate_name;

    if (UNLIKELY(! slot->sha224_pass_valid))
    {
        LOGE("Users: user \"%s\" does not have a usable SHA-224 password hash", usersUserNameForLog(slot));
        return false;
    }
    if (UNLIKELY(! slot->sha256_pass_valid))
    {
        LOGE("Users: user \"%s\" does not have a usable SHA-256 password hash", usersUserNameForLog(slot));
        return false;
    }
    if (UNLIKELY(! userPasswordDataValid(slot)))
    {
        LOGE("Users: user \"%s\" has inconsistent password lookup data", usersUserNameForLog(slot));
        return false;
    }

    duplicate_name = usersFindByNameLocked(users, slot->name, NULL);
    if (UNLIKELY(duplicate_name != NULL))
    {
        LOGE("Users: duplicate username \"%s\" in user database", slot->name);
        return false;
    }
    if (UNLIKELY(! usersEnsureLookupCapacityLocked(users, users->count + 1U)))
    {
        return false;
    }
    if (UNLIKELY(usersSHA224TableLookupLocked(users, slot->sha224_pass.bytes) != NULL))
    {
        char key_hex[SHA224_DIGEST_SIZE * 2U + 1U];
        usersSha224ToHex(slot->sha224_pass.bytes, key_hex);
        LOGE("Users: duplicate SHA-224 lookup key %s while loading user \"%s\"",
             key_hex,
             usersUserNameForLog(slot));
        return false;
    }
    if (UNLIKELY(usersSHA256TableLookupLocked(users, slot->sha256_pass.bytes) != NULL))
    {
        char key_hex[SHA256_DIGEST_SIZE * 2U + 1U];
        usersSha256ToHex(slot->sha256_pass.bytes, key_hex);
        LOGE("Users: duplicate SHA-256 lookup key %s while loading user \"%s\"",
             key_hex,
             usersUserNameForLog(slot));
        return false;
    }
    if (UNLIKELY(slot->uuid_pass_valid && usersUUIDTableLookupLocked(users, slot->uuid_pass) != NULL))
    {
        char key_text[kWwUuidCanonicalStringLen + 1U];
        wwUuidToCanonicalString(slot->uuid_pass, key_text);
        LOGE("Users: duplicate UUID credential %s while loading user \"%s\"",
             key_text,
             usersUserNameForLog(slot));
        return false;
    }
    if (UNLIKELY(slot->wireguard_publickey_valid &&
                 usersWireGuardPublicKeyTableLookupLocked(users, slot->wireguard_publickey) != NULL))
    {
        LOGE("Users: duplicate WireGuard public key while loading user \"%s\"", usersUserNameForLog(slot));
        return false;
    }
    if (UNLIKELY(slot->id != 0 && usersIDTableLookupLocked(users, slot->id) != NULL))
    {
        LOGE("Users: duplicate id %" PRIu64 " while loading user \"%s\"",
             slot->id,
             usersUserNameForLog(slot));
        return false;
    }

    if (UNLIKELY(! usersSHA224TableInsertLocked(users, slot)))
    {
        return false;
    }
    if (UNLIKELY(! usersSHA256TableInsertLocked(users, slot)))
    {
        if (UNLIKELY(! usersRebuildLookupTablesLocked(users)))
        {
            LOGF("Users: failed to restore lookup tables after an insertion failure");
            terminateProgram(1);
        }
        return false;
    }
    if (UNLIKELY(! usersUUIDTableInsertLocked(users, slot)))
    {
        if (UNLIKELY(! usersRebuildLookupTablesLocked(users)))
        {
            LOGF("Users: failed to restore lookup tables after an insertion failure");
            terminateProgram(1);
        }
        return false;
    }
    if (UNLIKELY(! usersWireGuardPublicKeyTableInsertLocked(users, slot)))
    {
        if (UNLIKELY(! usersRebuildLookupTablesLocked(users)))
        {
            LOGF("Users: failed to restore lookup tables after an insertion failure");
            terminateProgram(1);
        }
        return false;
    }
    if (UNLIKELY(! usersIDTableInsertLocked(users, slot)))
    {
        if (UNLIKELY(! usersRebuildLookupTablesLocked(users)))
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

static users_add_result_t usersValidateNewUserNoFatalLocked(const users_t *users, const user_t *user)
{
    if (UNLIKELY(user == NULL || ! user->initialized || ! user->sha224_pass_valid || ! user->sha256_pass_valid ||
                 ! userPasswordDataValid((user_t *) user)))
    {
        return kUsersAddResultInvalidUser;
    }
    if (UNLIKELY(usersFindByNameLocked(users, user->name, NULL) != NULL))
    {
        return kUsersAddResultDuplicateName;
    }

    for (size_t i = 0; i < users->count; ++i)
    {
        user_t *existing = usersGetAtLocked(users, i);

        if (UNLIKELY(existing->sha224_pass_valid &&
                     usersSha224Equal(existing->sha224_pass.bytes, user->sha224_pass.bytes)))
        {
            return kUsersAddResultDuplicateSHA224;
        }
        if (UNLIKELY(existing->sha256_pass_valid &&
                     usersSha256Equal(existing->sha256_pass.bytes, user->sha256_pass.bytes)))
        {
            return kUsersAddResultDuplicateSHA256;
        }
        if (UNLIKELY(user->uuid_pass_valid && existing->uuid_pass_valid &&
                     usersUUIDEqual(existing->uuid_pass, user->uuid_pass)))
        {
            return kUsersAddResultDuplicateUUID;
        }
        if (UNLIKELY(user->wireguard_publickey_valid && existing->wireguard_publickey_valid &&
                     usersWireGuardPublicKeyEqual(existing->wireguard_publickey, user->wireguard_publickey)))
        {
            return kUsersAddResultDuplicateWireGuardPublicKey;
        }
        if (UNLIKELY(user->id != 0 && existing->id == user->id))
        {
            return kUsersAddResultDuplicateId;
        }
    }

    return kUsersAddResultOk;
}

users_add_result_t usersAddUserChecked(users_t *users, const user_t *user)
{
    user_t            *slot;
    users_add_result_t result;

    if (UNLIKELY(users == NULL || user == NULL))
    {
        return kUsersAddResultInvalidArgument;
    }

    rwlockWriteLock(&users->lock);

    result = usersValidateNewUserNoFatalLocked(users, user);
    if (UNLIKELY(result != kUsersAddResultOk))
    {
        rwlockWriteUnlock(&users->lock);
        return result;
    }
    if (UNLIKELY(! usersReserveLocked(users, users->count + 1U)))
    {
        rwlockWriteUnlock(&users->lock);
        return kUsersAddResultAllocationFailed;
    }

    slot = usersStorageAtLocked(users, users->slot_count);
    if (UNLIKELY(! userCopy(slot, user)))
    {
        rwlockWriteUnlock(&users->lock);
        return kUsersAddResultAllocationFailed;
    }
    if (UNLIKELY(! usersCommitNewUserLocked(users, slot)))
    {
        userDestroy(slot);
        rwlockWriteUnlock(&users->lock);
        return kUsersAddResultCommitFailed;
    }

    rwlockWriteUnlock(&users->lock);
    return kUsersAddResultOk;
}

static users_update_result_t usersChangePasswordLocked(users_t *users, user_t *user, const char *password)
{
    user_t                *sha224_duplicate;
    user_t                *sha256_duplicate;
    user_t                *uuid_duplicate;
    user_t                *wireguard_publickey_duplicate;
    users_password_probe_t password_probe;

    if (UNLIKELY(! usersIndexOfLocked(users, user, NULL)))
    {
        return kUsersUpdateResultUserNotFound;
    }

    memoryZero(&password_probe, sizeof(password_probe));
    if (UNLIKELY(! usersPasswordProbeCreate(&password_probe, password, true)))
    {
        return kUsersUpdateResultPasswordUpdateFailed;
    }
    if (UNLIKELY(! password_probe.sha224_pass_valid))
    {
        LOGE("Users: updated password for user \"%s\" does not produce a usable SHA-224 hash",
             usersUserNameForLog(user));
        usersPasswordProbeDestroy(&password_probe);
        return kUsersUpdateResultPasswordUpdateFailed;
    }
    if (UNLIKELY(! password_probe.sha256_pass_valid))
    {
        LOGE("Users: updated password for user \"%s\" does not produce a usable SHA-256 hash",
             usersUserNameForLog(user));
        usersPasswordProbeDestroy(&password_probe);
        return kUsersUpdateResultPasswordUpdateFailed;
    }

    if (password_probe.uuid_pass_valid)
    {
        uuid_duplicate = usersUUIDTableLookupLocked(users, password_probe.uuid_pass);
        if (UNLIKELY(uuid_duplicate != NULL && uuid_duplicate != user))
        {
            char key_text[kWwUuidCanonicalStringLen + 1U];
            wwUuidToCanonicalString(password_probe.uuid_pass, key_text);
            LOGE("Users: duplicate UUID credential %s while updating user \"%s\"",
                 key_text,
                 usersUserNameForLog(user));
            usersPasswordProbeDestroy(&password_probe);
            return kUsersUpdateResultDuplicateUUID;
        }
    }
    if (LIKELY(password_probe.wireguard_publickey_valid))
    {
        wireguard_publickey_duplicate =
            usersWireGuardPublicKeyTableLookupLocked(users, password_probe.wireguard_publickey);
        if (UNLIKELY(wireguard_publickey_duplicate != NULL && wireguard_publickey_duplicate != user))
        {
            LOGE("Users: duplicate WireGuard public key while updating user \"%s\"", usersUserNameForLog(user));
            usersPasswordProbeDestroy(&password_probe);
            return kUsersUpdateResultDuplicateWireGuardPublicKey;
        }
    }

    sha224_duplicate = usersSHA224TableLookupLocked(users, password_probe.sha224_pass.bytes);
    if (UNLIKELY(sha224_duplicate != NULL && sha224_duplicate != user))
    {
        char key_hex[SHA224_DIGEST_SIZE * 2U + 1U];
        usersSha224ToHex(password_probe.sha224_pass.bytes, key_hex);
        LOGE("Users: duplicate SHA-224 lookup key %s while updating user \"%s\"",
             key_hex,
             usersUserNameForLog(user));
        usersPasswordProbeDestroy(&password_probe);
        return kUsersUpdateResultPasswordUpdateFailed;
    }

    sha256_duplicate = usersSHA256TableLookupLocked(users, password_probe.sha256_pass.bytes);
    if (UNLIKELY(sha256_duplicate != NULL && sha256_duplicate != user))
    {
        char key_hex[SHA256_DIGEST_SIZE * 2U + 1U];
        usersSha256ToHex(password_probe.sha256_pass.bytes, key_hex);
        LOGE("Users: duplicate SHA-256 lookup key %s while updating user \"%s\"",
             key_hex,
             usersUserNameForLog(user));
        usersPasswordProbeDestroy(&password_probe);
        return kUsersUpdateResultPasswordUpdateFailed;
    }
    if (UNLIKELY(! usersEnsureLookupCapacityLocked(users, users->count)))
    {
        usersPasswordProbeDestroy(&password_probe);
        return kUsersUpdateResultAllocationFailed;
    }
    if (UNLIKELY(! userChangePassword(user, password)))
    {
        usersPasswordProbeDestroy(&password_probe);
        return kUsersUpdateResultPasswordUpdateFailed;
    }
    if (UNLIKELY(! usersRebuildLookupTablesLocked(users)))
    {
        LOGF("Users: failed to rebuild lookup tables after updating user \"%s\"", usersUserNameForLog(user));
        usersPasswordProbeDestroy(&password_probe);
        terminateProgram(1);
    }

    usersPasswordProbeDestroy(&password_probe);
    return kUsersUpdateResultOk;
}

static user_t *usersLookupByPasswordLocked(users_t *users, const users_password_probe_t *password_probe,
                                           const char *password)
{
    user_t *candidate = NULL;

    if (LIKELY(password_probe->sha256_pass_valid))
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

    if (UNLIKELY(! usersIndexOfLocked(users, user, &index)))
    {
        return false;
    }

    user_t *victim = usersGetAtLocked(users, index);
    userDestroy(victim);

    if (LIKELY(index + 1U < users->count))
    {
        memoryMove(
            &users->items[index], &users->items[index + 1U], (users->count - index - 1U) * sizeof(*users->items));
    }
    users->count -= 1U;
    users->items[users->count] = NULL;
    if (UNLIKELY(! usersRebuildLookupTablesLocked(users)))
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
    usersSHA224TableClear(users->sha224_table);
    usersSHA256TableClear(users->sha256_table);
    usersUUIDTableClear(users->uuid_table);
    usersWireGuardPublicKeyTableClear(users->wireguard_publickey_table);
    usersIDTableClear(users->id_table);
}

static void usersRollbackFeedLocked(users_t *users, size_t old_count, size_t old_slot_count)
{
    for (size_t i = old_count; i < users->count; ++i)
    {
        userDestroy(usersGetAtLocked(users, i));
        users->items[i] = NULL;
    }

    users->count      = old_count;
    users->slot_count = old_slot_count;

    if (UNLIKELY(! usersRebuildLookupTablesLocked(users)))
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
    if (UNLIKELY(! usersStringDuplicate(&name, name_hint)))
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

    if (UNLIKELY(! cJSON_IsObject(user_json)))
    {
        LOGE("Users: user entry must be a JSON object");
        return false;
    }
    if (UNLIKELY(! usersReserveLocked(users, users->count + 1U)))
    {
        return false;
    }

    slot = usersStorageAtLocked(users, users->slot_count);
    if (UNLIKELY(! userCreateFromJson(slot, user_json)))
    {
        LOGE("Users: failed to create user from JSON entry at index %zu", users->count);
        return false;
    }
    if (UNLIKELY(! usersApplyNameHint(slot, name_hint)))
    {
        userDestroy(slot);
        return false;
    }
    if (LIKELY(usersCommitNewUserLocked(users, slot)))
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
        if (UNLIKELY(! usersAppendJsonUserLocked(users, entry, NULL)))
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
        if (UNLIKELY(! usersAppendJsonUserLocked(users, entry, entry->string)))
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
    if (UNLIKELY(json == NULL || cJSON_IsNull(json)))
    {
        return true;
    }
    if (cJSON_IsArray(json))
    {
        return usersFeedJsonArrayLocked(users, json);
    }
    if (UNLIKELY(! cJSON_IsObject(json)))
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
    if (UNLIKELY(cJSON_IsNull(users_array)))
        {
            return true;
        }
        if (UNLIKELY(! cJSON_IsArray(users_array)))
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
        if (UNLIKELY(! a->sha224_pass_valid))
        {
            LOGE("Users: user \"%s\" has no SHA-224 lookup key", usersUserNameForLog(a));
            return false;
        }
        if (UNLIKELY(! a->sha256_pass_valid))
        {
            LOGE("Users: user \"%s\" has no SHA-256 lookup key", usersUserNameForLog(a));
            return false;
        }
        if (UNLIKELY(! a->wireguard_publickey_valid))
        {
            LOGE("Users: user \"%s\" has no WireGuard public key lookup key", usersUserNameForLog(a));
            return false;
        }
        if (UNLIKELY(! userPasswordDataValid((user_t *) a)))
        {
            LOGE("Users: user \"%s\" has inconsistent password lookup data", usersUserNameForLog(a));
            return false;
        }
        if (UNLIKELY(usersSHA224TableLookupLocked(users, a->sha224_pass.bytes) != a))
        {
            LOGE("Users: SHA-224 lookup table does not point back to user \"%s\"", usersUserNameForLog(a));
            return false;
        }
        if (UNLIKELY(usersSHA256TableLookupLocked(users, a->sha256_pass.bytes) != a))
        {
            LOGE("Users: SHA-256 lookup table does not point back to user \"%s\"", usersUserNameForLog(a));
            return false;
        }
        if (UNLIKELY(a->uuid_pass_valid && usersUUIDTableLookupLocked(users, a->uuid_pass) != a))
        {
            LOGE("Users: UUID lookup table does not point back to user \"%s\"", usersUserNameForLog(a));
            return false;
        }
        if (UNLIKELY(usersWireGuardPublicKeyTableLookupLocked(users, a->wireguard_publickey) != a))
        {
            LOGE("Users: WireGuard public key lookup table does not point back to user \"%s\"",
                 usersUserNameForLog(a));
            return false;
        }
        if (UNLIKELY(a->id != 0 && usersIDTableLookupLocked(users, a->id) != a))
        {
            LOGE("Users: id lookup table does not point back to user \"%s\"", usersUserNameForLog(a));
            return false;
        }

        for (size_t j = i + 1U; j < users->count; ++j)
        {
            const user_t *b = usersGetAtLocked(users, j);
            if (UNLIKELY(usersSha224Equal(a->sha224_pass.bytes, b->sha224_pass.bytes)))
            {
                char key_hex[SHA224_DIGEST_SIZE * 2U + 1U];
                usersSha224ToHex(a->sha224_pass.bytes, key_hex);
                LOGE("Users: duplicate SHA-224 lookup key %s between users \"%s\" and \"%s\"",
                     key_hex,
                     usersUserNameForLog(a),
                     usersUserNameForLog(b));
                return false;
            }
            if (UNLIKELY(usersSha256Equal(a->sha256_pass.bytes, b->sha256_pass.bytes)))
            {
                char key_hex[SHA256_DIGEST_SIZE * 2U + 1U];
                usersSha256ToHex(a->sha256_pass.bytes, key_hex);
                LOGE("Users: duplicate SHA-256 lookup key %s between users \"%s\" and \"%s\"",
                     key_hex,
                     usersUserNameForLog(a),
                     usersUserNameForLog(b));
                return false;
            }
            if (UNLIKELY(a->uuid_pass_valid && b->uuid_pass_valid && usersUUIDEqual(a->uuid_pass, b->uuid_pass)))
            {
                char key_text[kWwUuidCanonicalStringLen + 1U];
                wwUuidToCanonicalString(a->uuid_pass, key_text);
                LOGE("Users: duplicate UUID credential %s between users \"%s\" and \"%s\"",
                     key_text,
                     usersUserNameForLog(a),
                     usersUserNameForLog(b));
                return false;
            }
            if (UNLIKELY(usersWireGuardPublicKeyEqual(a->wireguard_publickey, b->wireguard_publickey)))
            {
                LOGE("Users: duplicate WireGuard public key between users \"%s\" and \"%s\"",
                     usersUserNameForLog(a),
                     usersUserNameForLog(b));
                return false;
            }
            if (UNLIKELY(a->id != 0 && a->id == b->id))
            {
                LOGE("Users: duplicate id %" PRIu64 " between users \"%s\" and \"%s\"",
                     a->id,
                     usersUserNameForLog(a),
                     usersUserNameForLog(b));
                return false;
            }
            if (UNLIKELY(a->name != NULL && a->name[0] != '\0' && b->name != NULL &&
                         stringCompare(a->name, b->name) == 0))
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
    if (UNLIKELY(users == NULL))
    {
        return false;
    }

    memoryZero(users, sizeof(*users));
    rwlockinit(&users->lock);
    if (UNLIKELY(! usersSHA224TableCreateIfNeeded(users) || ! usersSHA256TableCreateIfNeeded(users) ||
                 ! usersUUIDTableCreateIfNeeded(users) || ! usersWireGuardPublicKeyTableCreateIfNeeded(users) ||
                 ! usersIDTableCreateIfNeeded(users)))
    {
        usersSHA224TableDestroy(users->sha224_table);
        usersSHA256TableDestroy(users->sha256_table);
        usersUUIDTableDestroy(users->uuid_table);
        usersWireGuardPublicKeyTableDestroy(users->wireguard_publickey_table);
        usersIDTableDestroy(users->id_table);
        rwlockDestroy(&users->lock);
        memoryZero(users, sizeof(*users));
        return false;
    }

    return true;
}

void usersDestroy(users_t *users)
{
    if (UNLIKELY(users == NULL))
    {
        return;
    }

    usersClearLocked(users);
    for (size_t i = 0; i < users->block_count; ++i)
    {
        memoryFreeAligned(users->blocks[i]);
    }

    memoryFreeAligned(users->blocks);
    memoryFreeAligned(users->items);
    usersSHA224TableDestroy(users->sha224_table);
    usersSHA256TableDestroy(users->sha256_table);
    usersUUIDTableDestroy(users->uuid_table);
    usersWireGuardPublicKeyTableDestroy(users->wireguard_publickey_table);
    usersIDTableDestroy(users->id_table);

    rwlockDestroy(&users->lock);
    memoryZero(users, sizeof(*users));
}

bool usersAddUser(users_t *users, const user_t *user)
{
    user_t *slot;
    user_t  user_copy;
    bool    result = false;

    if (UNLIKELY(users == NULL || user == NULL))
    {
        return false;
    }

    memoryZero(&user_copy, sizeof(user_copy));
    if (UNLIKELY(! userCopy(&user_copy, user)))
    {
        return false;
    }

    rwlockWriteLock(&users->lock);
    if (LIKELY(usersReserveLocked(users, users->count + 1U)))
    {
        slot = usersStorageAtLocked(users, users->slot_count);
        if (LIKELY(userCopy(slot, &user_copy)))
        {
            result = usersCommitNewUserLocked(users, slot);
            if (UNLIKELY(! result))
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

    if (UNLIKELY(users == NULL || ! cJSON_IsObject(json)))
    {
        return false;
    }

    memoryZero(&user, sizeof(user));
    if (UNLIKELY(! userCreateFromJson(&user, json)))
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

    if (UNLIKELY(users == NULL))
    {
        return kUsersAddResultInvalidArgument;
    }
    if (UNLIKELY(! cJSON_IsObject(json)))
    {
        return kUsersAddResultInvalidJson;
    }

    memoryZero(&user, sizeof(user));
    if (UNLIKELY(! userCreateFromJson(&user, json)))
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
    bool   result;

    if (UNLIKELY(users == NULL))
    {
        return false;
    }

    rwlockWriteLock(&users->lock);
    old_count      = users->count;
    old_slot_count = users->slot_count;

    result = usersFeedJsonLocked(users, json);
    if (UNLIKELY(! result))
    {
        usersRollbackFeedLocked(users, old_count, old_slot_count);
    }

    rwlockWriteUnlock(&users->lock);
    return result;
}

bool usersClear(users_t *users)
{
    if (UNLIKELY(users == NULL))
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

    if (UNLIKELY(users == NULL))
    {
        return NULL;
    }

    root = cJSON_CreateObject();
    if (UNLIKELY(root == NULL))
    {
        return NULL;
    }
    array = cJSON_CreateArray();
    if (UNLIKELY(array == NULL))
    {
        cJSON_Delete(root);
        return NULL;
    }
    if (UNLIKELY(! cJSON_AddItemToObject(root, "users", array)))
    {
        cJSON_Delete(array);
        cJSON_Delete(root);
        return NULL;
    }

    rwlockReadLock(&self->lock);
    for (size_t i = 0; i < users->count; ++i)
    {
        cJSON *user_json = userToJson(usersGetAtLocked(users, i));
        if (UNLIKELY(user_json == NULL))
        {
            rwlockReadUnlock(&self->lock);
            cJSON_Delete(root);
            return NULL;
        }
        if (UNLIKELY(! cJSON_AddItemToArray(array, user_json)))
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

user_t *usersLookupBySHA224(users_t *users, const uint8_t sha224[SHA224_DIGEST_SIZE])
{
    user_t *result;

    if (UNLIKELY(users == NULL || sha224 == NULL))
    {
        return NULL;
    }

    rwlockReadLock(&users->lock);
    result = usersSHA224TableLookupLocked(users, sha224);
    rwlockReadUnlock(&users->lock);
    return result;
}

const user_t *usersLookupBySHA224Const(const users_t *users, const uint8_t sha224[SHA224_DIGEST_SIZE])
{
    return usersLookupBySHA224((users_t *) users, sha224);
}

user_t *usersLookupBySHA256(users_t *users, const uint8_t sha256[SHA256_DIGEST_SIZE])
{
    user_t *result;

    if (UNLIKELY(users == NULL || sha256 == NULL))
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

user_t *usersLookupByUUID(users_t *users, const uint8_t uuid[kWwUuidBytesLen])
{
    user_t *result;

    if (UNLIKELY(users == NULL || uuid == NULL))
    {
        return NULL;
    }

    rwlockReadLock(&users->lock);
    result = usersUUIDTableLookupLocked(users, uuid);
    rwlockReadUnlock(&users->lock);
    return result;
}

const user_t *usersLookupByUUIDConst(const users_t *users, const uint8_t uuid[kWwUuidBytesLen])
{
    return usersLookupByUUID((users_t *) users, uuid);
}

user_t *usersLookupByWireGuardPublicKey(users_t *users, const uint8_t publickey[USER_WIREGUARD_PUBLICKEY_SIZE])
{
    user_t *result;

    if (UNLIKELY(users == NULL || publickey == NULL))
    {
        return NULL;
    }

    rwlockReadLock(&users->lock);
    result = usersWireGuardPublicKeyTableLookupLocked(users, publickey);
    rwlockReadUnlock(&users->lock);
    return result;
}

const user_t *usersLookupByWireGuardPublicKeyConst(const users_t *users,
                                                   const uint8_t publickey[USER_WIREGUARD_PUBLICKEY_SIZE])
{
    return usersLookupByWireGuardPublicKey((users_t *) users, publickey);
}

user_t *usersLookupByIdentifier(users_t *users, uint64_t id)
{
    user_t *result;

    if (UNLIKELY(users == NULL || id == 0))
    {
        return NULL;
    }

    rwlockReadLock(&users->lock);
    result = usersIDTableLookupLocked(users, id);
    rwlockReadUnlock(&users->lock);
    return result;
}

const user_t *usersLookupByIdentifierConst(const users_t *users, uint64_t id)
{
    return usersLookupByIdentifier((users_t *) users, id);
}

cJSON *usersUserToJsonBySHA224(const users_t *users, const uint8_t sha224[SHA224_DIGEST_SIZE])
{
    users_t *self = (users_t *) users;
    user_t  *user = NULL;
    cJSON   *json = NULL;

    if (UNLIKELY(users == NULL || sha224 == NULL))
    {
        return NULL;
    }

    rwlockReadLock(&self->lock);
    user = usersSHA224TableLookupLocked(self, sha224);
    if (LIKELY(user != NULL))
    {
        json = userToJson(user);
    }
    rwlockReadUnlock(&self->lock);
    return json;
}

cJSON *usersUserToJsonBySHA256(const users_t *users, const uint8_t sha256[SHA256_DIGEST_SIZE])
{
    users_t *self = (users_t *) users;
    user_t  *user = NULL;
    cJSON   *json = NULL;

    if (UNLIKELY(users == NULL || sha256 == NULL))
    {
        return NULL;
    }

    rwlockReadLock(&self->lock);
    user = usersSHA256TableLookupLocked(self, sha256);
    if (LIKELY(user != NULL))
    {
        json = userToJson(user);
    }
    rwlockReadUnlock(&self->lock);
    return json;
}

cJSON *usersUserToJsonByIdentifier(const users_t *users, uint64_t id)
{
    users_t *self = (users_t *) users;
    user_t  *user = NULL;
    cJSON   *json = NULL;

    if (UNLIKELY(users == NULL || id == 0))
    {
        return NULL;
    }

    rwlockReadLock(&self->lock);
    user = usersIDTableLookupLocked(self, id);
    if (LIKELY(user != NULL))
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

    if (UNLIKELY(users == NULL || password == NULL))
    {
        return NULL;
    }

    memoryZero(&password_probe, sizeof(password_probe));
    if (UNLIKELY(! usersPasswordProbeCreate(&password_probe, password, false)))
    {
        return NULL;
    }

    rwlockReadLock(&self->lock);
    user = usersLookupByPasswordLocked(self, &password_probe, password);
    if (LIKELY(user != NULL))
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

    if (UNLIKELY(users == NULL || password == NULL))
    {
        return NULL;
    }

    memoryZero(&password_probe, sizeof(password_probe));
    if (UNLIKELY(! usersPasswordProbeCreate(&password_probe, password, false)))
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

    if (UNLIKELY(users == NULL || user == NULL))
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

    if (UNLIKELY(users == NULL || sha256 == NULL))
    {
        return false;
    }

    rwlockWriteLock(&users->lock);
    user = usersSHA256TableLookupLocked(users, sha256);
    if (LIKELY(user != NULL))
    {
        result = usersRemoveUserLocked(users, user);
    }
    rwlockWriteUnlock(&users->lock);
    return result;
}

bool usersRemoveUserByIdentifier(users_t *users, uint64_t id)
{
    user_t *user;
    bool    result = false;

    if (UNLIKELY(users == NULL || id == 0))
    {
        return false;
    }

    rwlockWriteLock(&users->lock);
    user = usersIDTableLookupLocked(users, id);
    if (LIKELY(user != NULL))
    {
        result = usersRemoveUserLocked(users, user);
    }
    rwlockWriteUnlock(&users->lock);
    return result;
}

bool usersChangePassword(users_t *users, user_t *user, const char *password)
{
    users_update_result_t result;

    if (UNLIKELY(users == NULL || user == NULL))
    {
        return false;
    }

    rwlockWriteLock(&users->lock);
    result = usersChangePasswordLocked(users, user, password);
    rwlockWriteUnlock(&users->lock);
    return result == kUsersUpdateResultOk;
}

static users_update_result_t usersValidateUpdateRequest(const user_update_t *update)
{
    if (UNLIKELY(update == NULL))
    {
        return kUsersUpdateResultInvalidArgument;
    }
    if (UNLIKELY((update->mask & ~((uint32_t) kKnownUserUpdateMask)) != 0U))
    {
        LOGE("Users: update request contains unknown fields");
        return kUsersUpdateResultUnknownFields;
    }
    if (UNLIKELY((update->mask & kUserUpdateRecordStatInterval) != 0U && update->record_stat_interval_ms < 0))
    {
        LOGE("Users: record stat interval must not be negative");
        return kUsersUpdateResultInvalidRecordStatInterval;
    }

    return kUsersUpdateResultOk;
}

static void usersFreeUpdateStringCopies(char *name_copy, char *email_copy, char *notes_copy)
{
    memoryFree(name_copy);
    memoryFree(email_copy);
    memoryFree(notes_copy);
}

static users_update_result_t usersCopyUpdateStrings(const user_update_t *update, char **name_copy, char **email_copy,
                                                    char **notes_copy)
{
    *name_copy  = NULL;
    *email_copy = NULL;
    *notes_copy = NULL;

    if (UNLIKELY((update->mask & kUserUpdateName) != 0U && ! usersStringDuplicate(name_copy, update->name)))
    {
        return kUsersUpdateResultAllocationFailed;
    }
    if (UNLIKELY((update->mask & kUserUpdateEmail) != 0U && ! usersStringDuplicate(email_copy, update->email)))
    {
        usersFreeUpdateStringCopies(*name_copy, *email_copy, *notes_copy);
        *name_copy = *email_copy = *notes_copy = NULL;
        return kUsersUpdateResultAllocationFailed;
    }
    if (UNLIKELY((update->mask & kUserUpdateNotes) != 0U && ! usersStringDuplicate(notes_copy, update->notes)))
    {
        usersFreeUpdateStringCopies(*name_copy, *email_copy, *notes_copy);
        *name_copy = *email_copy = *notes_copy = NULL;
        return kUsersUpdateResultAllocationFailed;
    }

    return kUsersUpdateResultOk;
}

static users_update_result_t usersPrepareUpdate(const user_update_t *update, char **name_copy, char **email_copy,
                                                char **notes_copy)
{
    users_update_result_t result = usersValidateUpdateRequest(update);
    if (UNLIKELY(result != kUsersUpdateResultOk))
    {
        return result;
    }

    return usersCopyUpdateStrings(update, name_copy, email_copy, notes_copy);
}

static users_update_result_t usersApplyUpdateToExistingUserLocked(users_t *users, user_t *user,
                                                                  const user_update_t *update, char **name_copy,
                                                                  char **email_copy, char **notes_copy)
{
    user_t *duplicate_name;

    if ((update->mask & kUserUpdateName) != 0U)
    {
        duplicate_name = usersFindByNameLocked(users, *name_copy, user);
        if (UNLIKELY(duplicate_name != NULL))
        {
            LOGE("Users: duplicate username \"%s\" in update", *name_copy);
            return kUsersUpdateResultDuplicateName;
        }
    }
    if ((update->mask & kUserUpdatePassword) != 0U)
    {
        users_update_result_t result = usersChangePasswordLocked(users, user, update->password);
        if (UNLIKELY(result != kUsersUpdateResultOk))
        {
            return result;
        }
    }

    rwlockWriteLock(&user->lock);
    if ((update->mask & kUserUpdateName) != 0U)
    {
        usersReplaceStringOwned(&user->name, name_copy);
    }
    if ((update->mask & kUserUpdateEmail) != 0U)
    {
        usersReplaceStringOwned(&user->email, email_copy);
    }
    if ((update->mask & kUserUpdateNotes) != 0U)
    {
        usersReplaceStringOwned(&user->notes, notes_copy);
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

    return kUsersUpdateResultOk;
}

bool usersUpdateUser(users_t *users, user_t *user, const user_update_t *update)
{
    char                 *name_copy  = NULL;
    char                 *email_copy = NULL;
    char                 *notes_copy = NULL;
    users_update_result_t result;

    if (UNLIKELY(users == NULL || user == NULL))
    {
        return false;
    }

    result = usersPrepareUpdate(update, &name_copy, &email_copy, &notes_copy);
    if (UNLIKELY(result != kUsersUpdateResultOk))
    {
        return false;
    }

    rwlockWriteLock(&users->lock);
    if (UNLIKELY(! usersIndexOfLocked(users, user, NULL)))
    {
        result = kUsersUpdateResultUserNotFound;
    }
    else
    {
        result = usersApplyUpdateToExistingUserLocked(users, user, update, &name_copy, &email_copy, &notes_copy);
    }
    rwlockWriteUnlock(&users->lock);

    usersFreeUpdateStringCopies(name_copy, email_copy, notes_copy);
    return result == kUsersUpdateResultOk;
}

users_update_result_t usersUpdateUserBySHA256(users_t *users, const uint8_t sha256[SHA256_DIGEST_SIZE],
                                              const user_update_t *update)
{
    char                 *name_copy  = NULL;
    char                 *email_copy = NULL;
    char                 *notes_copy = NULL;
    users_update_result_t result;
    user_t               *user;

    if (UNLIKELY(users == NULL || sha256 == NULL))
    {
        return kUsersUpdateResultInvalidArgument;
    }

    result = usersPrepareUpdate(update, &name_copy, &email_copy, &notes_copy);
    if (UNLIKELY(result != kUsersUpdateResultOk))
    {
        return result;
    }

    rwlockWriteLock(&users->lock);
    user = usersSHA256TableLookupLocked(users, sha256);
    if (UNLIKELY(user == NULL))
    {
        result = kUsersUpdateResultUserNotFound;
    }
    else
    {
        result = usersApplyUpdateToExistingUserLocked(users, user, update, &name_copy, &email_copy, &notes_copy);
    }
    rwlockWriteUnlock(&users->lock);

    usersFreeUpdateStringCopies(name_copy, email_copy, notes_copy);
    return result;
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

    if (UNLIKELY(limit == NULL))
    {
        return false;
    }

    update.limit = *limit;
    return usersUpdateUser(users, user, &update);
}

bool usersSetUserTimeInfo(users_t *users, user_t *user, const user_time_info_t *timeinfo)
{
    user_update_t update = {.mask = kUserUpdateTimeInfo};

    if (UNLIKELY(timeinfo == NULL))
    {
        return false;
    }

    update.timeinfo = *timeinfo;
    return usersUpdateUser(users, user, &update);
}

bool usersSetUserStats(users_t *users, user_t *user, const user_stat_t *stats)
{
    user_update_t update = {.mask = kUserUpdateStats};

    if (UNLIKELY(stats == NULL))
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

    if (UNLIKELY(users == NULL || user == NULL))
    {
        return false;
    }

    rwlockReadLock(&users->lock);
    result = usersIndexOfLocked(users, user, NULL);
    if (LIKELY(result))
    {
        userAddTraffic(user, upload_bytes, download_bytes);
    }
    rwlockReadUnlock(&users->lock);
    return result;
}

users_update_result_t usersAddTrafficBySHA256(users_t *users, const uint8_t sha256[SHA256_DIGEST_SIZE],
                                              uint64_t upload_bytes, uint64_t download_bytes)
{
    user_t *user;

    if (UNLIKELY(users == NULL || sha256 == NULL))
    {
        return kUsersUpdateResultInvalidArgument;
    }

    rwlockReadLock(&users->lock);
    user = usersSHA256TableLookupLocked(users, sha256);
    if (LIKELY(user != NULL))
    {
        userAddTraffic(user, upload_bytes, download_bytes);
    }
    rwlockReadUnlock(&users->lock);

    return user != NULL ? kUsersUpdateResultOk : kUsersUpdateResultUserNotFound;
}

users_update_result_t usersAddTrafficByIdentifier(users_t *users, uint64_t id, uint64_t upload_bytes,
                                                  uint64_t download_bytes)
{
    user_t *user;

    if (UNLIKELY(users == NULL || id == 0))
    {
        return kUsersUpdateResultInvalidArgument;
    }

    rwlockReadLock(&users->lock);
    user = usersIDTableLookupLocked(users, id);
    if (LIKELY(user != NULL))
    {
        userAddTraffic(user, upload_bytes, download_bytes);
    }
    rwlockReadUnlock(&users->lock);

    return user != NULL ? kUsersUpdateResultOk : kUsersUpdateResultUserNotFound;
}

static void usersClearRuntimeStateLocked(user_t *user)
{
    if (user->runtime.ip_usages != NULL)
    {
        memoryFree(user->runtime.ip_usages);
    }
    memoryZero(&user->runtime, sizeof(user->runtime));
}

static void usersMoveRuntimeStateLocked(user_t *dest, user_t *src)
{
    usersClearRuntimeStateLocked(dest);
    dest->runtime = src->runtime;
    memoryZero(&src->runtime, sizeof(src->runtime));
}

bool usersMigrateRuntimeStateByIdentifier(users_t *dest, users_t *src)
{
    if (UNLIKELY(dest == NULL || src == NULL))
    {
        return false;
    }
    if (dest == src)
    {
        return true;
    }

    users_t *first  = (uintptr_t) dest < (uintptr_t) src ? dest : src;
    users_t *second = first == dest ? src : dest;

    rwlockWriteLock(&first->lock);
    rwlockWriteLock(&second->lock);

    for (size_t i = 0; i < src->count; ++i)
    {
        user_t *old_user = usersGetAtLocked(src, i);
        if (UNLIKELY(old_user == NULL || old_user->id == 0))
        {
            continue;
        }

        user_t *new_user = usersIDTableLookupLocked(dest, old_user->id);
        if (new_user == NULL)
        {
            continue;
        }

        usersMoveRuntimeStateLocked(new_user, old_user);
    }

    rwlockWriteUnlock(&second->lock);
    rwlockWriteUnlock(&first->lock);
    return true;
}

users_update_result_t usersSetFirstUsageIfMissingBySHA256(users_t *users,
                                                          const uint8_t sha256[SHA256_DIGEST_SIZE],
                                                          uint64_t first_usage_at_ms,
                                                          bool    *changed)
{
    user_t *user;
    bool    local_changed = false;

    if (changed != NULL)
    {
        *changed = false;
    }

    if (UNLIKELY(users == NULL || sha256 == NULL || first_usage_at_ms == 0))
    {
        return kUsersUpdateResultInvalidArgument;
    }

    rwlockReadLock(&users->lock);
    user = usersSHA256TableLookupLocked(users, sha256);
    if (LIKELY(user != NULL))
    {
        rwlockWriteLock(&user->lock);
        if (user->timeinfo.first_usage_at_ms == 0)
        {
            user->timeinfo.first_usage_at_ms = first_usage_at_ms;
            local_changed                    = true;
        }
        rwlockWriteUnlock(&user->lock);
    }
    rwlockReadUnlock(&users->lock);

    if (changed != NULL)
    {
        *changed = local_changed;
    }
    return user != NULL ? kUsersUpdateResultOk : kUsersUpdateResultUserNotFound;
}

users_update_result_t usersSetFirstUsageIfMissingByIdentifier(users_t *users,
                                                              uint64_t id,
                                                              uint64_t first_usage_at_ms,
                                                              bool    *changed)
{
    user_t *user;
    bool    local_changed = false;

    if (changed != NULL)
    {
        *changed = false;
    }

    if (UNLIKELY(users == NULL || id == 0 || first_usage_at_ms == 0))
    {
        return kUsersUpdateResultInvalidArgument;
    }

    rwlockReadLock(&users->lock);
    user = usersIDTableLookupLocked(users, id);
    if (LIKELY(user != NULL))
    {
        rwlockWriteLock(&user->lock);
        if (user->timeinfo.first_usage_at_ms == 0)
        {
            user->timeinfo.first_usage_at_ms = first_usage_at_ms;
            local_changed                    = true;
        }
        rwlockWriteUnlock(&user->lock);
    }
    rwlockReadUnlock(&users->lock);

    if (changed != NULL)
    {
        *changed = local_changed;
    }
    return user != NULL ? kUsersUpdateResultOk : kUsersUpdateResultUserNotFound;
}

user_admission_result_t usersTryAdmitConnectionByIdentifier(users_t *users, uint64_t id,
                                                            const user_ip_key_t *ip_key, uint64_t now_ms)
{
    user_t                 *user;
    user_admission_result_t result;

    if (UNLIKELY(users == NULL || id == 0))
    {
        return kUserAdmissionInvalid;
    }

    rwlockReadLock(&users->lock);
    user   = usersIDTableLookupLocked(users, id);
    result = user != NULL ? userTryAdmitConnection(user, ip_key, now_ms) : kUserAdmissionInvalid;
    rwlockReadUnlock(&users->lock);

    return result;
}

void usersReleaseConnectionByIdentifier(users_t *users, uint64_t id, const user_ip_key_t *ip_key)
{
    user_t *user;

    if (UNLIKELY(users == NULL || id == 0))
    {
        return;
    }

    rwlockReadLock(&users->lock);
    user = usersIDTableLookupLocked(users, id);
    if (LIKELY(user != NULL))
    {
        userReleaseConnection(user, ip_key);
    }
    rwlockReadUnlock(&users->lock);
}

bool usersAccountTrafficByIdentifier(users_t *users, uint64_t id, uint64_t upload_bytes, uint64_t download_bytes,
                                     uint64_t now_ms, bool *found, bool *first_usage_push_needed)
{
    user_t *user;
    bool    should_close = true;

    if (first_usage_push_needed != NULL)
    {
        *first_usage_push_needed = false;
    }

    if (UNLIKELY(users == NULL || id == 0))
    {
        if (found != NULL)
        {
            *found = false;
        }
        return true;
    }

    rwlockReadLock(&users->lock);
    user = usersIDTableLookupLocked(users, id);
    if (LIKELY(user != NULL))
    {
        should_close = userAccountTraffic(user, upload_bytes, download_bytes, now_ms, first_usage_push_needed);
    }
    rwlockReadUnlock(&users->lock);

    if (found != NULL)
    {
        *found = user != NULL;
    }
    return should_close;
}

void usersResetFirstUsagePushRequests(users_t *users)
{
    if (UNLIKELY(users == NULL))
    {
        return;
    }

    rwlockReadLock(&users->lock);
    for (size_t i = 0; i < users->count; ++i)
    {
        user_t *user = usersGetAtLocked(users, i);
        if (UNLIKELY(user == NULL))
        {
            continue;
        }

        rwlockWriteLock(&user->stats_lock);
        user->runtime.first_usage_push_requested = false;
        rwlockWriteUnlock(&user->stats_lock);
    }
    rwlockReadUnlock(&users->lock);
}

void usersResetFirstUsagePushRequestByIdentifier(users_t *users, uint64_t id)
{
    if (UNLIKELY(users == NULL || id == 0))
    {
        return;
    }

    rwlockReadLock(&users->lock);
    user_t *user = usersIDTableLookupLocked(users, id);
    if (LIKELY(user != NULL))
    {
        rwlockWriteLock(&user->stats_lock);
        user->runtime.first_usage_push_requested = false;
        rwlockWriteUnlock(&user->stats_lock);
    }
    rwlockReadUnlock(&users->lock);
}

bool usersRuntimeShouldCloseByIdentifier(users_t *users, uint64_t id, uint64_t now_ms)
{
    user_t *user;
    bool    should_close = true;

    if (UNLIKELY(users == NULL || id == 0))
    {
        return true;
    }

    rwlockReadLock(&users->lock);
    user = usersIDTableLookupLocked(users, id);
    if (LIKELY(user != NULL))
    {
        should_close = userRuntimeShouldClose(user, now_ms);
    }
    rwlockReadUnlock(&users->lock);

    return should_close;
}

bool usersAddUserUsage(users_t *users, user_t *user, uint64_t upload_bytes, uint64_t download_bytes)
{
    return usersAddTraffic(users, user, upload_bytes, download_bytes);
}

bool usersAddSpeed(users_t *users, user_t *user, uint64_t upload_bytes_per_sec, uint64_t download_bytes_per_sec)
{
    bool result;

    if (UNLIKELY(users == NULL || user == NULL))
    {
        return false;
    }

    rwlockReadLock(&users->lock);
    result = usersIndexOfLocked(users, user, NULL);
    if (LIKELY(result))
    {
        userAddSpeed(user, upload_bytes_per_sec, download_bytes_per_sec);
    }
    rwlockReadUnlock(&users->lock);
    return result;
}

bool usersAddConnection(users_t *users, user_t *user, bool inbound)
{
    bool result;

    if (UNLIKELY(users == NULL || user == NULL))
    {
        return false;
    }

    rwlockReadLock(&users->lock);
    result = usersIndexOfLocked(users, user, NULL);
    if (LIKELY(result))
    {
        userAddConnection(user, inbound);
    }
    rwlockReadUnlock(&users->lock);
    return result;
}

bool usersRemoveConnection(users_t *users, user_t *user, bool inbound)
{
    bool result;

    if (UNLIKELY(users == NULL || user == NULL))
    {
        return false;
    }

    rwlockReadLock(&users->lock);
    result = usersIndexOfLocked(users, user, NULL);
    if (LIKELY(result))
    {
        userRemoveConnection(user, inbound);
    }
    rwlockReadUnlock(&users->lock);
    return result;
}

bool usersSetIpCount(users_t *users, user_t *user, uint64_t ips)
{
    bool result;

    if (UNLIKELY(users == NULL || user == NULL))
    {
        return false;
    }

    rwlockReadLock(&users->lock);
    result = usersIndexOfLocked(users, user, NULL);
    if (LIKELY(result))
    {
        userSetIpCount(user, ips);
    }
    rwlockReadUnlock(&users->lock);
    return result;
}

bool usersSetDeviceCount(users_t *users, user_t *user, uint64_t devices)
{
    bool result;

    if (UNLIKELY(users == NULL || user == NULL))
    {
        return false;
    }

    rwlockReadLock(&users->lock);
    result = usersIndexOfLocked(users, user, NULL);
    if (LIKELY(result))
    {
        userSetDeviceCount(user, devices);
    }
    rwlockReadUnlock(&users->lock);
    return result;
}

bool usersMarkFirstUsage(users_t *users, user_t *user, uint64_t now_ms)
{
    bool result;

    if (UNLIKELY(users == NULL || user == NULL))
    {
        return false;
    }

    rwlockReadLock(&users->lock);
    result = usersIndexOfLocked(users, user, NULL);
    if (LIKELY(result))
    {
        userMarkFirstUsage(user, now_ms);
    }
    rwlockReadUnlock(&users->lock);
    return result;
}

bool usersResetUsage(users_t *users, user_t *user)
{
    bool result;

    if (UNLIKELY(users == NULL || user == NULL))
    {
        return false;
    }

    rwlockReadLock(&users->lock);
    result = usersIndexOfLocked(users, user, NULL);
    if (LIKELY(result))
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

    if (UNLIKELY(users == NULL || user == NULL))
    {
        return false;
    }

    rwlockReadLock(&users->lock);
    result = usersIndexOfLocked(users, user, NULL);
    if (LIKELY(result))
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

    if (UNLIKELY(users == NULL || user == NULL))
    {
        return false;
    }

    rwlockReadLock(&users->lock);
    if (LIKELY(usersIndexOfLocked(users, user, NULL)))
    {
        result = userHasReachedLimit((user_t *) user);
    }
    rwlockReadUnlock(&users->lock);
    return result;
}

bool usersUserEnabled(users_t *users, const user_t *user)
{
    bool result = false;

    if (UNLIKELY(users == NULL || user == NULL))
    {
        return false;
    }

    rwlockReadLock(&users->lock);
    if (LIKELY(usersIndexOfLocked(users, user, NULL)))
    {
        result = userIsEnabled((user_t *) user);
    }
    rwlockReadUnlock(&users->lock);
    return result;
}

bool usersUserDisabled(users_t *users, const user_t *user)
{
    bool result = false;

    if (UNLIKELY(users == NULL || user == NULL))
    {
        return false;
    }

    rwlockReadLock(&users->lock);
    if (LIKELY(usersIndexOfLocked(users, user, NULL)))
    {
        result = userIsDisabled((user_t *) user);
    }
    rwlockReadUnlock(&users->lock);
    return result;
}

bool usersUserExpired(users_t *users, const user_t *user, uint64_t now_ms)
{
    bool result = false;

    if (UNLIKELY(users == NULL || user == NULL))
    {
        return false;
    }

    rwlockReadLock(&users->lock);
    if (LIKELY(usersIndexOfLocked(users, user, NULL)))
    {
        result = userIsExpired((user_t *) user, now_ms);
    }
    rwlockReadUnlock(&users->lock);
    return result;
}

bool usersUserActive(users_t *users, const user_t *user, uint64_t now_ms)
{
    bool result = false;

    if (UNLIKELY(users == NULL || user == NULL))
    {
        return false;
    }

    rwlockReadLock(&users->lock);
    if (LIKELY(usersIndexOfLocked(users, user, NULL)))
    {
        result = userIsActive((user_t *) user, now_ms);
    }
    rwlockReadUnlock(&users->lock);
    return result;
}

size_t usersCount(const users_t *users)
{
    size_t result;

    if (UNLIKELY(users == NULL))
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

    if (UNLIKELY(users == NULL))
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

    if (UNLIKELY(users == NULL))
    {
        return NULL;
    }

    rwlockReadLock(&users->lock);
    if (LIKELY(index < users->count))
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

    if (UNLIKELY(users == NULL))
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

    if (UNLIKELY(users == NULL))
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

    if (UNLIKELY(users == NULL))
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

    if (UNLIKELY(users == NULL || base == NULL || current == NULL))
    {
        return diff;
    }

    rwlockReadLock(&users->lock);
    if (LIKELY(usersIndexOfLocked(users, base, NULL) && usersIndexOfLocked(users, current, NULL)))
    {
        diff = userStatsDiff(base, current);
    }
    rwlockReadUnlock(&users->lock);
    return diff;
}

user_t *usersFindFirstExpired(users_t *users, uint64_t now_ms)
{
    user_t *result = NULL;

    if (UNLIKELY(users == NULL))
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

    if (UNLIKELY(users == NULL))
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

    if (UNLIKELY(users == NULL))
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
