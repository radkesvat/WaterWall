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

typedef struct users_password_probe_s
{
    MSVC_ATTR_ALIGNED_32 sha224_hash_t sha224_pass GNU_ATTR_ALIGNED_32;
    uint8_t                                        sha224_pass_padding[SHA256_DIGEST_SIZE - SHA224_DIGEST_SIZE];
    MSVC_ATTR_ALIGNED_32 sha256_hash_t sha256_pass GNU_ATTR_ALIGNED_32;
    uint8_t                                        uuid_pass[kWwUuidBytesLen];
    uint8_t                                        wireguard_publickey[USER_WIREGUARD_PUBLICKEY_SIZE];
    bool                                           sha224_pass_valid;
    bool                                           sha256_pass_valid;
    bool                                           uuid_pass_valid;
    bool                                           wireguard_publickey_valid;
} users_password_probe_t;

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

_Static_assert(offsetof(users_password_probe_t, sha224_pass) % 32U == 0,
               "users_password_probe_t.sha224_pass must be 32-byte aligned");
_Static_assert(offsetof(users_password_probe_t, sha256_pass) % 32U == 0,
               "users_password_probe_t.sha256_pass must be 32-byte aligned");
_Static_assert(_Alignof(users_password_probe_t) >= 32U,
               "users_password_probe_t storage must be at least 32-byte aligned");
_Static_assert(sizeof(users_password_probe_t) % 32U == 0,
               "users_password_probe_t storage size must be a 32-byte multiple");

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

static void *usersAllocateAlignedZero32(size_t size)
{
    assert((size & 31U) == 0);

    /*
     * users_t-owned user_t objects rely on real 32-byte base alignment so their
     * SHA fields are actually 32-byte aligned at runtime. Keep this as aligned
     * zero allocation; do not replace it with memoryAllocateZero().
     */
    return memoryAllocateAlignedZero(size, 32);
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

static bool usersWireGuardAllowedIpContainsFields(bool valid, const ip_addr_t *network, const ip_addr_t *mask,
                                                  uint8_t family, const ip_addr_t *ip)
{
    if (! valid || network == NULL || mask == NULL || ip == NULL)
    {
        return false;
    }
    if (family == 4U && ip->type == IPADDR_TYPE_V4)
    {
        return ip4AddrNetcmp(ip_2_ip4(ip), ip_2_ip4(network), ip_2_ip4(mask)) != 0;
    }
    if (family == 6U && ip->type == IPADDR_TYPE_V6)
    {
        return ip6AddrNetcmp(ip_2_ip6(ip), ip_2_ip6(network), ip_2_ip6(mask)) != 0;
    }
    return false;
}

static bool usersWireGuardAllowedIpContainsUser(const user_t *user, const ip_addr_t *ip)
{
    return user != NULL && usersWireGuardAllowedIpContainsFields(user->wireguard_allowed_ips_valid,
                                                                 &user->wireguard_allowed_ip,
                                                                 &user->wireguard_allowed_mask,
                                                                 user->wireguard_allowed_ip_family,
                                                                 ip);
}

/*
 * Serializes an ip_addr_t of the given family into a fixed 16-byte network-order
 * buffer. IPv4 fills the first four bytes and leaves the rest zero; IPv6 fills
 * all sixteen. The raw ip_addr_t struct is never compared directly because its
 * padding and platform layout are not part of the interval key.
 */
static bool usersAllowedIpExtractBytes(const ip_addr_t *addr, uint8_t family, uint8_t out[16])
{
    memoryZero(out, 16);
    if (family == 4U)
    {
        uint32_t network_order = ip4AddrGetU32(ip_2_ip4(addr));
        memoryCopy(out, &network_order, sizeof(network_order));
        return true;
    }
    if (family == 6U)
    {
        const ip6_addr_t *v6 = ip_2_ip6(addr);
        memoryCopy(out, v6->addr, 16U);
        return true;
    }
    return false;
}

/*
 * Computes the inclusive [start, end] range of a CIDR as fixed network-order
 * byte arrays. start = network & mask (defensively masked); end = start | ~mask
 * over the family's meaningful bytes, with trailing bytes left zero.
 */
static bool usersAllowedIpRangeFromFields(const ip_addr_t *network, const ip_addr_t *mask, uint8_t family,
                                          uint8_t start16[16], uint8_t end16[16])
{
    uint8_t network_bytes[16];
    uint8_t mask_bytes[16];
    size_t  len;

    if (family != 4U && family != 6U)
    {
        return false;
    }
    len = family == 4U ? 4U : 16U;
    if (! usersAllowedIpExtractBytes(network, family, network_bytes) ||
        ! usersAllowedIpExtractBytes(mask, family, mask_bytes))
    {
        return false;
    }

    memoryZero(start16, 16);
    memoryZero(end16, 16);
    for (size_t i = 0; i < len; ++i)
    {
        uint8_t start = (uint8_t) (network_bytes[i] & mask_bytes[i]);
        start16[i]    = start;
        end16[i]      = (uint8_t) (start | (uint8_t) ~mask_bytes[i]);
    }
    return true;
}

static bool usersAllowedIpEntryFromUser(const user_t *user, users_allowed_ip_key_t *key,
                                        users_allowed_ip_value_t *value)
{
    uint8_t start16[16];
    uint8_t end16[16];

    if (! user->wireguard_allowed_ips_valid)
    {
        return false;
    }
    if (! usersAllowedIpRangeFromFields(&user->wireguard_allowed_ip,
                                        &user->wireguard_allowed_mask,
                                        user->wireguard_allowed_ip_family,
                                        start16,
                                        end16))
    {
        return false;
    }

    memoryZero(key, sizeof(*key));
    memoryZero(value, sizeof(*value));
    key->family = user->wireguard_allowed_ip_family;
    memoryCopy(key->end, end16, sizeof(key->end));
    memoryCopy(value->start, start16, sizeof(value->start));
    value->user = (user_t *) user;
    return true;
}

static bool usersAllowedIpUserFieldsIndexable(const user_t *user)
{
    uint8_t start16[16];
    uint8_t end16[16];

    if (! user->wireguard_allowed_ips_valid)
    {
        return true;
    }
    if (user->wireguard_allowed_ips == NULL || user->wireguard_allowed_ips[0] == '\0' ||
        (user->wireguard_allowed_ip_family != 4U && user->wireguard_allowed_ip_family != 6U) ||
        user->wireguard_allowed_ip_count == 0U)
    {
        return false;
    }
    return usersAllowedIpRangeFromFields(
        &user->wireguard_allowed_ip, &user->wireguard_allowed_mask, user->wireguard_allowed_ip_family, start16, end16);
}

static bool usersAllowedIpTableCreateIfNeeded(users_t *users)
{
    users_allowed_ip_table_t *table;

    if (LIKELY(users->allowed_ip_table != NULL))
    {
        return true;
    }

    table = memoryAllocateZero(sizeof(*table));
    if (UNLIKELY(table == NULL))
    {
        LOGE("Users: failed to allocate Allowed-IP lookup table");
        return false;
    }

    users->allowed_ip_table = table;
    return true;
}

static size_t usersAllowedIpTableSize(const users_allowed_ip_table_t *table)
{
    return table != NULL ? (size_t) users_allowed_ip_map_t_size(&table->map) : 0U;
}

/*
 * Reserves node headroom in the ordered Allowed-IP tree for actual configured
 * ranges, not total users. smap's reserve request is exact, so this helper grows
 * geometrically from the current tree capacity instead of asking for 17, 18, 19,
 * ... one node at a time. A reserved tree absorbs a later insert without
 * allocating, which keeps post-mutation reinsert paths transactional. Note that
 * smap's _clear() frees the node array, so rebuild/copy callers count valid
 * ranges and reserve that count after clearing.
 */
static bool usersAllowedIpTableReserve(users_allowed_ip_table_t *table, size_t min_capacity)
{
    size_t capacity = (size_t) users_allowed_ip_map_t_capacity(&table->map);

    if (capacity >= min_capacity)
    {
        return true;
    }
    if (UNLIKELY(min_capacity > (size_t) INT32_MAX))
    {
        LOGE("Users: Allowed-IP lookup table capacity overflow");
        return false;
    }
    if (capacity < kUsersInitialTableCapacity)
    {
        capacity = kUsersInitialTableCapacity;
    }
    while (capacity < min_capacity)
    {
        if (UNLIKELY(capacity > (size_t) INT32_MAX / 2U))
        {
            capacity = min_capacity;
            break;
        }
        capacity *= 2U;
    }
    if (UNLIKELY(capacity > (size_t) INT32_MAX))
    {
        LOGE("Users: Allowed-IP lookup table capacity overflow");
        return false;
    }
    if (UNLIKELY(! users_allowed_ip_map_t_reserve(&table->map, (isize) capacity)))
    {
        LOGE("Users: failed to reserve Allowed-IP lookup table");
        return false;
    }

    return true;
}

static bool usersAllowedIpTableEnsureCapacity(users_t *users, size_t count)
{
    return usersAllowedIpTableCreateIfNeeded(users) && usersAllowedIpTableReserve(users->allowed_ip_table, count);
}

static bool usersAllowedIpTableEnsureOneMoreRange(users_t *users)
{
    size_t range_count = usersAllowedIpTableSize(users->allowed_ip_table);

    if (UNLIKELY(range_count == SIZE_MAX))
    {
        LOGE("Users: Allowed-IP lookup table capacity overflow");
        return false;
    }
    return usersAllowedIpTableEnsureCapacity(users, range_count + 1U);
}

static void usersAllowedIpTableClear(users_allowed_ip_table_t *table)
{
    if (UNLIKELY(table == NULL))
    {
        return;
    }

    users_allowed_ip_map_t_clear(&table->map);
}

static void usersAllowedIpTableDestroy(users_allowed_ip_table_t *table)
{
    if (UNLIKELY(table == NULL))
    {
        return;
    }

    users_allowed_ip_map_t_drop(&table->map);
    memoryFree(table);
}

/* Inserts the user's configured range. Users without a range are not indexed. */
static bool usersAllowedIpTableInsertLocked(users_t *users, user_t *user)
{
    users_allowed_ip_key_t   key;
    users_allowed_ip_value_t value;

    if (! user->wireguard_allowed_ips_valid)
    {
        return true;
    }
    if (UNLIKELY(! usersAllowedIpEntryFromUser(user, &key, &value)))
    {
        LOGE("Users: user \"%s\" has an unparseable WireGuard Allowed-IP range", usersUserNameForLog(user));
        return false;
    }
    if (UNLIKELY(! usersAllowedIpTableCreateIfNeeded(users)))
    {
        return false;
    }

    users_allowed_ip_map_t_result result = users_allowed_ip_map_t_insert(&users->allowed_ip_table->map, key, value);
    if (UNLIKELY(result.ref == NULL))
    {
        LOGE("Users: failed to insert Allowed-IP lookup entry");
        return false;
    }
    if (UNLIKELY(! result.inserted && result.ref->second.user != user))
    {
        LOGE("Users: duplicate WireGuard Allowed-IPs \"%s\"", user->wireguard_allowed_ips);
        return false;
    }

    return true;
}

/* Erases the user's current range entry. Reads the user's live range fields, so
 * the caller must call this before those fields are replaced. */
static bool usersAllowedIpTableEraseLocked(users_t *users, const user_t *user)
{
    users_allowed_ip_key_t   key;
    users_allowed_ip_value_t value;

    if (! user->wireguard_allowed_ips_valid)
    {
        return true;
    }
    if (UNLIKELY(users->allowed_ip_table == NULL))
    {
        LOGE("Users: Allowed-IP range to erase has no lookup table (corrupted index)");
        return false;
    }
    if (UNLIKELY(! usersAllowedIpEntryFromUser(user, &key, &value)))
    {
        LOGE("Users: valid Allowed-IP range to erase is unparseable (corrupted user/index)");
        return false;
    }

    users_allowed_ip_map_t_iter it = users_allowed_ip_map_t_find(&users->allowed_ip_table->map, key);
    if (UNLIKELY(it.ref == NULL))
    {
        /* A user with a valid range is always indexed, so a miss here is a
         * corrupted index, not a no-op; fail closed so the caller can recover. */
        LOGE("Users: Allowed-IP range to erase is missing (corrupted index)");
        return false;
    }
    if (UNLIKELY(it.ref->second.user != user))
    {
        LOGE("Users: refusing to erase an Allowed-IP range owned by a different user");
        return false;
    }

    users_allowed_ip_map_t_erase(&users->allowed_ip_table->map, key);
    return true;
}

/* Returns the user whose range contains addr16, or NULL. O(log M). */
static user_t *usersAllowedIpTableFindContainingLocked(const users_t *users, uint8_t family, const uint8_t addr16[16])
{
    users_allowed_ip_table_t *table = users->allowed_ip_table;

    if (UNLIKELY(table == NULL))
    {
        return NULL;
    }

    users_allowed_ip_key_t probe;
    memoryZero(&probe, sizeof(probe));
    probe.family = family;
    memoryCopy(probe.end, addr16, sizeof(probe.end));

    /* First entry whose (family, end) >= (family, addr): its end >= addr. */
    users_allowed_ip_map_t_iter it = users_allowed_ip_map_t_lower_bound(&table->map, probe);
    if (it.ref == NULL || it.ref->first.family != family)
    {
        return NULL;
    }
    return memoryCompare(it.ref->second.start, addr16, sizeof(probe.end)) <= 0 ? it.ref->second.user : NULL;
}

/*
 * Returns a user whose configured range overlaps [start16, end16], ignoring
 * `ignore` (the caller's own current entry during an update). O(log M): only the
 * first candidate whose end >= start needs checking, because ranges never
 * overlap and are ordered by end.
 */
static user_t *usersAllowedIpTableFindOverlapLocked(const users_t *users, uint8_t family, const uint8_t start16[16],
                                                    const uint8_t end16[16], const user_t *ignore)
{
    users_allowed_ip_table_t *table = users->allowed_ip_table;

    if (UNLIKELY(table == NULL))
    {
        return NULL;
    }

    users_allowed_ip_key_t probe;
    memoryZero(&probe, sizeof(probe));
    probe.family = family;
    memoryCopy(probe.end, start16, sizeof(probe.end));

    users_allowed_ip_map_t_iter it = users_allowed_ip_map_t_lower_bound(&table->map, probe);
    if (it.ref != NULL && it.ref->first.family == family && it.ref->second.user == ignore)
    {
        /* Skip our own old range; the next entry still has end >= start. */
        users_allowed_ip_map_t_next(&it);
    }
    if (it.ref == NULL || it.ref->first.family != family)
    {
        return NULL;
    }
    return memoryCompare(it.ref->second.start, end16, sizeof(probe.end)) <= 0 ? it.ref->second.user : NULL;
}

static user_t *usersFindWireGuardAllowedIpsOverlapLocked(const users_t *users, bool valid, const ip_addr_t *network,
                                                         const ip_addr_t *mask, uint8_t family, const user_t *ignore,
                                                         bool *range_ok)
{
    uint8_t start16[16];
    uint8_t end16[16];

    if (range_ok != NULL)
    {
        *range_ok = true;
    }
    if (! valid)
    {
        return NULL;
    }
    if (UNLIKELY(! usersAllowedIpRangeFromFields(network, mask, family, start16, end16)))
    {
        if (range_ok != NULL)
        {
            *range_ok = false;
        }
        return NULL;
    }

    return usersAllowedIpTableFindOverlapLocked(users, family, start16, end16, ignore);
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
    if (UNLIKELY(wCryptoSHA224(&probe->sha224_pass, (const unsigned char *) password, password_len) != kWCryptoOk))
    {
        memorySecureZero(&probe->sha224_pass, sizeof(probe->sha224_pass));
        return false;
    }
    if (UNLIKELY(wCryptoSHA256(&probe->sha256_pass, (const unsigned char *) password, password_len) != kWCryptoOk))
    {
        memorySecureZero(&probe->sha224_pass, sizeof(probe->sha224_pass));
        memorySecureZero(&probe->sha256_pass, sizeof(probe->sha256_pass));
        return false;
    }
    probe->sha224_pass_valid = true;
    probe->sha256_pass_valid = true;
    if (derive_wireguard_publickey)
    {
        if (UNLIKELY(wCryptoX25519(probe->wireguard_publickey, probe->sha256_pass.bytes, wireguard_basepoint) !=
                     kWCryptoOk))
        {
            memorySecureZero(&probe->sha224_pass, sizeof(probe->sha224_pass));
            memorySecureZero(&probe->sha256_pass, sizeof(probe->sha256_pass));
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

    memorySecureZero(&probe->sha224_pass, sizeof(probe->sha224_pass));
    memorySecureZero(&probe->sha256_pass, sizeof(probe->sha256_pass));
    memorySecureZero(probe->uuid_pass, sizeof(probe->uuid_pass));
    memoryZero(probe->wireguard_publickey, sizeof(probe->wireguard_publickey));
    memoryZero(probe, sizeof(*probe));
}

/*
 * Derives only the SHA-256 lookup key for a plaintext password. The hot
 * plaintext-lookup path indexes exclusively by SHA-256, so it must not pay for
 * the SHA-224/UUID/WireGuard-public-key material that usersPasswordProbeCreate()
 * derives for the cold password-change path. Callers securely zero *sha256 once
 * they are done with it.
 */
static bool usersPasswordLookupKeyCreate(sha256_hash_t *sha256, const char *password)
{
    if (UNLIKELY(sha256 == NULL || password == NULL || password[0] == '\0'))
    {
        return false;
    }

    if (UNLIKELY(wCryptoSHA256(sha256, (const unsigned char *) password, stringLength(password)) != kWCryptoOk))
    {
        memorySecureZero(sha256, sizeof(*sha256));
        return false;
    }

    return true;
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

    table = memoryAllocateZero(sizeof(*table));
    if (UNLIKELY(table == NULL))
    {
        LOGE("Users: failed to allocate SHA-224 lookup table");
        return false;
    }

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

    table = memoryAllocateZero(sizeof(*table));
    if (UNLIKELY(table == NULL))
    {
        LOGE("Users: failed to allocate SHA-256 lookup table");
        return false;
    }

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

    table = memoryAllocateZero(sizeof(*table));
    if (UNLIKELY(table == NULL))
    {
        LOGE("Users: failed to allocate UUID lookup table");
        return false;
    }

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

    table = memoryAllocateZero(sizeof(*table));
    if (UNLIKELY(table == NULL))
    {
        LOGE("Users: failed to allocate WireGuard public key lookup table");
        return false;
    }

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

    table = memoryAllocateZero(sizeof(*table));
    if (UNLIKELY(table == NULL))
    {
        LOGE("Users: failed to allocate id lookup table");
        return false;
    }

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

static user_t *usersWireGuardPublicKeyTableLookupLocked(const users_t *users,
                                                        const uint8_t  key_bytes[USER_WIREGUARD_PUBLICKEY_SIZE])
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

/*
 * Capacity-free credential inserts. These never reserve, so a caller that has
 * already reserved headroom (see usersEnsureLookupCapacityLocked) can run them
 * after an irreversible mutation without risking a rehash-time allocation
 * failure. The password-change commit relies on this to stay transactional.
 */
static bool usersSHA224TableInsertEntryLocked(users_t *users, user_t *user)
{
    users_sha224_key_t        key;
    users_sha224_map_t_result result;

    if (UNLIKELY(! user->sha224_pass_valid))
    {
        LOGE("Users: user \"%s\" does not have a usable SHA-224 password hash", usersUserNameForLog(user));
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

static bool usersSHA224TableInsertLocked(users_t *users, user_t *user)
{
    if (UNLIKELY(! usersSHA224TableEnsureCapacity(users, users->count + 1U)))
    {
        return false;
    }
    return usersSHA224TableInsertEntryLocked(users, user);
}

static bool usersSHA256TableInsertEntryLocked(users_t *users, user_t *user)
{
    users_sha256_key_t        key;
    users_sha256_map_t_result result;

    if (UNLIKELY(! user->sha256_pass_valid))
    {
        LOGE("Users: user \"%s\" does not have a usable SHA-256 password hash", usersUserNameForLog(user));
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

static bool usersSHA256TableInsertLocked(users_t *users, user_t *user)
{
    if (UNLIKELY(! usersSHA256TableEnsureCapacity(users, users->count + 1U)))
    {
        return false;
    }
    return usersSHA256TableInsertEntryLocked(users, user);
}

static bool usersUUIDTableInsertEntryLocked(users_t *users, user_t *user)
{
    users_uuid_key_t        key;
    users_uuid_map_t_result result;

    if (! user->uuid_pass_valid)
    {
        return true;
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

static bool usersUUIDTableInsertLocked(users_t *users, user_t *user)
{
    if (! user->uuid_pass_valid)
    {
        return true;
    }
    if (UNLIKELY(! usersUUIDTableEnsureCapacity(users, users->count + 1U)))
    {
        return false;
    }
    return usersUUIDTableInsertEntryLocked(users, user);
}

static bool usersWireGuardPublicKeyTableInsertEntryLocked(users_t *users, user_t *user)
{
    users_wireguard_publickey_key_t        key;
    users_wireguard_publickey_map_t_result result;

    if (UNLIKELY(! user->wireguard_publickey_valid))
    {
        LOGE("Users: user \"%s\" does not have a usable WireGuard public key", usersUserNameForLog(user));
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

static bool usersWireGuardPublicKeyTableInsertLocked(users_t *users, user_t *user)
{
    if (UNLIKELY(! user->wireguard_publickey_valid))
    {
        LOGE("Users: user \"%s\" does not have a usable WireGuard public key", usersUserNameForLog(user));
        return false;
    }
    if (UNLIKELY(! usersWireGuardPublicKeyTableEnsureCapacity(users, users->count + 1U)))
    {
        return false;
    }
    return usersWireGuardPublicKeyTableInsertEntryLocked(users, user);
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

/*
 * Exact-erase helpers. Each takes the key bytes explicitly so a caller can erase
 * a user's OLD credential entry (captured before a password change) or its live
 * entry (during removal). Each confirms the entry maps to the expected user
 * before erasing; refusing to erase another user's entry surfaces an invariant
 * violation instead of silently corrupting a second user's index.
 */
static bool usersSHA224TableEraseLocked(users_t *users, const user_t *user, const uint8_t bytes[SHA224_DIGEST_SIZE])
{
    if (users->sha224_table == NULL)
    {
        LOGE("Users: SHA-224 entry to erase has no lookup table (corrupted index)");
        return false;
    }
    users_sha224_key_t      key = usersSHA224KeyFromBytes(bytes);
    users_sha224_map_t_iter it  = users_sha224_map_t_find(&users->sha224_table->map, key);
    if (UNLIKELY(it.ref == NULL))
    {
        /* Every committed user carries a SHA-224 entry, so a missing one is a
         * corrupted index, not a no-op; fail closed so the caller can recover. */
        LOGE("Users: SHA-224 entry to erase is missing (corrupted index)");
        return false;
    }
    if (UNLIKELY(it.ref->second != user))
    {
        LOGE("Users: refusing to erase a SHA-224 entry owned by a different user");
        return false;
    }
    users_sha224_map_t_erase_at(&users->sha224_table->map, it);
    return true;
}

static bool usersSHA256TableEraseLocked(users_t *users, const user_t *user, const uint8_t bytes[SHA256_DIGEST_SIZE])
{
    if (users->sha256_table == NULL)
    {
        LOGE("Users: SHA-256 entry to erase has no lookup table (corrupted index)");
        return false;
    }
    users_sha256_key_t      key = usersSHA256KeyFromBytes(bytes);
    users_sha256_map_t_iter it  = users_sha256_map_t_find(&users->sha256_table->map, key);
    if (UNLIKELY(it.ref == NULL))
    {
        /* Every committed user carries a SHA-256 entry, so a missing one is a
         * corrupted index, not a no-op; fail closed so the caller can recover. */
        LOGE("Users: SHA-256 entry to erase is missing (corrupted index)");
        return false;
    }
    if (UNLIKELY(it.ref->second != user))
    {
        LOGE("Users: refusing to erase a SHA-256 entry owned by a different user");
        return false;
    }
    users_sha256_map_t_erase_at(&users->sha256_table->map, it);
    return true;
}

static bool usersUUIDTableEraseLocked(users_t *users, const user_t *user, const uint8_t bytes[kWwUuidBytesLen])
{
    if (users->uuid_table == NULL)
    {
        LOGE("Users: UUID entry to erase has no lookup table (corrupted index)");
        return false;
    }
    users_uuid_key_t      key = usersUUIDKeyFromBytes(bytes);
    users_uuid_map_t_iter it  = users_uuid_map_t_find(&users->uuid_table->map, key);
    if (UNLIKELY(it.ref == NULL))
    {
        /* Callers only erase a UUID entry for a user that has one, so a miss here
         * is a corrupted index, not a no-op; fail closed so the caller recovers. */
        LOGE("Users: UUID entry to erase is missing (corrupted index)");
        return false;
    }
    if (UNLIKELY(it.ref->second != user))
    {
        LOGE("Users: refusing to erase a UUID entry owned by a different user");
        return false;
    }
    users_uuid_map_t_erase_at(&users->uuid_table->map, it);
    return true;
}

static bool usersWireGuardPublicKeyTableEraseLocked(users_t *users, const user_t *user,
                                                    const uint8_t bytes[USER_WIREGUARD_PUBLICKEY_SIZE])
{
    if (users->wireguard_publickey_table == NULL)
    {
        LOGE("Users: WireGuard public key entry to erase has no lookup table (corrupted index)");
        return false;
    }
    users_wireguard_publickey_key_t      key = usersWireGuardPublicKeyFromBytes(bytes);
    users_wireguard_publickey_map_t_iter it =
        users_wireguard_publickey_map_t_find(&users->wireguard_publickey_table->map, key);
    if (UNLIKELY(it.ref == NULL))
    {
        /* Callers only erase a WireGuard-key entry for a user that has one, so a
         * miss here is a corrupted index; fail closed so the caller recovers. */
        LOGE("Users: WireGuard public key entry to erase is missing (corrupted index)");
        return false;
    }
    if (UNLIKELY(it.ref->second != user))
    {
        LOGE("Users: refusing to erase a WireGuard public key entry owned by a different user");
        return false;
    }
    users_wireguard_publickey_map_t_erase_at(&users->wireguard_publickey_table->map, it);
    return true;
}

static bool usersIDTableEraseLocked(users_t *users, const user_t *user, uint64_t id)
{
    if (id == 0)
    {
        return true;
    }
    if (users->id_table == NULL)
    {
        LOGE("Users: id entry to erase has no lookup table (corrupted index)");
        return false;
    }
    users_id_map_t_iter it = users_id_map_t_find(&users->id_table->map, id);
    if (UNLIKELY(it.ref == NULL))
    {
        /* A nonzero id is always indexed, so a miss here is a corrupted index;
         * fail closed so the caller can recover. */
        LOGE("Users: id entry to erase is missing (corrupted index)");
        return false;
    }
    if (UNLIKELY(it.ref->second != user))
    {
        LOGE("Users: refusing to erase an id entry owned by a different user");
        return false;
    }
    users_id_map_t_erase_at(&users->id_table->map, it);
    return true;
}

static bool usersNameTableReserve(users_name_table_t *table, size_t count)
{
    size_t capacity = count < kUsersInitialTableCapacity ? kUsersInitialTableCapacity : count;

    if (UNLIKELY(capacity > (size_t) PTRDIFF_MAX))
    {
        LOGE("Users: name lookup table capacity overflow");
        return false;
    }
    if (UNLIKELY(! users_name_map_t_reserve(&table->map, (isize) capacity)))
    {
        LOGE("Users: failed to reserve name lookup table");
        return false;
    }

    return true;
}

static bool usersNameTableCreateIfNeeded(users_t *users)
{
    users_name_table_t *table;

    if (LIKELY(users->name_table != NULL))
    {
        return true;
    }

    table = memoryAllocateZero(sizeof(*table));
    if (UNLIKELY(table == NULL))
    {
        LOGE("Users: failed to allocate name lookup table");
        return false;
    }

    if (UNLIKELY(! usersNameTableReserve(table, kUsersInitialTableCapacity)))
    {
        users_name_map_t_drop(&table->map);
        memoryFree(table);
        return false;
    }

    users->name_table = table;
    return true;
}

static bool usersNameTableEnsureCapacity(users_t *users, size_t count)
{
    return usersNameTableCreateIfNeeded(users) && usersNameTableReserve(users->name_table, count);
}

static void usersNameTableClear(users_name_table_t *table)
{
    if (UNLIKELY(table == NULL))
    {
        return;
    }

    users_name_map_t_clear(&table->map);
}

static void usersNameTableDestroy(users_name_table_t *table)
{
    if (UNLIKELY(table == NULL))
    {
        return;
    }

    users_name_map_t_drop(&table->map);
    memoryFree(table);
}

static user_t *usersNameTableLookupLocked(const users_t *users, const char *name)
{
    users_name_table_t *table = users->name_table;

    if (UNLIKELY(table == NULL || name == NULL || name[0] == '\0'))
    {
        return NULL;
    }

    users_name_key_t      key = {.name = name};
    users_name_map_t_iter it  = users_name_map_t_find(&table->map, key);
    return it.ref != NULL ? it.ref->second : NULL;
}

/*
 * Inserts the user's non-empty name. Empty names are intentionally not indexed;
 * multiple unnamed users remain allowed. The stored key borrows user->name, so
 * the caller must not free or replace that string while the entry lives.
 */
static bool usersNameTableInsertLocked(users_t *users, user_t *user)
{
    users_name_key_t        key;
    users_name_map_t_result result;

    if (user->name == NULL || user->name[0] == '\0')
    {
        return true;
    }
    if (UNLIKELY(! usersNameTableEnsureCapacity(users, users->count + 1U)))
    {
        return false;
    }

    key    = (users_name_key_t) {.name = user->name};
    result = users_name_map_t_insert(&users->name_table->map, key, user);
    if (UNLIKELY(result.ref == NULL))
    {
        LOGE("Users: failed to insert name lookup entry");
        return false;
    }
    if (UNLIKELY(! result.inserted && result.ref->second != user))
    {
        LOGE("Users: duplicate username \"%s\" between two users", user->name);
        return false;
    }

    return true;
}

/*
 * Erases the entry for `name` when it maps to `user`. `name` is passed
 * explicitly so the caller can erase the old string before it is replaced or
 * freed. Erasing an entry owned by a different user is an invariant violation.
 */
static bool usersNameTableEraseLocked(users_t *users, const user_t *user, const char *name)
{
    users_name_table_t *table = users->name_table;

    if (name == NULL || name[0] == '\0')
    {
        return true;
    }
    if (table == NULL)
    {
        LOGE("Users: name \"%s\" to erase has no lookup table (corrupted index)", name);
        return false;
    }

    users_name_key_t      key = {.name = name};
    users_name_map_t_iter it  = users_name_map_t_find(&table->map, key);
    if (UNLIKELY(it.ref == NULL))
    {
        /* A non-empty name is always indexed, so a miss here is a corrupted index
         * (a borrowed name key that outlived its user); fail closed. */
        LOGE("Users: name \"%s\" to erase is missing (corrupted index)", name);
        return false;
    }
    if (UNLIKELY(it.ref->second != user))
    {
        LOGE("Users: refusing to erase name \"%s\" owned by a different user", name);
        return false;
    }

    users_name_map_t_erase_at(&table->map, it);
    return true;
}

static bool usersPointerTableReserve(users_pointer_table_t *table, size_t count)
{
    size_t capacity = count < kUsersInitialTableCapacity ? kUsersInitialTableCapacity : count;

    if (UNLIKELY(capacity > (size_t) PTRDIFF_MAX))
    {
        LOGE("Users: pointer lookup table capacity overflow");
        return false;
    }
    if (UNLIKELY(! users_pointer_map_t_reserve(&table->map, (isize) capacity)))
    {
        LOGE("Users: failed to reserve pointer lookup table");
        return false;
    }

    return true;
}

static bool usersPointerTableCreateIfNeeded(users_t *users)
{
    users_pointer_table_t *table;

    if (LIKELY(users->pointer_table != NULL))
    {
        return true;
    }

    table = memoryAllocateZero(sizeof(*table));
    if (UNLIKELY(table == NULL))
    {
        LOGE("Users: failed to allocate pointer lookup table");
        return false;
    }

    if (UNLIKELY(! usersPointerTableReserve(table, kUsersInitialTableCapacity)))
    {
        users_pointer_map_t_drop(&table->map);
        memoryFree(table);
        return false;
    }

    users->pointer_table = table;
    return true;
}

static bool usersPointerTableEnsureCapacity(users_t *users, size_t count)
{
    return usersPointerTableCreateIfNeeded(users) && usersPointerTableReserve(users->pointer_table, count);
}

static void usersPointerTableClear(users_pointer_table_t *table)
{
    if (UNLIKELY(table == NULL))
    {
        return;
    }

    users_pointer_map_t_clear(&table->map);
}

static void usersPointerTableDestroy(users_pointer_table_t *table)
{
    if (UNLIKELY(table == NULL))
    {
        return;
    }

    users_pointer_map_t_drop(&table->map);
    memoryFree(table);
}

static bool usersPointerTableLookupLocked(const users_t *users, const user_t *user, size_t *index_out)
{
    users_pointer_table_t *table = users->pointer_table;

    if (UNLIKELY(table == NULL || user == NULL))
    {
        return false;
    }

    users_pointer_map_t_iter it = users_pointer_map_t_find(&table->map, (uintptr_t) user);
    if (it.ref == NULL)
    {
        return false;
    }
    if (index_out != NULL)
    {
        *index_out = it.ref->second;
    }
    return true;
}

/* Records (or updates) the active items[] index for a stored user. */
static bool usersPointerTableSetLocked(users_t *users, user_t *user, size_t index)
{
    users_pointer_map_t_result result;

    if (UNLIKELY(! usersPointerTableEnsureCapacity(users, users->count + 1U)))
    {
        return false;
    }

    result = users_pointer_map_t_insert_or_assign(&users->pointer_table->map, (uintptr_t) user, index);
    if (UNLIKELY(result.ref == NULL))
    {
        LOGE("Users: failed to insert pointer lookup entry");
        return false;
    }

    return true;
}

/*
 * Repoints an already-indexed user at a new active items[] slot. It only rewrites
 * an existing entry's value, so unlike usersPointerTableSetLocked() it never
 * reserves and cannot allocate; the swap-with-last removal relies on this to stay
 * transactional after items[] has been mutated. A false return means the user was
 * not in the index, i.e. the pointer index is already corrupt.
 */
static bool usersPointerTableUpdateExistingLocked(users_t *users, const user_t *user, size_t index)
{
    if (UNLIKELY(users->pointer_table == NULL || user == NULL))
    {
        return false;
    }

    users_pointer_map_t_iter it = users_pointer_map_t_find(&users->pointer_table->map, (uintptr_t) user);
    if (UNLIKELY(it.ref == NULL))
    {
        return false;
    }
    it.ref->second = index;
    return true;
}

static void usersPointerTableEraseLocked(users_t *users, const user_t *user)
{
    if (UNLIKELY(users->pointer_table == NULL || user == NULL))
    {
        return;
    }

    users_pointer_map_t_erase(&users->pointer_table->map, (uintptr_t) user);
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
    if (UNLIKELY(! usersNameTableEnsureCapacity(users, count)))
    {
        return false;
    }
    if (UNLIKELY(! usersPointerTableEnsureCapacity(users, count)))
    {
        return false;
    }

    return true;
}

static bool usersLookupTablesCreateIfNeededLocked(users_t *users)
{
    return usersSHA224TableCreateIfNeeded(users) && usersSHA256TableCreateIfNeeded(users) &&
           usersUUIDTableCreateIfNeeded(users) && usersWireGuardPublicKeyTableCreateIfNeeded(users) &&
           usersIDTableCreateIfNeeded(users) && usersNameTableCreateIfNeeded(users) &&
           usersPointerTableCreateIfNeeded(users) && usersAllowedIpTableCreateIfNeeded(users);
}

static void usersLookupTablesDestroy(users_t *users)
{
    usersSHA224TableDestroy(users->sha224_table);
    usersSHA256TableDestroy(users->sha256_table);
    usersUUIDTableDestroy(users->uuid_table);
    usersWireGuardPublicKeyTableDestroy(users->wireguard_publickey_table);
    usersIDTableDestroy(users->id_table);
    usersNameTableDestroy(users->name_table);
    usersPointerTableDestroy(users->pointer_table);
    usersAllowedIpTableDestroy(users->allowed_ip_table);

    users->sha224_table              = NULL;
    users->sha256_table              = NULL;
    users->uuid_table                = NULL;
    users->wireguard_publickey_table = NULL;
    users->id_table                  = NULL;
    users->name_table                = NULL;
    users->pointer_table             = NULL;
    users->allowed_ip_table          = NULL;
}

static void usersLookupTablesSwapLocked(users_t *a, users_t *b)
{
#define USERS_SWAP_TABLE_PTR(field)                                                                                    \
    do                                                                                                                 \
    {                                                                                                                  \
        void *swap_tmp = a->field;                                                                                     \
        a->field       = b->field;                                                                                     \
        b->field       = swap_tmp;                                                                                     \
    } while (0)

    USERS_SWAP_TABLE_PTR(sha224_table);
    USERS_SWAP_TABLE_PTR(sha256_table);
    USERS_SWAP_TABLE_PTR(uuid_table);
    USERS_SWAP_TABLE_PTR(wireguard_publickey_table);
    USERS_SWAP_TABLE_PTR(id_table);
    USERS_SWAP_TABLE_PTR(name_table);
    USERS_SWAP_TABLE_PTR(pointer_table);
    USERS_SWAP_TABLE_PTR(allowed_ip_table);

#undef USERS_SWAP_TABLE_PTR
}

static bool usersBuildLookupTablesForItemsLocked(users_t *lookup_users, user_t **items, size_t count)
{
    size_t ranged_count    = 0;
    size_t lookup_capacity = count;

    lookup_users->count = count;
    for (size_t i = 0; i < count; ++i)
    {
        if (items[i]->wireguard_allowed_ips_valid)
        {
            ranged_count += 1U;
        }
    }

    if (UNLIKELY(lookup_capacity == SIZE_MAX))
    {
        LOGE("Users: lookup table capacity overflow");
        return false;
    }
    lookup_capacity += 1U;

    if (UNLIKELY(! usersLookupTablesCreateIfNeededLocked(lookup_users) ||
                 ! usersEnsureLookupCapacityLocked(lookup_users, lookup_capacity) ||
                 ! usersAllowedIpTableReserve(lookup_users->allowed_ip_table, ranged_count)))
    {
        return false;
    }

    for (size_t i = 0; i < count; ++i)
    {
        user_t *user = items[i];
        if (UNLIKELY(! usersSHA224TableInsertLocked(lookup_users, user)))
        {
            return false;
        }
        if (UNLIKELY(! usersSHA256TableInsertLocked(lookup_users, user)))
        {
            return false;
        }
        if (UNLIKELY(! usersUUIDTableInsertLocked(lookup_users, user)))
        {
            return false;
        }
        if (UNLIKELY(! usersWireGuardPublicKeyTableInsertLocked(lookup_users, user)))
        {
            return false;
        }
        if (UNLIKELY(! usersIDTableInsertLocked(lookup_users, user)))
        {
            return false;
        }
        if (UNLIKELY(! usersNameTableInsertLocked(lookup_users, user)))
        {
            return false;
        }
        if (UNLIKELY(! usersPointerTableSetLocked(lookup_users, user, i)))
        {
            return false;
        }
        if (UNLIKELY(! usersAllowedIpTableInsertLocked(lookup_users, user)))
        {
            return false;
        }
    }

    return true;
}

static bool usersRebuildLookupTablesLocked(users_t *users)
{
    users_t temp;
    bool    ok;

    memoryZero(&temp, sizeof(temp));
    ok = usersBuildLookupTablesForItemsLocked(&temp, users->items, users->count);
    if (LIKELY(ok))
    {
        usersLookupTablesSwapLocked(users, &temp);
    }
    usersLookupTablesDestroy(&temp);
    return ok;
}

/*
 * Erases every index entry a user owns, reading the user's live key fields. Used
 * by incremental removal before the user object is destroyed. Returns false if
 * any entry resolved to a different user (an invariant violation); it still
 * attempts every erase so the tables are left as consistent as possible.
 */
static bool usersEraseAllIndexEntriesLocked(users_t *users, user_t *user)
{
    bool ok = true;

    if (! usersSHA224TableEraseLocked(users, user, user->sha224_pass.bytes))
    {
        ok = false;
    }
    if (! usersSHA256TableEraseLocked(users, user, user->sha256_pass.bytes))
    {
        ok = false;
    }
    if (user->uuid_pass_valid && ! usersUUIDTableEraseLocked(users, user, user->uuid_pass))
    {
        ok = false;
    }
    if (user->wireguard_publickey_valid &&
        ! usersWireGuardPublicKeyTableEraseLocked(users, user, user->wireguard_publickey))
    {
        ok = false;
    }
    if (! usersIDTableEraseLocked(users, user, user->id))
    {
        ok = false;
    }
    if (! usersNameTableEraseLocked(users, user, user->name))
    {
        ok = false;
    }
    if (! usersAllowedIpTableEraseLocked(users, user))
    {
        ok = false;
    }
    usersPointerTableEraseLocked(users, user);
    return ok;
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
    /* Average-O(1): the pointer table maps each stored user to its items[] index. */
    return usersPointerTableLookupLocked(users, user, index_out);
}

static user_t *usersFindByNameLocked(const users_t *users, const char *name, const user_t *exclude)
{
    /*
     * Average-O(1) via the name table. Non-empty names are unique, so a hit that
     * is not the excluded user is a genuine duplicate; a hit equal to `exclude`
     * (a no-op rename to the same name) is not a conflict.
     */
    user_t *found = usersNameTableLookupLocked(users, name);
    return (found != NULL && found != exclude) ? found : NULL;
}

/*
 * Commits a fully-initialized slot into the active set and every lookup index.
 *
 * When `prevalidated` is true the caller has already run
 * usersValidateNewUserNoFatalLocked() on the identical source under the same held
 * write lock, so the derived-password revalidation and duplicate-key probes here
 * would only repeat that work (recomputing SHA-224/256, the UUID form, and the
 * WireGuard key, plus every index lookup) for no benefit; they are skipped. The
 * capacity reservation and the index inserts always run, so a false return on the
 * prevalidated path can only be an allocation failure.
 */
static bool usersCommitNewUserLocked(users_t *users, user_t *slot, bool prevalidated)
{
    if (! prevalidated)
    {
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
        if (UNLIKELY(! usersAllowedIpUserFieldsIndexable(slot)))
        {
            LOGE("Users: user \"%s\" has inconsistent WireGuard Allowed-IP range data", usersUserNameForLog(slot));
            return false;
        }
        if (UNLIKELY(usersFindByNameLocked(users, slot->name, NULL) != NULL))
        {
            LOGE("Users: duplicate username \"%s\" in user database", slot->name);
            return false;
        }
        if (UNLIKELY(usersSHA224TableLookupLocked(users, slot->sha224_pass.bytes) != NULL))
        {
            char key_hex[SHA224_DIGEST_SIZE * 2U + 1U];
            usersSha224ToHex(slot->sha224_pass.bytes, key_hex);
            LOGE(
                "Users: duplicate SHA-224 lookup key %s while loading user \"%s\"", key_hex, usersUserNameForLog(slot));
            return false;
        }
        if (UNLIKELY(usersSHA256TableLookupLocked(users, slot->sha256_pass.bytes) != NULL))
        {
            char key_hex[SHA256_DIGEST_SIZE * 2U + 1U];
            usersSha256ToHex(slot->sha256_pass.bytes, key_hex);
            LOGE(
                "Users: duplicate SHA-256 lookup key %s while loading user \"%s\"", key_hex, usersUserNameForLog(slot));
            return false;
        }
        if (UNLIKELY(slot->uuid_pass_valid && usersUUIDTableLookupLocked(users, slot->uuid_pass) != NULL))
        {
            char key_text[kWwUuidCanonicalStringLen + 1U];
            wwUuidToCanonicalString(slot->uuid_pass, key_text);
            LOGE("Users: duplicate UUID credential %s while loading user \"%s\"", key_text, usersUserNameForLog(slot));
            return false;
        }
        if (UNLIKELY(slot->wireguard_publickey_valid &&
                     usersWireGuardPublicKeyTableLookupLocked(users, slot->wireguard_publickey) != NULL))
        {
            LOGE("Users: duplicate WireGuard public key while loading user \"%s\"", usersUserNameForLog(slot));
            return false;
        }
        bool range_ok = true;
        if (UNLIKELY(usersFindWireGuardAllowedIpsOverlapLocked(users,
                                                               slot->wireguard_allowed_ips_valid,
                                                               &slot->wireguard_allowed_ip,
                                                               &slot->wireguard_allowed_mask,
                                                               slot->wireguard_allowed_ip_family,
                                                               NULL,
                                                               &range_ok) != NULL))
        {
            LOGE("Users: overlapping WireGuard allowed IPs \"%s\" while loading user \"%s\"",
                 slot->wireguard_allowed_ips,
                 usersUserNameForLog(slot));
            return false;
        }
        if (UNLIKELY(! range_ok))
        {
            LOGE("Users: user \"%s\" has an unparseable WireGuard Allowed-IP range", usersUserNameForLog(slot));
            return false;
        }
        if (UNLIKELY(slot->id != 0 && usersIDTableLookupLocked(users, slot->id) != NULL))
        {
            LOGE("Users: duplicate id %" PRIu64 " while loading user \"%s\"", slot->id, usersUserNameForLog(slot));
            return false;
        }
    }
    if (UNLIKELY(! usersEnsureLookupCapacityLocked(users, users->count + 1U)))
    {
        return false;
    }
    if (UNLIKELY(slot->wireguard_allowed_ips_valid && ! usersAllowedIpTableEnsureOneMoreRange(users)))
    {
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
    if (UNLIKELY(! usersNameTableInsertLocked(users, slot)))
    {
        if (UNLIKELY(! usersRebuildLookupTablesLocked(users)))
        {
            LOGF("Users: failed to restore lookup tables after an insertion failure");
            terminateProgram(1);
        }
        return false;
    }
    if (UNLIKELY(! usersPointerTableSetLocked(users, slot, users->count)))
    {
        if (UNLIKELY(! usersRebuildLookupTablesLocked(users)))
        {
            LOGF("Users: failed to restore lookup tables after an insertion failure");
            terminateProgram(1);
        }
        return false;
    }
    if (UNLIKELY(! usersAllowedIpTableInsertLocked(users, slot)))
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

typedef struct users_duplicate_result_s
{
    users_add_result_t result;
    size_t             index;
    uint8_t            priority;
    bool               found;
} users_duplicate_result_t;

static void usersDuplicateResultConsider(const users_t *users, users_duplicate_result_t *best, user_t *owner,
                                         users_add_result_t result, uint8_t priority)
{
    size_t index = SIZE_MAX;

    if (owner == NULL)
    {
        return;
    }
    (void) usersIndexOfLocked(users, owner, &index);
    if (! best->found || index < best->index || (index == best->index && priority < best->priority))
    {
        best->result   = result;
        best->index    = index;
        best->priority = priority;
        best->found    = true;
    }
}

static users_add_result_t usersValidateNewUserNoFatalLocked(const users_t *users, const user_t *user)
{
    if (UNLIKELY(user == NULL || ! user->initialized || ! user->sha224_pass_valid || ! user->sha256_pass_valid ||
                 ! userPasswordDataValid((user_t *) user)))
    {
        return kUsersAddResultInvalidUser;
    }
    if (UNLIKELY(! usersAllowedIpUserFieldsIndexable(user)))
    {
        return kUsersAddResultInvalidWireGuardAllowedIps;
    }
    /*
     * Classify duplicates through the lookup indexes instead of scanning every
     * existing user. Each index already yields the owning user, so this is
     * average O(1) per key (O(log M) for the Allowed-IP overlap probe) rather
     * than O(N), which keeps a full feed average O(N) instead of O(N^2).
     */
    if (UNLIKELY(usersFindByNameLocked(users, user->name, NULL) != NULL))
    {
        return kUsersAddResultDuplicateName;
    }

    bool    range_ok = true;
    user_t *overlap  = usersFindWireGuardAllowedIpsOverlapLocked(users,
                                                                user->wireguard_allowed_ips_valid,
                                                                &user->wireguard_allowed_ip,
                                                                &user->wireguard_allowed_mask,
                                                                user->wireguard_allowed_ip_family,
                                                                NULL,
                                                                &range_ok);
    if (UNLIKELY(! range_ok))
    {
        return kUsersAddResultInvalidWireGuardAllowedIps;
    }

    /*
     * Preserve the old checked-add compatibility rule without restoring the old
     * O(N) scan: non-empty duplicate names win first, then the earliest existing
     * conflicting user wins. If the same existing user conflicts on multiple
     * keys, keep the former per-user key order.
     */
    users_duplicate_result_t duplicate = {0};
    usersDuplicateResultConsider(users,
                                 &duplicate,
                                 usersSHA224TableLookupLocked(users, user->sha224_pass.bytes),
                                 kUsersAddResultDuplicateSHA224,
                                 0U);
    usersDuplicateResultConsider(users,
                                 &duplicate,
                                 usersSHA256TableLookupLocked(users, user->sha256_pass.bytes),
                                 kUsersAddResultDuplicateSHA256,
                                 1U);
    if (user->uuid_pass_valid)
    {
        usersDuplicateResultConsider(
            users, &duplicate, usersUUIDTableLookupLocked(users, user->uuid_pass), kUsersAddResultDuplicateUUID, 2U);
    }
    if (user->wireguard_publickey_valid)
    {
        usersDuplicateResultConsider(users,
                                     &duplicate,
                                     usersWireGuardPublicKeyTableLookupLocked(users, user->wireguard_publickey),
                                     kUsersAddResultDuplicateWireGuardPublicKey,
                                     3U);
    }
    usersDuplicateResultConsider(users, &duplicate, overlap, kUsersAddResultDuplicateWireGuardAllowedIps, 4U);
    if (user->id != 0)
    {
        usersDuplicateResultConsider(
            users, &duplicate, usersIDTableLookupLocked(users, user->id), kUsersAddResultDuplicateId, 5U);
    }
    if (UNLIKELY(duplicate.found))
    {
        return duplicate.result;
    }

    return kUsersAddResultOk;
}

users_add_result_t usersAddUserChecked(users_t *users, const user_t *user)
{
    user_t            *slot;
    user_t             user_copy;
    users_add_result_t result;

    if (UNLIKELY(users == NULL || user == NULL))
    {
        return kUsersAddResultInvalidArgument;
    }
    if (UNLIKELY(! user->initialized))
    {
        return kUsersAddResultInvalidUser;
    }
    memoryZero(&user_copy, sizeof(user_copy));
    if (UNLIKELY(! userCopy(&user_copy, user)))
    {
        return kUsersAddResultAllocationFailed;
    }

    rwlockWriteLock(&users->lock);

    result = usersValidateNewUserNoFatalLocked(users, &user_copy);
    if (UNLIKELY(result != kUsersAddResultOk))
    {
        rwlockWriteUnlock(&users->lock);
        userDestroy(&user_copy);
        return result;
    }
    if (UNLIKELY(! usersReserveLocked(users, users->count + 1U)))
    {
        rwlockWriteUnlock(&users->lock);
        userDestroy(&user_copy);
        return kUsersAddResultAllocationFailed;
    }

    slot = usersStorageAtLocked(users, users->slot_count);
    if (UNLIKELY(! userCopy(slot, &user_copy)))
    {
        rwlockWriteUnlock(&users->lock);
        userDestroy(&user_copy);
        return kUsersAddResultAllocationFailed;
    }
    /*
     * `slot` is an exact copy of the immutable, just-validated snapshot, so
     * commit skips the redundant revalidation. Its only remaining failure mode
     * is an index-capacity allocation failure, which is reported as such rather
     * than collapsed into a generic commit error.
     */
    if (UNLIKELY(! usersCommitNewUserLocked(users, slot, true)))
    {
        userDestroy(slot);
        rwlockWriteUnlock(&users->lock);
        userDestroy(&user_copy);
        return kUsersAddResultAllocationFailed;
    }

    rwlockWriteUnlock(&users->lock);
    userDestroy(&user_copy);
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
            LOGE("Users: duplicate UUID credential %s while updating user \"%s\"", key_text, usersUserNameForLog(user));
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
        LOGE("Users: duplicate SHA-224 lookup key %s while updating user \"%s\"", key_hex, usersUserNameForLog(user));
        usersPasswordProbeDestroy(&password_probe);
        return kUsersUpdateResultPasswordUpdateFailed;
    }

    sha256_duplicate = usersSHA256TableLookupLocked(users, password_probe.sha256_pass.bytes);
    if (UNLIKELY(sha256_duplicate != NULL && sha256_duplicate != user))
    {
        char key_hex[SHA256_DIGEST_SIZE * 2U + 1U];
        usersSha256ToHex(password_probe.sha256_pass.bytes, key_hex);
        LOGE("Users: duplicate SHA-256 lookup key %s while updating user \"%s\"", key_hex, usersUserNameForLog(user));
        usersPasswordProbeDestroy(&password_probe);
        return kUsersUpdateResultPasswordUpdateFailed;
    }
    if (UNLIKELY(! usersEnsureLookupCapacityLocked(users, users->count)))
    {
        usersPasswordProbeDestroy(&password_probe);
        return kUsersUpdateResultAllocationFailed;
    }

    /* Snapshot the credential keys that are about to be overwritten so they can
     * be erased from the four credential indexes after the password changes. */
    sha224_hash_t old_sha224 = user->sha224_pass;
    sha256_hash_t old_sha256 = user->sha256_pass;
    uint8_t       old_uuid[kWwUuidBytesLen];
    uint8_t       old_wireguard_publickey[USER_WIREGUARD_PUBLICKEY_SIZE];
    bool          old_uuid_valid      = user->uuid_pass_valid;
    bool          old_wireguard_valid = user->wireguard_publickey_valid;
    memoryCopy(old_uuid, user->uuid_pass, sizeof(old_uuid));
    memoryCopy(old_wireguard_publickey, user->wireguard_publickey, sizeof(old_wireguard_publickey));

    if (UNLIKELY(! userChangePassword(user, password)))
    {
        usersPasswordProbeDestroy(&password_probe);
        return kUsersUpdateResultPasswordUpdateFailed;
    }

    /*
     * Incrementally update only the four password-derived indexes: erase the old
     * keys, then insert the new ones. The id/name/Allowed-IP indexes do not
     * change. Capacity for `count` entries was reserved above and each erase
     * frees the user's own slot before the matching insert reclaims it, so the
     * table never grows and the capacity-free entry inserts cannot allocate; an
     * unexpected failure is an unrecoverable invariant violation that triggers a
     * rebuild and terminates.
     */
    bool ok = true;
    if (! usersSHA224TableEraseLocked(users, user, old_sha224.bytes))
    {
        ok = false;
    }
    if (! usersSHA256TableEraseLocked(users, user, old_sha256.bytes))
    {
        ok = false;
    }
    if (old_uuid_valid && ! usersUUIDTableEraseLocked(users, user, old_uuid))
    {
        ok = false;
    }
    if (old_wireguard_valid && ! usersWireGuardPublicKeyTableEraseLocked(users, user, old_wireguard_publickey))
    {
        ok = false;
    }
    if (ok && ! usersSHA224TableInsertEntryLocked(users, user))
    {
        ok = false;
    }
    if (ok && ! usersSHA256TableInsertEntryLocked(users, user))
    {
        ok = false;
    }
    if (ok && ! usersUUIDTableInsertEntryLocked(users, user))
    {
        ok = false;
    }
    if (ok && ! usersWireGuardPublicKeyTableInsertEntryLocked(users, user))
    {
        ok = false;
    }

    memorySecureZero(&old_sha224, sizeof(old_sha224));
    memorySecureZero(&old_sha256, sizeof(old_sha256));
    memorySecureZero(old_uuid, sizeof(old_uuid));
    memoryZero(old_wireguard_publickey, sizeof(old_wireguard_publickey));

    if (UNLIKELY(! ok))
    {
        if (UNLIKELY(! usersRebuildLookupTablesLocked(users)))
        {
            LOGF("Users: failed to rebuild lookup tables after a password index update failure");
            usersPasswordProbeDestroy(&password_probe);
            terminateProgram(1);
        }
        LOGF("Users: credential index update failed while changing password for user \"%s\"",
             usersUserNameForLog(user));
        usersPasswordProbeDestroy(&password_probe);
        terminateProgram(1);
    }

    usersPasswordProbeDestroy(&password_probe);
    return kUsersUpdateResultOk;
}

#if defined(USERS_TEST_PASSWORD_LOOKUP_VISIT_COUNTER)
/*
 * Test-only instrumentation. Counts how many candidate users the plaintext
 * lookup path examines with an exact verification. It is never defined in
 * production builds and exists only so unit tests can prove the fallback scan
 * over users->count is gone (any value greater than one would be a regression).
 */
size_t users_test_password_lookup_visits = 0;
#endif

static user_t *usersLookupByPasswordLocked(users_t *users, const sha256_hash_t *sha256_key, const char *password)
{
    /*
     * Average-O(1) plaintext lookup. The SHA-256 table is the canonical password
     * index: every committed user has a valid SHA-256 key, is inserted into the
     * SHA-256 table, duplicates are rejected, password changes update the table,
     * and usersValidate() checks that each user maps back to itself. A miss is
     * therefore either a genuine miss or an invariant violation, so there is no
     * full-table fallback scan to hide a corrupted index. The exact plaintext
     * comparison in userPasswordMatches() is the authoritative collision-safe
     * check, so a hypothetical SHA-256 collision fails closed.
     */
    user_t *candidate = usersSHA256TableLookupLocked(users, sha256_key->bytes);
    if (candidate == NULL)
    {
        return NULL;
    }

#if defined(USERS_TEST_PASSWORD_LOOKUP_VISIT_COUNTER)
    users_test_password_lookup_visits += 1U;
#endif

    return userPasswordMatches(candidate, password) ? candidate : NULL;
}

static bool usersRemoveUserLocked(users_t *users, user_t *user)
{
    size_t index;

    if (UNLIKELY(! usersIndexOfLocked(users, user, &index)))
    {
        return false;
    }

    user_t *victim = usersGetAtLocked(users, index);

    /*
     * Incremental removal: erase only the victim's own index entries (its fields
     * are still valid here), then swap the last active pointer into the freed
     * slot. No table is rebuilt on the success path. A false return means an
     * index resolved to a different user, i.e. it is already corrupt.
     */
    if (UNLIKELY(! usersEraseAllIndexEntriesLocked(users, victim)))
    {
        if (UNLIKELY(! usersRebuildLookupTablesLocked(users)))
        {
            LOGF("Users: failed to rebuild lookup tables after a removal index inconsistency");
            terminateProgram(1);
        }
        terminateProgram(1);
    }

    size_t last = users->count - 1U;
    if (index != last)
    {
        user_t *moved       = users->items[last];
        users->items[index] = moved;
        /* Repoint the moved user at its new active index. This only rewrites an
         * existing entry's value, so it cannot allocate; a false return means the
         * moved user was missing from the pointer index, i.e. it is corrupt. */
        if (UNLIKELY(! usersPointerTableUpdateExistingLocked(users, moved, index)))
        {
            LOGF("Users: failed to update the pointer index after a swap-with-last removal");
            terminateProgram(1);
        }
    }
    users->items[last] = NULL;
    users->count -= 1U;

    /*
     * The victim's stable storage slot is intentionally orphaned (not reused)
     * until usersClear()/usersDestroy(); slot_count stays monotonic.
     */
    userDestroy(victim);
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
    usersNameTableClear(users->name_table);
    usersPointerTableClear(users->pointer_table);
    usersAllowedIpTableClear(users->allowed_ip_table);
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
    if (LIKELY(usersCommitNewUserLocked(users, slot, false)))
    {
        return true;
    }

    userDestroy(slot);
    return false;
}

/*
 * Reserves active-pointer, stable-slot, and all lookup-table capacity for a JSON
 * container's children in one step, so a bulk feed does not repeatedly grow and
 * rehash. Append-to-existing semantics are preserved (capacity targets the old
 * count plus the incoming children); rollback still restores the old counts.
 */
static bool usersReserveForFeedLocked(users_t *users, const cJSON *container)
{
    int entry_count = cJSON_GetArraySize(container);
    if (entry_count <= 0)
    {
        return true;
    }

    size_t total = users->count + (size_t) entry_count;
    if (UNLIKELY(total < users->count))
    {
        LOGE("Users: JSON feed size overflow");
        return false;
    }

    return usersReserveLocked(users, total) && usersEnsureLookupCapacityLocked(users, total);
}

static bool usersFeedJsonArrayLocked(users_t *users, const cJSON *array)
{
    const cJSON *entry = NULL;

    if (UNLIKELY(! usersReserveForFeedLocked(users, array)))
    {
        return false;
    }

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

    if (UNLIKELY(! usersReserveForFeedLocked(users, object)))
    {
        return false;
    }

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

static bool usersUserJsonWireGuardAllowedIpsValid(const cJSON *json)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(json, "wireguard-allowed-ips");

    if (item == NULL || cJSON_IsNull(item))
    {
        return true;
    }
    if (UNLIKELY(! cJSON_IsString(item) || item->valuestring == NULL))
    {
        return false;
    }
    return userWireGuardAllowedIpsStringValid(item->valuestring);
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
        if (UNLIKELY(a->wireguard_allowed_ips_valid &&
                     (a->wireguard_allowed_ips == NULL || a->wireguard_allowed_ips[0] == '\0' ||
                      (a->wireguard_allowed_ip_family != 4U && a->wireguard_allowed_ip_family != 6U) ||
                      a->wireguard_allowed_ip_count == 0U ||
                      ! usersWireGuardAllowedIpContainsUser(a, &a->wireguard_allowed_ip))))
        {
            LOGE("Users: user \"%s\" has inconsistent WireGuard allowed IPs data", usersUserNameForLog(a));
            return false;
        }
        if (UNLIKELY(! a->wireguard_allowed_ips_valid && a->wireguard_allowed_ips != NULL &&
                     a->wireguard_allowed_ips[0] != '\0'))
        {
            LOGE("Users: user \"%s\" has WireGuard allowed IPs text without parsed data", usersUserNameForLog(a));
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
            LOGE("Users: WireGuard public key lookup table does not point back to user \"%s\"", usersUserNameForLog(a));
            return false;
        }
        if (UNLIKELY(a->id != 0 && usersIDTableLookupLocked(users, a->id) != a))
        {
            LOGE("Users: id lookup table does not point back to user \"%s\"", usersUserNameForLog(a));
            return false;
        }
        if (UNLIKELY(a->name != NULL && a->name[0] != '\0' && usersNameTableLookupLocked(users, a->name) != a))
        {
            LOGE("Users: name lookup table does not point back to user \"%s\"", usersUserNameForLog(a));
            return false;
        }
        size_t pointer_index = 0;
        if (UNLIKELY(! usersPointerTableLookupLocked(users, a, &pointer_index) || pointer_index != i))
        {
            LOGE("Users: pointer lookup table does not resolve user \"%s\" to its active index",
                 usersUserNameForLog(a));
            return false;
        }
        if (a->wireguard_allowed_ips_valid)
        {
            users_allowed_ip_key_t   range_key;
            users_allowed_ip_value_t range_value;
            if (UNLIKELY(! usersAllowedIpEntryFromUser(a, &range_key, &range_value) || users->allowed_ip_table == NULL))
            {
                LOGE("Users: user \"%s\" has an unindexable Allowed-IP range", usersUserNameForLog(a));
                return false;
            }
            users_allowed_ip_map_t_iter it = users_allowed_ip_map_t_find(&users->allowed_ip_table->map, range_key);
            if (UNLIKELY(it.ref == NULL || it.ref->second.user != a))
            {
                LOGE("Users: Allowed-IP lookup table does not point back to user \"%s\"", usersUserNameForLog(a));
                return false;
            }
            /*
             * Overlap detection (not just exact-key duplication): two distinct
             * ranges that nest have different end keys, so the size check below
             * cannot see them. Query the ordered index for any other user whose
             * range overlaps this one, in O(log M).
             */
            const user_t *overlap = usersAllowedIpTableFindOverlapLocked(
                users, a->wireguard_allowed_ip_family, range_value.start, range_key.end, a);
            if (UNLIKELY(overlap != NULL))
            {
                LOGE("Users: overlapping WireGuard allowed IPs \"%s\" and \"%s\" between users \"%s\" and \"%s\"",
                     a->wireguard_allowed_ips,
                     overlap->wireguard_allowed_ips,
                     usersUserNameForLog(a),
                     usersUserNameForLog(overlap));
                return false;
            }
        }
    }

    /*
     * With every user proven above to map back to itself in each of its indexes,
     * comparing table sizes to the expected populations rules out duplicates
     * without any pairwise user comparison: two users sharing a key would leave
     * the map one entry short of the number of users requiring that key. This
     * turns full validation from O(N^2) into O(N) (plus O(N log M) for the
     * Allowed-IP overlap probes above).
     */
    size_t named_count  = 0;
    size_t ranged_count = 0;
    size_t uuid_count   = 0;
    size_t id_count     = 0;
    for (size_t i = 0; i < users->count; ++i)
    {
        const user_t *a = usersGetAtLocked(users, i);
        if (a->name != NULL && a->name[0] != '\0')
        {
            named_count += 1U;
        }
        if (a->wireguard_allowed_ips_valid)
        {
            ranged_count += 1U;
        }
        if (a->uuid_pass_valid)
        {
            uuid_count += 1U;
        }
        if (a->id != 0)
        {
            id_count += 1U;
        }
    }
    if (UNLIKELY(users->sha224_table == NULL ||
                 (size_t) users_sha224_map_t_size(&users->sha224_table->map) != users->count))
    {
        LOGE("Users: SHA-224 lookup table size does not match the active user count");
        return false;
    }
    if (UNLIKELY(users->sha256_table == NULL ||
                 (size_t) users_sha256_map_t_size(&users->sha256_table->map) != users->count))
    {
        LOGE("Users: SHA-256 lookup table size does not match the active user count");
        return false;
    }
    if (UNLIKELY(users->wireguard_publickey_table == NULL ||
                 (size_t) users_wireguard_publickey_map_t_size(&users->wireguard_publickey_table->map) != users->count))
    {
        LOGE("Users: WireGuard public key lookup table size does not match the active user count");
        return false;
    }
    if (UNLIKELY(users->pointer_table == NULL ||
                 (size_t) users_pointer_map_t_size(&users->pointer_table->map) != users->count))
    {
        LOGE("Users: pointer lookup table size does not match the active user count");
        return false;
    }
    if (UNLIKELY(users->uuid_table == NULL || (size_t) users_uuid_map_t_size(&users->uuid_table->map) != uuid_count))
    {
        LOGE("Users: UUID lookup table size does not match the number of UUID users");
        return false;
    }
    if (UNLIKELY(users->id_table == NULL || (size_t) users_id_map_t_size(&users->id_table->map) != id_count))
    {
        LOGE("Users: id lookup table size does not match the number of identified users");
        return false;
    }
    /*
     * Check the name and Allowed-IP table sizes unconditionally, including the
     * zero case: a stale final entry left behind by a botched erase would make
     * the size exceed the expected count, and gating on a nonzero expected count
     * would let that corruption pass. A borrowed name key that outlives its user
     * is especially dangerous, so it must be caught here.
     */
    if (UNLIKELY(users->name_table == NULL || (size_t) users_name_map_t_size(&users->name_table->map) != named_count))
    {
        LOGE("Users: name lookup table size does not match the number of named users");
        return false;
    }
    if (UNLIKELY(users->allowed_ip_table == NULL ||
                 (size_t) users_allowed_ip_map_t_size(&users->allowed_ip_table->map) != ranged_count))
    {
        LOGE("Users: Allowed-IP lookup table size does not match the number of ranged users");
        return false;
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
                 ! usersIDTableCreateIfNeeded(users) || ! usersNameTableCreateIfNeeded(users) ||
                 ! usersPointerTableCreateIfNeeded(users) || ! usersAllowedIpTableCreateIfNeeded(users)))
    {
        usersSHA224TableDestroy(users->sha224_table);
        usersSHA256TableDestroy(users->sha256_table);
        usersUUIDTableDestroy(users->uuid_table);
        usersWireGuardPublicKeyTableDestroy(users->wireguard_publickey_table);
        usersIDTableDestroy(users->id_table);
        usersNameTableDestroy(users->name_table);
        usersPointerTableDestroy(users->pointer_table);
        usersAllowedIpTableDestroy(users->allowed_ip_table);
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
    usersNameTableDestroy(users->name_table);
    usersPointerTableDestroy(users->pointer_table);
    usersAllowedIpTableDestroy(users->allowed_ip_table);

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
            result = usersCommitNewUserLocked(users, slot, false);
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
    if (UNLIKELY(! usersUserJsonWireGuardAllowedIpsValid(json)))
    {
        return kUsersAddResultInvalidWireGuardAllowedIps;
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
                                                   const uint8_t  publickey[USER_WIREGUARD_PUBLICKEY_SIZE])
{
    return usersLookupByWireGuardPublicKey((users_t *) users, publickey);
}

user_t *usersLookupByWireGuardAllowedIp(users_t *users, const ip_addr_t *ip)
{
    user_t *result = NULL;

    if (UNLIKELY(users == NULL || ip == NULL))
    {
        return NULL;
    }

    uint8_t family = 0;
    uint8_t addr16[16];
    if (ip->type == IPADDR_TYPE_V4)
    {
        family = 4U;
    }
    else if (ip->type == IPADDR_TYPE_V6)
    {
        family = 6U;
    }
    else
    {
        return NULL;
    }
    if (UNLIKELY(! usersAllowedIpExtractBytes(ip, family, addr16)))
    {
        return NULL;
    }

    rwlockReadLock(&users->lock);
    result = usersAllowedIpTableFindContainingLocked(users, family, addr16);
    rwlockReadUnlock(&users->lock);
    return result;
}

const user_t *usersLookupByWireGuardAllowedIpConst(const users_t *users, const ip_addr_t *ip)
{
    return usersLookupByWireGuardAllowedIp((users_t *) users, ip);
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
    sha256_hash_t sha256_key;
    users_t      *self = (users_t *) users;
    user_t       *user = NULL;
    cJSON        *json = NULL;

    if (UNLIKELY(users == NULL || password == NULL))
    {
        return NULL;
    }

    if (UNLIKELY(! usersPasswordLookupKeyCreate(&sha256_key, password)))
    {
        return NULL;
    }

    /*
     * Keep the table read lock held across serialization so a concurrent removal
     * cannot invalidate the selected user pointer between lookup and conversion.
     */
    rwlockReadLock(&self->lock);
    user = usersLookupByPasswordLocked(self, &sha256_key, password);
    if (LIKELY(user != NULL))
    {
        json = userToJson(user);
    }
    rwlockReadUnlock(&self->lock);

    memorySecureZero(&sha256_key, sizeof(sha256_key));
    return json;
}

user_t *usersLookupByPassword(users_t *users, const char *password)
{
    sha256_hash_t sha256_key;
    user_t       *result;

    if (UNLIKELY(users == NULL || password == NULL))
    {
        return NULL;
    }

    if (UNLIKELY(! usersPasswordLookupKeyCreate(&sha256_key, password)))
    {
        return NULL;
    }

    rwlockReadLock(&users->lock);
    result = usersLookupByPasswordLocked(users, &sha256_key, password);
    rwlockReadUnlock(&users->lock);

    memorySecureZero(&sha256_key, sizeof(sha256_key));
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

static void usersFreeUpdateStringCopies(char *name_copy, char *email_copy, char *notes_copy,
                                        users_wireguard_allowed_ips_update_t *wireguard_allowed_ips)
{
    memoryFree(name_copy);
    memoryFree(email_copy);
    memoryFree(notes_copy);
    if (wireguard_allowed_ips != NULL)
    {
        memoryFree(wireguard_allowed_ips->copy);
        memoryZero(wireguard_allowed_ips, sizeof(*wireguard_allowed_ips));
    }
}

static users_update_result_t usersCopyUpdateStrings(const user_update_t *update, char **name_copy, char **email_copy,
                                                    char                                **notes_copy,
                                                    users_wireguard_allowed_ips_update_t *wireguard_allowed_ips)
{
    *name_copy  = NULL;
    *email_copy = NULL;
    *notes_copy = NULL;
    memoryZero(wireguard_allowed_ips, sizeof(*wireguard_allowed_ips));

    if (UNLIKELY((update->mask & kUserUpdateName) != 0U && ! usersStringDuplicate(name_copy, update->name)))
    {
        return kUsersUpdateResultAllocationFailed;
    }
    if (UNLIKELY((update->mask & kUserUpdateEmail) != 0U && ! usersStringDuplicate(email_copy, update->email)))
    {
        usersFreeUpdateStringCopies(*name_copy, *email_copy, *notes_copy, wireguard_allowed_ips);
        *name_copy = *email_copy = *notes_copy = NULL;
        return kUsersUpdateResultAllocationFailed;
    }
    if (UNLIKELY((update->mask & kUserUpdateNotes) != 0U && ! usersStringDuplicate(notes_copy, update->notes)))
    {
        usersFreeUpdateStringCopies(*name_copy, *email_copy, *notes_copy, wireguard_allowed_ips);
        *name_copy = *email_copy = *notes_copy = NULL;
        return kUsersUpdateResultAllocationFailed;
    }
    if ((update->mask & kUserUpdateWireGuardAllowedIps) != 0U)
    {
        if (UNLIKELY(! userWireGuardAllowedIpsParse(update->wireguard_allowed_ips,
                                                    &wireguard_allowed_ips->copy,
                                                    &wireguard_allowed_ips->ip,
                                                    &wireguard_allowed_ips->mask,
                                                    &wireguard_allowed_ips->family,
                                                    &wireguard_allowed_ips->prefix,
                                                    &wireguard_allowed_ips->count,
                                                    &wireguard_allowed_ips->valid)))
        {
            usersFreeUpdateStringCopies(*name_copy, *email_copy, *notes_copy, wireguard_allowed_ips);
            *name_copy = *email_copy = *notes_copy = NULL;
            return kUsersUpdateResultInvalidWireGuardAllowedIps;
        }
    }

    return kUsersUpdateResultOk;
}

static users_update_result_t usersPrepareUpdate(const user_update_t *update, char **name_copy, char **email_copy,
                                                char                                **notes_copy,
                                                users_wireguard_allowed_ips_update_t *wireguard_allowed_ips)
{
    users_update_result_t result = usersValidateUpdateRequest(update);
    if (UNLIKELY(result != kUsersUpdateResultOk))
    {
        return result;
    }

    return usersCopyUpdateStrings(update, name_copy, email_copy, notes_copy, wireguard_allowed_ips);
}

static users_update_result_t usersApplyUpdateToExistingUserLocked(
    users_t *users, user_t *user, const user_update_t *update, char **name_copy, char **email_copy, char **notes_copy,
    users_wireguard_allowed_ips_update_t *wireguard_allowed_ips)
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
        /*
         * Reserve name-index headroom before any irreversible mutation so the
         * post-commit insert below cannot fail on a rehash. A rename does not
         * grow the active user count, but the table may need to rehash.
         */
        if (UNLIKELY(! usersNameTableEnsureCapacity(users, users->count + 1U)))
        {
            return kUsersUpdateResultAllocationFailed;
        }
    }
    if ((update->mask & kUserUpdateWireGuardAllowedIps) != 0U)
    {
        bool    range_ok = true;
        user_t *overlap  = usersFindWireGuardAllowedIpsOverlapLocked(users,
                                                                    wireguard_allowed_ips->valid,
                                                                    &wireguard_allowed_ips->ip,
                                                                    &wireguard_allowed_ips->mask,
                                                                    wireguard_allowed_ips->family,
                                                                    user,
                                                                    &range_ok);
        if (UNLIKELY(! range_ok))
        {
            LOGE("Users: WireGuard allowed IPs \"%s\" are not indexable in update", wireguard_allowed_ips->copy);
            return kUsersUpdateResultInvalidWireGuardAllowedIps;
        }
        if (UNLIKELY(overlap != NULL))
        {
            LOGE("Users: WireGuard allowed IPs \"%s\" overlap with user \"%s\" in update",
                 wireguard_allowed_ips->copy,
                 usersUserNameForLog(overlap));
            return kUsersUpdateResultDuplicateWireGuardAllowedIps;
        }
        if (UNLIKELY(! user->wireguard_allowed_ips_valid && wireguard_allowed_ips->valid &&
                     ! usersAllowedIpTableEnsureOneMoreRange(users)))
        {
            return kUsersUpdateResultAllocationFailed;
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

    /*
     * Erase the old name entry while the old string is still alive, before
     * usersReplaceStringOwned() frees it. The users_t write lock is held, so
     * reading user->name outside user->lock is safe here. A false return means
     * the old name resolved to a different user, i.e. the name index is already
     * corrupt; that is an unrecoverable invariant violation.
     */
    if (UNLIKELY((update->mask & kUserUpdateName) != 0U && ! usersNameTableEraseLocked(users, user, user->name)))
    {
        LOGF("Users: name index inconsistency while updating user \"%s\"", usersUserNameForLog(user));
        terminateProgram(1);
    }
    /*
     * Erase the old Allowed-IP range entry while the user still carries its old
     * range fields, before they are overwritten below.
     */
    if (UNLIKELY((update->mask & kUserUpdateWireGuardAllowedIps) != 0U &&
                 ! usersAllowedIpTableEraseLocked(users, user)))
    {
        LOGF("Users: Allowed-IP index inconsistency while updating user \"%s\"", usersUserNameForLog(user));
        terminateProgram(1);
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
    if ((update->mask & kUserUpdateWireGuardAllowedIps) != 0U)
    {
        usersReplaceStringOwned(&user->wireguard_allowed_ips, &wireguard_allowed_ips->copy);
        user->wireguard_allowed_ip        = wireguard_allowed_ips->ip;
        user->wireguard_allowed_mask      = wireguard_allowed_ips->mask;
        user->wireguard_allowed_ip_count  = wireguard_allowed_ips->count;
        user->wireguard_allowed_ip_family = wireguard_allowed_ips->family;
        user->wireguard_allowed_ip_prefix = wireguard_allowed_ips->prefix;
        user->wireguard_allowed_ips_valid = wireguard_allowed_ips->valid;
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

    /*
     * Insert the replacement name entry. Capacity was reserved above and the old
     * entry was erased, so this cannot fail on a rehash; a failure would be an
     * unrecoverable invariant violation.
     */
    if (UNLIKELY((update->mask & kUserUpdateName) != 0U && ! usersNameTableInsertLocked(users, user)))
    {
        LOGF("Users: failed to reinsert name index entry while updating user \"%s\"", usersUserNameForLog(user));
        terminateProgram(1);
    }
    /*
     * Insert the replacement Allowed-IP range. A spare tree node was reserved
     * before any mutation and the old range's node (if any) was just freed for
     * reuse, so this cannot fail on an allocation; a failure is an unrecoverable
     * invariant violation.
     */
    if (UNLIKELY((update->mask & kUserUpdateWireGuardAllowedIps) != 0U &&
                 ! usersAllowedIpTableInsertLocked(users, user)))
    {
        LOGF("Users: failed to reinsert Allowed-IP range while updating user \"%s\"", usersUserNameForLog(user));
        terminateProgram(1);
    }

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
    char                                *name_copy  = NULL;
    char                                *email_copy = NULL;
    char                                *notes_copy = NULL;
    users_wireguard_allowed_ips_update_t wireguard_allowed_ips;
    users_update_result_t                result;

    if (UNLIKELY(users == NULL || user == NULL))
    {
        return false;
    }

    result = usersPrepareUpdate(update, &name_copy, &email_copy, &notes_copy, &wireguard_allowed_ips);
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
        result = usersApplyUpdateToExistingUserLocked(
            users, user, update, &name_copy, &email_copy, &notes_copy, &wireguard_allowed_ips);
    }
    rwlockWriteUnlock(&users->lock);

    usersFreeUpdateStringCopies(name_copy, email_copy, notes_copy, &wireguard_allowed_ips);
    return result == kUsersUpdateResultOk;
}

users_update_result_t usersUpdateUserBySHA256(users_t *users, const uint8_t sha256[SHA256_DIGEST_SIZE],
                                              const user_update_t *update)
{
    char                                *name_copy  = NULL;
    char                                *email_copy = NULL;
    char                                *notes_copy = NULL;
    users_wireguard_allowed_ips_update_t wireguard_allowed_ips;
    users_update_result_t                result;
    user_t                              *user;

    if (UNLIKELY(users == NULL || sha256 == NULL))
    {
        return kUsersUpdateResultInvalidArgument;
    }

    result = usersPrepareUpdate(update, &name_copy, &email_copy, &notes_copy, &wireguard_allowed_ips);
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
        result = usersApplyUpdateToExistingUserLocked(
            users, user, update, &name_copy, &email_copy, &notes_copy, &wireguard_allowed_ips);
    }
    rwlockWriteUnlock(&users->lock);

    usersFreeUpdateStringCopies(name_copy, email_copy, notes_copy, &wireguard_allowed_ips);
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
    /* Delegated to user.c so the adaptive IP index is released exactly once. */
    userRuntimeStateClear(&user->runtime);
}

static void usersMoveRuntimeStateLocked(user_t *dest, user_t *src)
{
    /* Delegated to user.c so the adaptive IP index moves without a double free. */
    userRuntimeStateMove(&dest->runtime, &src->runtime);
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

users_update_result_t usersSetFirstUsageIfMissingBySHA256(users_t *users, const uint8_t sha256[SHA256_DIGEST_SIZE],
                                                          uint64_t first_usage_at_ms, bool *changed)
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

users_update_result_t usersSetFirstUsageIfMissingByIdentifier(users_t *users, uint64_t id, uint64_t first_usage_at_ms,
                                                              bool *changed)
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

user_admission_result_t usersTryAdmitConnectionByIdentifier(users_t *users, uint64_t id, const user_ip_key_t *ip_key,
                                                            uint64_t now_ms)
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

/*
 * Moves every data and index field between two tables, deliberately excluding
 * the wrwlock_t lock in each (a lock must never be memcpy'd or swapped). Update
 * this whenever a new stored field or index is added.
 */
static void usersSwapContentsLocked(users_t *a, users_t *b)
{
#define USERS_SWAP_PTR(field)                                                                                          \
    do                                                                                                                 \
    {                                                                                                                  \
        void *swap_tmp = a->field;                                                                                     \
        a->field       = b->field;                                                                                     \
        b->field       = swap_tmp;                                                                                     \
    } while (0)
#define USERS_SWAP_SIZE(field)                                                                                         \
    do                                                                                                                 \
    {                                                                                                                  \
        size_t swap_tmp = a->field;                                                                                    \
        a->field        = b->field;                                                                                    \
        b->field        = swap_tmp;                                                                                    \
    } while (0)

    USERS_SWAP_PTR(blocks);
    USERS_SWAP_PTR(items);
    USERS_SWAP_SIZE(count);
    USERS_SWAP_SIZE(capacity);
    USERS_SWAP_SIZE(slot_count);
    USERS_SWAP_SIZE(slot_capacity);
    USERS_SWAP_SIZE(block_count);
    USERS_SWAP_SIZE(block_capacity);
    USERS_SWAP_PTR(sha224_table);
    USERS_SWAP_PTR(sha256_table);
    USERS_SWAP_PTR(uuid_table);
    USERS_SWAP_PTR(wireguard_publickey_table);
    USERS_SWAP_PTR(id_table);
    USERS_SWAP_PTR(name_table);
    USERS_SWAP_PTR(pointer_table);
    USERS_SWAP_PTR(allowed_ip_table);

#undef USERS_SWAP_SIZE
#undef USERS_SWAP_PTR
}

/*
 * Inserts an already-copied user into every index of a freshly built table and
 * appends it. No duplicate pre-scan and no credential rederivation: the source
 * table was already valid and userCopy() carried the derived material over. The
 * per-index insert helpers still fail closed on an unexpected duplicate.
 */
static bool usersCommitCopiedUserLocked(users_t *dest, user_t *slot)
{
    if (UNLIKELY(! usersSHA224TableInsertLocked(dest, slot) || ! usersSHA256TableInsertLocked(dest, slot) ||
                 ! usersUUIDTableInsertLocked(dest, slot) || ! usersWireGuardPublicKeyTableInsertLocked(dest, slot) ||
                 ! usersIDTableInsertLocked(dest, slot) || ! usersNameTableInsertLocked(dest, slot) ||
                 ! usersPointerTableSetLocked(dest, slot, dest->count) ||
                 ! usersAllowedIpTableInsertLocked(dest, slot)))
    {
        return false;
    }

    dest->items[dest->count] = slot;
    dest->count += 1U;
    dest->slot_count += 1U;
    return true;
}

bool usersCopy(users_t *dest, const users_t *src)
{
    users_t  temp;
    users_t *src_mut = (users_t *) src;
    bool     ok      = true;

    if (UNLIKELY(dest == NULL || src == NULL))
    {
        return false;
    }
    if (dest == src)
    {
        return true;
    }

    /*
     * Build a complete copy in an isolated temporary table first, then swap it
     * into the destination under the destination lock. The source and
     * destination locks are never held at the same time, so no cross-copy
     * deadlock or address-ordered locking protocol is needed, and the
     * destination is untouched until the copy has fully succeeded.
     */
    if (UNLIKELY(! usersCreate(&temp)))
    {
        return false;
    }

    rwlockReadLock(&src_mut->lock);
    size_t src_count        = src->count;
    size_t src_ranged_count = 0;
    for (size_t i = 0; i < src_count; ++i)
    {
        if (usersGetAtLocked(src_mut, i)->wireguard_allowed_ips_valid)
        {
            src_ranged_count += 1U;
        }
    }
    if (UNLIKELY(! usersReserveLocked(&temp, src_count) || ! usersEnsureLookupCapacityLocked(&temp, src_count)))
    {
        ok = false;
    }
    if (ok && UNLIKELY(! usersAllowedIpTableEnsureCapacity(&temp, src_ranged_count)))
    {
        ok = false;
    }
    for (size_t i = 0; ok && i < src_count; ++i)
    {
        user_t *src_user = usersGetAtLocked(src_mut, i);
        user_t *slot     = usersStorageAtLocked(&temp, temp.slot_count);

        if (UNLIKELY(! userCopy(slot, src_user)))
        {
            ok = false;
            break;
        }
        if (UNLIKELY(! usersCommitCopiedUserLocked(&temp, slot)))
        {
            userDestroy(slot);
            ok = false;
            break;
        }
    }
    rwlockReadUnlock(&src_mut->lock);

#ifndef NDEBUG
    if (ok && UNLIKELY(! usersValidateUserLookupKeysLocked(&temp)))
    {
        LOGF("Users: internal copy produced an inconsistent table");
        ok = false;
    }
#endif

    if (UNLIKELY(! ok))
    {
        usersDestroy(&temp);
        return false;
    }

    rwlockWriteLock(&dest->lock);
    usersSwapContentsLocked(dest, &temp);
    rwlockWriteUnlock(&dest->lock);

    /* temp now owns the destination's previous contents; destroy frees them. */
    usersDestroy(&temp);
    return true;
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

/*
 * Intentionally an O(N) scan. Effective expiry changes when first usage is
 * recorded or when a client-view expiry is projected, so a maintained expiry
 * heap would add work to the hot accounting/sync paths for a diagnostic query.
 * Add an index only if a production caller polls this frequently and a benchmark
 * shows the scan matters.
 */
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

/*
 * Intentionally an O(N) scan. No AuthenticationClient/Server hot path polls this
 * today; a maintained "disabled" set would add work to configuration updates to
 * speed up an unused query. Add an index only when a real caller and a benchmark
 * justify it.
 */
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

/*
 * Intentionally an O(N) scan. Limit state depends on frequently changing traffic
 * statistics and runtime counters, so a maintained "limited" set would add
 * contention to traffic accounting, which is more performance-critical than this
 * diagnostic scan.
 */
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
