/*
 * User database manager implementation.
 */

#include "objects/users.h"
#include "objects/user_index_geometry.h"

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

static bool usersConfigDeadlineExpired(uint64_t deadline_ms)
{
    return deadline_ms != 0 && getHRTimeUs() / 1000U >= deadline_ms;
}

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

static void usersStringDuplicate(char **dest, const char *value)
{
    *dest = stringDuplicate(value != NULL ? value : "");
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

static void usersAllowedIpTableCreateIfNeeded(users_t *users)
{
    if (users->allowed_ip_table != NULL)
        return;
    users_allowed_ip_table_t *table = memoryAllocateZero(sizeof(*table));
    users->allowed_ip_table         = table;
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
static bool usersAllowedIpTableGrowthGeometry(const users_allowed_ip_table_t *table, size_t min_capacity,
                                              size_t *capacity_out, size_t *extent_out)
{
    const size_t maximum_capacity =
        min((size_t) INT32_MAX, (size_t) PTRDIFF_MAX / sizeof(users_allowed_ip_map_t_node) - 1U);
    size_t capacity = table != NULL ? (size_t) users_allowed_ip_map_t_capacity(&table->map) : 0U;

    *capacity_out = capacity;
    *extent_out   = 0;
    if (capacity >= min_capacity)
    {
        return true;
    }
    if (UNLIKELY(min_capacity > maximum_capacity))
    {
        return false;
    }
    if (capacity < kUsersInitialTableCapacity)
    {
        capacity = kUsersInitialTableCapacity;
    }
    while (capacity < min_capacity)
    {
        if (UNLIKELY(capacity > maximum_capacity / 2U))
        {
            capacity = min_capacity;
            break;
        }
        capacity *= 2U;
    }
    if (UNLIKELY(capacity > maximum_capacity))
    {
        return false;
    }
    *capacity_out = capacity;
    *extent_out   = (capacity + 1U) * sizeof(users_allowed_ip_map_t_node);
    return true;
}

static bool usersAllowedIpTableReserve(users_allowed_ip_table_t *table, size_t min_capacity)
{
    size_t capacity, extent;
    if (! usersAllowedIpTableGrowthGeometry(table, min_capacity, &capacity, &extent))
    {
        LOGE("Users: Allowed-IP lookup table capacity overflow");
        return false;
    }
    if (extent == 0)
        return true;
    discard users_allowed_ip_map_t_reserve(&table->map, (isize) capacity);

    return true;
}

static bool usersAllowedIpTableEnsureCapacity(users_t *users, size_t count)
{
    usersAllowedIpTableCreateIfNeeded(users);
    return usersAllowedIpTableReserve(users->allowed_ip_table, count);
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
        LOGE("Users: unparseable WireGuard Allowed-IP range in index insertion");
        return false;
    }
    usersAllowedIpTableCreateIfNeeded(users);

    users_allowed_ip_map_t_result result = users_allowed_ip_map_t_insert(&users->allowed_ip_table->map, key, value);
    if (UNLIKELY(! result.inserted && result.ref->second.user != user))
    {
        LOGE("Users: duplicate WireGuard Allowed-IP range in index insertion");
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

#if defined(USERS_TEST_CREDENTIAL_SNAPSHOT_WIPE_COUNTER)
/*
 * Test-only instrumentation. Counts how many times the credential-snapshot wipe
 * helper runs so a unit test can prove every post-snapshot exit of
 * usersCommitPasswordLocked() clears the old secret material. Never defined in
 * production builds.
 */
size_t users_test_credential_snapshot_wipes = 0;
#endif

/*
 * Wipes the four password-derived credential snapshots that
 * usersCommitPasswordLocked() captures before a user's password is overwritten.
 * SHA-224, SHA-256, and the UUID bytes are secret-equivalent and use
 * non-optimizable secure zeroing; the WireGuard public key is derived public
 * data and is cleared with a plain zero, matching the rest of this file. Routing
 * every post-snapshot exit through here keeps the wipe policy in one place so no
 * old secret is left behind on the stack.
 */
static void usersWipeCredentialSnapshot(sha224_hash_t *old_sha224, sha256_hash_t *old_sha256,
                                        uint8_t old_uuid[kWwUuidBytesLen],
                                        uint8_t old_wireguard_publickey[USER_WIREGUARD_PUBLICKEY_SIZE])
{
    memorySecureZero(old_sha224, sizeof(*old_sha224));
    memorySecureZero(old_sha256, sizeof(*old_sha256));
    memorySecureZero(old_uuid, kWwUuidBytesLen);
    memoryZero(old_wireguard_publickey, USER_WIREGUARD_PUBLICKEY_SIZE);

#if defined(USERS_TEST_CREDENTIAL_SNAPSHOT_WIPE_COUNTER)
    users_test_credential_snapshot_wipes += 1U;
#endif
}

/*
 * Derives only the SHA-256 lookup key for a plaintext password. The hot
 * plaintext-lookup path indexes exclusively by SHA-256, so it must not pay for
 * the SHA-224/UUID/WireGuard-public-key material that userPreparePassword()
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

    if (UNLIKELY(! userIndexHashCapacityIsRepresentable(capacity, sizeof(*table->map.table), sizeof(*table->map.meta))))
    {
        LOGE("Users: SHA-224 lookup table capacity overflow");
        return false;
    }
    discard users_sha224_map_t_reserve(&table->map, (isize) capacity);

    return true;
}

static bool usersSHA256TableReserve(users_sha256_table_t *table, size_t count)
{
    size_t capacity = count < kUsersInitialTableCapacity ? kUsersInitialTableCapacity : count;

    if (UNLIKELY(! userIndexHashCapacityIsRepresentable(capacity, sizeof(*table->map.table), sizeof(*table->map.meta))))
    {
        LOGE("Users: SHA-256 lookup table capacity overflow");
        return false;
    }
    discard users_sha256_map_t_reserve(&table->map, (isize) capacity);

    return true;
}

static bool usersUUIDTableReserve(users_uuid_table_t *table, size_t count)
{
    size_t capacity = count < kUsersInitialTableCapacity ? kUsersInitialTableCapacity : count;

    if (UNLIKELY(! userIndexHashCapacityIsRepresentable(capacity, sizeof(*table->map.table), sizeof(*table->map.meta))))
    {
        LOGE("Users: UUID lookup table capacity overflow");
        return false;
    }
    discard users_uuid_map_t_reserve(&table->map, (isize) capacity);

    return true;
}

static bool usersWireGuardPublicKeyTableReserve(users_wireguard_publickey_table_t *table, size_t count)
{
    size_t capacity = count < kUsersInitialTableCapacity ? kUsersInitialTableCapacity : count;

    if (UNLIKELY(! userIndexHashCapacityIsRepresentable(capacity, sizeof(*table->map.table), sizeof(*table->map.meta))))
    {
        LOGE("Users: WireGuard public key lookup table capacity overflow");
        return false;
    }
    discard users_wireguard_publickey_map_t_reserve(&table->map, (isize) capacity);

    return true;
}

static bool usersIDTableReserve(users_id_table_t *table, size_t count)
{
    size_t capacity = count < kUsersInitialTableCapacity ? kUsersInitialTableCapacity : count;

    if (UNLIKELY(! userIndexHashCapacityIsRepresentable(capacity, sizeof(*table->map.table), sizeof(*table->map.meta))))
    {
        LOGE("Users: id lookup table capacity overflow");
        return false;
    }
    discard users_id_map_t_reserve(&table->map, (isize) capacity);

    return true;
}

static void usersSHA224TableCreateIfNeeded(users_t *users)
{
    if (users->sha224_table != NULL)
        return;
    users_sha224_table_t *table = memoryAllocateZero(sizeof(*table));
    discard               users_sha224_map_t_reserve(&table->map, kUsersInitialTableCapacity);
    users->sha224_table = table;
}

static void usersSHA256TableCreateIfNeeded(users_t *users)
{
    if (users->sha256_table != NULL)
        return;
    users_sha256_table_t *table = memoryAllocateZero(sizeof(*table));
    discard               users_sha256_map_t_reserve(&table->map, kUsersInitialTableCapacity);
    users->sha256_table = table;
}

static void usersUUIDTableCreateIfNeeded(users_t *users)
{
    if (users->uuid_table != NULL)
        return;
    users_uuid_table_t *table = memoryAllocateZero(sizeof(*table));
    discard             users_uuid_map_t_reserve(&table->map, kUsersInitialTableCapacity);
    users->uuid_table = table;
}

static void usersWireGuardPublicKeyTableCreateIfNeeded(users_t *users)
{
    if (users->wireguard_publickey_table != NULL)
        return;
    users_wireguard_publickey_table_t *table = memoryAllocateZero(sizeof(*table));
    discard                            users_wireguard_publickey_map_t_reserve(&table->map, kUsersInitialTableCapacity);
    users->wireguard_publickey_table = table;
}

static void usersIDTableCreateIfNeeded(users_t *users)
{
    if (users->id_table != NULL)
        return;
    users_id_table_t *table = memoryAllocateZero(sizeof(*table));
    discard           users_id_map_t_reserve(&table->map, kUsersInitialTableCapacity);
    users->id_table = table;
}

static bool usersSHA256TableEnsureCapacity(users_t *users, size_t count)
{
    usersSHA256TableCreateIfNeeded(users);
    return usersSHA256TableReserve(users->sha256_table, count);
}

static bool usersSHA224TableEnsureCapacity(users_t *users, size_t count)
{
    usersSHA224TableCreateIfNeeded(users);
    return usersSHA224TableReserve(users->sha224_table, count);
}

static bool usersUUIDTableEnsureCapacity(users_t *users, size_t count)
{
    usersUUIDTableCreateIfNeeded(users);
    return usersUUIDTableReserve(users->uuid_table, count);
}

static bool usersWireGuardPublicKeyTableEnsureCapacity(users_t *users, size_t count)
{
    usersWireGuardPublicKeyTableCreateIfNeeded(users);
    return usersWireGuardPublicKeyTableReserve(users->wireguard_publickey_table, count);
}

static bool usersIDTableEnsureCapacity(users_t *users, size_t count)
{
    usersIDTableCreateIfNeeded(users);
    return usersIDTableReserve(users->id_table, count);
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
    memorySecureZero(&key, sizeof(key));
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
    memorySecureZero(&key, sizeof(key));
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
    memorySecureZero(&key, sizeof(key));
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
    memorySecureZero(&key, sizeof(key));
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
 * after an irreversible mutation without growing their storage. Duplicate-key
 * and invalid-credential checks remain part of the transactional commit.
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
    if (UNLIKELY(! result.inserted && result.ref->second != user))
    {
        LOGE("Users: duplicate SHA-224 lookup key between users \"%s\" and \"%s\"",
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
    if (UNLIKELY(! result.inserted && result.ref->second != user))
    {
        LOGE("Users: duplicate SHA-256 lookup key between users \"%s\" and \"%s\"",
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
    if (UNLIKELY(! result.inserted && result.ref->second != user))
    {
        LOGE("Users: duplicate UUID credential between users \"%s\" and \"%s\"",
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
    memorySecureZero(&key, sizeof(key));
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
    users_sha224_map_t_erase_entry(&users->sha224_table->map, it.ref);
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
    memorySecureZero(&key, sizeof(key));
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
    users_sha256_map_t_erase_entry(&users->sha256_table->map, it.ref);
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
    memorySecureZero(&key, sizeof(key));
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
    users_uuid_map_t_erase_entry(&users->uuid_table->map, it.ref);
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
    memorySecureZero(&key, sizeof(key));
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
    users_wireguard_publickey_map_t_erase_entry(&users->wireguard_publickey_table->map, it.ref);
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

    if (UNLIKELY(! userIndexHashCapacityIsRepresentable(capacity, sizeof(*table->map.table), sizeof(*table->map.meta))))
    {
        LOGE("Users: name lookup table capacity overflow");
        return false;
    }
    discard users_name_map_t_reserve(&table->map, (isize) capacity);

    return true;
}

static void usersNameTableCreateIfNeeded(users_t *users)
{
    if (users->name_table != NULL)
        return;
    users_name_table_t *table = memoryAllocateZero(sizeof(*table));
    discard             users_name_map_t_reserve(&table->map, kUsersInitialTableCapacity);
    users->name_table = table;
}

static bool usersNameTableEnsureCapacity(users_t *users, size_t count)
{
    usersNameTableCreateIfNeeded(users);
    return usersNameTableReserve(users->name_table, count);
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
        LOGE("Users: name to erase has no lookup table (corrupted index)");
        return false;
    }

    users_name_key_t      key = {.name = name};
    users_name_map_t_iter it  = users_name_map_t_find(&table->map, key);
    if (UNLIKELY(it.ref == NULL))
    {
        /* A non-empty name is always indexed, so a miss here is a corrupted index
         * (a borrowed name key that outlived its user); fail closed. */
        LOGE("Users: name to erase is missing (corrupted index)");
        return false;
    }
    if (UNLIKELY(it.ref->second != user))
    {
        LOGE("Users: refusing to erase name owned by a different user");
        return false;
    }

    users_name_map_t_erase_entry(&table->map, it.ref);
    return true;
}

/* Capacity and uniqueness are established before the commit point. This calls
 * STC's no-grow bucket primitive and updates only this insertion's occupancy. */
static bool usersNameTableInsertReservedLocked(users_t *users, user_t *user)
{
    if (user->name == NULL || user->name[0] == '\0')
        return true;
    users_name_map_t *map = &users->name_table->map;
    assert(map->size < users_name_map_t_capacity(map));
    users_name_key_t        key    = {.name = user->name};
    users_name_map_t_result result = users_name_map_t_bucket_insert_(map, &key);
    if (! result.inserted)
        return result.ref->second == user;
    ++map->size;
    result.ref->first  = key;
    result.ref->second = user;
    return true;
}

static bool usersPointerTableReserve(users_pointer_table_t *table, size_t count)
{
    size_t capacity = count < kUsersInitialTableCapacity ? kUsersInitialTableCapacity : count;

    if (UNLIKELY(! userIndexHashCapacityIsRepresentable(capacity, sizeof(*table->map.table), sizeof(*table->map.meta))))
    {
        LOGE("Users: pointer lookup table capacity overflow");
        return false;
    }
    discard users_pointer_map_t_reserve(&table->map, (isize) capacity);

    return true;
}

static void usersPointerTableCreateIfNeeded(users_t *users)
{
    if (users->pointer_table != NULL)
        return;
    users_pointer_table_t *table = memoryAllocateZero(sizeof(*table));
    discard                users_pointer_map_t_reserve(&table->map, kUsersInitialTableCapacity);
    users->pointer_table = table;
}

static bool usersPointerTableEnsureCapacity(users_t *users, size_t count)
{
    usersPointerTableCreateIfNeeded(users);
    return usersPointerTableReserve(users->pointer_table, count);
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
    if (UNLIKELY(! usersPointerTableEnsureCapacity(users, users->count + 1U)))
    {
        return false;
    }

    discard users_pointer_map_t_insert_or_assign(&users->pointer_table->map, (uintptr_t) user, index);

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

static void usersLookupTablesCreateIfNeededLocked(users_t *users)
{
    usersSHA224TableCreateIfNeeded(users);
    usersSHA256TableCreateIfNeeded(users);
    usersUUIDTableCreateIfNeeded(users);
    usersWireGuardPublicKeyTableCreateIfNeeded(users);
    usersIDTableCreateIfNeeded(users);
    usersNameTableCreateIfNeeded(users);
    usersPointerTableCreateIfNeeded(users);
    usersAllowedIpTableCreateIfNeeded(users);
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

    usersLookupTablesCreateIfNeededLocked(lookup_users);
    if (UNLIKELY(! usersEnsureLookupCapacityLocked(lookup_users, lookup_capacity) ||
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
    const size_t bytes = new_capacity * sizeof(*users->items);
    if (UNLIKELY(! memoryAlignedAllocationSizeIsRepresentable(bytes, 32)))
    {
        LOGE("Users: active user pointer capacity overflow");
        return false;
    }
    user_t **new_items = usersAllocateAlignedZero32(bytes);
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
            const size_t bytes = new_block_capacity * sizeof(*users->blocks);
            if (UNLIKELY(! memoryAlignedAllocationSizeIsRepresentable(bytes, 32)))
            {
                LOGE("Users: user block pointer capacity overflow");
                return false;
            }
            user_t **new_blocks = usersAllocateAlignedZero32(bytes);
            if (LIKELY(users->blocks != NULL))
            {
                memoryCopy(new_blocks, users->blocks, users->block_capacity * sizeof(*new_blocks));
                memoryFreeAligned(users->blocks);
            }

            users->blocks         = new_blocks;
            users->block_capacity = new_block_capacity;
        }

        block = usersAllocateAlignedZero32(kUsersBlockSize * sizeof(*block));

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

/* No reserve or rehash is permitted once index publication starts. Callers
 * establish unique keys and complete capacity before entering this commit. */
#define USERS_INSERT_RESERVED(table_field, map_type, key_value, mapped_value)                                          \
    do                                                                                                                 \
    {                                                                                                                  \
        map_type *map = &users->table_field->map;                                                                      \
        if (map->size >= map_type##_capacity(map))                                                                     \
        {                                                                                                              \
            LOGF("Users: missing reserved insertion capacity");                                                        \
            abortProgramNow(1);                                                                                        \
        }                                                                                                              \
        map_type##_key    key    = (key_value);                                                                        \
        map_type##_result result = map_type##_bucket_insert_(map, &key);                                               \
        if (! result.inserted)                                                                                         \
        {                                                                                                              \
            LOGF("Users: duplicate key during reserved insertion");                                                    \
            abortProgramNow(1);                                                                                        \
        }                                                                                                              \
        ++map->size;                                                                                                   \
        result.ref->first  = key;                                                                                      \
        result.ref->second = (mapped_value);                                                                           \
        memorySecureZero(&key, sizeof(key));                                                                           \
    } while (0)

static void usersCommitReservedCredentialsLocked(users_t *users, user_t *slot)
{
    USERS_INSERT_RESERVED(sha224_table, users_sha224_map_t, usersSHA224KeyFromBytes(slot->sha224_pass.bytes), slot);
    USERS_INSERT_RESERVED(sha256_table, users_sha256_map_t, usersSHA256KeyFromBytes(slot->sha256_pass.bytes), slot);
    if (slot->uuid_pass_valid)
        USERS_INSERT_RESERVED(uuid_table, users_uuid_map_t, usersUUIDKeyFromBytes(slot->uuid_pass), slot);
    if (slot->wireguard_publickey_valid)
        USERS_INSERT_RESERVED(wireguard_publickey_table,
                              users_wireguard_publickey_map_t,
                              usersWireGuardPublicKeyFromBytes(slot->wireguard_publickey),
                              slot);
}

static void usersCommitReservedUserLocked(users_t *users, user_t *slot)
{
    /* Initialize a newly installed finite policy before publication, so an
     * edit before first traffic still preserves/clamps its original credit. */
    rwlockWriteLock(&slot->lock);
    rwlockWriteLock(&slot->stats_lock);
    userBandwidthReconcileLocked(slot, getHRTimeUs() / 1000U);
    rwlockWriteUnlock(&slot->stats_lock);
    rwlockWriteUnlock(&slot->lock);
    usersCommitReservedCredentialsLocked(users, slot);
    if (slot->id != 0)
        USERS_INSERT_RESERVED(id_table, users_id_map_t, slot->id, slot);
    if (! usersNameTableInsertReservedLocked(users, slot))
    {
        LOGF("Users: duplicate name during reserved insertion");
        abortProgramNow(1);
    }
    USERS_INSERT_RESERVED(pointer_table, users_pointer_map_t, (uintptr_t) slot, users->count);
#undef USERS_INSERT_RESERVED
    if (slot->wireguard_allowed_ips_valid)
    {
        users_allowed_ip_map_t *map = &users->allowed_ip_table->map;
        if ((map->disp == 0 && map->head >= map->capacity) || ! usersAllowedIpTableInsertLocked(users, slot))
        {
            LOGF("Users: inconsistent reserved Allowed-IP insertion");
            abortProgramNow(1);
        }
    }
    users->items[users->count++] = slot;
    ++users->slot_count;
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
 * prevalidated path reflects rejected capacity geometry. Publication thereafter
 * uses the shared reserved primitive; impossible index inconsistencies are fatal.
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
            LOGE("Users: duplicate SHA-224 lookup key while loading user \"%s\"", usersUserNameForLog(slot));
            return false;
        }
        if (UNLIKELY(usersSHA256TableLookupLocked(users, slot->sha256_pass.bytes) != NULL))
        {
            LOGE("Users: duplicate SHA-256 lookup key while loading user \"%s\"", usersUserNameForLog(slot));
            return false;
        }
        if (UNLIKELY(slot->uuid_pass_valid && usersUUIDTableLookupLocked(users, slot->uuid_pass) != NULL))
        {
            LOGE("Users: duplicate UUID credential while loading user \"%s\"", usersUserNameForLog(slot));
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

    usersCommitReservedUserLocked(users, slot);
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

static users_add_result_t usersValidateNewUserIndexesLocked(const users_t *users, const user_t *user)
{
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

static users_add_result_t usersValidateNewUserNoFatalLocked(const users_t *users, const user_t *user)
{
    if (UNLIKELY(user == NULL || ! user->initialized || ! user->sha224_pass_valid || ! user->sha256_pass_valid ||
                 ! userPasswordDataValid((user_t *) user)))
        return kUsersAddResultInvalidUser;
    if (UNLIKELY(! usersAllowedIpUserFieldsIndexable(user)))
        return kUsersAddResultInvalidWireGuardAllowedIps;
    return usersValidateNewUserIndexesLocked(users, user);
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
        return kUsersAddResultStorageUnavailable;
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
        return kUsersAddResultStorageUnavailable;
    }

    slot = usersStorageAtLocked(users, users->slot_count);
    if (UNLIKELY(! userCopy(slot, &user_copy)))
    {
        rwlockWriteUnlock(&users->lock);
        userDestroy(&user_copy);
        return kUsersAddResultStorageUnavailable;
    }
    /*
     * `slot` is an exact copy of the immutable, just-validated snapshot, so
     * commit skips the redundant revalidation. Capacity geometry refusal keeps
     * the public storage-unavailable result; heap exhaustion does not return.
     */
    if (UNLIKELY(! usersCommitNewUserLocked(users, slot, true)))
    {
        userDestroy(slot);
        rwlockWriteUnlock(&users->lock);
        userDestroy(&user_copy);
        return kUsersAddResultStorageUnavailable;
    }

    rwlockWriteUnlock(&users->lock);
    userDestroy(&user_copy);
    return kUsersAddResultOk;
}

/* Both collection and target configuration ownership are required. Preparation
 * has already derived credentials, so this performs only indexed checks. */
static users_update_result_t usersPasswordPreflightLocked(users_t *users, user_t *user,
                                                          const user_prepared_password_t *prepared)
{
    user_t *duplicate;
    if (prepared->uuid_pass_valid && (duplicate = usersUUIDTableLookupLocked(users, prepared->uuid_pass)) != NULL &&
        duplicate != user)
        return kUsersUpdateResultDuplicateUUID;
    if (prepared->wireguard_publickey_valid &&
        (duplicate = usersWireGuardPublicKeyTableLookupLocked(users, prepared->wireguard_publickey)) != NULL &&
        duplicate != user)
        return kUsersUpdateResultDuplicateWireGuardPublicKey;
    if ((duplicate = usersSHA224TableLookupLocked(users, prepared->sha224_pass.bytes)) != NULL && duplicate != user)
        return kUsersUpdateResultPasswordUpdateFailed;
    if ((duplicate = usersSHA256TableLookupLocked(users, prepared->sha256_pass.bytes)) != NULL && duplicate != user)
        return kUsersUpdateResultPasswordUpdateFailed;

    /* Every credential map reserves for the total active count, including
     * accounts without UUIDs. Check actual post-erase/add occupancy, never
     * reserve or invoke an insertion that may choose to grow. */
#define USERS_PASSWORD_CAPACITY(field, type, old_valid, new_valid)                                                     \
    do                                                                                                                 \
    {                                                                                                                  \
        if (users->field == NULL || users->field->map.size < (intptr_t) ! ! (old_valid))                               \
            return kUsersUpdateResultCapacityRejected;                                                                 \
        size_t occupancy = (size_t) users->field->map.size - (size_t) ! ! (old_valid);                                 \
        size_t capacity  = (size_t) type##_capacity(&users->field->map);                                               \
        if (occupancy > capacity || ((new_valid) && occupancy == capacity))                                            \
            return kUsersUpdateResultCapacityRejected;                                                                 \
    } while (0)
    USERS_PASSWORD_CAPACITY(sha224_table, users_sha224_map_t, user->sha224_pass_valid, prepared->sha224_pass_valid);
    USERS_PASSWORD_CAPACITY(sha256_table, users_sha256_map_t, user->sha256_pass_valid, prepared->sha256_pass_valid);
    USERS_PASSWORD_CAPACITY(uuid_table, users_uuid_map_t, user->uuid_pass_valid, prepared->uuid_pass_valid);
    USERS_PASSWORD_CAPACITY(wireguard_publickey_table,
                            users_wireguard_publickey_map_t,
                            user->wireguard_publickey_valid,
                            prepared->wireguard_publickey_valid);
#undef USERS_PASSWORD_CAPACITY
    return kUsersUpdateResultOk;
}

/* No allocation, refusal, lock acquisition, or table repair is possible after
 * the first erase. Corruption is fatal, rather than a partial update result. */
static void usersCommitPasswordLocked(users_t *users, user_t *user, user_prepared_password_t *prepared,
                                      size_t old_password_length)
{
    sha224_hash_t old_sha224 = user->sha224_pass;
    sha256_hash_t old_sha256 = user->sha256_pass;
    uint8_t       old_uuid[kWwUuidBytesLen];
    uint8_t       old_wireguard_publickey[USER_WIREGUARD_PUBLICKEY_SIZE];
    memoryCopy(old_uuid, user->uuid_pass, sizeof(old_uuid));
    memoryCopy(old_wireguard_publickey, user->wireguard_publickey, sizeof(old_wireguard_publickey));
    bool ok = usersSHA224TableEraseLocked(users, user, old_sha224.bytes) &&
              usersSHA256TableEraseLocked(users, user, old_sha256.bytes) &&
              (! user->uuid_pass_valid || usersUUIDTableEraseLocked(users, user, old_uuid)) &&
              (! user->wireguard_publickey_valid ||
               usersWireGuardPublicKeyTableEraseLocked(users, user, old_wireguard_publickey));
    usersWipeCredentialSnapshot(&old_sha224, &old_sha256, old_uuid, old_wireguard_publickey);
    if (! ok)
    {
        LOGF("Users: credential index inconsistency during password commit");
        abortProgramNow(1);
    }
    userCommitPreparedPasswordLocked(user, prepared, old_password_length);
    usersCommitReservedCredentialsLocked(users, user);
}

static users_update_result_t usersChangePasswordLocked(users_t *users, user_t *user, const char *password)
{
    if (! usersIndexOfLocked(users, user, NULL))
        return kUsersUpdateResultUserNotFound;
    user_prepared_password_t prepared = {0};
    if (password == NULL || password[0] == '\0' || ! userPreparePassword(&prepared, password, stringLength(password)))
        return kUsersUpdateResultPasswordUpdateFailed;
    rwlockWriteLock(&user->lock);
    users_update_result_t result = usersPasswordPreflightLocked(users, user, &prepared);
    /* Preserve existing object-caller diagnostics. The bounded API's shared
     * preflight remains silent and returns only its fixed typed outcome. */
    if (result == kUsersUpdateResultDuplicateUUID)
        LOGE("Users: duplicate UUID credential while updating user \"%s\"", usersUserNameForLog(user));
    else if (result == kUsersUpdateResultDuplicateWireGuardPublicKey)
        LOGE("Users: duplicate WireGuard public key while updating user \"%s\"", usersUserNameForLog(user));
    if (result == kUsersUpdateResultOk)
        usersCommitPasswordLocked(users, user, &prepared, user->password == NULL ? 0 : stringLength(user->password));
    rwlockWriteUnlock(&user->lock);
    userFreePreparedPassword(&prepared);
    return result;
}

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
            abortProgramNow(1);
        }
        abortProgramNow(1);
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
            abortProgramNow(1);
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
        abortProgramNow(1);
    }
}

static void usersApplyNameHint(user_t *user, const char *name_hint)
{
    if (name_hint == NULL || name_hint[0] == '\0' || (user->name != NULL && user->name[0] != '\0'))
        return;
    char *name = stringDuplicate(name_hint);
    memoryFree(user->name);
    user->name = name;
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
    usersApplyNameHint(slot, name_hint);
    if (LIKELY(usersCommitNewUserLocked(users, slot, false)))
    {
        return true;
    }

    userDestroy(slot);
    return false;
}

/*
 * Bound speculative storage before validating a container. Later entries grow
 * stable storage and indexes only as they are accepted; rollback restores counts.
 */
static bool usersReserveForFeedLocked(users_t *users, const cJSON *container)
{
    int entry_count = cJSON_GetArraySize(container);
    if (entry_count <= 0)
    {
        return true;
    }

    size_t total = users->count + min((size_t) entry_count, (size_t) kUsersBlockSize);
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
    return cJSON_IsString(cJSON_GetObjectItemCaseSensitive(json, "password")) ||
           cJSON_IsString(cJSON_GetObjectItemCaseSensitive(json, "pass"));
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
 * - A single user object when "password" or "pass" has a string value.
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
    if (UNLIKELY(! rwlockTryInit(&users->lock)))
    {
        return false;
    }
    usersLookupTablesCreateIfNeededLocked(users);

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

    if ((update->mask & kUserUpdateName) != 0U)
        usersStringDuplicate(name_copy, update->name);
    if ((update->mask & kUserUpdateEmail) != 0U)
        usersStringDuplicate(email_copy, update->email);
    if ((update->mask & kUserUpdateNotes) != 0U)
        usersStringDuplicate(notes_copy, update->notes);
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

static users_update_result_t usersPreflightConfigIndexesLocked(users_t *users, user_t *user,
                                                               const user_update_t *update, const char *name_copy,
                                                               const users_wireguard_allowed_ips_update_t *allowed_ips,
                                                               bool bounded, size_t max_growth_bytes,
                                                               uint64_t deadline_ms)
{
    if (usersConfigDeadlineExpired(deadline_ms))
        return kUsersUpdateResultTimeout;
    if ((update->mask & kUserUpdateName) != 0U)
    {
        if (bounded && user->name != NULL)
        {
            size_t length = 0;
            while (length <= kUsersConfigOldNameLimit && user->name[length] != '\0')
                ++length;
            if (length > kUsersConfigOldNameLimit)
                return kUsersUpdateResultResourceLimit;
        }
        if (usersFindByNameLocked(users, name_copy, user) != NULL)
            return kUsersUpdateResultDuplicateName;
        if (! bounded && ! usersNameTableEnsureCapacity(users, users->count))
            return kUsersUpdateResultCapacityRejected;
        if (users->name_table == NULL)
            return kUsersUpdateResultCapacityRejected;
        const users_name_map_t *map       = &users->name_table->map;
        const size_t            old_named = user->name != NULL && user->name[0] != '\0' ? 1U : 0U;
        const size_t            new_named = name_copy != NULL && name_copy[0] != '\0' ? 1U : 0U;
        if ((size_t) map->size < old_named)
        {
            LOGF("Users: invalid name index occupancy");
            abortProgramNow(1);
        }
        const size_t post_erase = (size_t) map->size - old_named;
        if (post_erase > (size_t) users_name_map_t_capacity(map) ||
            new_named > (size_t) users_name_map_t_capacity(map) - post_erase)
            return kUsersUpdateResultCapacityRejected;
    }
    if ((update->mask & kUserUpdateWireGuardAllowedIps) != 0U)
    {
        bool    range_ok = true;
        user_t *overlap  = usersFindWireGuardAllowedIpsOverlapLocked(
            users, allowed_ips->valid, &allowed_ips->ip, &allowed_ips->mask, allowed_ips->family, user, &range_ok);
        if (! range_ok)
            return kUsersUpdateResultInvalidWireGuardAllowedIps;
        if (overlap != NULL)
            return kUsersUpdateResultDuplicateWireGuardAllowedIps;
        if (! user->wireguard_allowed_ips_valid && allowed_ips->valid)
        {
            size_t count = usersAllowedIpTableSize(users->allowed_ip_table);
            size_t capacity, extent;
            if (count == SIZE_MAX ||
                ! usersAllowedIpTableGrowthGeometry(users->allowed_ip_table, count + 1U, &capacity, &extent))
                return kUsersUpdateResultCapacityRejected;
            const size_t table_bytes = users->allowed_ip_table == NULL ? sizeof(*users->allowed_ip_table) : 0U;
            if (bounded && (extent > kUsersConfigRangeGrowthLimit || extent > max_growth_bytes ||
                            table_bytes > max_growth_bytes - extent))
                return kUsersUpdateResultResourceLimit;
            if (usersConfigDeadlineExpired(deadline_ms))
                return kUsersUpdateResultTimeout;
            usersAllowedIpTableCreateIfNeeded(users);
            if (extent != 0)
                discard users_allowed_ip_map_t_reserve(&users->allowed_ip_table->map, (isize) capacity);
        }
    }
    return usersConfigDeadlineExpired(deadline_ms) ? kUsersUpdateResultTimeout : kUsersUpdateResultOk;
}

/* Collection and user configuration write locks precede the first index erase.
 * Capacity and uniqueness are already established; no ordinary refusal follows. */
static void usersApplyConfigValues(user_t *user, const user_update_t *update, char **name_copy, char **email_copy,
                                   char **notes_copy, users_wireguard_allowed_ips_update_t *wireguard_allowed_ips,
                                   const user_config_patch_t *patch)
{
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
    if (patch != NULL)
    {
        /* Merge leaves while locked: a whole timeinfo snapshot could overwrite
         * first usage published concurrently by an accounting helper. */
        if ((patch->mask & kUserConfigTrafficUp) != 0U)
            user->limit.traffic.u = patch->limit.traffic.u;
        if ((patch->mask & kUserConfigTrafficDown) != 0U)
            user->limit.traffic.d = patch->limit.traffic.d;
        if ((patch->mask & kUserConfigTrafficTotal) != 0U)
            user->limit.traffic.total = patch->limit.traffic.total;
        if ((patch->mask & kUserConfigBandwidthUp) != 0U)
            user->limit.bandwidth.u = patch->limit.bandwidth.u;
        if ((patch->mask & kUserConfigBandwidthDown) != 0U)
            user->limit.bandwidth.d = patch->limit.bandwidth.d;
        if ((patch->mask & kUserConfigIps) != 0U)
            user->limit.ips = patch->limit.ips;
        if ((patch->mask & kUserConfigDevices) != 0U)
            user->limit.devices = patch->limit.devices;
        if ((patch->mask & kUserConfigConnectionsIn) != 0U)
            user->limit.cons_in = patch->limit.cons_in;
        if ((patch->mask & kUserConfigConnectionsOut) != 0U)
            user->limit.cons_out = patch->limit.cons_out;
        if ((patch->mask & kUserConfigExpireAt) != 0U)
            user->timeinfo.expire_at_ms = patch->expire_at_ms;
        if ((patch->mask & kUserConfigExpireAfterFirstUsage) != 0U)
            user->timeinfo.expire_after_first_usage_ms = patch->expire_after_first_usage_ms;
    }
}

static bool usersUpdateTouchesBandwidth(const user_update_t *update, const user_config_patch_t *patch)
{
    return (update->mask & kUserUpdateLimit) != 0 ||
           (patch != NULL && (patch->mask & (kUserConfigBandwidthUp | kUserConfigBandwidthDown)) != 0);
}

static void usersCommitConfigUpdateLocked(users_t *users, user_t *user, const user_update_t *update, char **name_copy,
                                          char **email_copy, char **notes_copy,
                                          users_wireguard_allowed_ips_update_t *wireguard_allowed_ips,
                                          const user_config_patch_t            *patch)
{
    /*
     * Erase the old name entry while the old string is still alive, before
     * usersReplaceStringOwned() frees it. Both collection and configuration
     * write locks are held. A false return means
     * the old name resolved to a different user, i.e. the name index is already
     * corrupt; that is an unrecoverable invariant violation.
     */
    if (UNLIKELY((update->mask & kUserUpdateName) != 0U && ! usersNameTableEraseLocked(users, user, user->name)))
    {
        LOGF("Users: index inconsistency during configuration commit");
        abortProgramNow(1);
    }
    /*
     * Erase the old Allowed-IP range entry while the user still carries its old
     * range fields, before they are overwritten below.
     */
    if (UNLIKELY((update->mask & kUserUpdateWireGuardAllowedIps) != 0U &&
                 ! usersAllowedIpTableEraseLocked(users, user)))
    {
        LOGF("Users: index inconsistency during configuration commit");
        abortProgramNow(1);
    }

    usersApplyConfigValues(user, update, name_copy, email_copy, notes_copy, wireguard_allowed_ips, patch);
    if (usersUpdateTouchesBandwidth(update, patch))
        userBandwidthReconcileLocked(user, getHRTimeUs() / 1000U);

    /*
     * Insert the replacement name entry. Capacity was reserved above and the old
     * entry was erased, so this cannot fail on a rehash; a failure would be an
     * unrecoverable invariant violation.
     */
    if (UNLIKELY((update->mask & kUserUpdateName) != 0U && ! usersNameTableInsertReservedLocked(users, user)))
    {
        LOGF("Users: index inconsistency during configuration commit");
        abortProgramNow(1);
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
        LOGF("Users: index inconsistency during configuration commit");
        abortProgramNow(1);
    }
}

static users_update_result_t usersApplyUpdateToExistingUserLocked(
    users_t *users, user_t *user, const user_update_t *update, char **name_copy, char **email_copy, char **notes_copy,
    users_wireguard_allowed_ips_update_t *wireguard_allowed_ips)
{
    users_update_result_t result =
        usersPreflightConfigIndexesLocked(users, user, update, *name_copy, wireguard_allowed_ips, false, SIZE_MAX, 0);
    if (result != kUsersUpdateResultOk)
        return result;
    /* Credential changes own their own configuration lock. Do not call this
     * branch while holding a configuration-only patch's target lock. */
    if ((update->mask & kUserUpdatePassword) != 0U)
    {
        result = usersChangePasswordLocked(users, user, update->password);
        if (result != kUsersUpdateResultOk)
            return result;
    }
    rwlockWriteLock(&user->lock);
    bool bandwidth_locked = usersUpdateTouchesBandwidth(update, NULL);
    if (bandwidth_locked)
        rwlockWriteLock(&user->stats_lock);
    usersCommitConfigUpdateLocked(users, user, update, name_copy, email_copy, notes_copy, wireguard_allowed_ips, NULL);
    if (bandwidth_locked)
        rwlockWriteUnlock(&user->stats_lock);
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

static users_update_result_t usersConfigPatchToUpdate(const user_config_patch_t *patch, user_update_t *out)
{
    assert(patch != NULL && out != NULL);
    if (patch->mask == 0)
        return kUsersUpdateResultInvalidArgument;
    if ((patch->mask & ~((1U << 18U) - 1U)) != 0U)
        return kUsersUpdateResultUnknownFields;
    user_update_t update = {0};
    if ((patch->mask & kUserConfigName) != 0U)
    {
        assert(patch->name != NULL);
        update.mask |= kUserUpdateName;
        update.name = patch->name;
    }
    if ((patch->mask & kUserConfigEmail) != 0U)
    {
        assert(patch->email != NULL);
        update.mask |= kUserUpdateEmail;
        update.email = patch->email;
    }
    if ((patch->mask & kUserConfigNotes) != 0U)
    {
        assert(patch->notes != NULL);
        update.mask |= kUserUpdateNotes;
        update.notes = patch->notes;
    }
    if ((patch->mask & kUserConfigWireGuardAllowedIps) != 0U)
    {
        assert(patch->wireguard_allowed_ips != NULL);
        update.mask |= kUserUpdateWireGuardAllowedIps;
        update.wireguard_allowed_ips = patch->wireguard_allowed_ips;
    }
    if ((patch->mask & kUserConfigGid) != 0U)
    {
        update.mask |= kUserUpdateGid;
        update.gid = patch->gid;
    }
    if ((patch->mask & kUserConfigEnabled) != 0U)
    {
        update.mask |= kUserUpdateEnabled;
        update.enabled = patch->enabled;
    }
    if ((patch->mask & kUserConfigRecordStatInterval) != 0U)
    {
        update.mask |= kUserUpdateRecordStatInterval;
        update.record_stat_interval_ms = patch->record_stat_interval_ms;
    }
    *out = update;
    return usersValidateUpdateRequest(out);
}

/* Account before allocating, including CIDR's temporary compact input and local
 * normalization scratch. Scans are restricted by the supplied allowance. */
static bool usersConfigStringBytes(const char *value, size_t allowance, size_t *bytes)
{
    assert(value != NULL && bytes != NULL);
    for (size_t length = 0; length < allowance; ++length)
    {
        if (value[length] == '\0')
        {
            *bytes = length + 1U;
            return true;
        }
    }
    return false;
}

users_update_result_t usersPrepareConfigPatch(const user_config_patch_t *patch, size_t max_owned_bytes,
                                              uint64_t deadline_ms, user_config_prepared_patch_t **out)
{
    assert(patch != NULL && out != NULL);
    *out = NULL;
    if (usersConfigDeadlineExpired(deadline_ms))
        return kUsersUpdateResultTimeout;
    user_update_t         update;
    users_update_result_t result = usersConfigPatchToUpdate(patch, &update);
    if (result != kUsersUpdateResultOk)
        return result;
    size_t peak = sizeof(user_config_prepared_patch_t) + kUsersConfigPreparationScratchBytes;
    if (peak > max_owned_bytes)
        return kUsersUpdateResultResourceLimit;
    const char    *strings[]    = {update.name, update.email, update.notes};
    const uint32_t masks[]      = {kUserUpdateName, kUserUpdateEmail, kUserUpdateNotes};
    size_t         string_bytes = 0;
    for (size_t i = 0; i < 3U; ++i)
    {
        if ((update.mask & masks[i]) == 0U)
            continue;
        size_t bytes;
        if (! usersConfigStringBytes(strings[i], max_owned_bytes - peak, &bytes))
            return kUsersUpdateResultResourceLimit;
        peak += bytes;
        string_bytes += bytes;
    }
    if ((update.mask & kUserUpdateWireGuardAllowedIps) != 0U)
    {
        size_t bytes;
        if (! usersConfigStringBytes(update.wireguard_allowed_ips, max_owned_bytes - peak, &bytes))
            return kUsersUpdateResultResourceLimit;
        /* The legacy CIDR normalizer uses an int text length. */
        if (bytes > (size_t) INT_MAX)
            return kUsersUpdateResultResourceLimit;
        bytes = max(bytes, (size_t) USER_WIREGUARD_ALLOWED_IPS_MAX_TEXT);
        if (bytes > max_owned_bytes - peak)
            return kUsersUpdateResultResourceLimit;
        peak += bytes;
    }
    if (usersConfigDeadlineExpired(deadline_ms))
        return kUsersUpdateResultTimeout;
    user_config_prepared_patch_t *prepared = memoryAllocateZero(sizeof(*prepared));
    prepared->patch                        = *patch;
    prepared->update                       = update;
    prepared->peak_bytes                   = peak;
    result = usersPrepareUpdate(&update, &prepared->name, &prepared->email, &prepared->notes, &prepared->allowed_ips);
    if (result != kUsersUpdateResultOk)
    {
        usersFreePreparedConfigPatch(prepared);
        return result;
    }
    prepared->owned_bytes = sizeof(*prepared) + string_bytes;
    if ((update.mask & kUserUpdateWireGuardAllowedIps) != 0U)
        prepared->owned_bytes += stringLength(prepared->allowed_ips.copy) + 1U;
    prepared->patch.name = prepared->update.name = prepared->name;
    prepared->patch.email = prepared->update.email = prepared->email;
    prepared->patch.notes = prepared->update.notes = prepared->notes;
    prepared->patch.wireguard_allowed_ips = prepared->update.wireguard_allowed_ips = prepared->allowed_ips.copy;
    if (usersConfigDeadlineExpired(deadline_ms))
    {
        usersFreePreparedConfigPatch(prepared);
        return kUsersUpdateResultTimeout;
    }
    *out = prepared;
    return kUsersUpdateResultOk;
}

void usersFreePreparedConfigPatch(user_config_prepared_patch_t *prepared)
{
    if (prepared == NULL)
        return;
    usersFreeUpdateStringCopies(prepared->name, prepared->email, prepared->notes, &prepared->allowed_ips);
    memoryFree(prepared);
}

size_t usersPreparedConfigPatchOwnedBytes(const user_config_prepared_patch_t *prepared)
{
    assert(prepared != NULL);
    return prepared->owned_bytes;
}

size_t usersPreparedConfigPatchPeakBytes(const user_config_prepared_patch_t *prepared)
{
    assert(prepared != NULL);
    return prepared->peak_bytes;
}

/* Password staging owns only credentials, with no native locks or user state. */
struct user_prepared_password_change_s
{
    user_prepared_password_t material;
    size_t                   owned_bytes, peak_bytes;
};

enum
{
    kUsersPasswordTextLimit           = 32U * 1024U,
    kUsersPasswordPrepareScratchBytes = 256U,
    kUsersPasswordCommitScratchBytes  = 1024U
};

/* Admits at most limit text bytes and its terminator. Inspect incrementally so
 * imported large passwords cannot turn this operation into unbounded work. */
static users_password_result_t usersPasswordAdmitLength(const char *password, size_t limit, uint64_t deadline_ms,
                                                        size_t *length_out)
{
    assert(password != NULL && limit < SIZE_MAX && length_out != NULL);
    for (size_t offset = 0; offset <= limit; ++offset)
    {
        if (offset % 256U == 0 && usersConfigDeadlineExpired(deadline_ms))
            return kUsersPasswordTimeout;
        if (password[offset] == '\0')
        {
            *length_out = offset;
            return kUsersPasswordOk;
        }
    }
    return kUsersPasswordResourceLimit;
}

users_password_result_t usersPreparePasswordChange(const char *password, size_t max_owned_bytes, uint64_t deadline_ms,
                                                   user_prepared_password_change_t **out)
{
    assert(password != NULL && out != NULL);
    *out = NULL;
    if (password[0] == '\0')
        return kUsersPasswordInvalidArgument;
    if (usersConfigDeadlineExpired(deadline_ms))
        return kUsersPasswordTimeout;
    const size_t base    = sizeof(user_prepared_password_change_t) + 32U;
    const size_t scratch = kUsersPasswordPrepareScratchBytes;
    if (max_owned_bytes < base + scratch + 2U)
        return kUsersPasswordResourceLimit;
    size_t                  limit = min((size_t) kUsersPasswordTextLimit, max_owned_bytes - base - scratch - 1U);
    size_t                  length;
    users_password_result_t result = usersPasswordAdmitLength(password, limit, deadline_ms, &length);
    if (result != kUsersPasswordOk)
        return result;
    user_prepared_password_change_t *prepared = memoryAllocateAlignedZero(sizeof(*prepared), 32U);
    prepared->owned_bytes                     = base + length + 1U;
    prepared->peak_bytes                      = prepared->owned_bytes + scratch;
    if (! userPreparePassword(&prepared->material, password, length))
    {
        usersFreePreparedPasswordChange(prepared);
        return kUsersPasswordPreparationFailed;
    }
    if (usersConfigDeadlineExpired(deadline_ms))
    {
        usersFreePreparedPasswordChange(prepared);
        return kUsersPasswordTimeout;
    }
    *out = prepared;
    return kUsersPasswordOk;
}

void usersFreePreparedPasswordChange(user_prepared_password_change_t *prepared)
{
    if (prepared == NULL)
        return;
    userFreePreparedPassword(&prepared->material);
    memorySecureZero(prepared, sizeof(*prepared));
    memoryFreeAligned(prepared);
}

size_t usersPreparedPasswordChangeOwnedBytes(const user_prepared_password_change_t *prepared)
{
    assert(prepared != NULL);
    return prepared->owned_bytes;
}

size_t usersPreparedPasswordChangePeakBytes(const user_prepared_password_change_t *prepared)
{
    assert(prepared != NULL);
    return prepared->peak_bytes;
}

size_t usersPreparedPasswordChangeCommitBytes(const user_prepared_password_change_t *prepared)
{
    assert(prepared != NULL);
    discard prepared;
    return kUsersPasswordCommitScratchBytes;
}

users_password_result_t usersTryChangePreparedPasswordByIdentifier(users_t *users, uint64_t id,
                                                                   user_prepared_password_change_t *prepared,
                                                                   size_t max_working_bytes, uint64_t deadline_ms,
                                                                   users_config_precommit_fn precommit, void *context)
{
    assert(users != NULL && prepared != NULL && prepared->material.password != NULL);
    if (id == 0)
        return kUsersPasswordInvalidArgument;
    if (max_working_bytes < kUsersPasswordCommitScratchBytes)
        return kUsersPasswordResourceLimit;
    if (usersConfigDeadlineExpired(deadline_ms))
        return kUsersPasswordTimeout;
    if (! rwlockTryWriteLock(&users->lock))
        return kUsersPasswordBusy;
    users_password_result_t result = kUsersPasswordNotFound;
    user_t                 *user   = usersIDTableLookupLocked(users, id);
    if (user == NULL)
        goto release_collection;
    if (! rwlockTryWriteLock(&user->lock))
    {
        result = kUsersPasswordBusy;
        goto release_collection;
    }
    users_update_result_t preflight = usersPasswordPreflightLocked(users, user, &prepared->material);
    switch (preflight)
    {
    case kUsersUpdateResultOk:
        result = kUsersPasswordOk;
        break;
    case kUsersUpdateResultCapacityRejected:
        result = kUsersPasswordResourceLimit;
        break;
    case kUsersUpdateResultDuplicateUUID:
    case kUsersUpdateResultDuplicateWireGuardPublicKey:
    case kUsersUpdateResultPasswordUpdateFailed:
        result = kUsersPasswordCredentialsExist;
        break;
    default:
        LOGF("Users: unexpected password preflight result");
        abortProgramNow(1);
    }
    if (result != kUsersPasswordOk)
        goto release_user;
    size_t old_password_length = 0;
    if (user->password != NULL)
    {
        result = usersPasswordAdmitLength(user->password, kUsersPasswordTextLimit, deadline_ms, &old_password_length);
        if (result != kUsersPasswordOk)
            goto release_user;
    }
    if (usersConfigDeadlineExpired(deadline_ms))
    {
        result = kUsersPasswordTimeout;
        goto release_user;
    }
    if (precommit != NULL && ! precommit(context))
    {
        result = kUsersPasswordPrecommitRejected;
        goto release_user;
    }
    if (usersConfigDeadlineExpired(deadline_ms))
    {
        result = kUsersPasswordTimeout;
        goto release_user;
    }
    usersCommitPasswordLocked(users, user, &prepared->material, old_password_length);
release_user:
    rwlockWriteUnlock(&user->lock);
release_collection:
    rwlockWriteUnlock(&users->lock);
    return result;
}

/* Fresh accounts own their strings and native locks throughout preparation.
 * The enclosing object is aligned because user_t contains aligned hashes. */
struct user_prepared_creation_s
{
    user_t user;
    size_t owned_bytes, peak_bytes, string_bytes;
};

users_add_result_t usersPrepareNewUser(uint64_t id, const char *password, const user_config_patch_t *config,
                                       size_t max_owned_bytes, uint64_t deadline_ms, user_prepared_creation_t **out)
{
    assert(password != NULL && out != NULL);
    *out = NULL;
    if (id == 0 || password[0] == '\0')
        return kUsersAddResultInvalidArgument;
    if (usersConfigDeadlineExpired(deadline_ms))
        return kUsersAddResultTimeout;
    /* userChangePassword's private credential staging and CIDR scratch remain
     * charged alongside the aligned private user and owned password. */
    const size_t base = sizeof(user_prepared_creation_t) + 32U + sizeof(user_prepared_password_t) +
                        kUsersConfigPreparationScratchBytes + 4U;
    if (max_owned_bytes < base)
        return kUsersAddResultResourceLimit;
    size_t password_bytes;
    if (! usersConfigStringBytes(password, max_owned_bytes - base, &password_bytes))
        return kUsersAddResultResourceLimit;
    size_t                        peak  = base + password_bytes;
    user_config_prepared_patch_t *patch = NULL;
    if (config != NULL && config->mask != 0U)
    {
        users_update_result_t result = usersPrepareConfigPatch(config, max_owned_bytes - peak, deadline_ms, &patch);
        if (result != kUsersUpdateResultOk)
        {
            if (result == kUsersUpdateResultTimeout)
                return kUsersAddResultTimeout;
            if (result == kUsersUpdateResultResourceLimit || result == kUsersUpdateResultCapacityRejected)
                return kUsersAddResultResourceLimit;
            if (result == kUsersUpdateResultInvalidWireGuardAllowedIps)
                return kUsersAddResultInvalidWireGuardAllowedIps;
            return kUsersAddResultInvalidArgument;
        }
        peak += patch->peak_bytes;
    }
    if (usersConfigDeadlineExpired(deadline_ms))
    {
        usersFreePreparedConfigPatch(patch);
        return kUsersAddResultTimeout;
    }
    user_prepared_creation_t *prepared = memoryAllocateAlignedZero(sizeof(*prepared), 32U);
    if (! userCreate(&prepared->user, password))
    {
        usersFreePreparedConfigPatch(patch);
        memoryFreeAligned(prepared);
        return kUsersAddResultCreationFailed;
    }
    prepared->user.id = id;
    if (patch != NULL)
    {
        usersApplyConfigValues(&prepared->user,
                               &patch->update,
                               &patch->name,
                               &patch->email,
                               &patch->notes,
                               &patch->allowed_ips,
                               &patch->patch);
        usersFreePreparedConfigPatch(patch);
    }
    prepared->string_bytes = password_bytes + stringLength(prepared->user.name) + 1U +
                             stringLength(prepared->user.email) + 1U + stringLength(prepared->user.notes) + 1U +
                             stringLength(prepared->user.wireguard_allowed_ips) + 1U;
    prepared->owned_bytes = sizeof(*prepared) + 32U + prepared->string_bytes;
    prepared->peak_bytes  = max(peak, prepared->owned_bytes);
    if (usersConfigDeadlineExpired(deadline_ms))
    {
        usersFreePreparedNewUser(prepared);
        return kUsersAddResultTimeout;
    }
    *out = prepared;
    return kUsersAddResultOk;
}

void usersFreePreparedNewUser(user_prepared_creation_t *prepared)
{
    if (prepared == NULL)
        return;
    userDestroy(&prepared->user);
    memoryFreeAligned(prepared);
}

size_t usersPreparedNewUserOwnedBytes(const user_prepared_creation_t *prepared)
{
    assert(prepared != NULL);
    return prepared->owned_bytes;
}

size_t usersPreparedNewUserPeakBytes(const user_prepared_creation_t *prepared)
{
    assert(prepared != NULL);
    return prepared->peak_bytes;
}

static bool usersCreationCharge(size_t *charge, size_t extent, size_t allowance)
{
    if (*charge > allowance || extent > allowance - *charge)
        return false;
    *charge += extent;
    return true;
}

/* All arithmetic and the aggregate allocation admission precede any reserve.
 * Charge complete new extents, including aligned-allocation back pointers. */
static bool usersCreationGrowthGeometry(const users_t *users, const user_prepared_creation_t *prepared,
                                        size_t allowance, bool *name_growth)
{
    *name_growth = false;
    if (users->count == SIZE_MAX || users->slot_count == SIZE_MAX)
        return false;
    size_t charge = 0;
    if (! usersCreationCharge(&charge, prepared->string_bytes, allowance) ||
        ! usersCreationCharge(&charge, sizeof(user_t) + kUsersConfigPreparationScratchBytes, allowance))
        return false;
    const size_t count = users->count + 1U;
    if (count > users->capacity)
    {
        size_t capacity = users->capacity == 0 ? kUsersBlockSize : users->capacity;
        while (capacity < count)
        {
            if (capacity > SIZE_MAX / 2U)
                return false;
            capacity *= 2U;
        }
        if (capacity > SIZE_MAX / sizeof(*users->items))
            return false;
        size_t bytes = capacity * sizeof(*users->items);
        if (! memoryAlignedAllocationSizeIsRepresentable(bytes, 32U) ||
            ! usersCreationCharge(&charge, bytes + 32U, allowance))
            return false;
    }
    if (users->slot_count + 1U > users->slot_capacity)
    {
        if (users->slot_capacity > SIZE_MAX - kUsersBlockSize || users->block_count == SIZE_MAX)
            return false;
        if (users->block_count == users->block_capacity)
        {
            size_t capacity = users->block_capacity == 0 ? (32U + sizeof(*users->blocks) - 1U) / sizeof(*users->blocks)
                                                         : users->block_capacity * 2U;
            if (capacity < users->block_capacity || capacity > SIZE_MAX / sizeof(*users->blocks))
                return false;
            size_t bytes = capacity * sizeof(*users->blocks);
            if (! memoryAlignedAllocationSizeIsRepresentable(bytes, 32U) ||
                ! usersCreationCharge(&charge, bytes + 32U, allowance))
                return false;
        }
        const size_t bytes = kUsersBlockSize * sizeof(user_t);
        if (! memoryAlignedAllocationSizeIsRepresentable(bytes, 32U) ||
            ! usersCreationCharge(&charge, bytes + 32U, allowance))
            return false;
    }
    const size_t capacity = max(count, (size_t) kUsersInitialTableCapacity);
#define USERS_CHARGE_HASH(field)                                                                                       \
    do                                                                                                                 \
    {                                                                                                                  \
        assert(users->field != NULL);                                                                                  \
        size_t buckets, extent;                                                                                        \
        if (! userIndexHashGrowthGeometry(capacity,                                                                    \
                                          (size_t) users->field->map.bucket_count,                                     \
                                          sizeof(*users->field->map.table),                                            \
                                          sizeof(*users->field->map.meta),                                             \
                                          &buckets,                                                                    \
                                          &extent) ||                                                                  \
            ! usersCreationCharge(&charge, extent, allowance))                                                         \
            return false;                                                                                              \
        if (users->field == (void *) users->name_table && extent != 0)                                                 \
            *name_growth = true;                                                                                       \
    } while (0)
    USERS_CHARGE_HASH(sha224_table);
    USERS_CHARGE_HASH(sha256_table);
    USERS_CHARGE_HASH(uuid_table);
    USERS_CHARGE_HASH(wireguard_publickey_table);
    USERS_CHARGE_HASH(id_table);
    USERS_CHARGE_HASH(name_table);
    USERS_CHARGE_HASH(pointer_table);
#undef USERS_CHARGE_HASH
    if (prepared->user.wireguard_allowed_ips_valid)
    {
        size_t ranges = usersAllowedIpTableSize(users->allowed_ip_table), range_capacity, extent;
        if (ranges == SIZE_MAX ||
            ! usersAllowedIpTableGrowthGeometry(users->allowed_ip_table, ranges + 1U, &range_capacity, &extent) ||
            ! usersCreationCharge(&charge, extent, allowance))
            return false;
        if (users->allowed_ip_table == NULL &&
            ! usersCreationCharge(&charge, sizeof(*users->allowed_ip_table), allowance))
            return false;
    }
    return true;
}

/* Rehash invokes uninterruptible native name hashing. Admit every old name's
 * complete NUL-terminated byte work before that reserve, only when it grows. */
static users_add_result_t usersCreationInspectNames(const users_t *users, size_t allowance, uint64_t deadline_ms)
{
    const users_name_map_t *map       = &users->name_table->map;
    size_t                  remaining = allowance;
    for (isize i = 0; i < map->bucket_count; ++i)
    {
        if ((i & 255) == 0 && usersConfigDeadlineExpired(deadline_ms))
            return kUsersAddResultTimeout;
        if (map->meta[i].dist == 0)
            continue;
        const char *name  = map->table[i].first.name;
        size_t      bytes = 0;
        for (;;)
        {
            if (remaining == 0)
                return kUsersAddResultResourceLimit;
            --remaining;
            if (name[bytes++] == '\0')
                break;
            if ((bytes & 1023U) == 0U && usersConfigDeadlineExpired(deadline_ms))
                return kUsersAddResultTimeout;
        }
    }
    return usersConfigDeadlineExpired(deadline_ms) ? kUsersAddResultTimeout : kUsersAddResultOk;
}

users_add_result_t usersTryAddPreparedUser(users_t *users, user_prepared_creation_t *prepared, size_t max_growth_bytes,
                                           uint64_t deadline_ms, users_config_precommit_fn precommit, void *context)
{
    assert(users != NULL && prepared != NULL && prepared->user.initialized);
    if (usersConfigDeadlineExpired(deadline_ms))
        return kUsersAddResultTimeout;
    if (! rwlockTryWriteLock(&users->lock))
        return kUsersAddResultBusy;
    const user_t      *candidate = &prepared->user;
    users_add_result_t result;
    user_t            *slot = NULL;
    /* Public creation prioritizes identity; legacy checked-add retains its own
     * duplicate precedence through the indexed validator below. */
    if (usersIDTableLookupLocked(users, candidate->id) != NULL)
    {
        result = kUsersAddResultDuplicateId;
        goto unlock;
    }
    result = usersValidateNewUserIndexesLocked(users, candidate);
    if (result != kUsersAddResultOk)
        goto unlock;
    bool name_growth;
    if (! usersCreationGrowthGeometry(users, prepared, max_growth_bytes, &name_growth))
    {
        result = kUsersAddResultResourceLimit;
        goto unlock;
    }
    if (name_growth)
    {
        result = usersCreationInspectNames(users, max_growth_bytes, deadline_ms);
        if (result != kUsersAddResultOk)
            goto unlock;
    }
#define USERS_CREATE_RESERVE(expression)                                                                               \
    do                                                                                                                 \
    {                                                                                                                  \
        if (usersConfigDeadlineExpired(deadline_ms))                                                                   \
        {                                                                                                              \
            result = kUsersAddResultTimeout;                                                                           \
            goto unlock;                                                                                               \
        }                                                                                                              \
        if (! (expression))                                                                                            \
        {                                                                                                              \
            result = kUsersAddResultResourceLimit;                                                                     \
            goto unlock;                                                                                               \
        }                                                                                                              \
        if (usersConfigDeadlineExpired(deadline_ms))                                                                   \
        {                                                                                                              \
            result = kUsersAddResultTimeout;                                                                           \
            goto unlock;                                                                                               \
        }                                                                                                              \
    } while (0)
    USERS_CREATE_RESERVE(usersReserveItemsLocked(users, users->count + 1U));
    USERS_CREATE_RESERVE(usersReserveStorageLocked(users, users->slot_count + 1U));
    USERS_CREATE_RESERVE(usersSHA224TableEnsureCapacity(users, users->count + 1U));
    USERS_CREATE_RESERVE(usersSHA256TableEnsureCapacity(users, users->count + 1U));
    USERS_CREATE_RESERVE(usersUUIDTableEnsureCapacity(users, users->count + 1U));
    USERS_CREATE_RESERVE(usersWireGuardPublicKeyTableEnsureCapacity(users, users->count + 1U));
    USERS_CREATE_RESERVE(usersIDTableEnsureCapacity(users, users->count + 1U));
    USERS_CREATE_RESERVE(usersNameTableEnsureCapacity(users, users->count + 1U));
    USERS_CREATE_RESERVE(usersPointerTableEnsureCapacity(users, users->count + 1U));
    if (candidate->wireguard_allowed_ips_valid)
        USERS_CREATE_RESERVE(usersAllowedIpTableEnsureOneMoreRange(users));
#undef USERS_CREATE_RESERVE
    slot = usersStorageAtLocked(users, users->slot_count);
    if (! userCopy(slot, candidate))
    {
        result = kUsersAddResultCreationFailed;
        slot   = NULL; /* userCopy owns cleanup of partial native initialization. */
        goto unlock;
    }
    if (precommit != NULL && ! precommit(context))
    {
        result = kUsersAddResultPrecommitRejected;
        goto unlock;
    }
    if (usersConfigDeadlineExpired(deadline_ms))
    {
        result = kUsersAddResultTimeout;
        goto unlock;
    }
    usersCommitReservedUserLocked(users, slot);
    slot   = NULL;
    result = kUsersAddResultOk;
unlock:
    if (slot != NULL)
        userDestroy(slot);
    rwlockWriteUnlock(&users->lock);
    return result;
}

static users_update_result_t usersApplyPreparedConfigByIdentifier(users_t *users, uint64_t id,
                                                                  user_config_prepared_patch_t *prepared, bool bounded,
                                                                  size_t max_growth_bytes, uint64_t deadline_ms,
                                                                  users_config_precommit_fn precommit, void *context)
{
    assert(users != NULL && prepared != NULL);
    if (id == 0)
        return kUsersUpdateResultInvalidArgument;
    if (usersConfigDeadlineExpired(deadline_ms))
        return kUsersUpdateResultTimeout;
    if (bounded)
    {
        if (! rwlockTryWriteLock(&users->lock))
            return kUsersUpdateResultBusy;
    }
    else
        rwlockWriteLock(&users->lock);
    user_t               *user             = usersIDTableLookupLocked(users, id);
    users_update_result_t result           = kUsersUpdateResultUserNotFound;
    bool                  bandwidth_locked = false;
    if (user == NULL)
        goto unlock_collection;
    if (bounded)
    {
        if (! rwlockTryWriteLock(&user->lock))
        {
            result = kUsersUpdateResultBusy;
            goto unlock_collection;
        }
    }
    else
        rwlockWriteLock(&user->lock);
    if (usersUpdateTouchesBandwidth(&prepared->update, &prepared->patch))
    {
        if (bounded)
        {
            if (! rwlockTryWriteLock(&user->stats_lock))
            {
                result = kUsersUpdateResultBusy;
                goto unlock_user;
            }
        }
        else
            rwlockWriteLock(&user->stats_lock);
        bandwidth_locked = true;
    }
    result = usersPreflightConfigIndexesLocked(
        users, user, &prepared->update, prepared->name, &prepared->allowed_ips, bounded, max_growth_bytes, deadline_ms);
    if (result != kUsersUpdateResultOk)
        goto unlock_user;
    if (precommit != NULL && ! precommit(context))
    {
        result = kUsersUpdateResultPrecommitRejected;
        goto unlock_user;
    }
    if (usersConfigDeadlineExpired(deadline_ms))
    {
        result = kUsersUpdateResultTimeout;
        goto unlock_user;
    }
    usersCommitConfigUpdateLocked(users,
                                  user,
                                  &prepared->update,
                                  &prepared->name,
                                  &prepared->email,
                                  &prepared->notes,
                                  &prepared->allowed_ips,
                                  &prepared->patch);
unlock_user:
    if (bandwidth_locked)
        rwlockWriteUnlock(&user->stats_lock);
    rwlockWriteUnlock(&user->lock);
unlock_collection:
    rwlockWriteUnlock(&users->lock);
    return result;
}

users_update_result_t usersTryApplyPreparedConfigByIdentifier(users_t *users, uint64_t id,
                                                              user_config_prepared_patch_t *prepared,
                                                              size_t max_growth_bytes, uint64_t deadline_ms,
                                                              users_config_precommit_fn precommit, void *context)
{
    return usersApplyPreparedConfigByIdentifier(
        users, id, prepared, true, max_growth_bytes, deadline_ms, precommit, context);
}

users_update_result_t usersPatchConfigByIdentifier(users_t *users, uint64_t id, const user_config_patch_t *patch)
{
    assert(users != NULL && patch != NULL);
    if (id == 0)
        return kUsersUpdateResultInvalidArgument;
    user_config_prepared_patch_t *prepared;
    users_update_result_t         result = usersPrepareConfigPatch(patch, SIZE_MAX, 0, &prepared);
    if (result == kUsersUpdateResultOk)
    {
        result = usersApplyPreparedConfigByIdentifier(users, id, prepared, false, SIZE_MAX, 0, NULL, NULL);
        usersFreePreparedConfigPatch(prepared);
    }
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

static void usersMoveRuntimeStateWithLocks(user_t *dest, user_t *src)
{
    if (dest == src)
    {
        return;
    }

    user_t *first  = (uintptr_t) dest < (uintptr_t) src ? dest : src;
    user_t *second = first == dest ? src : dest;

    /*
     * The caller's users_t write locks pin both user objects and serialize the
     * database wrapper APIs, but direct userTryAdmitConnection() and
     * userReleaseConnection() calls synchronize only through stats_lock. Lock
     * both user locks, then both stats locks, in address order before moving
     * time evidence and owned runtime buffers. Keep the destination policy.
     */
    rwlockWriteLock(&first->lock);
    rwlockWriteLock(&second->lock);
    rwlockWriteLock(&first->stats_lock);
    rwlockWriteLock(&second->stats_lock);
    userRuntimeStateMove(&dest->runtime, &src->runtime);
    userBandwidthReconcileLocked(dest, getHRTimeUs() / 1000U);
    dest->client_time = src->client_time;
    memoryZero(&src->client_time, sizeof(src->client_time));
    rwlockWriteUnlock(&second->stats_lock);
    rwlockWriteUnlock(&first->stats_lock);
    rwlockWriteUnlock(&second->lock);
    rwlockWriteUnlock(&first->lock);
}

bool usersSnapshotAccounting(const users_t *users, user_accounting_snapshot_t **entries_out, size_t *count_out)
{
    assert(users != NULL && entries_out != NULL && count_out != NULL);
    *entries_out = NULL;
    *count_out   = 0;
    rwlockReadLock((wrwlock_t *) &users->lock);
    size_t bytes;
    if (! memoryTryComputeArraySize(users->count, sizeof(**entries_out), &bytes))
    {
        rwlockReadUnlock((wrwlock_t *) &users->lock);
        return false;
    }
    user_accounting_snapshot_t *entries = memoryAllocate(bytes);
    for (size_t i = 0; i < users->count; ++i)
        userGetAccountingSnapshot(usersGetAtLocked(users, i), &entries[i]);
    *entries_out = entries;
    *count_out   = users->count;
    rwlockReadUnlock((wrwlock_t *) &users->lock);
    return true;
}

static bool usersPublicDeadlineExpired(uint64_t deadline_ms)
{
    return deadline_ms != 0 && getHRTimeUs() / 1000U >= deadline_ms;
}

user_public_result_t usersTryCount(const users_t *users, uint64_t deadline_ms, size_t *count_out)
{
    assert(users != NULL && count_out != NULL);
    *count_out = 0;
    if (usersPublicDeadlineExpired(deadline_ms))
        return kUserPublicTimeout;
    if (! rwlockTryReadLock((wrwlock_t *) &users->lock))
        return kUserPublicBusy;
    size_t count = users->count;
    rwlockReadUnlock((wrwlock_t *) &users->lock);
    if (usersPublicDeadlineExpired(deadline_ms))
        return kUserPublicTimeout;
    *count_out = count;
    return kUserPublicOk;
}

user_public_result_t usersCopyPublicDetailByIdentifier(const users_t *users, uint64_t id, size_t max_string_bytes,
                                                       uint64_t deadline_ms, user_public_detail_t *out)
{
    assert(users != NULL && id != 0 && out != NULL);
    memoryZero(out, sizeof(*out));
    if (usersPublicDeadlineExpired(deadline_ms))
        return kUserPublicTimeout;
    if (! rwlockTryReadLock((wrwlock_t *) &users->lock))
        return kUserPublicBusy;
    user_t              *user = usersIDTableLookupLocked(users, id);
    user_public_result_t result =
        user == NULL ? kUserPublicNotFound : userCopyPublicDetail(user, max_string_bytes, deadline_ms, out);
    rwlockReadUnlock((wrwlock_t *) &users->lock);
    if (usersPublicDeadlineExpired(deadline_ms))
    {
        userPublicDetailDestroy(out);
        result = kUserPublicTimeout;
    }
    return result;
}

user_public_result_t usersCopyPublicPage(const users_t *users, size_t position, size_t limit, uint64_t deadline_ms,
                                         user_public_summary_t *entries_out, size_t *count_out, size_t *total_out)
{
    assert(users != NULL && limit > 0 && limit <= USER_PUBLIC_PAGE_MAX && entries_out != NULL && count_out != NULL &&
           total_out != NULL);
    *count_out = 0;
    *total_out = 0;
    memoryZero(entries_out, limit * sizeof(*entries_out));
    if (usersPublicDeadlineExpired(deadline_ms))
        return kUserPublicTimeout;
    if (! rwlockTryReadLock((wrwlock_t *) &users->lock))
        return kUserPublicBusy;
    user_public_result_t result = kUserPublicOutOfRange;
    size_t               count  = 0;
    if (position > users->count)
        goto done;
    count = min(limit, users->count - position);
    for (size_t i = 0; i < count; ++i)
    {
        result = userCopyPublicSummary(usersGetAtLocked(users, position + i), deadline_ms, &entries_out[i]);
        if (result != kUserPublicOk)
            goto done;
    }
    result = usersPublicDeadlineExpired(deadline_ms) ? kUserPublicTimeout : kUserPublicOk;
    if (result == kUserPublicOk)
    {
        *count_out = count;
        *total_out = users->count;
    }
done:
    rwlockReadUnlock((wrwlock_t *) &users->lock);
    if (result != kUserPublicOk)
        memoryZero(entries_out, limit * sizeof(*entries_out));
    return result;
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

        usersMoveRuntimeStateWithLocks(new_user, old_user);
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
    return usersAccountTrafficScaledByIdentifier(
        users, id, upload_bytes, download_bytes, kUserTrafficMultiplierScale, now_ms, found, first_usage_push_needed);
}

bool usersAccountTrafficScaledByIdentifier(users_t *users, uint64_t id, uint64_t upload_bytes, uint64_t download_bytes,
                                           uint32_t multiplier, uint64_t now_ms, bool *found,
                                           bool *first_usage_push_needed)
{
    assert(multiplier > 0 && multiplier <= kUserTrafficMultiplierMax);
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
        should_close =
            userAccountTrafficScaled(user, upload_bytes, download_bytes, multiplier, now_ms, first_usage_push_needed);
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

bool usersObserveTrafficByIdentifier(users_t *users, uint64_t id, uint64_t upload_bytes, uint64_t download_bytes,
                                     uint64_t now_ms, bool *first_usage_push_needed)
{
    assert(users != NULL && id != 0);
    if (first_usage_push_needed != NULL)
        *first_usage_push_needed = false;
    rwlockReadLock(&users->lock);
    user_t *user = usersIDTableLookupLocked(users, id);
    bool    close =
        user == NULL || userObserveTraffic(user, upload_bytes, download_bytes, now_ms, first_usage_push_needed);
    rwlockReadUnlock(&users->lock);
    return close;
}

bool usersBandwidthRegisterByIdentifier(users_t *users, uint64_t id, user_bandwidth_direction_t direction,
                                        uint64_t ticket)
{
    assert(users != NULL && id != 0);
    rwlockReadLock(&users->lock);
    user_t *user   = usersIDTableLookupLocked(users, id);
    bool    result = user == NULL ? false : userBandwidthRegister(user, direction, ticket);
    rwlockReadUnlock(&users->lock);
    return result;
}

void usersBandwidthSetEligibleByIdentifier(users_t *users, uint64_t id, user_bandwidth_direction_t direction,
                                           uint64_t ticket, bool eligible)
{
    assert(users != NULL && id != 0);
    rwlockReadLock(&users->lock);
    user_t *user = usersIDTableLookupLocked(users, id);
    if (user != NULL)
        userBandwidthSetEligible(user, direction, ticket, eligible);
    rwlockReadUnlock(&users->lock);
}

void usersBandwidthCancelByIdentifier(users_t *users, uint64_t id, user_bandwidth_direction_t direction,
                                      uint64_t ticket)
{
    assert(users != NULL && id != 0);
    rwlockReadLock(&users->lock);
    user_t *user = usersIDTableLookupLocked(users, id);
    if (user != NULL)
        userBandwidthCancel(user, direction, ticket);
    rwlockReadUnlock(&users->lock);
}

bool usersBandwidthReserveByIdentifier(users_t *users, uint64_t id, user_bandwidth_direction_t direction,
                                       uint64_t ticket, buffer_budget_cost_t cost)
{
    assert(users != NULL && id != 0);
    rwlockReadLock(&users->lock);
    user_t *user   = usersIDTableLookupLocked(users, id);
    bool    result = user == NULL ? false : userBandwidthReserve(user, direction, ticket, cost);
    rwlockReadUnlock(&users->lock);
    return result;
}

void usersBandwidthReleaseByIdentifier(users_t *users, uint64_t id, user_bandwidth_direction_t direction,
                                       uint64_t ticket, buffer_budget_cost_t cost)
{
    assert(users != NULL && id != 0);
    rwlockReadLock(&users->lock);
    user_t *user = usersIDTableLookupLocked(users, id);
    if (user != NULL)
        userBandwidthRelease(user, direction, ticket, cost);
    rwlockReadUnlock(&users->lock);
}

user_bandwidth_result_t usersBandwidthPreviewByIdentifier(users_t *users, uint64_t id,
                                                          user_bandwidth_direction_t direction, uint64_t ticket,
                                                          uint64_t bytes, bool datagram)
{
    assert(users != NULL && id != 0);
    rwlockReadLock(&users->lock);
    user_t                 *user   = usersIDTableLookupLocked(users, id);
    user_bandwidth_result_t result = user == NULL ? (user_bandwidth_result_t) {.decision = kUserDeliveryReject}
                                                  : userBandwidthPreview(user, direction, ticket, bytes, datagram);
    rwlockReadUnlock(&users->lock);
    return result;
}

user_delivery_decision_t usersCommitDeliveryByIdentifier(users_t *users, uint64_t id,
                                                         user_bandwidth_direction_t direction, uint64_t ticket,
                                                         uint64_t bytes, bool datagram, bool more, uint32_t multiplier)
{
    assert(users != NULL && id != 0);
    rwlockReadLock(&users->lock);
    user_t                  *user = usersIDTableLookupLocked(users, id);
    user_delivery_decision_t result =
        user == NULL ? kUserDeliveryReject
                     : userCommitDelivery(user, direction, ticket, bytes, datagram, more, multiplier);
    rwlockReadUnlock(&users->lock);
    return result;
}
