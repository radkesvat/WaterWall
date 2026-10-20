#include "users_internal.h"

bool usersWireGuardAllowedIpContainsFields(bool valid, const ip_addr_t *network, const ip_addr_t *mask, uint8_t family,
                                           const ip_addr_t *ip)
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

bool usersWireGuardAllowedIpContainsUser(const user_t *user, const ip_addr_t *ip)
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
bool usersAllowedIpExtractBytes(const ip_addr_t *addr, uint8_t family, uint8_t out[16])
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
bool usersAllowedIpRangeFromFields(const ip_addr_t *network, const ip_addr_t *mask, uint8_t family, uint8_t start16[16],
                                   uint8_t end16[16])
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

bool usersAllowedIpEntryFromUser(const user_t *user, users_allowed_ip_key_t *key, users_allowed_ip_value_t *value)
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

bool usersAllowedIpUserFieldsIndexable(const user_t *user)
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

void usersAllowedIpTableCreateIfNeeded(users_t *users)
{
    if (users->allowed_ip_table != NULL)
        return;
    users_allowed_ip_table_t *table = memoryAllocateZero(sizeof(*table));
    users->allowed_ip_table         = table;
}

size_t usersAllowedIpTableSize(const users_allowed_ip_table_t *table)
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
bool usersAllowedIpTableGrowthGeometry(const users_allowed_ip_table_t *table, size_t min_capacity, size_t *capacity_out,
                                       size_t *extent_out)
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

bool usersAllowedIpTableReserve(users_allowed_ip_table_t *table, size_t min_capacity)
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

bool usersAllowedIpTableEnsureCapacity(users_t *users, size_t count)
{
    usersAllowedIpTableCreateIfNeeded(users);
    return usersAllowedIpTableReserve(users->allowed_ip_table, count);
}

bool usersAllowedIpTableEnsureOneMoreRange(users_t *users)
{
    size_t range_count = usersAllowedIpTableSize(users->allowed_ip_table);

    if (UNLIKELY(range_count == SIZE_MAX))
    {
        LOGE("Users: Allowed-IP lookup table capacity overflow");
        return false;
    }
    return usersAllowedIpTableEnsureCapacity(users, range_count + 1U);
}

void usersAllowedIpTableClear(users_allowed_ip_table_t *table)
{
    if (UNLIKELY(table == NULL))
    {
        return;
    }

    users_allowed_ip_map_t_clear(&table->map);
}

void usersAllowedIpTableDestroy(users_allowed_ip_table_t *table)
{
    if (UNLIKELY(table == NULL))
    {
        return;
    }

    users_allowed_ip_map_t_drop(&table->map);
    memoryFree(table);
}

/* Inserts the user's configured range. Users without a range are not indexed. */
bool usersAllowedIpTableInsertLocked(users_t *users, user_t *user)
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
bool usersAllowedIpTableEraseLocked(users_t *users, const user_t *user)
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
user_t *usersAllowedIpTableFindContainingLocked(const users_t *users, uint8_t family, const uint8_t addr16[16])
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
user_t *usersAllowedIpTableFindOverlapLocked(const users_t *users, uint8_t family, const uint8_t start16[16],
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
