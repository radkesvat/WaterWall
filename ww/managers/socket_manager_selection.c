#include "socket_manager_internal.h"

#include "loggers/internal_logger.h"
#include "wfrand.h"

/**
 * @brief Convert an ACL range wholly contained in the IPv4-mapped IPv6 prefix to native IPv4.
 */
static inline bool mappedAclRangeToV4(const ipmask_t *range, ip4_addr_t *ip, ip4_addr_t *mask)
{
    if (range->ip.type != IPADDR_TYPE_V6 || range->mask.type != IPADDR_TYPE_V6 ||
        ! needsV4SocketStrategy(range->ip.u_addr.ip6))
    {
        return false;
    }

    const ip6_addr_t *range_mask = &range->mask.u_addr.ip6;
    if (range_mask->addr[0] != UINT32_MAX || range_mask->addr[1] != UINT32_MAX || range_mask->addr[2] != UINT32_MAX)
    {
        return false;
    }

    memoryCopy(ip, &range->ip.u_addr.ip6.addr[3], sizeof(ip->addr));
    memoryCopy(mask, &range_mask->addr[3], sizeof(mask->addr));
    return true;
}

bool socketManagerIpMatchesAcl(ip_addr_t addr, const vec_ipmask_t *acl)
{
    normalizeIpAddr(&addr);

    for (isize i = 0; i < vec_ipmask_t_size(acl); ++i)
    {
        const ipmask_t *range = vec_ipmask_t_at(acl, i);

        if (addr.type == IPADDR_TYPE_V4)
        {
            if (range->ip.type == IPADDR_TYPE_V4 && range->mask.type == IPADDR_TYPE_V4 &&
                checkIPRange4(addr.u_addr.ip4, range->ip.u_addr.ip4, range->mask.u_addr.ip4))
            {
                return true;
            }

            ip4_addr_t mapped_ip;
            ip4_addr_t mapped_mask;
            if (mappedAclRangeToV4(range, &mapped_ip, &mapped_mask) &&
                checkIPRange4(addr.u_addr.ip4, mapped_ip, mapped_mask))
            {
                return true;
            }
        }
        if (addr.type == IPADDR_TYPE_V6 && range->ip.type == IPADDR_TYPE_V6 && range->mask.type == IPADDR_TYPE_V6 &&
            checkIPRange6(addr.u_addr.ip6, range->ip.u_addr.ip6, range->mask.u_addr.ip6))
        {
            return true;
        }
    }
    return false;
}

hash_t socketManagerCombineBalanceLocalHash(hash_t src_hash, const ip_addr_t *local_addr, uint16_t local_port,
                                            int match_tier)
{
    hash_t scope = ipaddrCalcHashNoPort(*local_addr);
    scope ^= (hash_t) local_port + 0x9E3779B97F4A7C15ULL + (scope << 6) + (scope >> 2);
    scope ^= ((hash_t) match_tier + 1U) + 0x9E3779B97F4A7C15ULL + (scope << 6) + (scope >> 2);
    return src_hash ^ (scope + 0x9E3779B97F4A7C15ULL + (src_hash << 6) + (src_hash >> 2));
}

bool socketManagerWildcardMatchesTier(bool bind_is_v6_wildcard, bool dest_is_v4, int tier)
{
    if (tier == kDispatchTierWildcardFamily)
    {
        // 0.0.0.0 serves IPv4, :: serves IPv6.
        return dest_is_v4 ? (! bind_is_v6_wildcard) : bind_is_v6_wildcard;
    }
    if (tier == kDispatchTierWildcardDual)
    {
        // :: also serves IPv4, but only after the family-matching tier found no consumer.
        return dest_is_v4 && bind_is_v6_wildcard;
    }
    return false;
}

/* Scope is eligibility, not an address/ACL priority tier. Unknown ingress
 * cannot prove an explicit device restriction; unrestricted filters can win. */
static bool scopeMatchesFilter(const socket_filter_t *filter, const listener_endpoint_t *endpoint)
{
    const char *scope = filterInterfaceScope(filter);
    return scope == NULL || (endpoint->interface_scope != NULL && strcmp(scope, endpoint->interface_scope) == 0);
}

static bool addrMatchesFilter(const socket_filter_t *filter, const ip_addr_t *local_addr, int tier)
{
    if (tier == kDispatchTierExact)
    {
        return ! filter->bind_is_wildcard && ipAddrEqualsExact(&filter->bind_addr, local_addr);
    }
    return filter->bind_is_wildcard &&
           socketManagerWildcardMatchesTier(filter->bind_family == AF_INET6, local_addr->type == IPADDR_TYPE_V4, tier);
}

static bool filterMatchesArrival(const socket_filter_t *filter, const listener_arrival_t *arrival, int tier)
{
    const socket_filter_option_t *option = &filter->option;
    if (option->protocol != arrival->protocol || ! scopeMatchesFilter(filter, arrival->endpoint) ||
        ! addrMatchesFilter(filter, &arrival->local_addr, tier))
    {
        return false;
    }
    if (vec_listener_port_t_size(&option->ports) > 0)
    {
        bool found = false;
        c_foreach(port, vec_listener_port_t, option->ports)
        {
            if (*port.ref == arrival->local_port)
            {
                found = true;
                break;
            }
        }
        if (! found)
            return false;
    }
    else if (arrival->local_port < option->port_min || arrival->local_port > option->port_max)
    {
        return false;
    }
    return (vec_ipmask_t_size(&option->white_list) == 0 ||
            socketManagerIpMatchesAcl(arrival->peer_addr, &option->white_list)) &&
           (vec_ipmask_t_size(&option->black_list) == 0 ||
            ! socketManagerIpMatchesAcl(arrival->peer_addr, &option->black_list));
}

hash_t socketManagerArrivalBalanceHash(const listener_arrival_t *arrival, int tier)
{
    ip_addr_t peer  = arrival->peer_addr;
    ip_addr_t local = arrival->local_addr;
    normalizeIpAddr(&peer);
    normalizeIpAddr(&local);
    hash_t key = socketManagerCombineBalanceLocalHash(ipaddrCalcHashNoPort(peer), &local, arrival->local_port, tier);
    const char  *scope      = arrival->endpoint->interface_scope;
    const hash_t scope_hash = scope == NULL ? 0 : calcHashBytes(scope, stringLength(scope));
    key ^= scope_hash + 0x9E3779B97F4A7C15ULL + (key << 6) + (key >> 2);
    key ^= (hash_t) arrival->protocol + 0x9E3779B97F4A7C15ULL + (key << 6) + (key >> 2);
    return key;
}

static uint64_t balanceInterval(const socket_filter_t *filter)
{
    return filter->option.balance_group_interval == 0 ? kDefaultBalanceInterval : filter->option.balance_group_interval;
}

listener_selection_t socketManagerSelect(const filters_t filters[kFilterLevels], wid_t wid,
                                         const listener_arrival_t *arrival)
{
    assert(currentThreadIsEventWorkerWID(wid));
    assert(arrival != NULL && arrival->endpoint != NULL);
    listener_arrival_t normalized = *arrival;
    normalizeIpAddr(&normalized.peer_addr);
    normalizeIpAddr(&normalized.local_addr);

    for (int tier = 0; tier < kDispatchTierCount; ++tier)
    {
        socket_filter_t *candidates[kMaxBalanceSelections];
        size_t           count          = 0;
        idle_table_t    *selected_table = NULL;
        hash_t           key            = 0;
        for (int level = kFilterLevels - 1; level >= 0; --level)
        {
            c_foreach(it, filters_t, filters[level])
            {
                socket_filter_t *filter = *it.ref;
                if (! filterMatchesArrival(filter, &normalized, tier))
                    continue;
                /* Preserve immediate unbalanced selection even after balanced
                 * candidates at a higher priority have accumulated. */
                if (filter->balance_table == NULL)
                    return (listener_selection_t) {.filter = filter};
                if (selected_table != NULL && filter->balance_table != selected_table)
                    continue;
                if (selected_table == NULL)
                    key = socketManagerArrivalBalanceHash(&normalized, tier);

                idle_item_t *item = idletableGetIdleItemByHash(wid, filter->balance_table, key);
                if (item != NULL)
                {
                    socket_filter_t *target = item->userdata;
                    if (target->balance_table == filter->balance_table &&
                        filterMatchesArrival(target, &normalized, tier))
                    {
                        /* The scanning filter supplies the refresh interval,
                         * matching the historical cached-hit timing. */
                        idletableKeepIdleItemForAtleast(filter->balance_table, item, balanceInterval(filter));
                        return (listener_selection_t) {.filter = target};
                    }
                }
                if (UNLIKELY(count >= kMaxBalanceSelections))
                {
                    LOGW("SocketManager: balance between more than %d tunnels is not supported", kMaxBalanceSelections);
                    continue;
                }
                candidates[count++] = filter;
                selected_table      = filter->balance_table;
            }
        }
        if (count > 0)
        {
            return (listener_selection_t) {
                .filter = candidates[count == 1 ? 0 : fastRand() % count], .sticky_key = key, .pending_sticky = true};
        }
    }
    return (listener_selection_t) {0};
}

void socketManagerCommitSelection(wid_t wid, const listener_selection_t *selection)
{
    assert(currentThreadIsEventWorkerWID(wid));
    assert(selection != NULL && selection->filter != NULL);
    if (selection->pending_sticky)
    {
        socket_filter_t *filter = selection->filter;
        /* Refusal (including an existing colliding entry) never cancels delivery. */
        idletableCreateItem(filter->balance_table, selection->sticky_key, filter, NULL, wid, balanceInterval(filter));
    }
}
