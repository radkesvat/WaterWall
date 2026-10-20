#include "users_internal.h"

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

void usersMoveRuntimeStateWithLocks(user_t *dest, user_t *src)
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
