#include "users_internal.h"

users_update_result_t usersConfigPatchToUpdate(const user_config_patch_t *patch, user_update_t *out)
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
bool usersConfigStringBytes(const char *value, size_t allowance, size_t *bytes)
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
    if (userDeadlineExpired(deadline_ms))
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
        /* Preserve the preparation's existing INT_MAX input-size policy. The
         * CIDR normalizer itself uses size_t lengths. */
        if (bytes > (size_t) INT_MAX)
            return kUsersUpdateResultResourceLimit;
        bytes = max(bytes, (size_t) USER_WIREGUARD_ALLOWED_IPS_MAX_TEXT);
        if (bytes > max_owned_bytes - peak)
            return kUsersUpdateResultResourceLimit;
        peak += bytes;
    }
    if (userDeadlineExpired(deadline_ms))
        return kUsersUpdateResultTimeout;
    user_config_prepared_patch_t *prepared = memoryAllocateZero(sizeof(*prepared));
    prepared->patch                        = *patch;
    prepared->update                       = update;
    prepared->peak_bytes                   = peak;
    result =
        usersCopyUpdateStrings(&update, &prepared->name, &prepared->email, &prepared->notes, &prepared->allowed_ips);
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
    if (userDeadlineExpired(deadline_ms))
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

users_password_result_t usersPasswordAdmitLength(const char *password, size_t limit, uint64_t deadline_ms,
                                                 size_t *length_out)
{
    assert(password != NULL && limit < SIZE_MAX && length_out != NULL);
    for (size_t offset = 0; offset <= limit; ++offset)
    {
        if (offset % 256U == 0 && userDeadlineExpired(deadline_ms))
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
    if (userDeadlineExpired(deadline_ms))
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
    if (userDeadlineExpired(deadline_ms))
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
    if (userDeadlineExpired(deadline_ms))
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
    if (userDeadlineExpired(deadline_ms))
    {
        result = kUsersPasswordTimeout;
        goto release_user;
    }
    if (precommit != NULL && ! precommit(context))
    {
        result = kUsersPasswordPrecommitRejected;
        goto release_user;
    }
    if (userDeadlineExpired(deadline_ms))
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

users_add_result_t usersPrepareNewUser(uint64_t id, const char *password, const user_config_patch_t *config,
                                       size_t max_owned_bytes, uint64_t deadline_ms, user_prepared_creation_t **out)
{
    assert(password != NULL && out != NULL);
    *out = NULL;
    if (id == 0 || password[0] == '\0')
        return kUsersAddResultInvalidArgument;
    if (userDeadlineExpired(deadline_ms))
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
    if (userDeadlineExpired(deadline_ms))
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
    if (userDeadlineExpired(deadline_ms))
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

bool usersCreationCharge(size_t *charge, size_t extent, size_t allowance)
{
    if (*charge > allowance || extent > allowance - *charge)
        return false;
    *charge += extent;
    return true;
}

/* All arithmetic and the aggregate allocation admission precede any reserve.
 * Charge complete new extents, including aligned-allocation back pointers. */
bool usersCreationGrowthGeometry(const users_t *users, const user_prepared_creation_t *prepared, size_t allowance,
                                 bool *name_growth)
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
#define USERS_CHARGE_HASH(field, is_name)                                                                              \
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
        if ((is_name) && extent != 0)                                                                                  \
            *name_growth = true;                                                                                       \
    } while (0)
    USERS_CHARGE_HASH(sha224_table, false);
    USERS_CHARGE_HASH(sha256_table, false);
    USERS_CHARGE_HASH(uuid_table, false);
    USERS_CHARGE_HASH(wireguard_publickey_table, false);
    USERS_CHARGE_HASH(id_table, false);
    USERS_CHARGE_HASH(name_table, true);
    USERS_CHARGE_HASH(pointer_table, false);
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
users_add_result_t usersCreationInspectNames(const users_t *users, size_t allowance, uint64_t deadline_ms)
{
    const users_name_map_t *map       = &users->name_table->map;
    size_t                  remaining = allowance;
    for (isize i = 0; i < map->bucket_count; ++i)
    {
        if ((i & 255) == 0 && userDeadlineExpired(deadline_ms))
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
            if ((bytes & 1023U) == 0U && userDeadlineExpired(deadline_ms))
                return kUsersAddResultTimeout;
        }
    }
    return userDeadlineExpired(deadline_ms) ? kUsersAddResultTimeout : kUsersAddResultOk;
}

users_add_result_t usersTryAddPreparedUser(users_t *users, user_prepared_creation_t *prepared, size_t max_growth_bytes,
                                           uint64_t deadline_ms, users_config_precommit_fn precommit, void *context)
{
    assert(users != NULL && prepared != NULL && prepared->user.initialized);
    if (userDeadlineExpired(deadline_ms))
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
        if (userDeadlineExpired(deadline_ms))                                                                          \
        {                                                                                                              \
            result = kUsersAddResultTimeout;                                                                           \
            goto unlock;                                                                                               \
        }                                                                                                              \
        if (! (expression))                                                                                            \
        {                                                                                                              \
            result = kUsersAddResultResourceLimit;                                                                     \
            goto unlock;                                                                                               \
        }                                                                                                              \
        if (userDeadlineExpired(deadline_ms))                                                                          \
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
    if (userDeadlineExpired(deadline_ms))
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

users_update_result_t usersApplyPreparedConfigByIdentifier(users_t *users, uint64_t id,
                                                           user_config_prepared_patch_t *prepared, bool bounded,
                                                           size_t max_growth_bytes, uint64_t deadline_ms,
                                                           users_config_precommit_fn precommit, void *context)
{
    assert(users != NULL && prepared != NULL && ! prepared->consumed);
    if (id == 0)
        return kUsersUpdateResultInvalidArgument;
    if (userDeadlineExpired(deadline_ms))
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
    if (userDeadlineExpired(deadline_ms))
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
    prepared->consumed   = true;
    prepared->patch.mask = prepared->update.mask = 0;
    prepared->patch.name = prepared->update.name = NULL;
    prepared->patch.email = prepared->update.email = NULL;
    prepared->patch.notes = prepared->update.notes = NULL;
    prepared->patch.wireguard_allowed_ips = prepared->update.wireguard_allowed_ips = NULL;
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
