#include "users_internal.h"

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
void usersWipeCredentialSnapshot(sha224_hash_t *old_sha224, sha256_hash_t *old_sha256,
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

/* Both collection and target configuration ownership are required. Preparation
 * has already derived credentials, so this performs only indexed checks. */
users_update_result_t usersPasswordPreflightLocked(users_t *users, user_t *user,
                                                   const user_prepared_password_t *prepared)
{
    /* The old key must still resolve to this account before any new-key
     * refusal can be considered. Missing ownership is corruption, not capacity. */
    if (! user->sha224_pass_valid || ! user->sha256_pass_valid ||
        usersSHA224TableLookupLocked(users, user->sha224_pass.bytes) != user ||
        usersSHA256TableLookupLocked(users, user->sha256_pass.bytes) != user ||
        (user->uuid_pass_valid && usersUUIDTableLookupLocked(users, user->uuid_pass) != user) ||
        (user->wireguard_publickey_valid &&
         usersWireGuardPublicKeyTableLookupLocked(users, user->wireguard_publickey) != user))
    {
        LOGF("Users: corrupted credential ownership during password preflight");
        abortProgramNow(1);
    }
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
        {                                                                                                              \
            LOGF("Users: corrupted credential index during password preflight");                                       \
            abortProgramNow(1);                                                                                        \
        }                                                                                                              \
        size_t occupancy = (size_t) users->field->map.size - (size_t) ! ! (old_valid);                                 \
        size_t capacity  = (size_t) type##_capacity(&users->field->map);                                               \
        if (occupancy > capacity)                                                                                      \
        {                                                                                                              \
            LOGF("Users: corrupted credential index occupancy during password preflight");                             \
            abortProgramNow(1);                                                                                        \
        }                                                                                                              \
        if ((new_valid) && occupancy == capacity)                                                                      \
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
void usersCommitPasswordLocked(users_t *users, user_t *user, user_prepared_password_t *prepared,
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

users_update_result_t usersChangePasswordLocked(users_t *users, user_t *user, const char *password)
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

users_update_result_t usersValidateUpdateRequest(const user_update_t *update)
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

void usersFreeUpdateStringCopies(char *name_copy, char *email_copy, char *notes_copy,
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

users_update_result_t usersCopyUpdateStrings(const user_update_t *update, char **name_copy, char **email_copy,
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

users_update_result_t usersPrepareUpdate(const user_update_t *update, char **name_copy, char **email_copy,
                                         char **notes_copy, users_wireguard_allowed_ips_update_t *wireguard_allowed_ips)
{
    users_update_result_t result = usersValidateUpdateRequest(update);
    if (UNLIKELY(result != kUsersUpdateResultOk))
    {
        return result;
    }

    return usersCopyUpdateStrings(update, name_copy, email_copy, notes_copy, wireguard_allowed_ips);
}

users_update_result_t usersPreflightConfigIndexesLocked(users_t *users, user_t *user, const user_update_t *update,
                                                        const char                                 *name_copy,
                                                        const users_wireguard_allowed_ips_update_t *allowed_ips,
                                                        bool bounded, size_t max_growth_bytes, uint64_t deadline_ms)
{
    if (userDeadlineExpired(deadline_ms))
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
            if (userDeadlineExpired(deadline_ms))
                return kUsersUpdateResultTimeout;
            usersAllowedIpTableCreateIfNeeded(users);
            if (extent != 0)
                discard users_allowed_ip_map_t_reserve(&users->allowed_ip_table->map, (isize) capacity);
        }
    }
    return userDeadlineExpired(deadline_ms) ? kUsersUpdateResultTimeout : kUsersUpdateResultOk;
}

/* Collection and user configuration write locks precede the first index erase.
 * Capacity and uniqueness are already established; no ordinary refusal follows. */
void usersApplyConfigValues(user_t *user, const user_update_t *update, char **name_copy, char **email_copy,
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

bool usersUpdateTouchesBandwidth(const user_update_t *update, const user_config_patch_t *patch)
{
    return (update->mask & kUserUpdateLimit) != 0 ||
           (patch != NULL && (patch->mask & (kUserConfigBandwidthUp | kUserConfigBandwidthDown)) != 0);
}

void usersCommitConfigUpdateLocked(users_t *users, user_t *user, const user_update_t *update, char **name_copy,
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

users_update_result_t usersApplyUpdateToExistingUserLocked(users_t *users, user_t *user, const user_update_t *update,
                                                           char **name_copy, char **email_copy, char **notes_copy,
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
