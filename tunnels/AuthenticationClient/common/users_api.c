#include "internal.h"

#include "loggers/network_logger.h"

typedef enum authenticationclient_first_usage_push_result_e
{
    kAuthenticationClientFirstUsagePushQueued = 0,
    kAuthenticationClientFirstUsagePushPending,
    kAuthenticationClientFirstUsagePushNotReady
} authenticationclient_first_usage_push_result_t;

authenticationclient_state_t authenticationclientGetState(tunnel_t *t)
{
    if (UNLIKELY(t == NULL))
        return kAuthenticationClientStateStopped;
    authenticationclient_tstate_t *ts = tunnelGetState(t);
    mutexLock(&ts->control_mutex);
    rwlockReadLock(&ts->users_lock);
    const authenticationclient_state_t state = authenticationclientStateLocked(ts);
    rwlockReadUnlock(&ts->users_lock);
    mutexUnlock(&ts->control_mutex);
    return state;
}

bool authenticationclientIsReady(tunnel_t *t)
{
    return authenticationclientGetState(t) == kAuthenticationClientStateReady;
}

bool authenticationclientCanAuthenticate(tunnel_t *t)
{
    if (t == NULL)
        return false;
    authenticationclient_tstate_t *ts = tunnelGetState(t);
    mutexLock(&ts->control_mutex);
    rwlockReadLock(&ts->users_lock);
    const bool available = authenticationclientCanAuthenticateLocked(ts);
    rwlockReadUnlock(&ts->users_lock);
    mutexUnlock(&ts->control_mutex);
    return available;
}

uint64_t authenticationclientUsersGeneration(tunnel_t *t)
{
    if (UNLIKELY(t == NULL))
    {
        return 0;
    }

    authenticationclient_tstate_t *ts         = tunnelGetState(t);
    uint64_t                       generation = 0;

    rwlockReadLock(&ts->users_lock);
    generation = ts->users_generation;
    rwlockReadUnlock(&ts->users_lock);

    return generation;
}

void authenticationclientUserProfileClear(authenticationclient_user_profile_t *profile)
{
    if (profile == NULL)
    {
        return;
    }
    if (profile->name != NULL)
    {
        memoryFree(profile->name);
        profile->name = NULL;
    }
    if (profile->password != NULL)
    {
        memorySecureZero(profile->password, strlen(profile->password) + 1);
        memoryFree(profile->password);
        profile->password = NULL;
    }
}

static void authenticationclientAssertProfileEmpty(authenticationclient_user_profile_t *profile, const char *fn_name)
{
    if (profile == NULL)
    {
        return;
    }

    assert(profile->name == NULL);
    assert(profile->password == NULL);
    if (UNLIKELY(profile->name != NULL || profile->password != NULL))
    {
        LOGF("AuthenticationClient: %s received a non-empty user profile output; clear it before reuse", fn_name);
        abortProgramNow(1);
    }
}

typedef enum authenticationclient_credential_kind_e
{
    kAuthenticationClientCredentialSHA224,
    kAuthenticationClientCredentialSHA256,
    kAuthenticationClientCredentialUUID,
    kAuthenticationClientCredentialWireGuard,
    kAuthenticationClientCredentialPassword
} authenticationclient_credential_kind_t;

/* control_mutex -> users_lock pins availability, generation and table identity;
 * userCopyAccess holds configuration/stats ownership for eligibility and profile. */
static authenticationclient_user_lookup_result_t authenticationclientResolveCredential(
    tunnel_t *t, authenticationclient_credential_kind_t kind, const void *credential, user_handle_t *handle_out,
    authenticationclient_user_profile_t *profile_out, const char *fn_name)
{
    authenticationclientAssertProfileEmpty(profile_out, fn_name);
    if (UNLIKELY(t == NULL || credential == NULL || handle_out == NULL ||
                 (kind == kAuthenticationClientCredentialPassword && ((const char *) credential)[0] == '\0')))
    {
        if (handle_out != NULL)
            userHandleClear(handle_out);
        return kAuthenticationClientUserLookupInvalidArgument;
    }

    sha256_hash_t sha256 = {0};
    if (kind == kAuthenticationClientCredentialPassword &&
        UNLIKELY(wCryptoSHA256(&sha256, credential, stringLength(credential)) != kWCryptoOk))
    {
        memorySecureZero(&sha256, sizeof(sha256));
        userHandleClear(handle_out);
        return kAuthenticationClientUserLookupHashFailed;
    }

    authenticationclient_tstate_t            *ts     = tunnelGetState(t);
    const uint64_t                            now_ms = authenticationclientLocalTimeMS();
    authenticationclient_user_lookup_result_t result = kAuthenticationClientUserLookupUserNotFound;
    mutexLock(&ts->control_mutex);
    rwlockReadLock(&ts->users_lock);
    user_t *user = NULL;
    if (! authenticationclientCanAuthenticateLocked(ts))
        result = kAuthenticationClientUserLookupUsersUnavailable;
    else
    {
        switch (kind)
        {
        case kAuthenticationClientCredentialSHA224:
            user = usersLookupBySHA224(ts->users, credential);
            break;
        case kAuthenticationClientCredentialSHA256:
            user = usersLookupBySHA256(ts->users, credential);
            break;
        case kAuthenticationClientCredentialUUID:
            user = usersLookupByUUID(ts->users, credential);
            break;
        case kAuthenticationClientCredentialWireGuard:
            user = usersLookupByWireGuardPublicKey(ts->users, credential);
            break;
        case kAuthenticationClientCredentialPassword:
            user = usersLookupBySHA256(ts->users, sha256.bytes);
            break;
        }
    }
    if (user != NULL)
    {
        if (kind == kAuthenticationClientCredentialPassword && ! userPasswordMatches(user, credential))
            result = kAuthenticationClientUserLookupPasswordMismatch;
        else
        {
            uint64_t                      user_id = 0;
            const user_admission_result_t access  = userCopyAccess(user,
                                                                  now_ms,
                                                                  &user_id,
                                                                  profile_out != NULL ? &profile_out->name : NULL,
                                                                  profile_out != NULL ? &profile_out->password : NULL);
            if (access == kUserAdmissionDisabled)
                result = kAuthenticationClientUserLookupUserDisabled;
            else if (access == kUserAdmissionExpired)
                result = kAuthenticationClientUserLookupUserExpired;
            else if (access == kUserAdmissionTrafficLimited)
                result = kAuthenticationClientUserLookupUserLimitReached;
            else
            {
                assert(access == kUserAdmissionOk);
                if (user_id == 0)
                    result = kAuthenticationClientUserLookupUserIdRequired;
                else
                {
                    userHandleSet(handle_out, ts->users_generation, user_id);
                    result = kAuthenticationClientUserLookupOk;
                }
            }
        }
    }
    rwlockReadUnlock(&ts->users_lock);
    mutexUnlock(&ts->control_mutex);
    memorySecureZero(&sha256, sizeof(sha256));
    if (result != kAuthenticationClientUserLookupOk)
        userHandleClear(handle_out);
    return result;
}

bool authenticationclientGetUserBySHA256(tunnel_t *t, const uint8_t sha256[SHA256_DIGEST_SIZE],
                                         user_handle_t *handle_out)
{
    return authenticationclientResolveCredential(t,
                                                 kAuthenticationClientCredentialSHA256,
                                                 sha256,
                                                 handle_out,
                                                 NULL,
                                                 "authenticationclientGetUserBySHA256") ==
           kAuthenticationClientUserLookupOk;
}

bool authenticationclientGetUserBySHA224(tunnel_t *t, const uint8_t sha224[SHA224_DIGEST_SIZE],
                                         user_handle_t *handle_out)
{
    return authenticationclientGetUserBySHA224WithProfile(t, sha224, handle_out, NULL);
}

bool authenticationclientGetUserBySHA224WithProfile(tunnel_t *t, const uint8_t sha224[SHA224_DIGEST_SIZE],
                                                    user_handle_t                       *handle_out,
                                                    authenticationclient_user_profile_t *profile_out)
{
    return authenticationclientResolveCredential(t,
                                                 kAuthenticationClientCredentialSHA224,
                                                 sha224,
                                                 handle_out,
                                                 profile_out,
                                                 "authenticationclientGetUserBySHA224WithProfile") ==
           kAuthenticationClientUserLookupOk;
}

bool authenticationclientGetUserByUUID(tunnel_t *t, const uint8_t uuid[kWwUuidBytesLen], user_handle_t *handle_out)
{
    return authenticationclientGetUserByUUIDWithProfile(t, uuid, handle_out, NULL) == kAuthenticationClientUserLookupOk;
}

authenticationclient_user_lookup_result_t authenticationclientGetUserByUUIDWithProfile(
    tunnel_t *t, const uint8_t uuid[kWwUuidBytesLen], user_handle_t *handle_out,
    authenticationclient_user_profile_t *profile_out)
{
    return authenticationclientResolveCredential(t,
                                                 kAuthenticationClientCredentialUUID,
                                                 uuid,
                                                 handle_out,
                                                 profile_out,
                                                 "authenticationclientGetUserByUUIDWithProfile");
}

bool authenticationclientGetUserByWireGuardPublicKey(tunnel_t      *t,
                                                     const uint8_t  publickey[USER_WIREGUARD_PUBLICKEY_SIZE],
                                                     user_handle_t *handle_out)
{
    return authenticationclientGetUserByWireGuardPublicKeyWithProfile(t, publickey, handle_out, NULL) ==
           kAuthenticationClientUserLookupOk;
}

authenticationclient_user_lookup_result_t authenticationclientGetUserByWireGuardPublicKeyWithProfile(
    tunnel_t *t, const uint8_t publickey[USER_WIREGUARD_PUBLICKEY_SIZE], user_handle_t *handle_out,
    authenticationclient_user_profile_t *profile_out)
{
    return authenticationclientResolveCredential(t,
                                                 kAuthenticationClientCredentialWireGuard,
                                                 publickey,
                                                 handle_out,
                                                 profile_out,
                                                 "authenticationclientGetUserByWireGuardPublicKeyWithProfile");
}

bool authenticationclientGetUserByPassword(tunnel_t *t, const char *password, user_handle_t *handle_out)
{
    return authenticationclientGetUserByPasswordWithResult(t, password, handle_out) ==
           kAuthenticationClientUserLookupOk;
}

const char *authenticationclientUserLookupResultString(authenticationclient_user_lookup_result_t result)
{
    switch (result)
    {
    case kAuthenticationClientUserLookupOk:
        return "ok";
    case kAuthenticationClientUserLookupInvalidArgument:
        return "invalid password lookup";
    case kAuthenticationClientUserLookupHashFailed:
        return "password hash failed";
    case kAuthenticationClientUserLookupUsersUnavailable:
        return "users table unavailable";
    case kAuthenticationClientUserLookupUserNotFound:
        return "user not found";
    case kAuthenticationClientUserLookupPasswordMismatch:
        return "password mismatch";
    case kAuthenticationClientUserLookupUserDisabled:
        return "user disabled";
    case kAuthenticationClientUserLookupUserExpired:
        return "user expired";
    case kAuthenticationClientUserLookupUserLimitReached:
        return "user limit reached";
    case kAuthenticationClientUserLookupUserIdRequired:
        return "user id required";
    default:
        return "unknown";
    }
}

authenticationclient_user_lookup_result_t authenticationclientGetUserByPasswordWithResult(tunnel_t      *t,
                                                                                          const char    *password,
                                                                                          user_handle_t *handle_out)
{
    return authenticationclientGetUserByPasswordWithProfile(t, password, handle_out, NULL);
}

authenticationclient_user_lookup_result_t authenticationclientGetUserByPasswordWithProfile(
    tunnel_t *t, const char *password, user_handle_t *handle_out, authenticationclient_user_profile_t *profile_out)
{
    return authenticationclientResolveCredential(t,
                                                 kAuthenticationClientCredentialPassword,
                                                 password,
                                                 handle_out,
                                                 profile_out,
                                                 "authenticationclientGetUserByPasswordWithProfile");
}

bool authenticationclientUserHandleIsLive(tunnel_t *t, const user_handle_t *handle)
{
    if (UNLIKELY(t == NULL || ! userHandleIsValid(handle)))
    {
        return false;
    }

    authenticationclient_tstate_t *ts     = tunnelGetState(t);
    bool                           live   = false;
    uint64_t                       now_ms = authenticationclientLocalTimeMS();

    rwlockReadLock(&ts->users_lock);
    user_t *user = NULL;
    if (LIKELY(ts->users != NULL) && handle->generation == ts->users_generation)
    {
        user = usersLookupByIdentifier(ts->users, handle->user_id);
    }
    live = user != NULL && ! userRuntimeShouldClose(user, now_ms);
    rwlockReadUnlock(&ts->users_lock);

    return live;
}

cJSON *authenticationclientUserToJson(tunnel_t *t, const user_handle_t *handle)
{
    if (UNLIKELY(t == NULL || ! userHandleIsValid(handle)))
    {
        return NULL;
    }

    authenticationclient_tstate_t *ts   = tunnelGetState(t);
    cJSON                         *json = NULL;

    rwlockReadLock(&ts->users_lock);
    if (LIKELY(ts->users != NULL) && handle->generation == ts->users_generation)
    {
        json = usersUserToJsonByIdentifier(ts->users, handle->user_id);
    }
    rwlockReadUnlock(&ts->users_lock);

    return json;
}

cJSON *authenticationclientUsersToJson(tunnel_t *t)
{
    if (UNLIKELY(t == NULL))
    {
        return NULL;
    }

    authenticationclient_tstate_t *ts   = tunnelGetState(t);
    cJSON                         *json = NULL;

    rwlockReadLock(&ts->users_lock);
    if (LIKELY(ts->users != NULL))
    {
        json = usersToJson(ts->users);
    }
    rwlockReadUnlock(&ts->users_lock);

    return json;
}

bool authenticationclientUserGetStats(tunnel_t *t, const user_handle_t *handle, user_stat_t *stats_out)
{
    if (UNLIKELY(t == NULL || stats_out == NULL || ! userHandleIsValid(handle)))
    {
        return false;
    }

    authenticationclient_tstate_t *ts = tunnelGetState(t);
    bool                           ok = false;

    rwlockReadLock(&ts->users_lock);
    user_t *user = NULL;
    if (LIKELY(ts->users != NULL) && handle->generation == ts->users_generation)
    {
        user = usersLookupByIdentifier(ts->users, handle->user_id);
    }
    if (user != NULL)
    {
        userGetStats(user, stats_out);
        ok = true;
    }
    rwlockReadUnlock(&ts->users_lock);

    if (UNLIKELY(! ok))
    {
        memoryZero(stats_out, sizeof(*stats_out));
    }
    return ok;
}

static user_admission_result_t authenticationclientUsersTryAdmitConnectionByHandle(users_t             *users,
                                                                                   const user_handle_t *handle,
                                                                                   const user_ip_key_t *ip_key,
                                                                                   uint64_t             now_ms)
{
    return usersTryAdmitConnectionByIdentifier(users, handle->user_id, ip_key, now_ms);
}

static void authenticationclientUsersReleaseConnectionByHandle(users_t *users, const user_handle_t *handle,
                                                               const user_ip_key_t *ip_key)
{
    usersReleaseConnectionByIdentifier(users, handle->user_id, ip_key);
}

static bool authenticationclientUsersAccountTrafficByHandle(users_t *users, const user_handle_t *handle,
                                                            uint64_t upload_bytes, uint64_t download_bytes,
                                                            uint32_t multiplier, uint64_t now_ms, bool *found,
                                                            bool *first_usage_push_needed)
{
    return usersAccountTrafficScaledByIdentifier(
        users, handle->user_id, upload_bytes, download_bytes, multiplier, now_ms, found, first_usage_push_needed);
}

static void authenticationclientUsersResetFirstUsagePushRequestByHandle(users_t *users, const user_handle_t *handle)
{
    usersResetFirstUsagePushRequestByIdentifier(users, handle->user_id);
}

static bool authenticationclientUsersRuntimeShouldCloseByHandle(users_t *users, const user_handle_t *handle,
                                                                uint64_t now_ms)
{
    return usersRuntimeShouldCloseByIdentifier(users, handle->user_id, now_ms);
}

/*
 * These enforcement helpers identify the user by durable id only. They deliberately do NOT gate on
 * handle->generation: a GetAllUsers refresh bumps the generation but the same logical user keeps the
 * same durable id, so enforcement (admission, accounting, closing) must keep working against the
 * refreshed user object. A miss means the user was actually removed from the table (revoked).
 */
user_admission_result_t authenticationclientUserTryAdmitConnection(tunnel_t *t, const user_handle_t *handle,
                                                                   const user_ip_key_t *ip_key, uint64_t now_ms)
{
    if (UNLIKELY(t == NULL || ! userHandleIsValid(handle)))
    {
        return kUserAdmissionInvalid;
    }

    authenticationclient_tstate_t *ts     = tunnelGetState(t);
    user_admission_result_t        result = kUserAdmissionInvalid;

    mutexLock(&ts->control_mutex);
    rwlockReadLock(&ts->users_lock);
    if (authenticationclientCanAuthenticateLocked(ts))
    {
        result = authenticationclientUsersTryAdmitConnectionByHandle(ts->users, handle, ip_key, now_ms);
    }
    rwlockReadUnlock(&ts->users_lock);
    mutexUnlock(&ts->control_mutex);

    return result;
}

void authenticationclientUserReleaseConnection(tunnel_t *t, const user_handle_t *handle, const user_ip_key_t *ip_key)
{
    if (UNLIKELY(t == NULL || ! userHandleIsValid(handle)))
    {
        return;
    }

    authenticationclient_tstate_t *ts = tunnelGetState(t);

    rwlockReadLock(&ts->users_lock);
    // Releasing by stable handle key hits the user even after a refresh; live counters are migrated
    // across the refresh so the release lands on the object that counted this connection. A miss
    // (revoked user) is a harmless no-op.
    if (LIKELY(ts->users != NULL))
    {
        authenticationclientUsersReleaseConnectionByHandle(ts->users, handle, ip_key);
    }
    rwlockReadUnlock(&ts->users_lock);
}

static void authenticationclientResetFirstUsagePushState(tunnel_t *t)
{
    if (UNLIKELY(t == NULL))
    {
        return;
    }

    authenticationclient_tstate_t *ts = tunnelGetState(t);

    mutexLock(&ts->control_mutex);
    ts->first_usage_push_requested = false;
    ts->first_usage_push_deferred  = false;
    mutexUnlock(&ts->control_mutex);

    authenticationclientResetFirstUsagePushRuntime(t);
}

static void authenticationclientFirstUsagePushOnWorker0(void *worker_ptr, void *arg1, void *arg2, void *arg3)
{
    discard worker_ptr;
    discard arg2;
    discard arg3;

    tunnel_t *t = arg1;
    if (UNLIKELY(t == NULL))
    {
        return;
    }

    if (UNLIKELY(! authenticationclientSendPushUserStats(t)))
    {
        authenticationclient_tstate_t *ts = tunnelGetState(t);
        mutexLock(&ts->control_mutex);
        const bool deferred = ts->push_in_flight || ts->pull_in_flight || ts->pull_required || ts->stats_push_refused ||
                              ts->write_paused ||
                              authenticationclientRetryNotBeforeLocked(ts) > authenticationclientLocalTimeMS();
        if (deferred)
        {
            ts->first_usage_push_deferred = true;
        }
        mutexUnlock(&ts->control_mutex);
        if (! deferred)
        {
            authenticationclientResetFirstUsagePushState(t);
        }
    }
}

static authenticationclient_first_usage_push_result_t authenticationclientRequestFirstUsagePush(tunnel_t *t)
{
    authenticationclient_tstate_t                 *ts     = tunnelGetState(t);
    authenticationclient_first_usage_push_result_t result = kAuthenticationClientFirstUsagePushNotReady;

    mutexLock(&ts->control_mutex);
    ts->push_requested = true;
    if (ts->push_in_flight || ts->pull_in_flight || ts->pull_required || ts->stats_push_refused || ts->write_paused ||
        authenticationclientRetryNotBeforeLocked(ts) > authenticationclientLocalTimeMS())
    {
        ts->first_usage_push_requested = true;
        ts->first_usage_push_deferred  = true;
        result                         = kAuthenticationClientFirstUsagePushPending;
    }
    else if (ts->first_usage_push_requested)
    {
        result = kAuthenticationClientFirstUsagePushPending;
    }
    else if (LIKELY(ts->authenticated && ts->connected && ! ts->stopping && ! ts->write_paused &&
                    ts->control_line != NULL))
    {
        ts->first_usage_push_requested = true;
        result                         = kAuthenticationClientFirstUsagePushQueued;
    }
    mutexUnlock(&ts->control_mutex);

    if (result == kAuthenticationClientFirstUsagePushQueued)
    {
        if (UNLIKELY(sendWorkerMessageForceQueueWithCleanup(
                         0, authenticationclientFirstUsagePushOnWorker0, NULL, t, NULL, NULL) !=
                     kWorkerMessageSubmitAccepted))
        {
            authenticationclientResetFirstUsagePushState(t);
            result = kAuthenticationClientFirstUsagePushNotReady;
        }
    }
    return result;
}

static bool authenticationclientAccountTraffic(tunnel_t *t, const user_handle_t *handle, uint64_t upload_bytes,
                                               uint64_t download_bytes, uint64_t now_ms, bool check_generation,
                                               bool *found_out)
{
    if (found_out != NULL)
        *found_out = false;
    if (UNLIKELY(t == NULL || ! userHandleIsValid(handle)))
    {
        return false;
    }

    authenticationclient_tstate_t *ts                      = tunnelGetState(t);
    bool                           should_close            = false;
    bool                           first_usage_push_needed = false;

    rwlockReadLock(&ts->users_lock);
    if (ts->users != NULL && (! check_generation || handle->generation == ts->users_generation))
    {
        // AccountTraffic returns close=true when the user is gone (revoked), so a removed user's
        // traffic is rejected and the connection is torn down.
        should_close = authenticationclientUsersAccountTrafficByHandle(ts->users,
                                                                       handle,
                                                                       upload_bytes,
                                                                       download_bytes,
                                                                       ts->traffic_multiplier,
                                                                       now_ms,
                                                                       found_out,
                                                                       &first_usage_push_needed);
    }
    rwlockReadUnlock(&ts->users_lock);

    if (first_usage_push_needed)
    {
        authenticationclient_first_usage_push_result_t result = authenticationclientRequestFirstUsagePush(t);
        if (result == kAuthenticationClientFirstUsagePushNotReady)
        {
            rwlockReadLock(&ts->users_lock);
            if (ts->users != NULL)
            {
                authenticationclientUsersResetFirstUsagePushRequestByHandle(ts->users, handle);
            }
            rwlockReadUnlock(&ts->users_lock);
        }
    }

    return should_close;
}

bool authenticationclientUserAddTraffic(tunnel_t *t, const user_handle_t *handle, uint64_t upload_bytes,
                                        uint64_t download_bytes)
{
    bool    found = false;
    discard authenticationclientAccountTraffic(t, handle, upload_bytes, download_bytes, 0, true, &found);
    return found;
}

bool authenticationclientUserAccountTraffic(tunnel_t *t, const user_handle_t *handle, uint64_t upload_bytes,
                                            uint64_t download_bytes, uint64_t now_ms)
{
    return authenticationclientAccountTraffic(t, handle, upload_bytes, download_bytes, now_ms, false, NULL);
}

bool authenticationclientUserShouldClose(tunnel_t *t, const user_handle_t *handle, uint64_t now_ms)
{
    if (UNLIKELY(t == NULL || ! userHandleIsValid(handle)))
    {
        return false;
    }

    authenticationclient_tstate_t *ts           = tunnelGetState(t);
    bool                           should_close = false;

    rwlockReadLock(&ts->users_lock);
    if (LIKELY(ts->users != NULL))
    {
        // Returns true when the user is disabled, expired, over quota, or removed from the table.
        should_close = authenticationclientUsersRuntimeShouldCloseByHandle(ts->users, handle, now_ms);
    }
    rwlockReadUnlock(&ts->users_lock);

    return should_close;
}

static void authenticationclientRequestPullOnWorker0(void *worker_ptr, void *arg1, void *arg2, void *arg3)
{
    discard worker_ptr;
    discard arg2;
    discard arg3;

    discard authenticationclientSendGetAllUsers(arg1);
}

static void authenticationclientRequestPushOnWorker0(void *worker_ptr, void *arg1, void *arg2, void *arg3)
{
    discard worker_ptr;
    discard arg2;
    discard arg3;

    discard authenticationclientSendPushUserStats(arg1);
}

void authenticationclientRequestPull(tunnel_t *t)
{
    if (UNLIKELY(t == NULL))
    {
        return;
    }

    if (currentThreadOwnsWorker(0))
    {
        discard authenticationclientSendGetAllUsers(t);
        return;
    }

    /* An external pull request is an explicit best-effort observation; the
     * periodic synchronization timer remains the required progress owner. */
    sendWorkerMessageForceQueueBestEffort(0, authenticationclientRequestPullOnWorker0, t, NULL, NULL);
}

void authenticationclientRequestPush(tunnel_t *t)
{
    if (UNLIKELY(t == NULL))
    {
        return;
    }

    if (currentThreadOwnsWorker(0))
    {
        discard authenticationclientSendPushUserStats(t);
        return;
    }

    /* See authenticationclientRequestPull(): this ad-hoc request owns no
     * latched progress state and may be superseded by the periodic push. */
    sendWorkerMessageForceQueueBestEffort(0, authenticationclientRequestPushOnWorker0, t, NULL, NULL);
}

bool authenticationclientUserObservePayload(tunnel_t *t, const user_handle_t *handle, uint64_t upload_bytes,
                                            uint64_t download_bytes, uint64_t now_ms)
{
    assert(t != NULL && userHandleIsValid(handle));
    authenticationclient_tstate_t *ts                      = tunnelGetState(t);
    bool                           first_usage_push_needed = false;
    rwlockReadLock(&ts->users_lock);
    bool close = ts->users == NULL ||
                 usersObserveTrafficByIdentifier(
                     ts->users, handle->user_id, upload_bytes, download_bytes, now_ms, &first_usage_push_needed);
    rwlockReadUnlock(&ts->users_lock);
    if (first_usage_push_needed &&
        authenticationclientRequestFirstUsagePush(t) == kAuthenticationClientFirstUsagePushNotReady)
    {
        rwlockReadLock(&ts->users_lock);
        if (ts->users != NULL)
            usersResetFirstUsagePushRequestByIdentifier(ts->users, handle->user_id);
        rwlockReadUnlock(&ts->users_lock);
    }
    return close;
}

static authenticationclient_bandwidth_ticket_t *authenticationclientBandwidthTicket(authenticationclient_tstate_t *ts,
                                                                                    uint64_t user_id, uint64_t ticket)
{
    if (ticket == 0 || ts->bandwidth_tickets == NULL)
        return NULL;
    authenticationclient_bandwidth_ticket_t *record =
        &ts->bandwidth_tickets[ticket % kAuthenticationClientBandwidthMaxTickets];
    return record->id == ticket && record->user_id == user_id ? record : NULL;
}

uint64_t authenticationclientUserBandwidthRegister(tunnel_t *t, const user_handle_t *handle,
                                                   user_bandwidth_direction_t direction)
{
    assert(t != NULL && userHandleIsValid(handle) && direction <= kUserBandwidthDownload);
    authenticationclient_tstate_t *ts     = tunnelGetState(t);
    uint64_t                       ticket = 0;
    mutexLock(&ts->control_mutex);
    if (ts->bandwidth_ticket_count >= kAuthenticationClientBandwidthMaxTickets ||
        ts->bandwidth_last_ticket == UINT64_MAX)
        goto done;
    if (ts->bandwidth_tickets == NULL)
        ts->bandwidth_tickets =
            memoryAllocateZero(kAuthenticationClientBandwidthMaxTickets * sizeof(*ts->bandwidth_tickets));
    for (size_t i = 0; i < kAuthenticationClientBandwidthMaxTickets && ts->bandwidth_last_ticket != UINT64_MAX; ++i)
    {
        uint64_t                                 candidate = ++ts->bandwidth_last_ticket;
        authenticationclient_bandwidth_ticket_t *record =
            &ts->bandwidth_tickets[candidate % kAuthenticationClientBandwidthMaxTickets];
        if (record->id != 0)
            continue;
        rwlockReadLock(&ts->users_lock);
        bool registered =
            ts->users != NULL && usersBandwidthRegisterByIdentifier(ts->users, handle->user_id, direction, candidate);
        rwlockReadUnlock(&ts->users_lock);
        if (registered)
        {
            *record = (authenticationclient_bandwidth_ticket_t) {
                .id = candidate, .user_id = handle->user_id, .direction = direction};
            ++ts->bandwidth_ticket_count;
            ticket = candidate;
        }
        break;
    }
done:
    mutexUnlock(&ts->control_mutex);
    return ticket;
}

void authenticationclientUserBandwidthSetEligible(tunnel_t *t, const user_handle_t *handle,
                                                  user_bandwidth_direction_t direction, uint64_t ticket, bool eligible)
{
    assert(t != NULL && userHandleIsValid(handle) && ticket != 0);
    authenticationclient_tstate_t *ts = tunnelGetState(t);
    rwlockReadLock(&ts->users_lock);
    if (ts->users != NULL)
        usersBandwidthSetEligibleByIdentifier(ts->users, handle->user_id, direction, ticket, eligible);
    rwlockReadUnlock(&ts->users_lock);
}

static void authenticationclientBandwidthCostSubtract(buffer_budget_cost_t *used, buffer_budget_cost_t cost)
{
    assert(used->bytes >= cost.bytes && used->charge >= cost.charge && used->entries >= cost.entries);
    used->bytes -= cost.bytes;
    used->charge -= cost.charge;
    used->entries -= cost.entries;
}

void authenticationclientUserBandwidthCancel(tunnel_t *t, const user_handle_t *handle,
                                             user_bandwidth_direction_t direction, uint64_t ticket)
{
    assert(t != NULL && userHandleIsValid(handle));
    if (ticket == 0)
        return;
    authenticationclient_tstate_t *ts = tunnelGetState(t);
    mutexLock(&ts->control_mutex);
    authenticationclient_bandwidth_ticket_t *record = authenticationclientBandwidthTicket(ts, handle->user_id, ticket);
    if (record != NULL)
    {
        assert(record->direction == direction);
        rwlockReadLock(&ts->users_lock);
        if (ts->users != NULL)
            usersBandwidthCancelByIdentifier(ts->users, handle->user_id, direction, ticket);
        rwlockReadUnlock(&ts->users_lock);
        authenticationclientBandwidthCostSubtract(&ts->bandwidth_queued_cost, record->cost);
        memoryZero(record, sizeof(*record));
        --ts->bandwidth_ticket_count;
    }
    mutexUnlock(&ts->control_mutex);
}

bool authenticationclientUserBandwidthReserve(tunnel_t *t, const user_handle_t *handle, uint64_t ticket,
                                              buffer_budget_cost_t cost)
{
    assert(t != NULL && userHandleIsValid(handle) && ticket != 0);
    authenticationclient_tstate_t *ts = tunnelGetState(t);
    bool                           ok = false;
    mutexLock(&ts->control_mutex);
    authenticationclient_bandwidth_ticket_t *record = authenticationclientBandwidthTicket(ts, handle->user_id, ticket);
    buffer_budget_cost_t                    *used   = &ts->bandwidth_queued_cost;
    if (record == NULL || cost.bytes > (64U << 20) - used->bytes || cost.charge > (128U << 20) - used->charge ||
        cost.entries > 16384 - used->entries)
        goto done;
    rwlockReadLock(&ts->users_lock);
    ok = ts->users != NULL &&
         usersBandwidthReserveByIdentifier(ts->users, handle->user_id, record->direction, ticket, cost);
    rwlockReadUnlock(&ts->users_lock);
    if (ok)
    {
        used->bytes += cost.bytes;
        used->charge += cost.charge;
        used->entries += cost.entries;
        record->cost.bytes += cost.bytes;
        record->cost.charge += cost.charge;
        record->cost.entries += cost.entries;
    }
done:
    mutexUnlock(&ts->control_mutex);
    return ok;
}

void authenticationclientUserBandwidthRelease(tunnel_t *t, const user_handle_t *handle, uint64_t ticket,
                                              buffer_budget_cost_t cost)
{
    assert(t != NULL && userHandleIsValid(handle) && ticket != 0);
    authenticationclient_tstate_t *ts = tunnelGetState(t);
    mutexLock(&ts->control_mutex);
    authenticationclient_bandwidth_ticket_t *record = authenticationclientBandwidthTicket(ts, handle->user_id, ticket);
    if (record != NULL)
    {
        rwlockReadLock(&ts->users_lock);
        if (ts->users != NULL)
            usersBandwidthReleaseByIdentifier(ts->users, handle->user_id, record->direction, ticket, cost);
        rwlockReadUnlock(&ts->users_lock);
        authenticationclientBandwidthCostSubtract(&record->cost, cost);
        authenticationclientBandwidthCostSubtract(&ts->bandwidth_queued_cost, cost);
    }
    mutexUnlock(&ts->control_mutex);
}

user_bandwidth_result_t authenticationclientUserBandwidthPreview(tunnel_t *t, const user_handle_t *handle,
                                                                 user_bandwidth_direction_t direction, uint64_t ticket,
                                                                 uint64_t bytes, bool datagram)
{
    assert(t != NULL && userHandleIsValid(handle));
    authenticationclient_tstate_t *ts     = tunnelGetState(t);
    user_bandwidth_result_t        result = {.decision = kUserDeliveryReject};
    rwlockReadLock(&ts->users_lock);
    if (ts->users != NULL)
        result = usersBandwidthPreviewByIdentifier(ts->users, handle->user_id, direction, ticket, bytes, datagram);
    rwlockReadUnlock(&ts->users_lock);
    return result;
}

user_delivery_decision_t authenticationclientUserCommitDelivery(tunnel_t *t, const user_handle_t *handle,
                                                                user_bandwidth_direction_t direction, uint64_t ticket,
                                                                uint64_t bytes, bool datagram, bool more)
{
    assert(t != NULL && userHandleIsValid(handle));
    authenticationclient_tstate_t *ts     = tunnelGetState(t);
    user_delivery_decision_t       result = kUserDeliveryReject;
    rwlockReadLock(&ts->users_lock);
    if (ts->users != NULL)
        result = usersCommitDeliveryByIdentifier(
            ts->users, handle->user_id, direction, ticket, bytes, datagram, more, ts->traffic_multiplier);
    rwlockReadUnlock(&ts->users_lock);
    return result;
}
