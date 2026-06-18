#include "structure.h"

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
    {
        return kAuthenticationClientStateStopped;
    }

    authenticationclient_tstate_t *ts    = tunnelGetState(t);
    authenticationclient_state_t   state = kAuthenticationClientStateStopped;

    mutexLock(&ts->control_mutex);
    if (LIKELY(ts->authenticated))
    {
        bool users_loaded = false;

        rwlockReadLock(&ts->users_lock);
        users_loaded = ts->users_loaded;
        rwlockReadUnlock(&ts->users_lock);

        state = users_loaded ? kAuthenticationClientStateReady : kAuthenticationClientStateAuthenticating;
    }
    else if (ts->connected)
    {
        state = kAuthenticationClientStateAuthenticating;
    }
    else if (ts->started && ! ts->stopping)
    {
        state = kAuthenticationClientStateConnecting;
    }
    mutexUnlock(&ts->control_mutex);

    return state;
}

bool authenticationclientIsReady(tunnel_t *t)
{
    return authenticationclientGetState(t) == kAuthenticationClientStateReady;
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

bool authenticationclientGetUserBySHA256(tunnel_t *t, const uint8_t sha256[SHA256_DIGEST_SIZE],
                                         user_handle_t *handle_out)
{
    if (UNLIKELY(t == NULL || sha256 == NULL || handle_out == NULL))
    {
        return false;
    }

    authenticationclient_tstate_t *ts     = tunnelGetState(t);
    bool                           found  = false;
    uint64_t                       now_ms = authenticationclientLocalTimeMS();

    rwlockReadLock(&ts->users_lock);
    user_t *user = ts->users != NULL ? usersLookupBySHA256(ts->users, sha256) : NULL;
    if (user != NULL && userIsActive(user, now_ms))
    {
        userHandleSet(handle_out, sha256, ts->users_generation, userGetId(user));
        found = true;
    }
    rwlockReadUnlock(&ts->users_lock);

    if (! found)
    {
        userHandleClear(handle_out);
    }
    return found;
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
        terminateProgram(1);
    }
}

// Duplicate the user's name/password into the profile. The caller must hold
// ts->users_lock (read); user->lock guards the name/password strings, matching
// the users_lock -> user->lock ordering used by usersToJson.
static void authenticationclientFillUserProfileLocked(authenticationclient_user_profile_t *profile, user_t *user)
{
    rwlockReadLock(&user->lock);
    profile->name     = (user->name != NULL && user->name[0] != '\0') ? stringDuplicate(user->name) : NULL;
    profile->password = (user->password != NULL && user->password[0] != '\0') ? stringDuplicate(user->password) : NULL;
    rwlockReadUnlock(&user->lock);
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
    authenticationclientAssertProfileEmpty(profile_out, "authenticationclientGetUserBySHA224WithProfile");

    if (UNLIKELY(t == NULL || sha224 == NULL || handle_out == NULL))
    {
        return false;
    }

    authenticationclient_tstate_t *ts     = tunnelGetState(t);
    bool                           found  = false;
    uint64_t                       now_ms = authenticationclientLocalTimeMS();

    rwlockReadLock(&ts->users_lock);
    user_t *user = ts->users != NULL ? usersLookupBySHA224(ts->users, sha224) : NULL;
    if (user != NULL && user->sha256_pass_valid && userIsActive(user, now_ms))
    {
        userHandleSet(handle_out, user->sha256_pass.bytes, ts->users_generation, userGetId(user));
        if (profile_out != NULL)
        {
            authenticationclientFillUserProfileLocked(profile_out, user);
        }
        found = true;
    }
    rwlockReadUnlock(&ts->users_lock);

    if (! found)
    {
        userHandleClear(handle_out);
    }
    return found;
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
    authenticationclientAssertProfileEmpty(profile_out, "authenticationclientGetUserByPasswordWithProfile");

    if (UNLIKELY(t == NULL || password == NULL || password[0] == '\0' || handle_out == NULL))
    {
        if (handle_out != NULL)
        {
            userHandleClear(handle_out);
        }
        return kAuthenticationClientUserLookupInvalidArgument;
    }

    sha256_hash_t sha256 = {0};
    if (UNLIKELY(wCryptoSHA256(&sha256, (const unsigned char *) password, stringLength(password)) != 0))
    {
        userHandleClear(handle_out);
        return kAuthenticationClientUserLookupHashFailed;
    }

    authenticationclient_tstate_t            *ts     = tunnelGetState(t);
    uint64_t                                  now_ms = authenticationclientLocalTimeMS();
    authenticationclient_user_lookup_result_t result = kAuthenticationClientUserLookupUserNotFound;

    rwlockReadLock(&ts->users_lock);
    user_t *user = NULL;
    if (UNLIKELY(ts->users == NULL || ! ts->users_loaded))
    {
        result = kAuthenticationClientUserLookupUsersUnavailable;
    }
    else
    {
        user = usersLookupBySHA256(ts->users, sha256.bytes);
    }

    if (user != NULL)
    {
        if (! userPasswordMatches(user, password))
        {
            result = kAuthenticationClientUserLookupPasswordMismatch;
        }
        else if (! userIsEnabled(user))
        {
            result = kAuthenticationClientUserLookupUserDisabled;
        }
        else if (userIsExpired(user, now_ms))
        {
            result = kAuthenticationClientUserLookupUserExpired;
        }
        else if (userHasReachedLimit(user))
        {
            result = kAuthenticationClientUserLookupUserLimitReached;
        }
        else
        {
            userHandleSet(handle_out, sha256.bytes, ts->users_generation, userGetId(user));
            if (profile_out != NULL)
            {
                authenticationclientFillUserProfileLocked(profile_out, user);
            }
            result = kAuthenticationClientUserLookupOk;
        }
    }
    rwlockReadUnlock(&ts->users_lock);

    memoryZero(&sha256, sizeof(sha256)); // i dont want to use wCryptoZero
    if (result != kAuthenticationClientUserLookupOk)
    {
        userHandleClear(handle_out);
    }
    return result;
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
        user = usersLookupBySHA256(ts->users, handle->sha256);
    }
    live = user != NULL && userIsActive(user, now_ms);
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
        json = usersUserToJsonBySHA256(ts->users, handle->sha256);
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
        user = usersLookupBySHA256(ts->users, handle->sha256);
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

static users_update_result_t authenticationclientUsersAddTrafficByHandle(users_t *users, const user_handle_t *handle,
                                                                         uint64_t upload_bytes, uint64_t download_bytes)
{
    if (handle->user_id != 0)
    {
        return usersAddTrafficByIdentifier(users, handle->user_id, upload_bytes, download_bytes);
    }
    return usersAddTrafficBySHA256(users, handle->sha256, upload_bytes, download_bytes);
}

static user_admission_result_t authenticationclientUsersTryAdmitConnectionByHandle(users_t             *users,
                                                                                   const user_handle_t *handle,
                                                                                   const user_ip_key_t *ip_key,
                                                                                   uint64_t             now_ms)
{
    if (handle->user_id != 0)
    {
        return usersTryAdmitConnectionByIdentifier(users, handle->user_id, ip_key, now_ms);
    }
    return usersTryAdmitConnectionBySHA256(users, handle->sha256, ip_key, now_ms);
}

static void authenticationclientUsersReleaseConnectionByHandle(users_t *users, const user_handle_t *handle,
                                                               const user_ip_key_t *ip_key)
{
    if (handle->user_id != 0)
    {
        usersReleaseConnectionByIdentifier(users, handle->user_id, ip_key);
        return;
    }
    usersReleaseConnectionBySHA256(users, handle->sha256, ip_key);
}

static bool authenticationclientUsersAccountTrafficByHandle(users_t *users, const user_handle_t *handle,
                                                            uint64_t upload_bytes, uint64_t download_bytes,
                                                            uint64_t now_ms, bool *found, bool *first_usage_push_needed)
{
    if (handle->user_id != 0)
    {
        return usersAccountTrafficByIdentifier(
            users, handle->user_id, upload_bytes, download_bytes, now_ms, found, first_usage_push_needed);
    }
    return usersAccountTrafficBySHA256(
        users, handle->sha256, upload_bytes, download_bytes, now_ms, found, first_usage_push_needed);
}

static void authenticationclientUsersResetFirstUsagePushRequestByHandle(users_t *users, const user_handle_t *handle)
{
    if (handle->user_id != 0)
    {
        usersResetFirstUsagePushRequestByIdentifier(users, handle->user_id);
        return;
    }
    usersResetFirstUsagePushRequestBySHA256(users, handle->sha256);
}

static bool authenticationclientUsersRuntimeShouldCloseByHandle(users_t *users, const user_handle_t *handle,
                                                                uint64_t now_ms)
{
    if (handle->user_id != 0)
    {
        return usersRuntimeShouldCloseByIdentifier(users, handle->user_id, now_ms);
    }
    return usersRuntimeShouldCloseBySHA256(users, handle->sha256, now_ms);
}

bool authenticationclientUserAddTraffic(tunnel_t *t, const user_handle_t *handle, uint64_t upload_bytes,
                                        uint64_t download_bytes)
{
    if (UNLIKELY(t == NULL || ! userHandleIsValid(handle)))
    {
        return false;
    }

    authenticationclient_tstate_t *ts     = tunnelGetState(t);
    users_update_result_t          result = kUsersUpdateResultUserNotFound;

    rwlockReadLock(&ts->users_lock);
    if (LIKELY(ts->users != NULL) && handle->generation == ts->users_generation)
    {
        result = authenticationclientUsersAddTrafficByHandle(ts->users, handle, upload_bytes, download_bytes);
    }
    rwlockReadUnlock(&ts->users_lock);

    return result == kUsersUpdateResultOk;
}

/*
 * These enforcement helpers identify the user by durable id when present, with SHA-256 password
 * digest as the legacy fallback. They deliberately do NOT gate on handle->generation: a GetAllUsers
 * refresh bumps the generation but the same logical user keeps the same durable id, so enforcement
 * (admission, accounting, closing) must keep working against the refreshed user object. A miss means
 * the user was actually removed from the table (revoked).
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

    rwlockReadLock(&ts->users_lock);
    if (LIKELY(ts->users != NULL))
    {
        result = authenticationclientUsersTryAdmitConnectionByHandle(ts->users, handle, ip_key, now_ms);
    }
    rwlockReadUnlock(&ts->users_lock);

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

    rwlockReadLock(&ts->users_lock);
    if (ts->users != NULL)
    {
        usersResetFirstUsagePushRequests(ts->users);
    }
    rwlockReadUnlock(&ts->users_lock);
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
        const bool push_in_flight = ts->push_in_flight;
        if (push_in_flight)
        {
            ts->first_usage_push_deferred = true;
        }
        mutexUnlock(&ts->control_mutex);
        if (! push_in_flight)
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
    if (ts->push_in_flight)
    {
        ts->first_usage_push_deferred = true;
        result                        = kAuthenticationClientFirstUsagePushPending;
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
        sendWorkerMessageForceQueue(0, authenticationclientFirstUsagePushOnWorker0, t, NULL, NULL);
    }
    return result;
}

bool authenticationclientUserAccountTraffic(tunnel_t *t, const user_handle_t *handle, uint64_t upload_bytes,
                                            uint64_t download_bytes, uint64_t now_ms)
{
    if (UNLIKELY(t == NULL || ! userHandleIsValid(handle)))
    {
        return false;
    }

    authenticationclient_tstate_t *ts                      = tunnelGetState(t);
    bool                           should_close            = false;
    bool                           first_usage_push_needed = false;

    rwlockReadLock(&ts->users_lock);
    if (LIKELY(ts->users != NULL))
    {
        // AccountTraffic returns close=true when the user is gone (revoked), so a removed user's
        // traffic is rejected and the connection is torn down.
        should_close = authenticationclientUsersAccountTrafficByHandle(
            ts->users, handle, upload_bytes, download_bytes, now_ms, NULL, &first_usage_push_needed);
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

    if (getWID() == 0)
    {
        discard authenticationclientSendGetAllUsers(t);
        return;
    }

    sendWorkerMessageForceQueue(0, authenticationclientRequestPullOnWorker0, t, NULL, NULL);
}

void authenticationclientRequestPush(tunnel_t *t)
{
    if (UNLIKELY(t == NULL))
    {
        return;
    }

    if (getWID() == 0)
    {
        discard authenticationclientSendPushUserStats(t);
        return;
    }

    sendWorkerMessageForceQueue(0, authenticationclientRequestPushOnWorker0, t, NULL, NULL);
}
