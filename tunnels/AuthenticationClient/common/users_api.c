#include "structure.h"

#include "loggers/network_logger.h"

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
        state = kAuthenticationClientStateReady;
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

    authenticationclient_tstate_t *ts    = tunnelGetState(t);
    bool                           found = false;

    rwlockReadLock(&ts->users_lock);
    if (LIKELY(ts->users != NULL) && usersLookupBySHA256(ts->users, sha256) != NULL)
    {
        userHandleSet(handle_out, sha256, ts->users_generation);
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
    if (UNLIKELY(t == NULL || password == NULL || password[0] == '\0' || handle_out == NULL))
    {
        return false;
    }

    sha256_hash_t sha256 = {0};
    if (UNLIKELY(wCryptoSHA256(&sha256, (const unsigned char *) password, stringLength(password)) != 0))
    {
        return false;
    }

    authenticationclient_tstate_t *ts    = tunnelGetState(t);
    bool                           found = false;

    rwlockReadLock(&ts->users_lock);
    user_t *user = ts->users != NULL ? usersLookupBySHA256(ts->users, sha256.bytes) : NULL;
    if (user != NULL && userPasswordMatches(user, password))
    {
        userHandleSet(handle_out, sha256.bytes, ts->users_generation);
        found = true;
    }
    rwlockReadUnlock(&ts->users_lock);

    memoryZero(&sha256, sizeof(sha256)); // i dont want to use wCryptoZero
    if (! found)
    {
        userHandleClear(handle_out);
    }
    return found;
}

bool authenticationclientUserHandleIsLive(tunnel_t *t, const user_handle_t *handle)
{
    if (UNLIKELY(t == NULL || ! userHandleIsValid(handle)))
    {
        return false;
    }

    authenticationclient_tstate_t *ts   = tunnelGetState(t);
    bool                           live = false;

    rwlockReadLock(&ts->users_lock);
    live = LIKELY(ts->users != NULL) && handle->generation == ts->users_generation &&
           usersLookupBySHA256(ts->users, handle->sha256) != NULL;
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
        result = usersAddTrafficBySHA256(ts->users, handle->sha256, upload_bytes, download_bytes);
    }
    rwlockReadUnlock(&ts->users_lock);

    return result == kUsersUpdateResultOk;
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
