#include "internal.h"

#include "loggers/network_logger.h"

static bool authenticationclientShouldSendGetAllUsers(tunnel_t *t, bool pull_due);

static uint32_t authenticationclientSmallestNonZero(uint32_t a, uint32_t b);

static uint32_t authenticationclientSyncInterval(authenticationclient_tstate_t *ts);

static bool authenticationclientSyncJobDue(uint32_t now_ms, uint32_t *last_attempt_ms, uint32_t interval_ms);

static bool authenticationclientUsersLoaded(tunnel_t *t);

bool authenticationclientRequestMayBeSentLocked(authenticationclient_tstate_t *ts, uint8_t request_type)
{
    if (UNLIKELY(ts->stopping || ts->continuity_error || ! ts->connected || ts->write_paused ||
                 (wloopNowMonotonicMS(getWorkerLoop(0)) < authenticationclientRetryNotBeforeLocked(ts)) ||
                 ts->control_line == NULL))
    {
        return false;
    }

    if (request_type == kAuthenticationClientRequestTypeAuthenticate)
    {
        return ! ts->authenticated && ! ts->auth_in_flight;
    }
    if (! ts->authenticated)
    {
        return false;
    }
    if (request_type == kAuthenticationClientRequestTypeGetAllUsers)
    {
        return ! ts->pull_in_flight && ! ts->push_in_flight && ts->pending_batch == NULL;
    }
    if (request_type == kAuthenticationClientRequestTypePushUserStats)
    {
        return ! ts->push_in_flight && ! ts->pull_in_flight && ! ts->staging.active &&
               ts->accounting_epoch[0] != '\0' && (ts->pending_batch != NULL || ! ts->pull_required);
    }
    return true;
}

static bool authenticationclientShouldSendGetAllUsers(tunnel_t *t, bool pull_due)
{
    authenticationclient_tstate_t *ts = tunnelGetState(t);

    uint64_t remote_config_revision     = 0;
    uint64_t remote_revision_generation = 0;

    mutexLock(&ts->control_mutex);
    remote_config_revision     = ts->remote_config_revision;
    remote_revision_generation = ts->remote_revision_generation;
    mutexUnlock(&ts->control_mutex);

    uint64_t local_config_revision     = 0;
    uint64_t local_revision_generation = 0;
    bool     users_loaded              = false;

    rwlockReadLock(&ts->users_lock);
    local_config_revision     = ts->local_config_revision;
    local_revision_generation = ts->local_revision_generation;
    users_loaded              = ts->users_loaded;
    rwlockReadUnlock(&ts->users_lock);

    if (! users_loaded)
    {
        return true;
    }
    if (remote_revision_generation == 0)
    {
        return pull_due;
    }
    if (local_revision_generation == 0)
    {
        return true;
    }
    if (remote_config_revision != local_config_revision)
    {
        return true;
    }

    return pull_due;
}

bool authenticationclientSendGetAllUsers(tunnel_t *t)
{
    authenticationclient_tstate_t *ts = tunnelGetState(t);
    mutexLock(&ts->control_mutex);
    ts->pull_requested = true;
    if (ts->staging.active)
    {
        mutexUnlock(&ts->control_mutex);
        return false; /* An explicit new pull coalesces behind the current traversal. */
    }
    const bool allowed = authenticationclientRequestMayBeSentLocked(ts, kAuthenticationClientRequestTypeGetAllUsers);
    if (allowed)
        ts->pull_requested = false;
    mutexUnlock(&ts->control_mutex);
    if (! allowed)
        return false;
    const bool sent = authenticationclientSendUsersPage(t);
    if (! sent)
    {
        mutexLock(&ts->control_mutex);
        ts->pull_requested = true;
        mutexUnlock(&ts->control_mutex);
        authenticationclientScheduleSyncProgress(t);
    }
    return sent;
}

void authenticationclientResumeSync(tunnel_t *t)
{
    authenticationclient_tstate_t *ts = tunnelGetState(t);
    mutexLock(&ts->control_mutex);
    const bool authenticated = ts->authenticated;
    const bool pull          = ts->pull_requested;
    const bool required_pull = ts->pull_required || ts->staging.active;
    const bool push          = ts->push_requested;
    mutexUnlock(&ts->control_mutex);
    if (! authenticated)
        discard authenticationclientSendAuthenticate(t);
    else if (ts->pending_batch != NULL)
        discard authenticationclientSendPushUserStats(t);
    else if (ts->staging.active)
    {
        mutexLock(&ts->control_mutex);
        const bool allowed =
            authenticationclientRequestMayBeSentLocked(ts, kAuthenticationClientRequestTypeGetUsersPage);
        mutexUnlock(&ts->control_mutex);
        if (allowed)
            discard authenticationclientSendUsersPage(t);
    }
    else if (required_pull)
        discard authenticationclientSendGetAllUsers(t);
    else if (ts->catchup_capture_needed && ! authenticationclientCaptureCatchup(t))
        authenticationclientScheduleSyncProgress(t);
    else if (authenticationclientHasCatchup(ts))
    {
        discard authenticationclientSendPushUserStats(t);
        authenticationclientScheduleSyncProgress(t);
    }
    else
    {
        /* Ordinary pulls coalesce behind a waiting push. Every successful push
         * requires a refresh, so both jobs progress even when both stay due. */
        if (push && authenticationclientSendPushUserStats(t))
            return;
        /* An empty/refused batch must not swallow an already requested pull. */
        if (pull)
            discard authenticationclientSendGetAllUsers(t);
    }
    authenticationclientScheduleSyncProgress(t);
}

void authenticationclientPingTimerCallback(wtimer_t *timer)
{
    tunnel_t *t = weventGetUserdata(timer);
    if (UNLIKELY(t == NULL))
    {
        return;
    }

    authenticationclient_tstate_t *ts            = tunnelGetState(t);
    bool                           authenticated = false;
    bool                           connected     = false;

    if (UNLIKELY(authenticationclientCloseTimedOutControlLine(t)))
    {
        return;
    }

    mutexLock(&ts->control_mutex);
    connected     = ts->connected;
    authenticated = ts->authenticated;
    mutexUnlock(&ts->control_mutex);

    if (ts->verbose)
    {
        LOGD("AuthenticationClient: ping timer tick connected=%s authenticated=%s",
             boolToTrueFalse(connected),
             boolToTrueFalse(authenticated));
    }

    if (UNLIKELY(! connected))
    {
        authenticationclientScheduleReconnect(t);
        return;
    }
    if (authenticated)
    {
        discard authenticationclientSendPing(t);
    }
    else
    {
        discard authenticationclientSendAuthenticate(t);
    }
}

static uint32_t authenticationclientSmallestNonZero(uint32_t a, uint32_t b)
{
    if (a == 0)
    {
        return b;
    }
    if (b == 0 || a < b)
    {
        return a;
    }
    return b;
}

static uint32_t authenticationclientSyncInterval(authenticationclient_tstate_t *ts)
{
    return authenticationclientSmallestNonZero(ts->pull_interval_ms, ts->push_interval_ms);
}

static bool authenticationclientSyncJobDue(uint32_t now_ms, uint32_t *last_attempt_ms, uint32_t interval_ms)
{
    if (interval_ms == 0)
    {
        return false;
    }
    if ((uint32_t) (now_ms - *last_attempt_ms) < interval_ms)
    {
        return false;
    }

    *last_attempt_ms = now_ms;
    return true;
}

static bool authenticationclientUsersLoaded(tunnel_t *t)
{
    authenticationclient_tstate_t *ts           = tunnelGetState(t);
    bool                           users_loaded = false;

    rwlockReadLock(&ts->users_lock);
    users_loaded = ts->users_loaded;
    rwlockReadUnlock(&ts->users_lock);

    return users_loaded;
}

bool authenticationclientStartSyncTimer(tunnel_t *t)
{
    authenticationclient_tstate_t *ts               = tunnelGetState(t);
    const uint32_t                 sync_interval_ms = authenticationclientSyncInterval(ts);

    if (sync_interval_ms == 0 || ts->sync_timer != NULL)
    {
        return true;
    }

    const uint32_t now_ms = getTickMS();
    ts->last_pull_sync_ms = now_ms;
    ts->last_push_sync_ms = now_ms;

    ts->sync_timer = wtimerAdd(getWorkerLoop(0), authenticationclientSyncTimerCallback, sync_interval_ms, INFINITE);
    if (UNLIKELY(ts->sync_timer == NULL))
    {
        LOGF("AuthenticationClient: failed to create sync timer");
        if (! requestProgramShutdown(1))
        {
            abortProgramNow(1);
        }
        return false;
    }
    weventSetUserData(ts->sync_timer, t);

    if (ts->verbose)
    {
        LOGD("AuthenticationClient: sync timer enabled every %u ms", (unsigned int) sync_interval_ms);
    }

    return true;
}

void authenticationclientSyncTimerCallback(wtimer_t *timer)
{
    tunnel_t *t = weventGetUserdata(timer);
    if (UNLIKELY(t == NULL))
    {
        return;
    }

    authenticationclient_tstate_t *ts = tunnelGetState(t);

    if (UNLIKELY(authenticationclientCloseTimedOutControlLine(t)))
    {
        return;
    }

    const uint32_t now_ms   = getTickMS();
    const bool     push_due = authenticationclientSyncJobDue(now_ms, &ts->last_push_sync_ms, ts->push_interval_ms);
    const bool     pull_due = authenticationclientSyncJobDue(now_ms, &ts->last_pull_sync_ms, ts->pull_interval_ms);

    if (ts->verbose)
    {
        LOGD("AuthenticationClient: sync timer tick push-due=%s pull-due=%s",
             boolToTrueFalse(push_due),
             boolToTrueFalse(pull_due));
    }

    if (push_due)
    {
        discard authenticationclientSendPushUserStats(t);
    }

    if (ts->pull_interval_ms == 0 && authenticationclientUsersLoaded(t))
    {
        return;
    }

    const bool should_pull = authenticationclientShouldSendGetAllUsers(t, pull_due);
    if (ts->verbose)
    {
        LOGD("AuthenticationClient: sync timer pull decision send=%s", boolToTrueFalse(should_pull));
    }

    if (! should_pull)
    {
        return;
    }

    ts->last_pull_sync_ms = now_ms;
    discard authenticationclientSendGetAllUsers(t);
}
