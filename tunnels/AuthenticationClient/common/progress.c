#include "internal.h"
#include "loggers/network_logger.h"

void authenticationclientRequiredWorkFailed(tunnel_t *t, const char *operation)
{
    authenticationclient_tstate_t *ts = tunnelGetState(t);
    mutexLock(&ts->control_mutex);
    const bool stopping = ts->stopping;
    mutexUnlock(&ts->control_mutex);
    /* Worker 0 admission closes before the node receives its quiesce hook.
     * A callback already in progress may still try to arm its next wakeup. */
    if (stopping || wloopQuiesceRequested(getWorkerLoop(0)))
        return;
    LOGF("AuthenticationClient: could not admit required %s", operation);
    if (! requestProgramShutdown(1))
    {
        abortProgramNow(1);
    }
}

static void syncProgress(wtimer_t *timer)
{
    tunnel_t *t = weventGetUserdata(timer);
    if (t == NULL)
        return;
    authenticationclient_tstate_t *ts = tunnelGetState(t);
    ts->progress_timer                = NULL;
    authenticationclientResumeSync(t);
    authenticationclientScheduleSyncProgress(t);
}

void authenticationclientScheduleSyncProgress(tunnel_t *t)
{
    assert(currentThreadOwnsWorker(0));
    authenticationclient_tstate_t *ts = tunnelGetState(t);
    mutexLock(&ts->control_mutex);
    const uint64_t now       = wloopNowMonotonicMS(getWorkerLoop(0));
    const bool     reporting = ! ts->pull_required && (ts->push_requested || ts->pending_batch != NULL ||
                                                   ts->catchup_capture_needed || authenticationclientHasCatchup(ts));
    const bool needed = ts->started && ! ts->stopping && ! ts->continuity_error && ts->authenticated && ts->connected &&
                        ! ts->write_paused && ts->pending_count < ts->max_pending_requests &&
                        (wloopNowMonotonicMS(getWorkerLoop(0)) >= authenticationclientRetryNotBeforeLocked(ts)) &&
                        ! ts->auth_in_flight && ! ts->pull_in_flight && ! ts->push_in_flight &&
                        (ts->pull_requested || ts->pull_required || ts->staging.active || ts->push_requested ||
                         ts->pending_batch != NULL || ts->catchup_capture_needed || authenticationclientHasCatchup(ts));
    uint32_t delay = ! reporting && now < ts->pull_retry_not_before_ms
                         ? (uint32_t) min(ts->pull_retry_not_before_ms - now, (uint64_t) UINT32_MAX)
                         : 1U;
    if (! ts->pull_required && ! ts->staging.active && ts->pending_batch == NULL && ts->catchup_capture_needed &&
        now < ts->catchup_retry_not_before_ms)
    {
        uint64_t due = ts->catchup_retry_not_before_ms;
        if (ts->pull_requested)
            due = min(due, ts->pull_retry_not_before_ms);
        delay = due > now ? (uint32_t) min(due - now, (uint64_t) UINT32_MAX) : 1U;
    }
    mutexUnlock(&ts->control_mutex);
    if (! needed || ts->progress_timer != NULL)
        return;
    /* Independent of optional jobs; nonzero delay also bounds retry and
     * synchronous fixture/reentrant transports to one continuation per turn. */
    ts->progress_timer = wtimerAdd(getWorkerLoop(0), syncProgress, delay, 1);
    if (ts->progress_timer != NULL)
        weventSetUserData(ts->progress_timer, t);
    else
        authenticationclientRequiredWorkFailed(t, "synchronization progress timer");
}

static void reconnectCancelled(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard                        arg2;
    discard                        arg3;
    discard                        reason;
    authenticationclient_tstate_t *ts = tunnelGetState(arg1);
    /* Tunnel lifetime extends through worker-message settlement. Cancellation
     * can be synchronous or foreign and never accesses owner-worker state. */
    mutexLock(&ts->control_mutex);
    ts->reconnect_work_pending = false;
    mutexUnlock(&ts->control_mutex);
}

static void reconnectOnWorker0(void *worker_ptr, void *arg1, void *arg2, void *arg3)
{
    worker_t *worker = worker_ptr;
    tunnel_t *t      = arg1;
    assert(worker->wid == 0);
    discard worker;
    reconnectCancelled(t, arg2, arg3, kWorkerMessageCancelQuiesced);
    authenticationclient_tstate_t *ts = tunnelGetState(t);
    if (ts->reconnect_interval_ms == 0)
        authenticationclientOpenControlLine(t);
    else
        authenticationclientScheduleReconnect(t);
}

void authenticationclientScheduleReconnect(tunnel_t *t)
{
    authenticationclient_tstate_t *ts    = tunnelGetState(t);
    const bool                     owner = currentThreadOwnsWorker(0);
    mutexLock(&ts->control_mutex);
    const uint64_t now           = owner ? wloopNowMonotonicMS(getWorkerLoop(0)) : 0;
    const uint64_t refusal_delay = owner && now < authenticationclientRetryNotBeforeLocked(ts)
                                       ? authenticationclientRetryNotBeforeLocked(ts) - now
                                       : 0;
    const bool     queue         = ! owner || (ts->reconnect_interval_ms == 0 && refusal_delay == 0);
    const bool     needed        = ts->started && ! ts->stopping && ! ts->continuity_error && ts->control_line == NULL;
    if (! needed || (queue && ts->reconnect_work_pending))
    {
        mutexUnlock(&ts->control_mutex);
        return;
    }
    if (queue)
        ts->reconnect_work_pending = true;
    mutexUnlock(&ts->control_mutex);
    if (queue)
    {
        const worker_message_submit_result_e result =
            sendWorkerMessageForceQueueWithCleanup(0, reconnectOnWorker0, reconnectCancelled, t, NULL, NULL);
        if (result != kWorkerMessageSubmitAccepted)
            authenticationclientRequiredWorkFailed(t, "reconnect work");
        return;
    }
    if (ts->reconnect_timer != NULL)
        return; /* Preserve the first retry deadline. */
    const uint32_t delay =
        (uint32_t) min(max((uint64_t) ts->reconnect_interval_ms, refusal_delay), (uint64_t) UINT32_MAX);
    ts->reconnect_due_ms = delay > UINT64_MAX - now ? UINT64_MAX : now + delay;
    ts->reconnect_timer  = wtimerAdd(getWorkerLoop(0), authenticationclientReconnectTimerCallback, delay, 1);
    if (ts->reconnect_timer == NULL)
        authenticationclientRequiredWorkFailed(t, "reconnect timer");
    else
        weventSetUserData(ts->reconnect_timer, t);
}

void authenticationclientReconnectTimerCallback(wtimer_t *timer)
{
    tunnel_t *t = weventGetUserdata(timer);
    if (t == NULL)
        return;
    authenticationclient_tstate_t *ts  = tunnelGetState(t);
    const uint64_t                 now = wloopNowMonotonicMS(weventGetLoop(timer));
    if (now < ts->reconnect_due_ms)
    {
        if (! wtimerReset(timer, (uint32_t) min(ts->reconnect_due_ms - now, (uint64_t) UINT32_MAX)))
        {
            ts->reconnect_timer = NULL;
            authenticationclientRequiredWorkFailed(t, "reconnect timer reset");
        }
        return;
    }
    ts->reconnect_timer = NULL;
    authenticationclientOpenControlLine(t);
}

void authenticationclientRecoverControlLine(tunnel_t *t, line_t *l, bool propagate_finish)
{
    authenticationclientCloseControlLine(t, l, propagate_finish);
    authenticationclientScheduleReconnect(t);
}

static void requestDeadline(wtimer_t *timer)
{
    tunnel_t *t = weventGetUserdata(timer);
    if (t == NULL)
        return;
    authenticationclient_tstate_t *ts = tunnelGetState(t);
    ts->request_timer                 = NULL;
    if (! authenticationclientCloseTimedOutControlLine(t))
        authenticationclientUpdateRequestTimer(t);
}

void authenticationclientUpdateRequestTimer(tunnel_t *t)
{
    assert(currentThreadOwnsWorker(0));
    authenticationclient_tstate_t *ts       = tunnelGetState(t);
    uint64_t                       earliest = UINT64_MAX;
    mutexLock(&ts->control_mutex);
    if (! ts->stopping && ts->request_timeout_ms != 0)
        for (uint32_t i = 0; i < ts->pending_count; ++i)
            earliest = min(earliest, ts->pending_requests[i].created_at_ms + ts->request_timeout_ms);
    mutexUnlock(&ts->control_mutex);
    if (ts->request_timer != NULL && earliest == ts->request_deadline_ms)
        return;
    if (ts->request_timer != NULL)
    {
        weventSetUserData(ts->request_timer, NULL);
        wtimerDelete(ts->request_timer);
        ts->request_timer = NULL;
    }
    ts->request_deadline_ms = earliest;
    if (earliest == UINT64_MAX)
        return;
    const uint64_t now   = wloopNowMonotonicMS(getWorkerLoop(0));
    const uint32_t delay = earliest > now ? (uint32_t) min(earliest - now, (uint64_t) UINT32_MAX) : 1U;
    ts->request_timer    = wtimerAdd(getWorkerLoop(0), requestDeadline, delay, 1);
    if (ts->request_timer != NULL)
        weventSetUserData(ts->request_timer, t);
    else
        authenticationclientRequiredWorkFailed(t, "request deadline timer");
}
