#include "loggers/network_logger.h"
#include "structure.h"

static void progressFailure(const char *operation)
{
    LOGF("AuthenticationClient: could not admit required %s", operation);
    if (! requestProgramShutdown(1))
        abortProgramNow(1);
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
    const bool                     queue = ! currentThreadIsEventWorkerWID(0) || ts->reconnect_interval_ms == 0;
    mutexLock(&ts->control_mutex);
    const bool needed = ts->started && ! ts->stopping && ts->control_line == NULL;
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
        {
            mutexLock(&ts->control_mutex);
            const bool stopping = ts->stopping;
            mutexUnlock(&ts->control_mutex);
            if (! stopping)
                progressFailure("reconnect work");
        }
        return;
    }
    if (ts->reconnect_timer != NULL)
        return; /* Preserve the first retry deadline. */
    ts->reconnect_due_ms = wloopNowMonotonicMS(getWorkerLoop(0)) + ts->reconnect_interval_ms;
    ts->reconnect_timer =
        wtimerAdd(getWorkerLoop(0), authenticationclientReconnectTimerCallback, ts->reconnect_interval_ms, 1);
    if (ts->reconnect_timer == NULL)
        progressFailure("reconnect timer");
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
        if (! wtimerReset(timer, (uint32_t) (ts->reconnect_due_ms - now)))
            ts->reconnect_timer = NULL;
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
    assert(currentThreadIsEventWorkerWID(0));
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
        progressFailure("request deadline timer");
}
