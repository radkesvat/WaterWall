#include "internal.h"

#include "loggers/network_logger.h"
#include "node_builder/config_lexical.h"

static void authenticationclientClearSessionLocked(authenticationclient_tstate_t *ts);

void authenticationclientResetFirstUsagePushRuntime(tunnel_t *t);

static void authenticationclientClearSessionLocked(authenticationclient_tstate_t *ts)
{
    memoryZero(ts->token, sizeof(ts->token));
    ts->authenticated  = false;
    ts->auth_in_flight = false;
    ts->pull_in_flight = false;
    ts->push_in_flight = false;
    ts->pull_requested = true;
    ts->pull_required  = true;
}

void authenticationclientResetFirstUsagePushRuntime(tunnel_t *t)
{
    authenticationclient_tstate_t *ts = tunnelGetState(t);

    rwlockReadLock(&ts->users_lock);
    if (ts->users != NULL)
    {
        usersResetFirstUsagePushRequests(ts->users);
    }
    rwlockReadUnlock(&ts->users_lock);
}

void authenticationclientOpenControlLine(tunnel_t *t)
{
    authenticationclient_tstate_t *ts = tunnelGetState(t);

    // The control line is structurally owned by worker 0; an unregistered or
    // lwIP caller must never reach here (it queues in
    // authenticationclientScheduleReconnect() instead).
    if (UNLIKELY(! currentThreadIsEventWorkerWID(0)))
    {
        LOGF("AuthenticationClient: control line must be opened on worker 0, caller worker: %d",
             workerWIDForLog(getWID()));
        abortProgramNow(1);
        return;
    }

    mutexLock(&ts->control_mutex);
    if (wloopNowMonotonicMS(getWorkerLoop(0)) < authenticationclientRetryNotBeforeLocked(ts))
    {
        mutexUnlock(&ts->control_mutex);
        authenticationclientScheduleReconnect(t);
        return;
    }
    if (UNLIKELY(! ts->started || ts->stopping || ts->continuity_error || ts->control_line != NULL))
    {
        if (ts->verbose)
        {
            LOGD("AuthenticationClient: skipped opening control line stopping=%s existing-line=%s",
                 boolToTrueFalse(ts->stopping),
                 boolToTrueFalse(ts->control_line != NULL));
        }
        mutexUnlock(&ts->control_mutex);
        return;
    }
    authenticationclientClearSessionLocked(ts);
    ts->connected     = false;
    ts->write_paused  = false;
    ts->pending_count = 0;
    mutexUnlock(&ts->control_mutex);
    authenticationclientResetFirstUsagePushRuntime(t);

    line_t                        *line = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), 0);
    authenticationclient_lstate_t *ls   = lineGetState(line, t);
    authenticationclientLinestateInitialize(ls, lineGetBufferPool(line));

    if (ts->verbose)
    {
        LOGD("AuthenticationClient: opening control line on worker %u", (unsigned int) lineGetWID(line));
    }

    mutexLock(&ts->control_mutex);
    ts->control_line = line;
    mutexUnlock(&ts->control_mutex);

    if (UNLIKELY(! lineCallWithRef(line, tunnelNextUpStreamInit, t)))
    {
        if (ts->verbose)
        {
            LOGD("AuthenticationClient: control line closed during upstream Init");
        }
        return;
    }
}

void authenticationclientCloseControlLine(tunnel_t *t, line_t *l, bool propagate_finish)
{
    authenticationclient_tstate_t *ts      = tunnelGetState(t);
    const bool                     verbose = ts->verbose;

    mutexLock(&ts->control_mutex);
    if (LIKELY(ts->control_line == l))
    {
        ts->control_line = NULL;
    }
    ts->connected     = false;
    ts->write_paused  = false;
    ts->pending_count = 0;
    authenticationclientClearSessionLocked(ts);
    mutexUnlock(&ts->control_mutex);
    /* Retain unacknowledged relative debt; a saturated A - B cannot rebuild it. */
    ts->catchup_capture_needed = true;
    authenticationclientDiscardStaging(ts);
    authenticationclientUpdateRequestTimer(t);
    authenticationclientResetFirstUsagePushRuntime(t);

    if (verbose)
    {
        LOGD("AuthenticationClient: closing control line propagate-finish=%s", boolToTrueFalse(propagate_finish));
    }

    authenticationclient_lstate_t *ls = lineGetState(l, t);
    authenticationclientLinestateDestroy(ls);

    // This tunnel owns the control line; upstream Finish is non-reentrant, then we destroy it locally.
    if (propagate_finish)
    {
        tunnelNextUpStreamFinish(t, l);
    }

    lineDestroy(l);
}
