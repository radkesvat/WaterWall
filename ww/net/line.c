#include "line.h"
#include "line_task_internal.h"

/*
 * Implements worker-thread task scheduling helpers for line-bound callbacks.
 */

#include "loggers/internal_logger.h"
#include "worker_messages_internal.h"

static void lineFreeCredentialString(char **value, bool secret)
{
    if (*value == NULL)
    {
        return;
    }

    if (secret)
    {
        memoryZero(*value, stringLength(*value));
    }
    memoryFree(*value);
    *value = NULL;
}

static void lineAuthEntryDestroy(line_user_auth_t *entry)
{
    if (entry->has_credentials)
    {
        lineFreeCredentialString(&entry->credentials.username, false);
        lineFreeCredentialString(&entry->credentials.password, true);
    }

    memoryZero(entry, sizeof(*entry));
}

static void lineEnsureAuthCapacity(const line_t *const line, uint8_t needed)
{
    if (LIKELY(line->user_count <= kLineMaxUsers && needed <= kLineMaxUsers - line->user_count))
    {
        return;
    }

    LOGF("Line: too many users added to line; maximum is %u", (unsigned int) kLineMaxUsers);
    abortProgramNow(1);
}

static void lineAddAuthEntry(line_t *const line, const user_handle_t *user_handle, bool add_handle,
                             const char *username, const char *password)
{
    line_user_auth_t *entry = &line->user_auths[line->user_count];

    *entry = (line_user_auth_t) {0};
    if (add_handle)
    {
        entry->has_handle = true;
        entry->handle     = userHandleEmpty();
        if (userHandleIsValid(user_handle))
        {
            entry->handle = *user_handle;
        }
    }

    entry->has_credentials = username != NULL || password != NULL;
    if (entry->has_credentials)
    {
        if (username != NULL)
        {
            entry->credentials.username = stringDuplicate(username);
        }
        if (password != NULL)
        {
            entry->credentials.password = stringDuplicate(password);
        }
    }
    line->user_count += 1;
}

static bool lineCredentialValueMatches(const char *stored, const char *expected)
{
    return expected == NULL || (stored != NULL && stringCompare(stored, expected) == 0);
}

void lineAddUser(line_t *const line, const user_handle_t *user_handle, const char *username, const char *password)
{
    bool has_credentials = username != NULL || password != NULL;
    bool add_handle      = userHandleIsValid(user_handle) || ! has_credentials;

    assert(line != NULL);

    lineEnsureAuthCapacity(line, 1);
    lineAddAuthEntry(line, user_handle, add_handle, username, password);
}

void lineAddAuthenticatedCredentials(line_t *const line, const char *username, const char *password)
{
    assert(line != NULL);

    if (username == NULL && password == NULL)
    {
        return;
    }

    lineEnsureAuthCapacity(line, 1);
    lineAddAuthEntry(line, NULL, false, username, password);
}

void lineSetAuthenticatedCredentials(line_t *const line, const char *username, const char *password)
{
    lineAddAuthenticatedCredentials(line, username, password);
}

void lineCopyUsers(line_t *const dest, const line_t *const src)
{
    assert(dest != NULL);
    assert(src != NULL);

    if (dest == src)
    {
        return;
    }

    if (UNLIKELY(dest->user_count != 0))
    {
        LOGF("Line: attempted to copy users into a line that already has user markers or credentials");
        abortProgramNow(1);
        return;
    }

    lineEnsureAuthCapacity(dest, src->user_count);

    for (uint8_t i = 0; i < src->user_count; ++i)
    {
        const line_user_auth_t *src_entry = &src->user_auths[i];

        lineAddAuthEntry(dest,
                         &src_entry->handle,
                         src_entry->has_handle,
                         src_entry->has_credentials ? src_entry->credentials.username : NULL,
                         src_entry->has_credentials ? src_entry->credentials.password : NULL);
    }
}

void lineClearUsers(line_t *const line)
{
    if (line == NULL)
    {
        return;
    }

    for (uint8_t i = 0; i < line->user_count; ++i)
    {
        lineAuthEntryDestroy(&line->user_auths[i]);
    }
    line->user_count = 0;
}

void lineUnRefInternal(line_t *l)
{
    /*
     * Reference-count publication is the lifetime edge for a line.  In
     * particular, the owner may zero tunnel state and mark the line dead on
     * one thread, release 2 -> 1, and leave a foreign refusal-cleanup thread
     * to release 1 -> 0 and reclaim the allocation.  Every decrement therefore
     * publishes preceding line writes; the final releaser acquires the release
     * sequence before inspecting any non-atomic line state.
     */
    const w_atomic_uint_value_t previous = atomicSubExplicit(&l->refc, 1, memory_order_acq_rel);
    assert(previous != 0);
    if (UNLIKELY(previous == 0))
    {
        LOGF("lineUnRefInternal: line reference count underflow");
        abortProgramNow(1);
    }
    if (previous > 1)
    {
        return;
    }
    assert(! l->alive);
    if (UNLIKELY(l->alive))
    {
        LOGF("lineUnRefInternal: line reclaimed while still logically alive");
        abortProgramNow(1);
    }

    /* Every line pool in a chain has one item geometry and one shared master.
     * Pool zero is therefore stable allocator metadata even when the line's
     * routing owner differs. It also avoids indexing by pseudo/invalid TLS. */
    generic_pool_t *const provenance_pool = l->pools[0];
    debugAssertZeroBuf(&l->tunnels_line_state[0], genericpoolGetItemSize(provenance_pool) - sizeof(line_t));

    if (l->routing_context.dest_ctx.domain != NULL && ! l->routing_context.dest_ctx.domain_constant)
    {
        memoryFree(l->routing_context.dest_ctx.domain);
        l->routing_context.dest_ctx.domain = NULL;
    }

    lineClearUsers(l);

    worker_t *current = tryGetCurrentEventWorker();
    if (current != NULL && current->wid == l->wid)
    {
        genericpoolReuseItem(l->pools[current->wid], l);
        return;
    }

    /* Refusal cleanup can run synchronously on an lwIP/device/plain thread or
     * on the event worker that attempted a cross-worker admission. Neither may
     * mutate the allocation owner's worker-local pool, so return through the
     * pool family's thread-safe master instead. */
    genericpoolReuseItemShared(provenance_pool, l);
}

const user_handle_t *lineGetCurrentUser(const line_t *const line)
{
    assert(line != NULL);

    for (uint8_t i = line->user_count; i > 0; --i)
    {
        const line_user_auth_t *entry = &line->user_auths[i - 1U];
        if (entry->has_handle)
        {
            return &entry->handle;
        }
    }

    return NULL;
}

const char *lineGetAuthenticatedUsername(const line_t *const line)
{
    assert(line != NULL);

    for (uint8_t i = line->user_count; i > 0; --i)
    {
        const line_user_auth_t *entry = &line->user_auths[i - 1U];
        if (entry->has_credentials)
        {
            return entry->credentials.username;
        }
    }

    return NULL;
}

const char *lineGetAuthenticatedPassword(const line_t *const line)
{
    assert(line != NULL);

    for (uint8_t i = line->user_count; i > 0; --i)
    {
        const line_user_auth_t *entry = &line->user_auths[i - 1U];
        if (entry->has_credentials)
        {
            return entry->credentials.password;
        }
    }

    return NULL;
}

bool lineHasAuthenticatedCredentials(const line_t *const line, const char *username, const char *password)
{
    assert(line != NULL);

    if (username == NULL && password == NULL)
    {
        return false;
    }

    for (uint8_t i = line->user_count; i > 0; --i)
    {
        const line_user_auth_t *entry = &line->user_auths[i - 1U];
        if (! entry->has_credentials)
        {
            continue;
        }
        if (lineCredentialValueMatches(entry->credentials.username, username) &&
            lineCredentialValueMatches(entry->credentials.password, password))
        {
            return true;
        }
    }

    return false;
}

bool lineHasAuthenticatedUsername(const line_t *const line, const char *username)
{
    if (username == NULL)
    {
        return false;
    }
    return lineHasAuthenticatedCredentials(line, username, NULL);
}

bool lineHasAuthenticatedPassword(const line_t *const line, const char *password)
{
    if (password == NULL)
    {
        return false;
    }
    return lineHasAuthenticatedCredentials(line, NULL, password);
}

typedef struct line_dns_resolve_msg_s
{
    LineDnsResolveFn callback;
    tunnel_t        *tunnel;
    line_t          *line;
    void            *userdata;
} line_dns_resolve_msg_t;

static void lineCheckScheduledTaskWorker(worker_t *worker, const line_t *line)
{
    if (UNLIKELY(worker->wid != lineGetWID(line)))
    {
        // This would mean the line moved workers after the task was posted. We have never seen that happen.
        LOGF("Worker thread mismatch when running scheduled line task. Expected WID: %u, actual WID: %u",
             lineGetWID(line),
             worker->wid);
        abortProgramNow(1);
    }
}

static line_task_msg_t *lineTaskMessageCreate(line_t *line, tunnel_t *t, LineTaskCancelFn on_cancel)
{
    line_task_msg_t *msg = workerMessagePoolAcquire(sizeof(*msg));
    *msg                 = (line_task_msg_t) {.on_cancel = on_cancel, .tunnel = t, .line = line, .buf = NULL};

    return msg;
}

static void lineTaskMessageRelease(line_task_msg_t *msg)
{
    workerMessagePoolRelease(msg);
}

static void lineReleaseScheduledTaskBuffer(line_t *line, sbuf_t *buf)
{
    if (buf == NULL)
    {
        return;
    }

    /*
     * Cross-thread cleanup: only the owning event worker may push the buffer
     * back into the line's pool. Anyone else (another worker, a device thread,
     * lwIP) destroys it instead of touching a pool it does not own.
     */
    if (lineIsOnCurrentEventWorker(line))
    {
        lineReuseBuffer(line, buf);
        return;
    }

    sbufDestroy(buf);
}

static line_task_cancel_reason_e lineMapWorkerTaskCancelReason(worker_message_cancel_reason_e reason)
{
    switch (reason)
    {
    case kWorkerMessageCancelTargetUnavailable:
        return kLineTaskCancelTargetUnavailable;
    case kWorkerMessageCancelAdmissionClosed:
        return kLineTaskCancelAdmissionClosed;
    case kWorkerMessageCancelEnqueueFailure:
        return kLineTaskCancelEnqueueFailure;
    case kWorkerMessageCancelResourceFailure:
        return kLineTaskCancelResourceFailure;
    case kWorkerMessageCancelQuiesced:
        return kLineTaskCancelQuiesced;
    case kWorkerMessageCancelTeardown:
        return kLineTaskCancelTeardown;
    }

    LOGF("Line: unknown worker-message cancellation reason %d", (int) reason);
    abortProgramNow(1);
}

static void lineSettleCancelledTask(line_task_msg_t *msg, line_task_cancel_reason_e reason)
{
    LineTaskCancelFn on_cancel = msg->on_cancel;
    tunnel_t        *t         = msg->tunnel;
    line_t          *line      = msg->line;
    sbuf_t          *buf       = msg->buf;

    /* The worker record no longer needs this scheduling record. Return it
     * before invoking re-entrant user code, retaining all settlement values in
     * locals and the scheduler's physical line reference until the end. */
    lineTaskMessageRelease(msg);

    if (on_cancel != NULL)
    {
        on_cancel(t, line, reason);
    }

    lineReleaseScheduledTaskBuffer(line, buf);
    lineUnref(line);
}

static void lineCleanupScheduledTask(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard arg2;
    discard arg3;

    lineSettleCancelledTask((line_task_msg_t *) arg1, lineMapWorkerTaskCancelReason(reason));
}

static void lineDnsResolveMsgDestroy(line_dns_resolve_msg_t *msg)
{
    memoryFree(msg);
}

static void lineDnsResolveResult(void *userdata, int status, const char *error, const dns_resolved_addr_t *addrs,
                                 size_t naddrs)
{
    line_dns_resolve_msg_t *msg  = userdata;
    line_t                 *line = msg->line;

    if (lineIsAlive(line) && ! asyncdnsStatusIsShutdown(status))
    {
        msg->callback(msg->tunnel, line, msg->userdata, status, error, addrs, naddrs);
    }

    lineUnref(line);
    lineDnsResolveMsgDestroy(msg);
}

/**
 * @brief Execute a scheduled no-buffer line task on the worker thread.
 *
 * @param worker Worker context.
 * @param arg1 Packed task message.
 * @param arg2 Unused.
 * @param arg3 Unused.
 */
static void lineRunScheduledTaskNoBuf(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard arg2;
    discard arg3;

    line_task_msg_t *msg  = (line_task_msg_t *) arg1;
    LineTaskFnNoBuf  task = msg->callback.no_buf;
    tunnel_t        *t    = msg->tunnel;
    line_t          *line = msg->line;

    lineCheckScheduledTaskWorker(worker, line);

    if (! lineIsAlive(line))
    {
        lineSettleCancelledTask(msg, kLineTaskCancelLineDead);
        return;
    }

    lineTaskMessageRelease(msg);
    task(t, line);
    lineUnref(line);
}

/**
 * @brief Execute a scheduled buffered line task on the worker thread.
 *
 * @param worker Worker context.
 * @param arg1 Packed task message.
 * @param arg2 Unused.
 * @param arg3 Unused.
 */
static void lineRunScheduledTaskWithBuf(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard arg2;
    discard arg3;

    line_task_msg_t  *msg  = (line_task_msg_t *) arg1;
    LineTaskFnWithBuf task = msg->callback.with_buf;
    tunnel_t         *t    = msg->tunnel;
    line_t           *line = msg->line;
    sbuf_t           *buf  = msg->buf;

    lineCheckScheduledTaskWorker(worker, line);

    if (! lineIsAlive(line))
    {
        lineSettleCancelledTask(msg, kLineTaskCancelLineDead);
        return;
    }

    lineTaskMessageRelease(msg);
    task(t, line, buf);
    lineUnref(line);
}

static line_task_submit_result_e lineMapQueuedTaskSubmitResult(worker_message_submit_result_e result)
{
    if (result == kWorkerMessageSubmitAccepted)
    {
        return kLineTaskSubmitAcceptedAsync;
    }
    if (result == kWorkerMessageSubmitRejectedCleanupRan)
    {
        return kLineTaskSubmitRejectedSettled;
    }

    LOGF("Line: cleanup-owned worker submission unexpectedly retained caller ownership");
    abortProgramNow(1);
}

line_task_submit_result_e lineScheduleTask(line_t *const line, LineTaskFnNoBuf task, tunnel_t *t,
                                           LineTaskCancelFn on_cancel)
{
    const wid_t target_wid = lineGetWID(line);
    lineRef(line);

    line_task_msg_t *msg = lineTaskMessageCreate(line, t, on_cancel);
    msg->callback.no_buf = task;

    /* A refusal may synchronously cancel, free msg, and destroy line. Only the
     * captured target and generic submission result remain valid afterward. */
    const worker_message_submit_result_e result = sendWorkerMessageForceQueueWithCleanup(
        target_wid, (WorkerMessageCallback) lineRunScheduledTaskNoBuf, lineCleanupScheduledTask, msg, NULL, NULL);
    return lineMapQueuedTaskSubmitResult(result);
}

line_task_submit_result_e lineScheduleTaskWithBuf(line_t *const line, LineTaskFnWithBuf task, tunnel_t *t, sbuf_t *buf,
                                                  LineTaskCancelFn on_cancel)
{
    const wid_t target_wid = lineGetWID(line);
    lineRef(line);

    line_task_msg_t *msg   = lineTaskMessageCreate(line, t, on_cancel);
    msg->callback.with_buf = task;
    msg->buf               = buf;

    const worker_message_submit_result_e result = sendWorkerMessageForceQueueWithCleanup(
        target_wid, (WorkerMessageCallback) lineRunScheduledTaskWithBuf, lineCleanupScheduledTask, msg, NULL, NULL);
    return lineMapQueuedTaskSubmitResult(result);
}

line_task_submit_result_e lineScheduleDelayedTask(line_t *const line, LineTaskFnNoBuf task, uint32_t delay_ms,
                                                  tunnel_t *t, LineTaskCancelFn on_cancel)
{
    const wid_t target_wid      = lineGetWID(line);
    const bool  timer_is_direct = delay_ms > 0 && currentThreadIsEventWorkerWID(target_wid);
    lineRef(line);

    line_task_msg_t *msg = lineTaskMessageCreate(line, t, on_cancel);
    msg->callback.no_buf = task;

    const worker_message_submit_result_e result =
        sendWorkerMessageTimedWithCleanup(target_wid,
                                          (WorkerMessageCallback) lineRunScheduledTaskNoBuf,
                                          lineCleanupScheduledTask,
                                          delay_ms,
                                          (void *) msg,
                                          NULL,
                                          NULL);
    const line_task_submit_result_e mapped = lineMapQueuedTaskSubmitResult(result);
    if (mapped == kLineTaskSubmitAcceptedAsync && timer_is_direct)
    {
        return kLineTaskSubmitTimerArmed;
    }
    return mapped;
}

line_task_submit_result_e lineScheduleDelayedTaskWithBuf(line_t *const line, LineTaskFnWithBuf task, uint32_t delay_ms,
                                                         tunnel_t *t, sbuf_t *buf, LineTaskCancelFn on_cancel)
{
    const wid_t target_wid      = lineGetWID(line);
    const bool  timer_is_direct = delay_ms > 0 && currentThreadIsEventWorkerWID(target_wid);
    lineRef(line);

    line_task_msg_t *msg   = lineTaskMessageCreate(line, t, on_cancel);
    msg->callback.with_buf = task;
    msg->buf               = buf;

    const worker_message_submit_result_e result =
        sendWorkerMessageTimedWithCleanup(target_wid,
                                          (WorkerMessageCallback) lineRunScheduledTaskWithBuf,
                                          lineCleanupScheduledTask,
                                          delay_ms,
                                          (void *) msg,
                                          NULL,
                                          NULL);
    const line_task_submit_result_e mapped = lineMapQueuedTaskSubmitResult(result);
    if (mapped == kLineTaskSubmitAcceptedAsync && timer_is_direct)
    {
        return kLineTaskSubmitTimerArmed;
    }
    return mapped;
}

int lineResolveDomainServiceAsync(line_t *const line, const char *domain, const char *service, int socktype,
                                  LineDnsResolveFn cb, tunnel_t *t, void *userdata)
{
    if (line == NULL || domain == NULL || domain[0] == '\0' || cb == NULL)
    {
        return ARES_EFORMERR;
    }

    /*
     * Resolution runs on the line's own worker: it submits to that worker's
     * resolver and the completion callback touches line state. Reject a foreign
     * or unregistered caller before taking a line reference, so the rejection
     * needs no unwind and cannot reach another worker's resolver in release
     * builds.
     */
    if (UNLIKELY(! lineIsOnCurrentEventWorker(line)))
    {
        return ARES_ENOTINITIALIZED;
    }

    lineRef(line);

    line_dns_resolve_msg_t *msg = memoryAllocate(sizeof(*msg));
    if (msg == NULL)
    {
        lineUnref(line);
        return ARES_ENOMEM;
    }

    *msg = (line_dns_resolve_msg_t) {
        .callback = cb,
        .tunnel   = t,
        .line     = line,
        .userdata = userdata,
    };

    int rc = workerResolveDomainServiceAsync(lineGetWID(line), domain, service, socktype, lineDnsResolveResult, msg);
    if (rc != ARES_SUCCESS)
    {
        lineUnref(line);
        lineDnsResolveMsgDestroy(msg);
        return rc;
    }

    return ARES_SUCCESS;
}

int lineResolveDomainAsync(line_t *const line, const char *domain, LineDnsResolveFn cb, tunnel_t *t, void *userdata)
{
    return lineResolveDomainServiceAsync(line, domain, NULL, 0, cb, t, userdata);
}
