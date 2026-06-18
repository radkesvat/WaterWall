#include "line.h"

/*
 * Implements worker-thread task scheduling helpers for line-bound callbacks.
 */

#include "loggers/internal_logger.h"

void lineAddUser(line_t *const line, const user_handle_t *user_handle, const char *username, const char *password)
{
    assert(line != NULL);

    if (UNLIKELY(line->user_count >= kLineMaxUsers))
    {
        LOGF("Line: too many users added to line; maximum is %u", (unsigned int) kLineMaxUsers);
        terminateProgram(1);
        return;
    }

    user_handle_t stored_user = userHandleEmpty();
    if (userHandleIsValid(user_handle))
    {
        stored_user = *user_handle;
    }

    line->user_handles[line->user_count] = stored_user;
    line->user_count += 1;

    // Store the raw credentials so routers can match by username/password without
    // a users-table lookup. Replace any previously stored values.
    if (line->last_authenticated_user_username != NULL)
    {
        memoryFree((void *) line->last_authenticated_user_username);
        line->last_authenticated_user_username = NULL;
    }
    if (username != NULL)
    {
        line->last_authenticated_user_username = stringDuplicate(username);
    }

    if (line->last_authenticated_user_password != NULL)
    {
        memoryFree((void *) line->last_authenticated_user_password);
        line->last_authenticated_user_password = NULL;
    }
    if (password != NULL)
    {
        line->last_authenticated_user_password = stringDuplicate(password);
    }
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
        LOGF("Line: attempted to copy users into a line that already has user markers");
        terminateProgram(1);
        return;
    }

    if (src->user_count == 0)
    {
        return;
    }

    memoryCopy(dest->user_handles, src->user_handles, sizeof(src->user_handles));
    dest->user_count = src->user_count;

    // Carry the raw credentials onto the companion line as owned duplicates.
    if (src->last_authenticated_user_username != NULL)
    {
        dest->last_authenticated_user_username = stringDuplicate(src->last_authenticated_user_username);
    }
    if (src->last_authenticated_user_password != NULL)
    {
        dest->last_authenticated_user_password = stringDuplicate(src->last_authenticated_user_password);
    }
}

const user_handle_t *lineGetCurrentUser(const line_t *const line)
{
    assert(line != NULL);

    if (line->user_count == 0)
    {
        return NULL;
    }

    return &line->user_handles[line->user_count - 1];
}

typedef union line_task_callback_u {
    LineTaskFnNoBuf   no_buf;
    LineTaskFnWithBuf with_buf;
} line_task_callback_t;

typedef struct line_task_msg_s
{
    line_task_callback_t callback;
    tunnel_t            *tunnel;
    line_t              *line;
    sbuf_t              *buf;
} line_task_msg_t;

static_assert(sizeof(line_task_msg_t) == sizeof(worker_msg_t), "line_task_msg_t size should match worker_msg_t size");

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
        terminateProgram(1);
    }
}

static line_task_msg_t *lineTaskMessageCreate(line_t *line, tunnel_t *t)
{
    line_task_msg_t *msg;

    masterpoolGetItems(GSTATE.masterpool_messages, (const void **) &(msg), 1, NULL);
    *msg = (line_task_msg_t) {.tunnel = t, .line = line, .buf = NULL};

    return msg;
}

static void lineTaskMessageRelease(line_task_msg_t *msg)
{
    masterpoolReuseItems(GSTATE.masterpool_messages, (void **) &msg, 1);
}

static void lineReleaseScheduledTaskBuffer(line_t *line, sbuf_t *buf)
{
    if (buf == NULL)
    {
        return;
    }

    if (getWID() == lineGetWID(line))
    {
        lineReuseBuffer(line, buf);
        return;
    }

    sbufDestroy(buf);
}

static void lineCleanupScheduledTaskNoBuf(void *arg1, void *arg2, void *arg3)
{
    discard arg2;
    discard arg3;

    line_task_msg_t *msg  = (line_task_msg_t *) arg1;
    line_t          *line = msg->line;

    lineUnlock(line);
    lineTaskMessageRelease(msg);
}

static void lineCleanupScheduledTaskWithBuf(void *arg1, void *arg2, void *arg3)
{
    discard arg2;
    discard arg3;

    line_task_msg_t *msg  = (line_task_msg_t *) arg1;
    line_t          *line = msg->line;

    lineReleaseScheduledTaskBuffer(line, msg->buf);

    lineUnlock(line);
    lineTaskMessageRelease(msg);
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

    lineUnlock(line);
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

    if (lineIsAlive(line))
    {
        task(t, line);
    }

    lineUnlock(line);
    lineTaskMessageRelease(msg);
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

    if (lineIsAlive(line))
    {
        task(t, line, buf);
    }
    else
    {
        lineReleaseScheduledTaskBuffer(line, buf);
    }

    lineUnlock(line);
    lineTaskMessageRelease(msg);
}

void lineScheduleTask(line_t *const line, LineTaskFnNoBuf task, tunnel_t *t)
{
    lineLock(line);

    line_task_msg_t *msg = lineTaskMessageCreate(line, t);
    msg->callback.no_buf = task;

    sendWorkerMessageForceQueueWithCleanup(lineGetWID(line),
                                           (WorkerMessageCallback) lineRunScheduledTaskNoBuf,
                                           lineCleanupScheduledTaskNoBuf,
                                           msg,
                                           NULL,
                                           NULL);
}

void lineScheduleTaskWithBuf(line_t *const line, LineTaskFnWithBuf task, tunnel_t *t, sbuf_t *buf)
{
    lineLock(line);

    line_task_msg_t *msg   = lineTaskMessageCreate(line, t);
    msg->callback.with_buf = task;
    msg->buf               = buf;

    sendWorkerMessageForceQueueWithCleanup(lineGetWID(line),
                                           (WorkerMessageCallback) lineRunScheduledTaskWithBuf,
                                           lineCleanupScheduledTaskWithBuf,
                                           msg,
                                           NULL,
                                           NULL);
}

void lineScheduleDelayedTask(line_t *const line, LineTaskFnNoBuf task, uint32_t delay_ms, tunnel_t *t)
{
    if (getWID() != lineGetWID(line))
    {
        LOGF("Attempted to schedule a delayed task on a line from a different worker thread");
        terminateProgram(1);
        return;
    }

    lineLock(line);

    line_task_msg_t *msg = lineTaskMessageCreate(line, t);
    msg->callback.no_buf = task;

    sendWorkerMessageTimedWithCleanup(lineGetWID(line),
                                      (WorkerMessageCallback) lineRunScheduledTaskNoBuf,
                                      lineCleanupScheduledTaskNoBuf,
                                      delay_ms,
                                      (void *) msg,
                                      NULL,
                                      NULL);
}

void lineScheduleDelayedTaskWithBuf(line_t *const line, LineTaskFnWithBuf task, uint32_t delay_ms, tunnel_t *t,
                                    sbuf_t *buf)
{
    if (getWID() != lineGetWID(line))
    {
        LOGF("Attempted to schedule a delayed task on a line from a different worker thread");
        terminateProgram(1);
        return;
    }

    lineLock(line);

    line_task_msg_t *msg   = lineTaskMessageCreate(line, t);
    msg->callback.with_buf = task;
    msg->buf               = buf;

    sendWorkerMessageTimedWithCleanup(lineGetWID(line),
                                      (WorkerMessageCallback) lineRunScheduledTaskWithBuf,
                                      lineCleanupScheduledTaskWithBuf,
                                      delay_ms,
                                      (void *) msg,
                                      NULL,
                                      NULL);
}

int lineResolveDomainServiceAsync(line_t *const line, const char *domain, const char *service, int socktype,
                                  LineDnsResolveFn cb, tunnel_t *t, void *userdata)
{
    if (line == NULL || domain == NULL || domain[0] == '\0' || cb == NULL)
    {
        return ARES_EFORMERR;
    }

    lineLock(line);
    assert(lineGetWID(line) == getWID());

    line_dns_resolve_msg_t *msg = memoryAllocate(sizeof(*msg));
    if (msg == NULL)
    {
        lineUnlock(line);
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
        lineUnlock(line);
        lineDnsResolveMsgDestroy(msg);
        return rc;
    }

    return ARES_SUCCESS;
}

int lineResolveDomainAsync(line_t *const line, const char *domain, LineDnsResolveFn cb, tunnel_t *t, void *userdata)
{
    return lineResolveDomainServiceAsync(line, domain, NULL, 0, cb, t, userdata);
}
