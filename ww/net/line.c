#include "line.h"

/*
 * Implements worker-thread task scheduling helpers for line-bound callbacks.
 */

#include "loggers/internal_logger.h"

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
    terminateProgram(1);
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
        terminateProgram(1);
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
