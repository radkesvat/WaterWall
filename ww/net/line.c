#include "line.h"

/*
 * Implements worker-thread task scheduling helpers for line-bound callbacks.
 */

#include "loggers/internal_logger.h"

enum
{
    kLineUserIdentifierInitialCap = 64
};

typedef struct line_user_identifier_key_s
{
    uint8_t sha256[SHA256_DIGEST_SIZE];
} line_user_identifier_key_t;

static uint64_t lineUserIdentifierKeyHash(const line_user_identifier_key_t *key)
{
    return calcHashBytes(key->sha256, SHA256_DIGEST_SIZE);
}

static bool lineUserIdentifierKeyEq(const line_user_identifier_key_t *a, const line_user_identifier_key_t *b)
{
    return memoryCompare(a->sha256, b->sha256, SHA256_DIGEST_SIZE) == 0;
}

#define i_type line_user_identifier_map_t      // NOLINT
#define i_key  line_user_identifier_key_t      // NOLINT
#define i_val  uint64_t                        // NOLINT
#define i_hash lineUserIdentifierKeyHash       // NOLINT
#define i_eq   lineUserIdentifierKeyEq         // NOLINT
#include "stc/hmap.h"
#undef i_eq
#undef i_hash
#undef i_val
#undef i_key
#undef i_type

struct line_user_identifier_registry_s
{
    wmutex_t                   mutex;
    line_user_identifier_map_t map;
};

static line_user_identifier_key_t lineUserIdentifierKeyFromHandle(const user_handle_t *user_handle)
{
    line_user_identifier_key_t key = {0};

    memoryCopy(key.sha256, user_handle->sha256, SHA256_DIGEST_SIZE);
    return key;
}

line_user_identifier_registry_t *lineUserIdentifierRegistryCreate(void)
{
    line_user_identifier_registry_t *registry = memoryAllocate(sizeof(*registry));
    if (UNLIKELY(registry == NULL))
    {
        LOGF("Line: failed to allocate user identifier registry");
        terminateProgram(1);
        return NULL;
    }

    memoryZero(registry, sizeof(*registry));
    mutexInit(&registry->mutex);
    registry->map = line_user_identifier_map_t_with_capacity(kLineUserIdentifierInitialCap);

    return registry;
}

void lineUserIdentifierRegistryDestroy(line_user_identifier_registry_t *registry)
{
    if (registry == NULL)
    {
        return;
    }

    line_user_identifier_map_t_drop(&registry->map);
    mutexDestroy(&registry->mutex);
    memoryFree(registry);
}

static uint64_t lineGetUserIdentifierForHandle(const user_handle_t *user_handle)
{
    if (! userHandleIsValid(user_handle))
    {
        return 0;
    }

    line_user_identifier_registry_t *registry = GSTATE.line_user_identifier_registry;
    if (UNLIKELY(registry == NULL))
    {
        LOGF("Line: user identifier registry is not initialized");
        terminateProgram(1);
        return 0;
    }

    line_user_identifier_key_t key = lineUserIdentifierKeyFromHandle(user_handle);

    mutexLock(&registry->mutex);

    line_user_identifier_map_t_iter it = line_user_identifier_map_t_find(&registry->map, key);
    if (it.ref != line_user_identifier_map_t_end(&registry->map).ref)
    {
        uint64_t id = it.ref->second;
        mutexUnlock(&registry->mutex);
        return id;
    }

    uint64_t id = (uint64_t) atomicAddExplicit(&GSTATE.next_user_identifier, 1, memory_order_relaxed);
    if (UNLIKELY(id == 0 || id == UINT64_MAX))
    {
        mutexUnlock(&registry->mutex);
        LOGF("Line: user identifier counter overflow");
        terminateProgram(1);
        return 0;
    }

    line_user_identifier_map_t_result result = line_user_identifier_map_t_insert(&registry->map, key, id);
    if (UNLIKELY(! result.inserted))
    {
        mutexUnlock(&registry->mutex);
        LOGF("Line: failed to register user identifier");
        terminateProgram(1);
        return 0;
    }

    mutexUnlock(&registry->mutex);
    return id;
}

void lineAuthenticate(line_t *const line, const user_handle_t *user_handle)
{
    // basic overflow protection
    assert(line->auth_cur < (((0x1ULL << ((sizeof(line->auth_cur) * 8ULL) - 1ULL)) - 1ULL) |
                             (0xFULL << ((sizeof(line->auth_cur) * 8ULL) - 4ULL))));

    uint64_t user_identifier = lineGetUserIdentifierForHandle(user_handle);
    if (user_identifier != 0)
    {
        line->last_user_identifier = user_identifier;
    }

    line->auth_cur += 1;
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
