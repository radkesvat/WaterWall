#include "line.h"

/*
 * Implements worker-thread task scheduling helpers for line-bound callbacks.
 */

#include "loggers/internal_logger.h"

typedef struct line_task_msg_no_buf_s
{
    LineTaskFnNoBuf callback;
    void           *arg1;
    void           *arg2;
    void           *arg3;
} line_task_msg_no_buf_t;

static_assert(sizeof(line_task_msg_no_buf_t) == sizeof(worker_msg_t),
              "line_task_msg_no_buf_t size should match worker_msg_t size");

typedef struct line_task_msg_with_buf_s
{
    LineTaskFnWithBuf callback;
    void             *arg1;
    void             *arg2;
    void             *arg3; // this will be sbuf_t* if not NULL
} line_task_msg_with_buf_t;

static_assert(sizeof(line_task_msg_with_buf_t) == sizeof(worker_msg_t),
              "line_task_msg_with_buf_t size should match worker_msg_t size");

typedef struct line_dns_resolve_msg_s
{
    LineDnsResolveFn callback;
    tunnel_t        *tunnel;
    line_t          *line;
    void            *userdata;
} line_dns_resolve_msg_t;

static void lineScheduledWorkerMessageReceived(wevent_t *ev)
{
    worker_msg_t *msg = weventGetUserdata(ev);
    wid_t         wid = (wid_t) wloopGetWid(weventGetLoop(ev));

    msg->callback(getWorker(wid), msg->arg1, msg->arg2, msg->arg3);
    masterpoolReuseItems(GSTATE.masterpool_messages, (void **) &msg, 1, NULL);
}

static bool linePostScheduledTask(wid_t target_wid, WorkerMessageCallback callback, line_t *line, void *task_msg)
{
    worker_msg_t *queue_msg;
    masterpoolGetItems(GSTATE.masterpool_messages, (const void **) &(queue_msg), 1, NULL);
    *queue_msg = (worker_msg_t) {.callback = callback, .arg1 = line, .arg2 = task_msg, .arg3 = NULL};

    wevent_t ev;
    memorySet(&ev, 0, sizeof(ev));
    ev.loop = getWorkerLoop(target_wid);
    ev.cb   = lineScheduledWorkerMessageReceived;
    weventSetUserData(&ev, queue_msg);

    if (UNLIKELY(false == wloopPostEvent(getWorkerLoop(target_wid), &ev)))
    {
        lineUnlock(line);
        masterpoolReuseItems(GSTATE.masterpool_messages, (void **) &task_msg, 1, NULL);
        masterpoolReuseItems(GSTATE.masterpool_messages, (void **) &queue_msg, 1, NULL);
        return false;
    }

    return true;
}

static void lineDnsResolveMsgDestroy(line_dns_resolve_msg_t *msg)
{
    if (msg == NULL)
    {
        return;
    }

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
 * @param worker Worker context (unused).
 * @param arg1 Line pointer.
 * @param arg2 Packed task message.
 * @param arg3 Unused.
 */
static void lineRunScheduledtaskNoBuf(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard                 worker;
    discard                 arg3;
    line_t                 *line = (line_t *) arg1;
    line_task_msg_no_buf_t *msg  = (line_task_msg_no_buf_t *) arg2;
    LineTaskFnNoBuf         task = msg->callback;

    if (lineIsAlive(line))
    {
        task(msg->arg1, msg->arg2);
    }

    lineUnlock(line);

    masterpoolReuseItems(GSTATE.masterpool_messages, (void **) &msg, 1, NULL);
}

/**
 * @brief Execute a scheduled buffered line task on the worker thread.
 *
 * @param worker Worker context (unused).
 * @param arg1 Line pointer.
 * @param arg2 Packed task message.
 * @param arg3 Unused.
 */
static void lineRunScheduledtaskWithBuf(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard                   worker;
    discard                   arg3;
    line_t                   *line = (line_t *) arg1;
    line_task_msg_with_buf_t *msg  = (line_task_msg_with_buf_t *) arg2;
    LineTaskFnWithBuf         task = msg->callback;

    if (lineIsAlive(line))
    {
        task(msg->arg1, msg->arg2, msg->arg3);
    }
    else
    {
        if (msg->arg3 != NULL)
        {
            sbuf_t *buf = (sbuf_t *) msg->arg3;
            lineReuseBuffer(line, buf);
        }
    }
    lineUnlock(line);

    masterpoolReuseItems(GSTATE.masterpool_messages, (void **) &msg, 1, NULL);
}

void lineScheduleTask(line_t *const line, LineTaskFnNoBuf task, tunnel_t *t)
{
    lineLock(line);

    line_task_msg_no_buf_t *msg;

    masterpoolGetItems(GSTATE.masterpool_messages, (const void **) &(msg), 1, NULL);

    *msg = (line_task_msg_no_buf_t) {.callback = task, .arg1 = (void *) t, .arg2 = (void *) line, .arg3 = NULL};
    discard linePostScheduledTask(lineGetWID(line), (WorkerMessageCallback) lineRunScheduledtaskNoBuf, line, msg);
}

void lineScheduleTaskWithBuf(line_t *const line, LineTaskFnWithBuf task, tunnel_t *t, sbuf_t *buf)
{
    lineLock(line);

    line_task_msg_with_buf_t *msg;

    masterpoolGetItems(GSTATE.masterpool_messages, (const void **) &(msg), 1, NULL);

    *msg =
        (line_task_msg_with_buf_t) {.callback = task, .arg1 = (void *) t, .arg2 = (void *) line, .arg3 = (void *) buf};
    discard linePostScheduledTask(lineGetWID(line), (WorkerMessageCallback) lineRunScheduledtaskWithBuf, line, msg);
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

    line_task_msg_no_buf_t *msg;

    masterpoolGetItems(GSTATE.masterpool_messages, (const void **) &(msg), 1, NULL);

    *msg = (line_task_msg_no_buf_t) {.callback = task, .arg1 = (void *) t, .arg2 = (void *) line, .arg3 = NULL};

    sendWorkerMessageTimed(
        lineGetWID(line), (WorkerMessageCallback) lineRunScheduledtaskNoBuf, delay_ms, line, (void *) msg, NULL);
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

    line_task_msg_with_buf_t *msg;

    masterpoolGetItems(GSTATE.masterpool_messages, (const void **) &(msg), 1, NULL);

    *msg =
        (line_task_msg_with_buf_t) {.callback = task, .arg1 = (void *) t, .arg2 = (void *) line, .arg3 = (void *) buf};

    sendWorkerMessageTimed(
        lineGetWID(line), (WorkerMessageCallback) lineRunScheduledtaskWithBuf, delay_ms, line, (void *) msg, NULL);
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

    int rc =
        workerResolveDomainServiceAsync(lineGetWID(line), domain, service, socktype, lineDnsResolveResult, msg);
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
