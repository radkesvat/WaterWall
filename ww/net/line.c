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
    if (getWID() != lineGetWID(line))
    {
        LOGF("Attempted to schedule a task on a line from a different worker thread");
        terminateProgram(1);
        return;
    }

    lineLock(line);

    line_task_msg_no_buf_t *msg;

    masterpoolGetItems(GSTATE.masterpool_messages, (const void **) &(msg), 1, NULL);

    *msg = (line_task_msg_no_buf_t) {.callback = task, .arg1 = (void *) t, .arg2 = (void *) line, .arg3 = NULL};

    sendWorkerMessageForceQueue(lineGetWID(line), (WorkerMessageCallback) lineRunScheduledtaskNoBuf, line, (void *) msg,
                                NULL);
}

void lineScheduleTaskWithBuf(line_t *const line, LineTaskFnWithBuf task, tunnel_t *t, sbuf_t *buf)
{
    if (getWID() != lineGetWID(line))
    {
        LOGF("Attempted to schedule a task on a line from a different worker thread");
        terminateProgram(1);
        return;
    }

    lineLock(line);

    line_task_msg_with_buf_t *msg;

    masterpoolGetItems(GSTATE.masterpool_messages, (const void **) &(msg), 1, NULL);

    *msg = (line_task_msg_with_buf_t) {.callback = task, .arg1 = (void *) t, .arg2 = (void *) line, .arg3 = (void *) buf};

    sendWorkerMessageForceQueue(lineGetWID(line), (WorkerMessageCallback) lineRunScheduledtaskWithBuf, line,
                                (void *) msg, NULL);
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

    sendWorkerMessageTimed(lineGetWID(line), (WorkerMessageCallback) lineRunScheduledtaskNoBuf, delay_ms, line,(void *) msg,
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

    line_task_msg_with_buf_t *msg;

    masterpoolGetItems(GSTATE.masterpool_messages, (const void **) &(msg), 1, NULL);

    *msg = (line_task_msg_with_buf_t) {.callback = task, .arg1 = (void *) t, .arg2 = (void *) line, .arg3 = (void *) buf};

    sendWorkerMessageTimed(lineGetWID(line), (WorkerMessageCallback) lineRunScheduledtaskWithBuf, delay_ms, line,
                           (void *) msg, NULL);
}
