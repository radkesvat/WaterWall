#include "worker_messages.h"

#include "global_state.h"
#include "wmutex.h"

typedef struct timed_worker_msg_s
{
    worker_msg_t                 base;
    uint64_t                     deadline_us;
    WorkerMessageCleanupCallback cleanup;
    wtimer_t                    *timer;
} timed_worker_msg_t;

#define i_type worker_msg_deque_t
#define i_key  timed_worker_msg_t *
#include "stc/deque.h"

struct worker_message_queue_s
{
    worker_msg_deque_t queued;
    worker_msg_deque_t timed;
    wmutex_t           mutex;
    bool               wakeup_pending;
};

static void workerMessageReceived(wevent_t *ev);

static master_pool_item_t *allocWorkerMessage(void *userdata)
{
    discard userdata;
    return memoryAllocate(sizeof(timed_worker_msg_t));
}

static void destroyWorkerMessage(master_pool_item_t *item)
{
    memoryFree(item);
}

static timed_worker_msg_t *getWorkerMessage(WorkerMessageCallback cb, WorkerMessageCleanupCallback cleanup, void *arg1,
                                            void *arg2, void *arg3)
{
    timed_worker_msg_t *msg;
    masterpoolGetItems(GSTATE.masterpool_messages, (const void **) &(msg), 1, NULL);
    *msg = (timed_worker_msg_t) {
        .base    = {.callback = cb, .arg1 = arg1, .arg2 = arg2, .arg3 = arg3},
        .cleanup = cleanup,
    };
    return msg;
}

static void runWorkerMessageCleanup(timed_worker_msg_t *msg)
{
    if (msg != NULL && msg->cleanup != NULL)
    {
        WorkerMessageCleanupCallback cleanup = msg->cleanup;
        msg->cleanup                         = NULL;
        cleanup(msg->base.arg1, msg->base.arg2, msg->base.arg3);
    }
}

static void reuseWorkerMessage(timed_worker_msg_t *msg)
{
    if (msg != NULL)
    {
        msg->cleanup = NULL;
        masterpoolReuseItems(GSTATE.masterpool_messages, (void **) &msg, 1);
    }
}

static void cleanupWorkerMessage(timed_worker_msg_t *msg)
{
    runWorkerMessageCleanup(msg);
    reuseWorkerMessage(msg);
}

static void cleanupQueuedTimedWorkerMessage(void *arg1, void *arg2, void *arg3)
{
    discard arg1;
    discard arg3;

    timed_worker_msg_t *timed_msg = (timed_worker_msg_t *) arg2;

    runWorkerMessageCleanup(timed_msg);
    reuseWorkerMessage(timed_msg);
}

static bool workerTimedMessageRemoveLocked(worker_message_queue_t *queue, timed_worker_msg_t *msg)
{
    for (worker_msg_deque_t_iter it = worker_msg_deque_t_begin(&(queue->timed)); it.ref != NULL;
         worker_msg_deque_t_next(&it))
    {
        if (*it.ref == msg)
        {
            worker_msg_deque_t_erase_at(&(queue->timed), it);
            return true;
        }
    }

    return false;
}

static bool workerMessagePostWakeup(worker_t *worker)
{
    wevent_t ev;
    memoryZero(&ev, sizeof(ev));
    ev.loop = worker->loop;
    ev.cb   = workerMessageReceived;
    return wloopPostEvent(worker->loop, &ev);
}

static void workerMessageDrainQueue(worker_t *worker)
{
    worker_message_queue_t *queue = worker->message_queue;
    assert(queue != NULL);

    for (;;)
    {
        mutexLock(&(queue->mutex));
        if (worker_msg_deque_t_is_empty(&(queue->queued)))
        {
            queue->wakeup_pending = false;
            mutexUnlock(&(queue->mutex));
            return;
        }

        timed_worker_msg_t *msg = worker_msg_deque_t_pull_front(&(queue->queued));
        mutexUnlock(&(queue->mutex));

        msg->base.callback(worker, msg->base.arg1, msg->base.arg2, msg->base.arg3);
        msg->cleanup = NULL;
        reuseWorkerMessage(msg);

        if (UNLIKELY(worker->message_queue != queue))
        {
            return;
        }
    }
}

static void workerMessageReceived(wevent_t *ev)
{
    wid_t wid = (wid_t) (wloopGetWid(weventGetLoop(ev)));
    workerMessageDrainQueue(getWorker(wid));
}

void workerMessagesInstallMasterPoolCallbacks(master_pool_t *pool)
{
    masterpoolInstallCallBacks(pool, allocWorkerMessage, destroyWorkerMessage);
}

void workerMessagesInit(worker_t *worker)
{
    assert(worker != NULL);
    worker_message_queue_t *queue = memoryAllocate(sizeof(*queue));
    *queue                        = (worker_message_queue_t) {
        .queued = worker_msg_deque_t_with_capacity(32),
        .timed  = worker_msg_deque_t_with_capacity(32),
    };
    mutexInit(&(queue->mutex));
    worker->message_queue = queue;
}

void workerMessagesCleanupPending(worker_t *worker)
{
    assert(worker != NULL);

    worker_message_queue_t *queue = worker->message_queue;
    if (queue == NULL)
    {
        return;
    }

    mutexLock(&(queue->mutex));

    while (! worker_msg_deque_t_is_empty(&(queue->queued)))
    {
        timed_worker_msg_t *msg = worker_msg_deque_t_pull_front(&(queue->queued));
        mutexUnlock(&(queue->mutex));
        cleanupWorkerMessage(msg);
        mutexLock(&(queue->mutex));
    }
    queue->wakeup_pending = false;

    while (! worker_msg_deque_t_is_empty(&(queue->timed)))
    {
        timed_worker_msg_t *msg   = worker_msg_deque_t_pull_front(&(queue->timed));
        wtimer_t           *timer = msg->timer;
        msg->timer                = NULL;
        mutexUnlock(&(queue->mutex));

        if (timer != NULL)
        {
            weventSetUserData(timer, NULL);
            wtimerDelete(timer);
        }
        cleanupWorkerMessage(msg);

        mutexLock(&(queue->mutex));
    }

    mutexUnlock(&(queue->mutex));
}

void workerMessagesDestroy(worker_t *worker)
{
    assert(worker != NULL);

    worker_message_queue_t *queue = worker->message_queue;
    if (queue == NULL)
    {
        return;
    }

    workerMessagesCleanupPending(worker);
    worker->message_queue = NULL;

    worker_msg_deque_t_drop(&(queue->queued));
    worker_msg_deque_t_drop(&(queue->timed));
    mutexDestroy(&(queue->mutex));
    memoryFree(queue);
}

void sendWorkerMessage(wid_t wid, WorkerMessageCallback cb, void *arg1, void *arg2, void *arg3)
{
    sendWorkerMessageWithCleanup(wid, cb, NULL, arg1, arg2, arg3);
}

void sendWorkerMessageWithCleanup(wid_t wid, WorkerMessageCallback cb, WorkerMessageCleanupCallback cleanup, void *arg1,
                                  void *arg2, void *arg3)
{

    if (getWID() == wid)
    {
        cb(getWorker(wid), arg1, arg2, arg3);
        return;
    }

    assert(wid < getWorkersCount());
    discard sendWorkerMessageForceQueueWithCleanup(wid, cb, cleanup, arg1, arg2, arg3);
}

void sendWorkerMessageForceQueue(wid_t wid, WorkerMessageCallback cb, void *arg1, void *arg2, void *arg3)
{
    discard sendWorkerMessageForceQueueWithCleanup(wid, cb, NULL, arg1, arg2, arg3);
}

bool sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback cb, WorkerMessageCleanupCallback cleanup,
                                            void *arg1, void *arg2, void *arg3)
{
    assert(wid < getWorkersCount());

    if (UNLIKELY(isApplicationTerminating()))
    {
        if (cleanup != NULL)
        {
            cleanup(arg1, arg2, arg3);
        }
        return false;
    }

    worker_t               *worker = getWorker(wid);
    worker_message_queue_t *queue  = worker->message_queue;
    assert(worker->loop != NULL);
    assert(queue != NULL);

    timed_worker_msg_t *msg = getWorkerMessage(cb, cleanup, arg1, arg2, arg3);

    mutexLock(&(queue->mutex));
    assert(worker->message_queue == queue);
    assert(worker->loop != NULL);
    if (UNLIKELY(isApplicationTerminating()))
    {
        mutexUnlock(&(queue->mutex));
        cleanupWorkerMessage(msg);
        return false;
    }

    if (UNLIKELY(worker_msg_deque_t_push_back(&(queue->queued), msg) == NULL))
    {
        mutexUnlock(&(queue->mutex));
        cleanupWorkerMessage(msg);
        return false;
    }

    if (queue->wakeup_pending)
    {
        mutexUnlock(&(queue->mutex));
        return true;
    }

    queue->wakeup_pending = true;
    if (LIKELY(workerMessagePostWakeup(worker)))
    {
        mutexUnlock(&(queue->mutex));
        return true;
    }

    queue->wakeup_pending          = false;
    timed_worker_msg_t *queued_msg = worker_msg_deque_t_pull_back(&(queue->queued));
    assert(queued_msg == msg);
    discard queued_msg;
    mutexUnlock(&(queue->mutex));

    cleanupWorkerMessage(msg);
    return false;
}

static void runTimedTask(wtimer_t *timer)
{
    timed_worker_msg_t *timed_msg = weventGetUserdata(timer);
    if (timed_msg == NULL)
    {
        wtimerDelete(timer);
        return;
    }

    wloop_t       *loop   = weventGetLoop(timer);
    const uint64_t now_us = wloopNowUS(loop);

    if (now_us < timed_msg->deadline_us)
    {
        const uint64_t remaining_us = timed_msg->deadline_us - now_us;
        uint32_t       remaining_ms = (remaining_us > ((uint64_t) UINT32_MAX * 1000ULL))
                                          ? UINT32_MAX
                                          : (uint32_t) ((remaining_us + 999ULL) / 1000ULL);

        if (remaining_ms == 0)
        {
            remaining_ms = 1;
        }

        // Some timeout buckets are rounded early, so do not release delayed work before its true deadline.
        wtimerReset(timer, remaining_ms);
        return;
    }

    worker_t               *worker = getWorker(getWID());
    worker_message_queue_t *queue  = worker->message_queue;
    assert(queue != NULL);
    mutexLock(&(queue->mutex));
    bool removed = workerTimedMessageRemoveLocked(queue, timed_msg);
    assert(removed);
    discard removed;
    timed_msg->timer = NULL;
    mutexUnlock(&(queue->mutex));

    WorkerMessageCallback cb = timed_msg->base.callback;
    cb(worker, timed_msg->base.arg1, timed_msg->base.arg2, timed_msg->base.arg3);

    timed_msg->cleanup = NULL;
    reuseWorkerMessage(timed_msg);
    weventSetUserData(timer, NULL);
    wtimerDelete(timer);
}

static void setupTimedTask(worker_t *worker, void *arg1, void *arg2, void *arg3)
{

    uint32_t            delay_ms  = (uint32_t) (uintptr_t) arg1;
    timed_worker_msg_t *timed_msg = (timed_worker_msg_t *) arg2;
    discard             arg3;

    assert(worker->loop != NULL);
    assert(worker->message_queue != NULL);
    if (UNLIKELY(isApplicationTerminating()))
    {
        cleanupWorkerMessage(timed_msg);
        return;
    }

    wtimer_t *k_timer = wtimerAdd(worker->loop, runTimedTask, delay_ms, 1);
    if (UNLIKELY(k_timer == NULL))
    {
        // fallback to immediate execution if timer creation fails
        WorkerMessageCallback cb = timed_msg->base.callback;
        cb(worker, timed_msg->base.arg1, timed_msg->base.arg2, timed_msg->base.arg3);
        timed_msg->cleanup = NULL;
        reuseWorkerMessage(timed_msg);
        return;
    }

    timed_msg->deadline_us = wloopNowUS(worker->loop) + ((uint64_t) delay_ms * 1000ULL);
    timed_msg->timer       = k_timer;
    weventSetUserData(k_timer, timed_msg);

    worker_message_queue_t *queue = worker->message_queue;
    mutexLock(&(queue->mutex));
    assert(worker->message_queue == queue);
    if (UNLIKELY(isApplicationTerminating()))
    {
        mutexUnlock(&(queue->mutex));
        weventSetUserData(k_timer, NULL);
        wtimerDelete(k_timer);
        cleanupWorkerMessage(timed_msg);
        return;
    }
    if (UNLIKELY(worker_msg_deque_t_push_back(&(queue->timed), timed_msg) == NULL))
    {
        mutexUnlock(&(queue->mutex));
        weventSetUserData(k_timer, NULL);
        wtimerDelete(k_timer);
        cleanupWorkerMessage(timed_msg);
        return;
    }
    mutexUnlock(&(queue->mutex));
}

void sendWorkerMessageTimed(wid_t wid, WorkerMessageCallback cb, uint32_t delay_ms, void *arg1, void *arg2, void *arg3)
{
    sendWorkerMessageTimedWithCleanup(wid, cb, NULL, delay_ms, arg1, arg2, arg3);
}

void sendWorkerMessageTimedWithCleanup(wid_t wid, WorkerMessageCallback cb, WorkerMessageCleanupCallback cleanup,
                                       uint32_t delay_ms, void *arg1, void *arg2, void *arg3)
{

    assert(wid < getWorkersCount());

    // delay=0 means "run on next event-loop iteration", not immediate inline execution
    if (delay_ms == 0)
    {
        discard sendWorkerMessageForceQueueWithCleanup(wid, cb, cleanup, arg1, arg2, arg3);
        return;
    }

    uintptr_t delay_ms_uiptr = (uintptr_t) delay_ms;

    if (UNLIKELY(isApplicationTerminating()))
    {
        if (cleanup != NULL)
        {
            cleanup(arg1, arg2, arg3);
        }
        return;
    }

    worker_t *worker = getWorker(wid);
    assert(worker->loop != NULL);
    assert(worker->message_queue != NULL);

    timed_worker_msg_t *msg = getWorkerMessage(cb, cleanup, arg1, arg2, arg3);

    if (getWID() == wid)
    {
        setupTimedTask(worker, (void *) delay_ms_uiptr, msg, NULL);
        return;
    }

    // Queue setupTimedTask manually so both wrapper and payload are reclaimed on post failure.
    if (UNLIKELY(false == sendWorkerMessageForceQueueWithCleanup(wid,
                                                                 (WorkerMessageCallback) setupTimedTask,
                                                                 cleanupQueuedTimedWorkerMessage,
                                                                 (void *) delay_ms_uiptr,
                                                                 msg,
                                                                 NULL)))
    {
        return;
    }
}
