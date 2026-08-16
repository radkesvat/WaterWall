#include "worker_messages.h"
#include "wloop_internal.h"

#include "global_state.h"
#include "wmutex.h"

#include "loggers/internal_logger.h"

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
    /* Lock order: worker_t::control_mutex, then this mutex. */
    wmutex_t mutex;
    bool     wakeup_pending;
};

static void workerMessageReceived(wevent_t *ev);

#ifdef WW_WORKER_MESSAGE_TEST_SEAM
static worker_message_init_test_failure_e    g_worker_message_init_failure;
static worker_message_enqueue_test_failure_e g_worker_message_enqueue_failure;

void workerMessagesInitTestSetFailure(worker_message_init_test_failure_e failure)
{
    g_worker_message_init_failure = failure;
}

void workerMessagesEnqueueTestSetFailure(worker_message_enqueue_test_failure_e failure)
{
    g_worker_message_enqueue_failure = failure;
}

static bool workerMessagesInitTestRefuse(worker_message_init_test_failure_e failure)
{
    if (g_worker_message_init_failure != failure)
    {
        return false;
    }
    g_worker_message_init_failure = kWorkerMessageInitFailNone;
    return true;
}

static bool workerMessagesEnqueueTestRefuse(worker_message_enqueue_test_failure_e failure)
{
    if (g_worker_message_enqueue_failure != failure)
    {
        return false;
    }
    g_worker_message_enqueue_failure = kWorkerMessageEnqueueFailNone;
    return true;
}
#else
static bool workerMessagesInitTestRefuse(int failure)
{
    discard failure;
    return false;
}

static bool workerMessagesEnqueueTestRefuse(int failure)
{
    discard failure;
    return false;
}
#endif

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
    masterpoolGetItems(GSTATE.masterpool_messages, (void **) &(msg), 1, NULL);
    *msg = (timed_worker_msg_t) {
        .base    = {.callback = cb, .arg1 = arg1, .arg2 = arg2, .arg3 = arg3},
        .cleanup = cleanup,
    };
    return msg;
}

static void runWorkerMessageCleanup(timed_worker_msg_t *msg, worker_message_cancel_reason_e reason)
{
    if (msg != NULL && msg->cleanup != NULL)
    {
        WorkerMessageCleanupCallback cleanup = msg->cleanup;
        msg->cleanup                         = NULL;
        cleanup(msg->base.arg1, msg->base.arg2, msg->base.arg3, reason);
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

static void cleanupWorkerMessage(timed_worker_msg_t *msg, worker_message_cancel_reason_e reason)
{
    runWorkerMessageCleanup(msg, reason);
    reuseWorkerMessage(msg);
}

static void cleanupQueuedTimedWorkerMessage(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard arg1;
    discard arg3;

    timed_worker_msg_t *timed_msg = (timed_worker_msg_t *) arg2;

    runWorkerMessageCleanup(timed_msg, reason);
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
    // Queued callbacks are written assuming they run on their target worker.
    assert(currentThreadIsEventWorkerWID(worker->wid));

    worker_message_queue_t *queue = worker->message_queue;
    assert(queue != NULL);

    for (;;)
    {
        mutexLock(&(queue->mutex));
        if (worker_msg_deque_t_is_empty(&(queue->queued)) || ! wloopNormalDispatchAllowed(worker->loop))
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

void workerMessagesCloseAdmissionLocked(worker_t *worker)
{
    assert(worker != NULL);
    atomicStoreExplicit(&worker->message_admission_open, false, memory_order_relaxed);
}

void workerMessagesCloseAdmission(worker_t *worker)
{
    if (worker == NULL)
    {
        return;
    }

    mutexLock(&worker->control_mutex);
    workerMessagesCloseAdmissionLocked(worker);
    mutexUnlock(&worker->control_mutex);
}

static void workerMessageReceived(wevent_t *ev)
{
    // The wakeup event was posted to exactly one worker loop, so the loop that
    // is dispatching it is the authoritative owner; never re-read TLS here.
    wid_t wid = (wid_t) (wloopGetWid(weventGetLoop(ev)));
    assert(currentThreadIsEventWorkerWID(wid));
    workerMessageDrainQueue(getWorker(wid));
}

/**
 * @brief Rejects a message aimed at a WID that can never drain a queue.
 *
 * Only ordinary event workers own a message queue and a loop to wake, so the
 * lwIP pseudo-worker, kInvalidWID, and out-of-range ids are refused here rather
 * than at an assertion inside getWorker(). Posting is fallible and reachable
 * from unregistered threads, so this runs the caller's cleanup exactly once and
 * reports failure instead of aborting.
 *
 * @return true when the message was rejected and its cleanup already ran.
 */
static bool workerMessageRejectUndeliverable(wid_t wid, WorkerMessageCleanupCallback cleanup, void *arg1, void *arg2,
                                             void *arg3)
{
    if (LIKELY(workerWIDIsEventWorker(wid)))
    {
        return false;
    }

    LOGE("worker message dropped: target WID %d is not an ordinary event worker (posted from worker %d, tid %llu)",
         workerWIDForLog(wid),
         workerWIDForLog(getWID()),
         (unsigned long long) getTID());

    if (cleanup != NULL)
    {
        cleanup(arg1, arg2, arg3, kWorkerMessageCancelTargetUnavailable);
    }
    return true;
}

void workerMessagesInstallMasterPoolCallbacks(master_pool_t *pool)
{
    masterpoolInstallCallBacks(pool, allocWorkerMessage, destroyWorkerMessage);
}

bool workerMessagesInit(worker_t *worker)
{
    assert(worker != NULL);
    assert(worker->message_queue == NULL);
    workerMessagesCloseAdmissionLocked(worker);

    if (workerMessagesInitTestRefuse(kWorkerMessageInitFailOuterAllocation))
    {
        return false;
    }
    worker_message_queue_t *queue = memoryAllocate(sizeof(*queue));
    if (UNLIKELY(queue == NULL))
    {
        return false;
    }
    *queue = (worker_message_queue_t) {
        .queued = worker_msg_deque_t_init(),
        .timed  = worker_msg_deque_t_init(),
    };

    const bool queued_ready = ! workerMessagesInitTestRefuse(kWorkerMessageInitFailQueuedReserve) &&
                              worker_msg_deque_t_reserve(&queue->queued, 32);
    const bool timed_ready = queued_ready && ! workerMessagesInitTestRefuse(kWorkerMessageInitFailTimedReserve) &&
                             worker_msg_deque_t_reserve(&queue->timed, 32);
    if (UNLIKELY(! timed_ready))
    {
        worker_msg_deque_t_drop(&queue->queued);
        worker_msg_deque_t_drop(&queue->timed);
        memoryFree(queue);
        return false;
    }

    if (UNLIKELY(! mutexTryInit(&queue->mutex)))
    {
        worker_msg_deque_t_drop(&queue->queued);
        worker_msg_deque_t_drop(&queue->timed);
        memoryFree(queue);
        return false;
    }
    worker->message_queue = queue;
    return true;
}

bool workerMessagesOpenAdmission(worker_t *worker)
{
    if (worker == NULL)
    {
        return false;
    }

    mutexLock(&worker->control_mutex);
    const bool ready = worker->has_event_loop && worker->loop != NULL && worker->message_queue != NULL &&
                       ! atomicLoadExplicit(&worker->resources_destroyed, memory_order_relaxed) &&
                       atomicLoadExplicit(&worker->lifecycle, memory_order_relaxed) ==
                           (w_atomic_int_value_t) kWorkerLifecycleInitialized &&
                       ! atomicLoadExplicit(&worker->message_admission_open, memory_order_relaxed);
    if (! ready)
    {
        mutexUnlock(&worker->control_mutex);
        return false;
    }
    atomicStoreExplicit(&worker->message_admission_open, true, memory_order_relaxed);
    mutexUnlock(&worker->control_mutex);
    return true;
}

void workerMessagesCloseAdmissionAndDetach(worker_t *worker, wloop_t **loop, worker_message_queue_t **queue)
{
    assert(worker != NULL);
    assert(loop != NULL);
    assert(queue != NULL);

    mutexLock(&worker->control_mutex);
    atomicStoreExplicit(&worker->message_admission_open, false, memory_order_relaxed);
    *loop                 = worker->loop;
    *queue                = worker->message_queue;
    worker->loop          = NULL;
    worker->message_queue = NULL;
    mutexUnlock(&worker->control_mutex);
}

void workerMessagesCleanupPendingDetached(worker_message_queue_t *queue, worker_message_cancel_reason_e reason)
{
    if (queue == NULL)
    {
        return;
    }

    mutexLock(&(queue->mutex));

    while (! worker_msg_deque_t_is_empty(&(queue->queued)))
    {
        timed_worker_msg_t *msg = worker_msg_deque_t_pull_front(&(queue->queued));
        mutexUnlock(&(queue->mutex));
        cleanupWorkerMessage(msg, reason);
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
        cleanupWorkerMessage(msg, reason);

        mutexLock(&(queue->mutex));
    }

    mutexUnlock(&(queue->mutex));
}

void workerMessagesCleanupPending(worker_t *worker)
{
    assert(worker != NULL);
    workerMessagesCleanupPendingDetached(worker->message_queue, kWorkerMessageCancelQuiesced);
}

void workerMessagesDestroyDetached(worker_message_queue_t *queue)
{
    if (queue == NULL)
    {
        return;
    }

    workerMessagesCleanupPendingDetached(queue, kWorkerMessageCancelTeardown);

    worker_msg_deque_t_drop(&(queue->queued));
    worker_msg_deque_t_drop(&(queue->timed));
    mutexDestroy(&(queue->mutex));
    memoryFree(queue);
}

void workerMessagesDestroy(worker_t *worker)
{
    assert(worker != NULL);

    wloop_t                *loop  = NULL;
    worker_message_queue_t *queue = NULL;
    workerMessagesCloseAdmissionAndDetach(worker, &loop, &queue);
    /* Test fixtures own and destroy their local loop separately. Production
     * teardown consumes both values through workerPerformTeardown(). */
    discard loop;
    workerMessagesDestroyDetached(queue);
}

void sendWorkerMessage(wid_t wid, WorkerMessageCallback cb, void *arg1, void *arg2, void *arg3)
{
    sendWorkerMessageWithCleanup(wid, cb, NULL, arg1, arg2, arg3);
}

void sendWorkerMessageWithCleanup(wid_t wid, WorkerMessageCallback cb, WorkerMessageCleanupCallback cleanup, void *arg1,
                                  void *arg2, void *arg3)
{
    if (UNLIKELY(workerMessageRejectUndeliverable(wid, cleanup, arg1, arg2, arg3)))
    {
        return;
    }

    worker_t *worker = getWorker(wid);
    if (currentThreadIsEventWorkerWID(wid) && wloopCurrentThreadInNormalCallback(worker->loop))
    {
        cb(worker, arg1, arg2, arg3);
        return;
    }

    const worker_message_submit_result_e result =
        sendWorkerMessageForceQueueWithCleanup(wid, cb, cleanup, arg1, arg2, arg3);
    discard result;
}

void sendWorkerMessageForceQueueBestEffort(wid_t wid, WorkerMessageCallback cb, void *arg1, void *arg2, void *arg3)
{
    const worker_message_submit_result_e result =
        sendWorkerMessageForceQueueWithCleanup(wid, cb, NULL, arg1, arg2, arg3);
    discard result;
}

void sendWorkerMessageForceQueueBestEffortWithCleanup(wid_t wid, WorkerMessageCallback cb,
                                                      WorkerMessageCleanupCallback cleanup, void *arg1, void *arg2,
                                                      void *arg3)
{
    const worker_message_submit_result_e result =
        sendWorkerMessageForceQueueWithCleanup(wid, cb, cleanup, arg1, arg2, arg3);
    discard result;
}

static worker_message_submit_result_e sendWorkerMessageForceQueueTransactional(wid_t wid, WorkerMessageCallback cb,
                                                                               WorkerMessageCleanupCallback cleanup,
                                                                               void *arg1, void *arg2, void *arg3,
                                                                               bool retain_on_refusal)
{
    WorkerMessageCleanupCallback refusal_cleanup = retain_on_refusal ? NULL : cleanup;

    if (UNLIKELY(workerMessageRejectUndeliverable(wid, refusal_cleanup, arg1, arg2, arg3)))
    {
        return retain_on_refusal ? kWorkerMessageSubmitRejectedCallerRetains : kWorkerMessageSubmitRejectedCleanupRan;
    }

    worker_t *worker = getWorker(wid);
    if (UNLIKELY(! atomicLoadExplicit(&worker->message_admission_open, memory_order_relaxed)))
    {
        if (refusal_cleanup != NULL)
        {
            refusal_cleanup(arg1, arg2, arg3, kWorkerMessageCancelAdmissionClosed);
        }
        return retain_on_refusal ? kWorkerMessageSubmitRejectedCallerRetains : kWorkerMessageSubmitRejectedCleanupRan;
    }

    timed_worker_msg_t *msg = getWorkerMessage(cb, cleanup, arg1, arg2, arg3);

#ifdef WW_WORKER_MESSAGE_TEST_SEAM
    workerMessageEnqueueTestSeam(worker, kWorkerMessageEnqueueBeforeLifetimeLock);
#endif

    /*
     * control_mutex protects the lifetime of both pointers through enqueue and
     * wakeup posting. Teardown detaches both under this same lock. The nested
     * order is always control_mutex then queue->mutex.
     */
    mutexLock(&(worker->control_mutex));
    worker_message_queue_t *queue = worker->message_queue;
    if (UNLIKELY(! atomicLoadExplicit(&worker->message_admission_open, memory_order_relaxed) || worker->loop == NULL ||
                 queue == NULL))
    {
        mutexUnlock(&(worker->control_mutex));
        if (retain_on_refusal)
        {
            reuseWorkerMessage(msg);
        }
        else
        {
            cleanupWorkerMessage(msg, kWorkerMessageCancelAdmissionClosed);
        }
        return retain_on_refusal ? kWorkerMessageSubmitRejectedCallerRetains : kWorkerMessageSubmitRejectedCleanupRan;
    }

#ifdef WW_WORKER_MESSAGE_TEST_SEAM
    workerMessageEnqueueTestSeam(worker, kWorkerMessageEnqueueBeforeQueueLock);
#endif

    mutexLock(&(queue->mutex));

    if (UNLIKELY(workerMessagesEnqueueTestRefuse(kWorkerMessageEnqueueFailDequeGrowth) ||
                 worker_msg_deque_t_push_back(&(queue->queued), msg) == NULL))
    {
        mutexUnlock(&(queue->mutex));
        mutexUnlock(&(worker->control_mutex));
        if (retain_on_refusal)
        {
            reuseWorkerMessage(msg);
        }
        else
        {
            cleanupWorkerMessage(msg, kWorkerMessageCancelEnqueueFailure);
        }
        return retain_on_refusal ? kWorkerMessageSubmitRejectedCallerRetains : kWorkerMessageSubmitRejectedCleanupRan;
    }

    if (queue->wakeup_pending)
    {
        mutexUnlock(&(queue->mutex));
        mutexUnlock(&(worker->control_mutex));
        return kWorkerMessageSubmitAccepted;
    }

    queue->wakeup_pending = true;
    if (LIKELY(! workerMessagesEnqueueTestRefuse(kWorkerMessageEnqueueFailWakeupPost) &&
               workerMessagePostWakeup(worker)))
    {
        mutexUnlock(&(queue->mutex));
        mutexUnlock(&(worker->control_mutex));
        return kWorkerMessageSubmitAccepted;
    }

    queue->wakeup_pending          = false;
    timed_worker_msg_t *queued_msg = worker_msg_deque_t_pull_back(&(queue->queued));
    assert(queued_msg == msg);
    discard queued_msg;
    mutexUnlock(&(queue->mutex));
    mutexUnlock(&(worker->control_mutex));

    if (retain_on_refusal)
    {
        reuseWorkerMessage(msg);
    }
    else
    {
        cleanupWorkerMessage(msg, kWorkerMessageCancelEnqueueFailure);
    }
    return retain_on_refusal ? kWorkerMessageSubmitRejectedCallerRetains : kWorkerMessageSubmitRejectedCleanupRan;
}

worker_message_submit_result_e sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback cb,
                                                                      WorkerMessageCleanupCallback cleanup, void *arg1,
                                                                      void *arg2, void *arg3)
{
    return sendWorkerMessageForceQueueTransactional(wid, cb, cleanup, arg1, arg2, arg3, false);
}

worker_message_submit_result_e sendWorkerMessageForceQueueRetainOnRefusal(wid_t wid, WorkerMessageCallback cb,
                                                                          WorkerMessageCleanupCallback cleanup,
                                                                          void *arg1, void *arg2, void *arg3)
{
    return sendWorkerMessageForceQueueTransactional(wid, cb, cleanup, arg1, arg2, arg3, true);
}

static void runTimedTask(wtimer_t *timer)
{
    timed_worker_msg_t *timed_msg = weventGetUserdata(timer);
    if (timed_msg == NULL)
    {
        wtimerDelete(timer);
        return;
    }

    wloop_t    *loop      = weventGetLoop(timer);
    const wid_t owner_wid = (wid_t) wloopGetWid(loop);
    assert(currentThreadIsEventWorkerWID(owner_wid));
#ifdef WW_WORKER_MESSAGE_TEST_SEAM
    workerMessageTimedRearmTestSeam(getWorker(owner_wid), &timed_msg->deadline_us);
#endif
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
        if (! wtimerReset(timer, remaining_ms))
        {
            worker_t               *worker = getWorker(owner_wid);
            worker_message_queue_t *queue  = worker->message_queue;
            assert(queue != NULL);
            mutexLock(&(queue->mutex));
            const bool removed = workerTimedMessageRemoveLocked(queue, timed_msg);
            assert(removed);
            discard removed;
            timed_msg->timer = NULL;
            mutexUnlock(&(queue->mutex));

            weventSetUserData(timer, NULL);
            cleanupWorkerMessage(timed_msg, kWorkerMessageCancelAdmissionClosed);
        }
        return;
    }

    // The timer was armed on exactly one worker loop, so that loop identifies
    // the owning worker; the current thread must be it.
    worker_t               *worker = getWorker(owner_wid);
    worker_message_queue_t *queue  = worker->message_queue;
    assert(queue != NULL);
    mutexLock(&(queue->mutex));
    bool removed = workerTimedMessageRemoveLocked(queue, timed_msg);
    assert(removed);
    discard removed;
    timed_msg->timer = NULL;
    mutexUnlock(&(queue->mutex));

    if (! wloopNormalDispatchAllowed(loop))
    {
        cleanupWorkerMessage(timed_msg, kWorkerMessageCancelQuiesced);
        weventSetUserData(timer, NULL);
        wtimerDelete(timer);
        return;
    }

    WorkerMessageCallback cb = timed_msg->base.callback;
    cb(worker, timed_msg->base.arg1, timed_msg->base.arg2, timed_msg->base.arg3);

    timed_msg->cleanup = NULL;
    reuseWorkerMessage(timed_msg);
    weventSetUserData(timer, NULL);
    wtimerDelete(timer);
}

static bool setupTimedTaskChecked(worker_t *worker, void *arg1, void *arg2, void *arg3, bool retain_on_refusal)
{

    uint32_t            delay_ms  = (uint32_t) (uintptr_t) arg1;
    timed_worker_msg_t *timed_msg = (timed_worker_msg_t *) arg2;
    discard             arg3;

    // Either called on the target worker or delivered as a worker message to
    // it; both mean the timer is armed on its own loop's thread.
    assert(currentThreadIsEventWorkerWID(worker->wid));

    mutexLock(&worker->control_mutex);
    worker_message_queue_t *queue = worker->message_queue;
    if (UNLIKELY(! atomicLoadExplicit(&worker->message_admission_open, memory_order_relaxed) || worker->loop == NULL ||
                 queue == NULL || ! wloopNormalDispatchAllowed(worker->loop)))
    {
        mutexUnlock(&worker->control_mutex);
        if (retain_on_refusal)
        {
            reuseWorkerMessage(timed_msg);
        }
        else
        {
            cleanupWorkerMessage(timed_msg, kWorkerMessageCancelAdmissionClosed);
        }
        return false;
    }

    wtimer_t *k_timer = wtimerAdd(worker->loop, runTimedTask, delay_ms, 1);
    if (UNLIKELY(k_timer == NULL))
    {
        /* A delayed callback may depend on a minimum delay and may schedule
         * itself again. Running it inline turns allocation pressure into
         * unbounded recursion and violates the timer contract. */
        mutexUnlock(&worker->control_mutex);
        if (retain_on_refusal)
        {
            reuseWorkerMessage(timed_msg);
        }
        else
        {
            cleanupWorkerMessage(timed_msg, kWorkerMessageCancelResourceFailure);
        }
        return false;
    }

    timed_msg->deadline_us = wloopNowUS(worker->loop) + ((uint64_t) delay_ms * 1000ULL);
    timed_msg->timer       = k_timer;
    weventSetUserData(k_timer, timed_msg);

    mutexLock(&(queue->mutex));
    assert(worker->message_queue == queue);
    if (UNLIKELY(worker_msg_deque_t_push_back(&(queue->timed), timed_msg) == NULL))
    {
        mutexUnlock(&(queue->mutex));
        mutexUnlock(&worker->control_mutex);
        weventSetUserData(k_timer, NULL);
        wtimerDelete(k_timer);
        if (retain_on_refusal)
        {
            reuseWorkerMessage(timed_msg);
        }
        else
        {
            cleanupWorkerMessage(timed_msg, kWorkerMessageCancelResourceFailure);
        }
        return false;
    }
    mutexUnlock(&(queue->mutex));
    mutexUnlock(&worker->control_mutex);
    return true;
}

static void setupTimedTask(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard setupTimedTaskChecked(worker, arg1, arg2, arg3, false);
}

void sendWorkerMessageTimed(wid_t wid, WorkerMessageCallback cb, uint32_t delay_ms, void *arg1, void *arg2, void *arg3)
{
    const worker_message_submit_result_e result =
        sendWorkerMessageTimedWithCleanup(wid, cb, NULL, delay_ms, arg1, arg2, arg3);
    discard result;
}

static worker_message_submit_result_e sendWorkerMessageTimedTransactional(wid_t wid, WorkerMessageCallback cb,
                                                                          WorkerMessageCleanupCallback cleanup,
                                                                          uint32_t delay_ms, void *arg1, void *arg2,
                                                                          void *arg3, bool retain_on_refusal)
{
    // delay=0 means "run on next event-loop iteration", not immediate inline execution
    if (delay_ms == 0)
    {
        return retain_on_refusal ? sendWorkerMessageForceQueueRetainOnRefusal(wid, cb, cleanup, arg1, arg2, arg3)
                                 : sendWorkerMessageForceQueueWithCleanup(wid, cb, cleanup, arg1, arg2, arg3);
    }

    WorkerMessageCleanupCallback refusal_cleanup = retain_on_refusal ? NULL : cleanup;
    if (UNLIKELY(workerMessageRejectUndeliverable(wid, refusal_cleanup, arg1, arg2, arg3)))
    {
        return retain_on_refusal ? kWorkerMessageSubmitRejectedCallerRetains : kWorkerMessageSubmitRejectedCleanupRan;
    }

    uintptr_t delay_ms_uiptr = (uintptr_t) delay_ms;

    worker_t *worker = getWorker(wid);
    if (UNLIKELY(! atomicLoadExplicit(&worker->message_admission_open, memory_order_relaxed)))
    {
        if (refusal_cleanup != NULL)
        {
            refusal_cleanup(arg1, arg2, arg3, kWorkerMessageCancelAdmissionClosed);
        }
        return retain_on_refusal ? kWorkerMessageSubmitRejectedCallerRetains : kWorkerMessageSubmitRejectedCleanupRan;
    }

    timed_worker_msg_t *msg = getWorkerMessage(cb, cleanup, arg1, arg2, arg3);

    // Arming the timer directly is only safe on the owning event worker's own
    // thread; every other caller (including lwIP and device threads) queues.
    if (currentThreadIsEventWorkerWID(wid))
    {
        return setupTimedTaskChecked(worker, (void *) delay_ms_uiptr, msg, NULL, retain_on_refusal)
                   ? kWorkerMessageSubmitAccepted
                   : (retain_on_refusal ? kWorkerMessageSubmitRejectedCallerRetains
                                        : kWorkerMessageSubmitRejectedCleanupRan);
    }

    // Queue setupTimedTask manually so both wrapper and payload are reclaimed on post failure.
    const worker_message_submit_result_e setup_result =
        retain_on_refusal ? sendWorkerMessageForceQueueRetainOnRefusal(wid,
                                                                       (WorkerMessageCallback) setupTimedTask,
                                                                       cleanupQueuedTimedWorkerMessage,
                                                                       (void *) delay_ms_uiptr,
                                                                       msg,
                                                                       NULL)
                          : sendWorkerMessageForceQueueWithCleanup(wid,
                                                                   (WorkerMessageCallback) setupTimedTask,
                                                                   cleanupQueuedTimedWorkerMessage,
                                                                   (void *) delay_ms_uiptr,
                                                                   msg,
                                                                   NULL);
    if (UNLIKELY(setup_result != kWorkerMessageSubmitAccepted))
    {
        if (retain_on_refusal)
        {
            reuseWorkerMessage(msg);
            return kWorkerMessageSubmitRejectedCallerRetains;
        }
        return kWorkerMessageSubmitRejectedCleanupRan;
    }
    return kWorkerMessageSubmitAccepted;
}

worker_message_submit_result_e sendWorkerMessageTimedWithCleanup(wid_t wid, WorkerMessageCallback cb,
                                                                 WorkerMessageCleanupCallback cleanup,
                                                                 uint32_t delay_ms, void *arg1, void *arg2, void *arg3)
{
    return sendWorkerMessageTimedTransactional(wid, cb, cleanup, delay_ms, arg1, arg2, arg3, false);
}

worker_message_submit_result_e sendWorkerMessageTimedRetainOnRefusal(wid_t wid, WorkerMessageCallback cb,
                                                                     WorkerMessageCleanupCallback cleanup,
                                                                     uint32_t delay_ms, void *arg1, void *arg2,
                                                                     void *arg3)
{
    return sendWorkerMessageTimedTransactional(wid, cb, cleanup, delay_ms, arg1, arg2, arg3, true);
}
