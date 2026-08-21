#include "worker_messages.h"
#include "wloop_internal.h"
#include "worker_message_batch.h"

#include "global_state.h"
#include "list.h"
#include "wmutex.h"

#include "loggers/internal_logger.h"

#ifdef WW_WORKER_MESSAGE_BENCHMARK_INSTRUMENTATION
#include "mimalloc.h"
#if defined(__linux__)
#include <malloc.h>
#endif
#endif

/* Ordinary messages live by value in the target worker's deque. Delayed
 * messages need a stable address because their timer stores it in userdata. */
typedef struct queued_worker_msg_s
{
    worker_msg_t                 base;
    WorkerMessageCleanupCallback cleanup;
} queued_worker_msg_t;

typedef struct timed_worker_msg_s
{
    queued_worker_msg_t task;
    uint64_t            deadline_us;
    wtimer_t           *timer;
    /* Used only after the record has moved to a local cancellation list. */
    wtimer_t        *detached_timer;
    struct list_node timed_node;
} timed_worker_msg_t;

#define i_type worker_msg_deque_t
#define i_key  queued_worker_msg_t
#include "stc/deque.h"

struct worker_message_queue_s
{
    worker_msg_deque_t queued;
    struct list_head   timed;
    /* Protected by worker_t::control_mutex. True while a drain root is queued
     * or executing; this is distinct from wloop_t::wakeup_pending. */
    bool wakeup_pending;
#ifdef WW_WORKER_MESSAGE_BENCHMARK_INSTRUMENTATION
    worker_message_benchmark_counters_t benchmark;
#endif
};

static void workerMessageReceived(wevent_t *ev);

#ifdef WW_WORKER_MESSAGE_BENCHMARK_INSTRUMENTATION
static atomic_uint_fast64_t g_worker_message_benchmark_loop_wake_write_attempts = ATOMIC_VAR_INIT(0);

typedef struct worker_message_benchmark_workload_atomic_counters_s
{
    atomic_uint_fast64_t line_task_submissions;
    atomic_uint_fast64_t line_task_same_worker_submissions;
    atomic_uint_fast64_t line_task_foreign_worker_submissions;
    atomic_uint_fast64_t line_task_delayed_submissions;
    atomic_uint_fast64_t line_task_allocations;
    atomic_uint_fast64_t line_task_releases;
    atomic_uint_fast64_t line_task_checked_out;
    atomic_uint_fast64_t line_task_peak_checked_out;
    atomic_uint_fast64_t speedtest_send_progress_continuations;
    atomic_uint_fast64_t tester_send_progress_continuations;
    atomic_uint_fast64_t bridge_retry_or_delivery_continuations;
    atomic_uint_fast64_t ipmanipulator_deferred_continuations;
} worker_message_benchmark_workload_atomic_counters_t;

static worker_message_benchmark_workload_atomic_counters_t g_worker_message_benchmark_workload;

static void workerMessagesBenchmarkResetWorkloadCounters(void)
{
#define RESET_WORKLOAD_COUNTER(field)                                                                                  \
    atomic_store_explicit(&g_worker_message_benchmark_workload.field, 0, memory_order_relaxed)
    RESET_WORKLOAD_COUNTER(line_task_submissions);
    RESET_WORKLOAD_COUNTER(line_task_same_worker_submissions);
    RESET_WORKLOAD_COUNTER(line_task_foreign_worker_submissions);
    RESET_WORKLOAD_COUNTER(line_task_delayed_submissions);
    RESET_WORKLOAD_COUNTER(line_task_allocations);
    RESET_WORKLOAD_COUNTER(line_task_releases);
    RESET_WORKLOAD_COUNTER(line_task_checked_out);
    RESET_WORKLOAD_COUNTER(line_task_peak_checked_out);
    RESET_WORKLOAD_COUNTER(speedtest_send_progress_continuations);
    RESET_WORKLOAD_COUNTER(tester_send_progress_continuations);
    RESET_WORKLOAD_COUNTER(bridge_retry_or_delivery_continuations);
    RESET_WORKLOAD_COUNTER(ipmanipulator_deferred_continuations);
#undef RESET_WORKLOAD_COUNTER
}

void workerMessagesBenchmarkRecordLineTaskSubmission(bool same_worker, bool delayed)
{
    atomic_fetch_add_explicit(&g_worker_message_benchmark_workload.line_task_submissions, 1, memory_order_relaxed);
    if (same_worker)
    {
        atomic_fetch_add_explicit(
            &g_worker_message_benchmark_workload.line_task_same_worker_submissions, 1, memory_order_relaxed);
    }
    else
    {
        atomic_fetch_add_explicit(
            &g_worker_message_benchmark_workload.line_task_foreign_worker_submissions, 1, memory_order_relaxed);
    }
    if (delayed)
    {
        atomic_fetch_add_explicit(
            &g_worker_message_benchmark_workload.line_task_delayed_submissions, 1, memory_order_relaxed);
    }
}

void workerMessagesBenchmarkRecordLineTaskAllocation(void)
{
    atomic_fetch_add_explicit(&g_worker_message_benchmark_workload.line_task_allocations, 1, memory_order_relaxed);
    const uint_fast64_t checked_out =
        atomic_fetch_add_explicit(&g_worker_message_benchmark_workload.line_task_checked_out, 1, memory_order_relaxed) +
        1;
    uint_fast64_t peak =
        atomic_load_explicit(&g_worker_message_benchmark_workload.line_task_peak_checked_out, memory_order_relaxed);
    while (peak < checked_out &&
           ! atomic_compare_exchange_weak_explicit(&g_worker_message_benchmark_workload.line_task_peak_checked_out,
                                                   &peak,
                                                   checked_out,
                                                   memory_order_relaxed,
                                                   memory_order_relaxed))
    {
    }
}

void workerMessagesBenchmarkRecordLineTaskRelease(void)
{
    const uint_fast64_t checked_out =
        atomic_fetch_sub_explicit(&g_worker_message_benchmark_workload.line_task_checked_out, 1, memory_order_relaxed);
    if (UNLIKELY(checked_out == 0))
    {
        LOGF("worker-message benchmark line-task accounting underflow");
        abortProgramNow(1);
    }
    atomic_fetch_add_explicit(&g_worker_message_benchmark_workload.line_task_releases, 1, memory_order_relaxed);
}

void workerMessagesBenchmarkRecordContinuation(worker_message_benchmark_continuation_e continuation)
{
    switch (continuation)
    {
    case kWorkerMessageBenchmarkContinuationSpeedTestSend:
        atomic_fetch_add_explicit(
            &g_worker_message_benchmark_workload.speedtest_send_progress_continuations, 1, memory_order_relaxed);
        break;
    case kWorkerMessageBenchmarkContinuationTesterSend:
        atomic_fetch_add_explicit(
            &g_worker_message_benchmark_workload.tester_send_progress_continuations, 1, memory_order_relaxed);
        break;
    case kWorkerMessageBenchmarkContinuationBridgeRetryOrDelivery:
        atomic_fetch_add_explicit(
            &g_worker_message_benchmark_workload.bridge_retry_or_delivery_continuations, 1, memory_order_relaxed);
        break;
    case kWorkerMessageBenchmarkContinuationIpManipulatorDeferred:
        atomic_fetch_add_explicit(
            &g_worker_message_benchmark_workload.ipmanipulator_deferred_continuations, 1, memory_order_relaxed);
        break;
    }
}

void workerMessagesBenchmarkGetWorkloadCounters(worker_message_benchmark_workload_counters_t *counters)
{
    if (counters == NULL)
    {
        return;
    }

    *counters = (worker_message_benchmark_workload_counters_t) {
        .line_task_submissions =
            atomic_load_explicit(&g_worker_message_benchmark_workload.line_task_submissions, memory_order_relaxed),
        .line_task_same_worker_submissions = atomic_load_explicit(
            &g_worker_message_benchmark_workload.line_task_same_worker_submissions, memory_order_relaxed),
        .line_task_foreign_worker_submissions = atomic_load_explicit(
            &g_worker_message_benchmark_workload.line_task_foreign_worker_submissions, memory_order_relaxed),
        .line_task_delayed_submissions = atomic_load_explicit(
            &g_worker_message_benchmark_workload.line_task_delayed_submissions, memory_order_relaxed),
        .line_task_allocations =
            atomic_load_explicit(&g_worker_message_benchmark_workload.line_task_allocations, memory_order_relaxed),
        .line_task_releases =
            atomic_load_explicit(&g_worker_message_benchmark_workload.line_task_releases, memory_order_relaxed),
        .line_task_peak_checked_out =
            atomic_load_explicit(&g_worker_message_benchmark_workload.line_task_peak_checked_out, memory_order_relaxed),
        .speedtest_send_progress_continuations = atomic_load_explicit(
            &g_worker_message_benchmark_workload.speedtest_send_progress_continuations, memory_order_relaxed),
        .tester_send_progress_continuations = atomic_load_explicit(
            &g_worker_message_benchmark_workload.tester_send_progress_continuations, memory_order_relaxed),
        .bridge_retry_or_delivery_continuations = atomic_load_explicit(
            &g_worker_message_benchmark_workload.bridge_retry_or_delivery_continuations, memory_order_relaxed),
        .ipmanipulator_deferred_continuations = atomic_load_explicit(
            &g_worker_message_benchmark_workload.ipmanipulator_deferred_continuations, memory_order_relaxed),
    };
}

void workerMessagesBenchmarkPrintWorkloadCounters(void)
{
    worker_message_benchmark_workload_counters_t counters;
    workerMessagesBenchmarkGetWorkloadCounters(&counters);
    if (counters.line_task_submissions == 0 && counters.speedtest_send_progress_continuations == 0 &&
        counters.tester_send_progress_continuations == 0 && counters.bridge_retry_or_delivery_continuations == 0 &&
        counters.ipmanipulator_deferred_continuations == 0)
    {
        return;
    }

    fprintf(stderr,
            "worker-message-benchmark workload: line-task submissions=%" PRIu64 " same-worker=%" PRIu64
            " foreign-worker=%" PRIu64 " delayed=%" PRIu64 " allocations=%" PRIu64 " releases=%" PRIu64
            " peak-checked-out=%" PRIu64 "\n",
            counters.line_task_submissions,
            counters.line_task_same_worker_submissions,
            counters.line_task_foreign_worker_submissions,
            counters.line_task_delayed_submissions,
            counters.line_task_allocations,
            counters.line_task_releases,
            counters.line_task_peak_checked_out);
    fprintf(stderr,
            "worker-message-benchmark workload: continuations speedtest=%" PRIu64 " tester=%" PRIu64
            " bridge-retry-or-delivery=%" PRIu64 " ipmanipulator-deferred=%" PRIu64 "\n",
            counters.speedtest_send_progress_continuations,
            counters.tester_send_progress_continuations,
            counters.bridge_retry_or_delivery_continuations,
            counters.ipmanipulator_deferred_continuations);
}

typedef enum worker_message_benchmark_delayed_counter_e
{
    kWorkerMessageBenchmarkDelayedCompletion,
    kWorkerMessageBenchmarkDelayedRearm,
    kWorkerMessageBenchmarkDelayedCancellation,
} worker_message_benchmark_delayed_counter_e;

static void workerMessageBenchmarkRecordDelayed(worker_t *worker, worker_message_benchmark_delayed_counter_e counter)
{
    if (worker == NULL)
    {
        return;
    }

    mutexLock(&worker->control_mutex);
    worker_message_queue_t *queue = worker->message_queue;
    if (queue != NULL)
    {
        switch (counter)
        {
        case kWorkerMessageBenchmarkDelayedCompletion:
            ++queue->benchmark.delayed_timer_completions;
            break;
        case kWorkerMessageBenchmarkDelayedRearm:
            ++queue->benchmark.delayed_timer_rearms;
            break;
        case kWorkerMessageBenchmarkDelayedCancellation:
            ++queue->benchmark.delayed_timer_cancellations;
            break;
        }
    }
    mutexUnlock(&worker->control_mutex);
}

void workerMessagesBenchmarkRecordLoopWakeWriteAttempt(void)
{
    atomic_fetch_add_explicit(&g_worker_message_benchmark_loop_wake_write_attempts, 1, memory_order_relaxed);
}
#endif

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

/* GSTATE.masterpool_messages is also used by compact line-task records. Keep
 * this allocation at least as large as both record shapes; only delayed worker
 * messages take this path. */
static master_pool_item_t *allocWorkerMessage(void *userdata)
{
    discard userdata;
    return memoryAllocate(sizeof(timed_worker_msg_t));
}

static void destroyWorkerMessage(master_pool_item_t *item)
{
    memoryFree(item);
}

#ifdef WW_WORKER_MESSAGE_BENCHMARK_INSTRUMENTATION
static size_t workerMessageBenchmarkAllocationUsableSize(size_t requested_size)
{
    void *allocation = memoryAllocate(requested_size);
    if (allocation == NULL)
    {
        return 0;
    }

    size_t usable_size = requested_size;
#if defined(ALLOCATOR_BYPASS) && ALLOCATOR_BYPASS
#if defined(__linux__)
    usable_size = malloc_usable_size(allocation);
#endif
#else
    usable_size = mi_usable_size(allocation);
#endif
    memoryFree(allocation);
    return usable_size;
}

void workerMessagesBenchmarkResetCounters(worker_t *worker)
{
    atomic_store_explicit(&g_worker_message_benchmark_loop_wake_write_attempts, 0, memory_order_relaxed);
    if (worker == NULL)
    {
        return;
    }

    mutexLock(&worker->control_mutex);
    if (worker->message_queue != NULL)
    {
        worker->message_queue->benchmark = (worker_message_benchmark_counters_t) {0};
    }
    mutexUnlock(&worker->control_mutex);
}

void workerMessagesBenchmarkGetCounters(worker_t *worker, worker_message_benchmark_counters_t *counters)
{
    if (counters == NULL)
    {
        return;
    }

    const size_t measured_timed_record_usable_size =
        workerMessageBenchmarkAllocationUsableSize(sizeof(timed_worker_msg_t));
    *counters = (worker_message_benchmark_counters_t) {
        .loop_os_wake_write_attempts =
            atomic_load_explicit(&g_worker_message_benchmark_loop_wake_write_attempts, memory_order_relaxed),
        .timed_record_size                         = sizeof(timed_worker_msg_t),
        .timed_record_usable_size                  = measured_timed_record_usable_size,
        .line_task_record_size                     = sizeof(worker_msg_t),
        .line_task_effective_pool_item_usable_size = measured_timed_record_usable_size,
    };
    if (worker == NULL)
    {
        return;
    }

    mutexLock(&worker->control_mutex);
    if (worker->message_queue != NULL)
    {
        const uint64_t loop_wake_write_attempts = counters->loop_os_wake_write_attempts;
        const size_t   timed_record_size        = counters->timed_record_size;
        const size_t   timed_record_usable_size = counters->timed_record_usable_size;
        const size_t   line_task_record_size    = counters->line_task_record_size;
        *counters                               = worker->message_queue->benchmark;
        counters->loop_os_wake_write_attempts   = loop_wake_write_attempts;
        counters->timed_record_size             = timed_record_size;
        counters->timed_record_usable_size      = timed_record_usable_size;
        counters->line_task_record_size         = line_task_record_size;
    }
    mutexUnlock(&worker->control_mutex);

    /* Compact line-task records use this same master pool, whose create
     * callback allocates the timed-record shape. Report their effective pool
     * item cost rather than the unrelated size class of a standalone
     * sizeof(worker_msg_t) allocation. */
    counters->line_task_effective_pool_item_usable_size = counters->timed_record_usable_size;
}
#endif

static timed_worker_msg_t *getTimedWorkerMessage(WorkerMessageCallback cb, WorkerMessageCleanupCallback cleanup,
                                                 void *arg1, void *arg2, void *arg3)
{
    timed_worker_msg_t *msg;
    masterpoolGetItems(GSTATE.masterpool_messages, (void **) &msg, 1, NULL);
    *msg = (timed_worker_msg_t) {
        .task =
            {
                .base    = {.callback = cb, .arg1 = arg1, .arg2 = arg2, .arg3 = arg3},
                .cleanup = cleanup,
            },
    };
    list_init(&msg->timed_node);
    return msg;
}

static void runQueuedWorkerMessageCleanup(queued_worker_msg_t *msg, worker_message_cancel_reason_e reason)
{
    if (msg != NULL && msg->cleanup != NULL)
    {
        WorkerMessageCleanupCallback cleanup = msg->cleanup;
        msg->cleanup                         = NULL;
        cleanup(msg->base.arg1, msg->base.arg2, msg->base.arg3, reason);
    }
}

static void runTimedWorkerMessageCleanup(timed_worker_msg_t *msg, worker_message_cancel_reason_e reason)
{
    if (msg != NULL)
    {
        runQueuedWorkerMessageCleanup(&msg->task, reason);
    }
}

static void reuseTimedWorkerMessage(timed_worker_msg_t *msg)
{
    if (msg != NULL)
    {
        assert(list_empty(&msg->timed_node));
        assert(msg->detached_timer == NULL);
        msg->task.cleanup = NULL;
        msg->timer        = NULL;
        masterpoolReuseItems(GSTATE.masterpool_messages, (void **) &msg, 1);
    }
}

static void cleanupTimedWorkerMessage(timed_worker_msg_t *msg, worker_message_cancel_reason_e reason)
{
    runTimedWorkerMessageCleanup(msg, reason);
    reuseTimedWorkerMessage(msg);
}

static void cleanupQueuedTimedWorkerMessage(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard arg1;

#ifdef WW_WORKER_MESSAGE_BENCHMARK_INSTRUMENTATION
    workerMessageBenchmarkRecordDelayed((worker_t *) arg3, kWorkerMessageBenchmarkDelayedCancellation);
#else
    discard arg3;
#endif
    cleanupTimedWorkerMessage((timed_worker_msg_t *) arg2, reason);
}

static bool queuedWorkerMessagesEqual(const queued_worker_msg_t *lhs, const queued_worker_msg_t *rhs)
{
    return lhs->base.callback == rhs->base.callback && lhs->base.arg1 == rhs->base.arg1 &&
           lhs->base.arg2 == rhs->base.arg2 && lhs->base.arg3 == rhs->base.arg3 && lhs->cleanup == rhs->cleanup;
}

static void workerTimedMessageUnlinkLocked(worker_message_queue_t *queue, timed_worker_msg_t *msg)
{
    discard queue;
    assert(queue != NULL);
    assert(msg != NULL);
    assert(msg->detached_timer == NULL);
    assert(! list_empty(&msg->timed_node));
    if (UNLIKELY(list_empty(&msg->timed_node)))
    {
        LOGF("worker message timed record was not linked during settlement");
        abortProgramNow(1);
    }

    list_del_init(&msg->timed_node);
    msg->timer = NULL;
}

static bool workerMessagePostWakeup(worker_t *worker, wloop_t *loop)
{
    wevent_t ev;
    memoryZero(&ev, sizeof(ev));
    ev.loop = loop;
    ev.cb   = workerMessageReceived;
    discard worker;
    return wloopPostEvent(loop, &ev);
}

typedef struct worker_message_cleanup_batch_context_s
{
    queued_worker_msg_t           *batch;
    size_t                         first;
    size_t                         count;
    worker_message_cancel_reason_e reason;
} worker_message_cleanup_batch_context_t;

static void workerMessageCleanupLocalBatchRoot(void *context)
{
    worker_message_cleanup_batch_context_t *cleanup_context = context;

    for (size_t i = cleanup_context->first; i < cleanup_context->count; ++i)
    {
        runQueuedWorkerMessageCleanup(&cleanup_context->batch[i], cleanup_context->reason);
    }
}

static void workerMessageCleanupLocalBatch(wloop_t *loop, queued_worker_msg_t *batch, size_t first, size_t count,
                                           worker_message_cancel_reason_e reason)
{
    worker_message_cleanup_batch_context_t context = {
        .batch  = batch,
        .first  = first,
        .count  = count,
        .reason = reason,
    };

    /* A drain callback carries normal authority for already-admitted work.
     * Cancellation cleanup does not: clear that inherited authority so cleanup
     * cannot execute a same-worker submission inline after quiescence. */
    wloopInvokeControlCallback(loop, workerMessageCleanupLocalBatchRoot, &context);
}

static void workerMessageDrainQueue(worker_t *worker)
{
    /* Queued callbacks are written assuming they run on their target worker. */
    assert(currentThreadIsEventWorkerWID(worker->wid));

#ifdef WW_WORKER_MESSAGE_BENCHMARK_INSTRUMENTATION
    bool drain_callback_recorded = false;
#endif
    for (;;)
    {
        queued_worker_msg_t batch[kWorkerMessageDrainBatchSize];
        size_t              batch_count = 0;

        mutexLock(&worker->control_mutex);
        worker_message_queue_t *queue = worker->message_queue;
        wloop_t                *loop  = worker->loop;
        if (UNLIKELY(queue == NULL || loop == NULL))
        {
            mutexUnlock(&worker->control_mutex);
            return;
        }
#ifdef WW_WORKER_MESSAGE_BENCHMARK_INSTRUMENTATION
        if (! drain_callback_recorded)
        {
            ++queue->benchmark.worker_drain_callbacks;
            drain_callback_recorded = true;
        }
#endif
        if (! wloopNormalDispatchAllowed(loop))
        {
            queue->wakeup_pending = false;
            mutexUnlock(&worker->control_mutex);
            return;
        }

        while (batch_count < ARRAY_SIZE(batch) && ! worker_msg_deque_t_is_empty(&queue->queued))
        {
            batch[batch_count++] = worker_msg_deque_t_pull_front(&queue->queued);
        }
#ifdef WW_WORKER_MESSAGE_BENCHMARK_INSTRUMENTATION
        queue->benchmark.messages_captured_by_drains += batch_count;
        if (queue->benchmark.maximum_messages_captured_by_one_drain < batch_count)
        {
            queue->benchmark.maximum_messages_captured_by_one_drain = batch_count;
        }
#endif
        if (batch_count == 0)
        {
            queue->wakeup_pending = false;
            mutexUnlock(&worker->control_mutex);
            return;
        }
        /* Keep wakeup_pending set while this local snapshot executes. A
         * producer therefore cannot create a second concurrent drain root. */
        mutexUnlock(&worker->control_mutex);

        size_t i = 0;
        for (; i < batch_count; ++i)
        {
            /* The drain root itself may have been admitted before closure, but
             * later records in its snapshot are independent callback roots. */
            if (! wloopNormalDispatchAllowed(loop))
            {
                workerMessageCleanupLocalBatch(loop, batch, i, batch_count, kWorkerMessageCancelQuiesced);
                break;
            }

            batch[i].base.callback(worker, batch[i].base.arg1, batch[i].base.arg2, batch[i].base.arg3);
            batch[i].cleanup = NULL;
        }

        mutexLock(&worker->control_mutex);
        if (UNLIKELY(worker->message_queue != queue || worker->loop != loop))
        {
            mutexUnlock(&worker->control_mutex);
            return;
        }
        if (worker_msg_deque_t_is_empty(&queue->queued))
        {
            queue->wakeup_pending = false;
            mutexUnlock(&worker->control_mutex);
            return;
        }
        if (! wloopNormalDispatchAllowed(loop))
        {
            queue->wakeup_pending = false;
            mutexUnlock(&worker->control_mutex);
            return;
        }

        /* A successor is deliberately appended at the loop tail. That gives
         * ready I/O, timers, control work, and existing custom events a turn
         * between bounded worker-message snapshots. */
#ifdef WW_WORKER_MESSAGE_BENCHMARK_INSTRUMENTATION
        ++queue->benchmark.successor_wake_post_attempts;
#endif
        if (LIKELY(workerMessagePostWakeup(worker, loop)))
        {
            mutexUnlock(&worker->control_mutex);
            return;
        }

        if (! wloopNormalDispatchAllowed(loop))
        {
            queue->wakeup_pending = false;
            mutexUnlock(&worker->control_mutex);
            return;
        }

#ifdef WW_WORKER_MESSAGE_BENCHMARK_INSTRUMENTATION
        ++queue->benchmark.hard_successor_wake_fallbacks;
#endif
        /* A hard wake failure cannot revoke already accepted work. Preserve
         * ownership and make progress from the admitted current callback; this
         * rare fallback intentionally trades fairness for settlement. */
        mutexUnlock(&worker->control_mutex);
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
    /* The wakeup event was posted to exactly one worker loop, so that loop is
     * the authoritative owner; never re-read TLS to choose a target. */
    wid_t wid = (wid_t) wloopGetWid(weventGetLoop(ev));
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
#ifdef WW_WORKER_MESSAGE_BENCHMARK_INSTRUMENTATION
    workerMessagesBenchmarkResetWorkloadCounters();
#endif
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
    };
    list_init(&queue->timed);

    const bool queued_ready = ! workerMessagesInitTestRefuse(kWorkerMessageInitFailQueuedReserve) &&
                              worker_msg_deque_t_reserve(&queue->queued, kWorkerMessageDrainBatchSize);
    if (UNLIKELY(! queued_ready))
    {
        worker_msg_deque_t_drop(&queue->queued);
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
    workerMessagesCloseAdmissionLocked(worker);
    *loop                 = worker->loop;
    *queue                = worker->message_queue;
    worker->loop          = NULL;
    worker->message_queue = NULL;
    mutexUnlock(&worker->control_mutex);
}

static void workerMessagesTakePending(worker_message_queue_t *queue, worker_msg_deque_t *queued,
                                      struct list_head *timed)
{
    assert(queue != NULL);
    assert(queued != NULL);
    assert(timed != NULL);

    *queued = worker_msg_deque_t_move(&queue->queued);
    list_splice_init(&queue->timed, timed);
    for (struct list_node *node = timed->next; node != timed; node = node->next)
    {
        timed_worker_msg_t *msg = container_of(node, timed_worker_msg_t, timed_node);
        assert(msg->detached_timer == NULL);
        msg->detached_timer = msg->timer;
        msg->timer          = NULL;
    }
    queue->wakeup_pending = false;
}

static void workerMessagesCleanupCollections(worker_msg_deque_t *queued, struct list_head *timed,
                                             worker_message_cancel_reason_e reason)
{
    while (! worker_msg_deque_t_is_empty(queued))
    {
        queued_worker_msg_t msg = worker_msg_deque_t_pull_front(queued);
        runQueuedWorkerMessageCleanup(&msg, reason);
    }
    worker_msg_deque_t_drop(queued);

    while (! list_empty(timed))
    {
        struct list_node   *node = timed->next;
        timed_worker_msg_t *msg  = container_of(node, timed_worker_msg_t, timed_node);
        list_del_init(node);

        wtimer_t *timer     = msg->detached_timer;
        msg->detached_timer = NULL;
        if (timer != NULL)
        {
            weventSetUserData(timer, NULL);
            wtimerDelete(timer);
        }
        cleanupTimedWorkerMessage(msg, reason);
    }
}

void workerMessagesCleanupPendingDetached(worker_message_queue_t *queue, worker_message_cancel_reason_e reason)
{
    if (queue == NULL)
    {
        return;
    }

    /* The caller owns a detached queue exclusively: admission has closed and
     * no producer can still retain a pointer to this queue. */
    worker_msg_deque_t queued = worker_msg_deque_t_init();
    struct list_head   timed;
    list_init(&timed);
    workerMessagesTakePending(queue, &queued, &timed);
    workerMessagesCleanupCollections(&queued, &timed, reason);
}

void workerMessagesCleanupPending(worker_t *worker)
{
    assert(worker != NULL);

    worker_msg_deque_t queued = worker_msg_deque_t_init();
    struct list_head   timed;
    list_init(&timed);

    mutexLock(&worker->control_mutex);
    worker_message_queue_t *queue = worker->message_queue;
    if (queue != NULL)
    {
        workerMessagesTakePending(queue, &queued, &timed);
#ifdef WW_WORKER_MESSAGE_BENCHMARK_INSTRUMENTATION
        for (const struct list_node *node = timed.next; node != &timed; node = node->next)
        {
            ++queue->benchmark.delayed_timer_cancellations;
        }
#endif
    }
    mutexUnlock(&worker->control_mutex);

    workerMessagesCleanupCollections(&queued, &timed, kWorkerMessageCancelQuiesced);
}

void workerMessagesDestroyDetached(worker_message_queue_t *queue)
{
    if (queue == NULL)
    {
        return;
    }

    workerMessagesCleanupPendingDetached(queue, kWorkerMessageCancelTeardown);
    worker_msg_deque_t_drop(&queue->queued);
    assert(list_empty(&queue->timed));
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

    queued_worker_msg_t msg = {
        .base    = {.callback = cb, .arg1 = arg1, .arg2 = arg2, .arg3 = arg3},
        .cleanup = cleanup,
    };

#ifdef WW_WORKER_MESSAGE_TEST_SEAM
    workerMessageEnqueueTestSeam(worker, kWorkerMessageEnqueueBeforeLifetimeLock);
#endif

    /* control_mutex protects queue/loop lifetime, admission, mutation, and
     * wake publication as one transaction. It is intentionally retained over
     * wloopPostEvent(), whose lock order continues normal-admission then
     * custom-events. */
    mutexLock(&worker->control_mutex);
    worker_message_queue_t *queue = worker->message_queue;
    wloop_t                *loop  = worker->loop;
    if (UNLIKELY(! atomicLoadExplicit(&worker->message_admission_open, memory_order_relaxed) || loop == NULL ||
                 queue == NULL))
    {
        mutexUnlock(&worker->control_mutex);
        if (! retain_on_refusal)
        {
            runQueuedWorkerMessageCleanup(&msg, kWorkerMessageCancelAdmissionClosed);
        }
        return retain_on_refusal ? kWorkerMessageSubmitRejectedCallerRetains : kWorkerMessageSubmitRejectedCleanupRan;
    }

#ifdef WW_WORKER_MESSAGE_TEST_SEAM
    workerMessageEnqueueTestSeam(worker, kWorkerMessageEnqueueBeforeEnqueue);
#endif

    if (UNLIKELY(workerMessagesEnqueueTestRefuse(kWorkerMessageEnqueueFailDequeGrowth) ||
                 worker_msg_deque_t_push_back(&queue->queued, msg) == NULL))
    {
        mutexUnlock(&worker->control_mutex);
        if (! retain_on_refusal)
        {
            runQueuedWorkerMessageCleanup(&msg, kWorkerMessageCancelEnqueueFailure);
        }
        return retain_on_refusal ? kWorkerMessageSubmitRejectedCallerRetains : kWorkerMessageSubmitRejectedCleanupRan;
    }

#ifdef WW_WORKER_MESSAGE_BENCHMARK_INSTRUMENTATION
    const uint64_t queued_count = (uint64_t) worker_msg_deque_t_size(&queue->queued);
    if (queue->benchmark.ordinary_queue_high_watermark < queued_count)
    {
        queue->benchmark.ordinary_queue_high_watermark = queued_count;
    }
#endif

    if (queue->wakeup_pending)
    {
        mutexUnlock(&worker->control_mutex);
        return kWorkerMessageSubmitAccepted;
    }

    queue->wakeup_pending = true;
#ifdef WW_WORKER_MESSAGE_BENCHMARK_INSTRUMENTATION
    ++queue->benchmark.initial_wake_post_attempts;
#endif
    if (LIKELY(! workerMessagesEnqueueTestRefuse(kWorkerMessageEnqueueFailWakeupPost) &&
               workerMessagePostWakeup(worker, loop)))
    {
        mutexUnlock(&worker->control_mutex);
        return kWorkerMessageSubmitAccepted;
    }

    queue->wakeup_pending               = false;
    queued_worker_msg_t rolled_back_msg = worker_msg_deque_t_pull_back(&queue->queued);
    if (UNLIKELY(! queuedWorkerMessagesEqual(&rolled_back_msg, &msg)))
    {
        LOGF("sendWorkerMessageForceQueueTransactional: queued message mismatch during refusal rollback");
        abortProgramNow(1);
    }
    mutexUnlock(&worker->control_mutex);

    if (! retain_on_refusal)
    {
        runQueuedWorkerMessageCleanup(&rolled_back_msg, kWorkerMessageCancelEnqueueFailure);
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

static void workerTimedMessageDetachFromOwner(worker_t *worker, wloop_t *loop, timed_worker_msg_t *timed_msg,
                                              const char *context)
{
    mutexLock(&worker->control_mutex);
    worker_message_queue_t *queue = worker->message_queue;
    if (UNLIKELY(queue == NULL || worker->loop != loop))
    {
        mutexUnlock(&worker->control_mutex);
        LOGF("runTimedTask: worker message queue detached during %s", context);
        abortProgramNow(1);
    }
    workerTimedMessageUnlinkLocked(queue, timed_msg);
    mutexUnlock(&worker->control_mutex);
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
    worker_t *worker = getWorker(owner_wid);

#ifdef WW_WORKER_MESSAGE_TEST_SEAM
    workerMessageTimedRearmTestSeam(worker, &timed_msg->deadline_us);
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

        /* Some timeout buckets are rounded early, so do not release delayed
         * work before its true deadline. */
        if (! wtimerReset(timer, remaining_ms))
        {
            workerTimedMessageDetachFromOwner(worker, loop, timed_msg, "timer reset failure");
            weventSetUserData(timer, NULL);
#ifdef WW_WORKER_MESSAGE_BENCHMARK_INSTRUMENTATION
            workerMessageBenchmarkRecordDelayed(worker, kWorkerMessageBenchmarkDelayedCancellation);
#endif
            cleanupTimedWorkerMessage(timed_msg, kWorkerMessageCancelAdmissionClosed);
        }
#ifdef WW_WORKER_MESSAGE_BENCHMARK_INSTRUMENTATION
        else
        {
            workerMessageBenchmarkRecordDelayed(worker, kWorkerMessageBenchmarkDelayedRearm);
        }
#endif
        return;
    }

    workerTimedMessageDetachFromOwner(worker, loop, timed_msg, "deadline completion");

    if (! wloopNormalDispatchAllowed(loop))
    {
        weventSetUserData(timer, NULL);
        wtimerDelete(timer);
#ifdef WW_WORKER_MESSAGE_BENCHMARK_INSTRUMENTATION
        workerMessageBenchmarkRecordDelayed(worker, kWorkerMessageBenchmarkDelayedCancellation);
#endif
        cleanupTimedWorkerMessage(timed_msg, kWorkerMessageCancelQuiesced);
        return;
    }

#ifdef WW_WORKER_MESSAGE_BENCHMARK_INSTRUMENTATION
    workerMessageBenchmarkRecordDelayed(worker, kWorkerMessageBenchmarkDelayedCompletion);
#endif
    WorkerMessageCallback cb = timed_msg->task.base.callback;
    cb(worker, timed_msg->task.base.arg1, timed_msg->task.base.arg2, timed_msg->task.base.arg3);

    timed_msg->task.cleanup = NULL;
    weventSetUserData(timer, NULL);
    wtimerDelete(timer);
    reuseTimedWorkerMessage(timed_msg);
}

static bool setupTimedTaskChecked(worker_t *worker, void *arg1, void *arg2, void *arg3, bool retain_on_refusal)
{
    const uint32_t      delay_ms  = (uint32_t) (uintptr_t) arg1;
    timed_worker_msg_t *timed_msg = (timed_worker_msg_t *) arg2;
    discard             arg3;

    /* Either called on the target worker or delivered as a worker message to
     * it; both mean the timer is armed on its own loop's thread. */
    assert(currentThreadIsEventWorkerWID(worker->wid));

    mutexLock(&worker->control_mutex);
    worker_message_queue_t *queue = worker->message_queue;
    wloop_t                *loop  = worker->loop;
    if (UNLIKELY(! atomicLoadExplicit(&worker->message_admission_open, memory_order_relaxed) || loop == NULL ||
                 queue == NULL || ! wloopNormalDispatchAllowed(loop)))
    {
        mutexUnlock(&worker->control_mutex);
        if (retain_on_refusal)
        {
            reuseTimedWorkerMessage(timed_msg);
        }
        else
        {
#ifdef WW_WORKER_MESSAGE_BENCHMARK_INSTRUMENTATION
            workerMessageBenchmarkRecordDelayed(worker, kWorkerMessageBenchmarkDelayedCancellation);
#endif
            cleanupTimedWorkerMessage(timed_msg, kWorkerMessageCancelAdmissionClosed);
        }
        return false;
    }

    wtimer_t *k_timer = wtimerAdd(loop, runTimedTask, delay_ms, 1);
    if (UNLIKELY(k_timer == NULL))
    {
        /* A delayed callback may depend on a minimum delay and may schedule
         * itself again. Running it inline turns allocation pressure into
         * unbounded recursion and violates the timer contract. */
        mutexUnlock(&worker->control_mutex);
        if (retain_on_refusal)
        {
            reuseTimedWorkerMessage(timed_msg);
        }
        else
        {
#ifdef WW_WORKER_MESSAGE_BENCHMARK_INSTRUMENTATION
            workerMessageBenchmarkRecordDelayed(worker, kWorkerMessageBenchmarkDelayedCancellation);
#endif
            cleanupTimedWorkerMessage(timed_msg, kWorkerMessageCancelResourceFailure);
        }
        return false;
    }

    timed_msg->deadline_us = wloopNowUS(loop) + ((uint64_t) delay_ms * 1000ULL);
    timed_msg->timer       = k_timer;
    weventSetUserData(k_timer, timed_msg);
    assert(timed_msg->detached_timer == NULL);
    assert(list_empty(&timed_msg->timed_node));
    list_add_tail(&timed_msg->timed_node, &queue->timed);
#ifdef WW_WORKER_MESSAGE_BENCHMARK_INSTRUMENTATION
    ++queue->benchmark.delayed_timer_setups;
#endif
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
    /* delay=0 means "run on next event-loop iteration", not immediate inline execution. */
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

    worker_t *worker = getWorker(wid);
    if (UNLIKELY(! atomicLoadExplicit(&worker->message_admission_open, memory_order_relaxed)))
    {
        if (refusal_cleanup != NULL)
        {
            refusal_cleanup(arg1, arg2, arg3, kWorkerMessageCancelAdmissionClosed);
        }
        return retain_on_refusal ? kWorkerMessageSubmitRejectedCallerRetains : kWorkerMessageSubmitRejectedCleanupRan;
    }

    timed_worker_msg_t *msg            = getTimedWorkerMessage(cb, cleanup, arg1, arg2, arg3);
    const uintptr_t     delay_ms_uiptr = (uintptr_t) delay_ms;

    /* Arming directly is only safe on the owning event worker's thread. A
     * foreign caller queues one by-value setup wrapper around this stable
     * delayed record; no second pooled message is allocated. */
    if (currentThreadIsEventWorkerWID(wid))
    {
        return setupTimedTaskChecked(worker, (void *) delay_ms_uiptr, msg, NULL, retain_on_refusal)
                   ? kWorkerMessageSubmitAccepted
                   : (retain_on_refusal ? kWorkerMessageSubmitRejectedCallerRetains
                                        : kWorkerMessageSubmitRejectedCleanupRan);
    }

    const worker_message_submit_result_e setup_result =
        retain_on_refusal ? sendWorkerMessageForceQueueRetainOnRefusal(wid,
                                                                       (WorkerMessageCallback) setupTimedTask,
                                                                       cleanupQueuedTimedWorkerMessage,
                                                                       (void *) delay_ms_uiptr,
                                                                       msg,
                                                                       worker)
                          : sendWorkerMessageForceQueueWithCleanup(wid,
                                                                   (WorkerMessageCallback) setupTimedTask,
                                                                   cleanupQueuedTimedWorkerMessage,
                                                                   (void *) delay_ms_uiptr,
                                                                   msg,
                                                                   worker);
    if (UNLIKELY(setup_result != kWorkerMessageSubmitAccepted))
    {
        if (retain_on_refusal)
        {
            reuseTimedWorkerMessage(msg);
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
