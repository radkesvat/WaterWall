#pragma once

#include "master_pool.h"
#include "worker.h"

// real callback signature: worker_t*, void* arg1, void* arg2, void* arg3
typedef void (*WorkerMessageCallback)(void *, void *, void *, void *);

typedef enum worker_message_cancel_reason_e
{
    kWorkerMessageCancelTargetUnavailable = 0,
    kWorkerMessageCancelAdmissionClosed,
    kWorkerMessageCancelEnqueueFailure,
    kWorkerMessageCancelQuiesced,
    kWorkerMessageCancelTeardown,
    kWorkerMessageCancelResourceFailure
} worker_message_cancel_reason_e;

typedef enum worker_message_submit_result_e
{
    kWorkerMessageSubmitRejectedCleanupRan = 0,
    kWorkerMessageSubmitAccepted,
    kWorkerMessageSubmitRejectedCallerRetains
} worker_message_submit_result_e;

typedef void (*WorkerMessageCleanupCallback)(void *, void *, void *, worker_message_cancel_reason_e);

#if defined(__GNUC__) || defined(__clang__)
#define WW_WORKER_MESSAGE_MUST_USE __attribute__((warn_unused_result))
#else
#define WW_WORKER_MESSAGE_MUST_USE
#endif

typedef struct worker_msg_s
{
    WorkerMessageCallback callback;
    void                 *arg1;
    void                 *arg2;
    void                 *arg3;
} worker_msg_t;

void workerMessagesInstallMasterPoolCallbacks(master_pool_t *pool);

bool workerMessagesInit(worker_t *worker);
bool workerMessagesOpenAdmission(worker_t *worker);
void workerMessagesCloseAdmission(worker_t *worker);
void workerMessagesCloseAdmissionLocked(worker_t *worker);
void workerMessagesCloseAdmissionAndDetach(worker_t *worker, wloop_t **loop, worker_message_queue_t **queue);
void workerMessagesCleanupPending(worker_t *worker);
void workerMessagesDestroy(worker_t *worker);
/* @p queue must already be detached under worker_t::control_mutex, so its
 * caller has exclusive access and message admission is closed. */
void workerMessagesCleanupPendingDetached(worker_message_queue_t *queue, worker_message_cancel_reason_e reason);
void workerMessagesDestroyDetached(worker_message_queue_t *queue);

typedef enum
{
    kWorkerMessageInitFailNone = 0,
    kWorkerMessageInitFailOuterAllocation,
    kWorkerMessageInitFailQueuedReserve
} worker_message_init_test_failure_e;

typedef enum
{
    kWorkerMessageEnqueueFailNone = 0,
    kWorkerMessageEnqueueFailDequeGrowth,
    kWorkerMessageEnqueueFailWakeupPost
} worker_message_enqueue_test_failure_e;

#ifdef WW_WORKER_MESSAGE_TEST_SEAM
typedef enum
{
    kWorkerMessageEnqueueBeforeLifetimeLock = 0,
    /* Runs with worker_t::control_mutex held after admission/lifetime
     * validation and before the value record is appended. */
    kWorkerMessageEnqueueBeforeEnqueue
} worker_message_enqueue_test_stage_e;

void workerMessageEnqueueTestSeam(worker_t *worker, worker_message_enqueue_test_stage_e stage);
void workerMessageTimedRearmTestSeam(worker_t *worker, uint64_t *deadline_us);
void workerMessagesInitTestSetFailure(worker_message_init_test_failure_e failure);
void workerMessagesEnqueueTestSetFailure(worker_message_enqueue_test_failure_e failure);
#endif

void sendWorkerMessage(wid_t wid, WorkerMessageCallback cb, void *arg1, void *arg2, void *arg3);
void sendWorkerMessageWithCleanup(wid_t wid, WorkerMessageCallback cb, WorkerMessageCleanupCallback cleanup, void *arg1,
                                  void *arg2, void *arg3);

/* Explicitly lossy form. Production uses require a source-policy rationale. */
void sendWorkerMessageForceQueueBestEffort(wid_t wid, WorkerMessageCallback cb, void *arg1, void *arg2, void *arg3);
void sendWorkerMessageForceQueueBestEffortWithCleanup(wid_t wid, WorkerMessageCallback cb,
                                                      WorkerMessageCleanupCallback cleanup, void *arg1, void *arg2,
                                                      void *arg3);
WW_WORKER_MESSAGE_MUST_USE worker_message_submit_result_e sendWorkerMessageForceQueueWithCleanup(
    wid_t wid, WorkerMessageCallback cb, WorkerMessageCleanupCallback cleanup, void *arg1, void *arg2, void *arg3);
/* Refusal retains caller ownership; acceptance transfers it to callback-or-cleanup settlement. */
WW_WORKER_MESSAGE_MUST_USE worker_message_submit_result_e sendWorkerMessageForceQueueRetainOnRefusal(
    wid_t wid, WorkerMessageCallback cb, WorkerMessageCleanupCallback cleanup, void *arg1, void *arg2, void *arg3);

// Same as above but with a delay in ms. delay=0 means next event-loop iteration.
// Note, order of execution is not guaranteed for messages with the same delay, so if you need to guarantee order,
// use your own FIFO queue (like buffer_queue_t forexample).
void sendWorkerMessageTimed(wid_t wid, WorkerMessageCallback cb, uint32_t delay_ms, void *arg1, void *arg2, void *arg3);
/* Accepted work runs its callback or receives one typed cancellation cleanup. */
WW_WORKER_MESSAGE_MUST_USE worker_message_submit_result_e
sendWorkerMessageTimedWithCleanup(wid_t wid, WorkerMessageCallback cb, WorkerMessageCleanupCallback cleanup,
                                  uint32_t delay_ms, void *arg1, void *arg2, void *arg3);
/* Refusal retains caller ownership; acceptance transfers it to callback-or-cleanup settlement. */
WW_WORKER_MESSAGE_MUST_USE worker_message_submit_result_e
sendWorkerMessageTimedRetainOnRefusal(wid_t wid, WorkerMessageCallback cb, WorkerMessageCleanupCallback cleanup,
                                      uint32_t delay_ms, void *arg1, void *arg2, void *arg3);

#undef WW_WORKER_MESSAGE_MUST_USE
