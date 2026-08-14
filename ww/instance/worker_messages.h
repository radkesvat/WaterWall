#pragma once

#include "master_pool.h"
#include "worker.h"

// real callback signature: worker_t*, void* arg1, void* arg2, void* arg3
typedef void (*WorkerMessageCallback)(void *, void *, void *, void *);
typedef void (*WorkerMessageCleanupCallback)(void *, void *, void *);

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
void workerMessagesCloseAdmissionAndDetach(worker_t *worker, wloop_t **loop, worker_message_queue_t **queue);
void workerMessagesCleanupPending(worker_t *worker);
void workerMessagesDestroy(worker_t *worker);
void workerMessagesCleanupPendingDetached(worker_message_queue_t *queue);
void workerMessagesDestroyDetached(worker_message_queue_t *queue);

typedef enum
{
    kWorkerMessageInitFailNone = 0,
    kWorkerMessageInitFailOuterAllocation,
    kWorkerMessageInitFailQueuedReserve,
    kWorkerMessageInitFailTimedReserve
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
    kWorkerMessageEnqueueBeforeQueueLock
} worker_message_enqueue_test_stage_e;

void workerMessageEnqueueTestSeam(worker_t *worker, worker_message_enqueue_test_stage_e stage);
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
WW_WORKER_MESSAGE_MUST_USE bool sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback cb,
                                                                       WorkerMessageCleanupCallback cleanup, void *arg1,
                                                                       void *arg2, void *arg3);
/*
 * Transactional variant: on an immediate false return no callback has run and
 * the caller still owns all arguments. Once true is returned, either the worker
 * callback or the late queue-cleanup callback owns them.
 */
WW_WORKER_MESSAGE_MUST_USE bool sendWorkerMessageForceQueueRetainOnRefusal(wid_t wid, WorkerMessageCallback cb,
                                                                           WorkerMessageCleanupCallback cleanup,
                                                                           void *arg1, void *arg2, void *arg3);

// Same as above but with a delay in ms. delay=0 means next event-loop iteration.
// Note, order of execution is not guaranteed for messages with the same delay, so if you need to guarantee order,
// use your own FIFO queue.
void sendWorkerMessageTimed(wid_t wid, WorkerMessageCallback cb, uint32_t delay_ms, void *arg1, void *arg2, void *arg3);
/*
 * Returns false when the message was rejected before it was accepted anywhere; the
 * cleanup callback has already run, on the calling thread, and the caller owns
 * recovery.
 *
 * Returns true when the message was accepted. A late failure can still drop it
 * after that point, in which case the cleanup callback runs on the target worker --
 * so a cleanup that needs to forward packets may do so when, and only when, it
 * confirms it is on that worker.
 */
WW_WORKER_MESSAGE_MUST_USE bool sendWorkerMessageTimedWithCleanup(wid_t wid, WorkerMessageCallback cb,
                                                                  WorkerMessageCleanupCallback cleanup,
                                                                  uint32_t delay_ms, void *arg1, void *arg2,
                                                                  void *arg3);

#undef WW_WORKER_MESSAGE_MUST_USE
