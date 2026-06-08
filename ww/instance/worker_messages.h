#pragma once

#include "master_pool.h"
#include "worker.h"

// real callback signature: worker_t*, void* arg1, void* arg2, void* arg3
typedef void (*WorkerMessageCallback)(void *, void *, void *, void *);
typedef void (*WorkerMessageCleanupCallback)(void *, void *, void *);

typedef struct worker_msg_s
{
    WorkerMessageCallback callback;
    void                 *arg1;
    void                 *arg2;
    void                 *arg3;
} worker_msg_t;

void workerMessagesInstallMasterPoolCallbacks(master_pool_t *pool);

void workerMessagesInit(worker_t *worker);
void workerMessagesCleanupPending(worker_t *worker);
void workerMessagesDestroy(worker_t *worker);

void sendWorkerMessage(wid_t wid, WorkerMessageCallback cb, void *arg1, void *arg2, void *arg3);
void sendWorkerMessageWithCleanup(wid_t wid, WorkerMessageCallback cb, WorkerMessageCleanupCallback cleanup, void *arg1,
                                  void *arg2, void *arg3);

// Same as above but does not do a direct call if the wid is the same as the current worker.
void sendWorkerMessageForceQueue(wid_t wid, WorkerMessageCallback cb, void *arg1, void *arg2, void *arg3);
bool sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback cb, WorkerMessageCleanupCallback cleanup,
                                            void *arg1, void *arg2, void *arg3);

// Same as above but with a delay in ms. delay=0 means next event-loop iteration.
void sendWorkerMessageTimed(wid_t wid, WorkerMessageCallback cb, uint32_t delay_ms, void *arg1, void *arg2, void *arg3);
void sendWorkerMessageTimedWithCleanup(wid_t wid, WorkerMessageCallback cb, WorkerMessageCleanupCallback cleanup,
                                       uint32_t delay_ms, void *arg1, void *arg2, void *arg3);
