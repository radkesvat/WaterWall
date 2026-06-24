#include "worker.h"
#include "context.h"
#include "global_state.h"
#include "managers/node_manager.h"
#include "managers/signal_manager.h"
#include "managers/socket_manager.h"
#include "tunnel.h"
#include "wevent.h"
#include "wloop.h"
#include "worker_messages.h"
#include "wthread.h"

#include "loggers/internal_logger.h"

#include "loggers/dns_logger.h"

thread_local wid_t tl_wid;

static void workerDestroyResources(worker_t *worker)
{

    if (worker->loop)
    {
        /*
         * Keep this order: asyncdnsCleanup() still owns timers and c-ares
         * socket watches registered on worker->loop, so it must run while the
         * event loop and its wio/timer storage are still alive.
         */
        nodemanagerStopWorkerResources(worker->wid);
        socketmanagerDrainUdpIdleForWorker(worker->wid);
        socketmanagerCloseListenersForLoop(worker->loop);
        asyncdnsCleanup(&worker->dns_resolver);
        workerMessagesCleanupPending(worker);
        wloopDestroy(&worker->loop);
    }
    workerMessagesDestroy(worker);
    if (worker->wios_pool)
    {
        threadsafegenericpoolDestroy(worker->wios_pool);
    }
    if (worker->context_pool)
    {
        genericpoolDestroy(worker->context_pool);
    }
    if (worker->buffer_pool)
    {
        bufferpoolDestroy(worker->buffer_pool);
    }

    worker->loop         = NULL;
    worker->wios_pool    = NULL;
    worker->context_pool = NULL;
    worker->buffer_pool  = NULL;
}

void workerFinish(worker_t *worker)
{
    if (worker->tid == getTID())
    {
        workerDestroyResources(worker);
    }
    else
    {
        if (worker->loop)
        {
            worker->loop->flags = worker->loop->flags | WLOOP_FLAG_RUN_ONCE;
            atomicThreadFence(memory_order_release);
        }
        else
        {
            // lwip thread
            workerDestroyResources(worker);
        }
    }
}

void workerJoin(worker_t *worker)
{
    if (worker->thread != (wthread_t) 0)
    {
        safeThreadJoin(worker->thread);
        worker->thread = (wthread_t) 0;
    }
}

void workerExitJoin(worker_t *worker)
{

    workerFinish(worker);
    workerJoin(worker);
}

void workerInit(worker_t *worker, wid_t wid, bool eventloop)
{
    *worker = (worker_t) {.wid = wid};

    workerMessagesInit(worker);

    worker->wios_pool =
        threadsafegenericpoolCreateWithDefaultAllocatorAndCapacity(GSTATE.masterpool_wios, sizeof(wio_t), RAM_PROFILE);

    worker->context_pool = genericpoolCreateWithDefaultAllocatorAndCapacity(
        GSTATE.masterpool_context_pools, sizeof(context_t), RAM_PROFILE);

    worker->buffer_pool = bufferpoolCreate(GSTATE.masterpool_buffer_pools_large,
                                           GSTATE.masterpool_buffer_pools_small,
                                           RAM_PROFILE,
                                           PROPER_LARGE_BUFFER_SIZE(RAM_PROFILE),
                                           SMALL_BUFFER_SIZE);

    if (eventloop)
    {
        // note that loop depeneds on worker->buffer_pool
        worker->loop = wloopCreate(0, worker->buffer_pool, wid);

        int dns_rc = asyncdnsInit(&worker->dns_resolver, worker->loop, &GSTATE.dns_options);
        if (dns_rc != ARES_SUCCESS)
        {
            loggerPrint(getDnsLogger(),
                        LOG_LEVEL_FATAL,
                        "Worker %d failed to initialize async DNS resolver: %s",
                        wid,
                        ares_strerror(dns_rc));
            terminateProgram(1);
        }
    }
    else
    {
        worker->loop = NULL;
    }
}

void workerRun(worker_t *worker)
{
    tl_wid    = worker->wid;
    wid_t wid = worker->wid;
    frandInit();

    while (atomicLoadExplicit(&GSTATE.workers_run_flag, memory_order_acquire) == false)
    {
        if (UNLIKELY(isApplicationTerminating()))
        {
            workerDestroyResources(worker);
            LOGD("Worker %d exited", wid);
            return;
        }
        // wait for the main thread to set the flag
        wwSleepMS(10);
    }

    wloopRun(worker->loop);

    workerDestroyResources(worker);

    LOGD("Worker %d exited", wid);
}

int workerResolveDomainServiceAsync(wid_t wid, const char *domain, const char *service, int socktype, dns_resolve_cb cb,
                                    void *userdata)
{
    assert(wid == getWID());
    assert(wid < getWorkersCount());

    worker_t *worker = getWorker(wid);
    assert(worker->loop != NULL);

    return asyncdnsResolve(&worker->dns_resolver, domain, service, socktype, cb, userdata);
}

int workerResolveDomainAsync(wid_t wid, const char *domain, dns_resolve_cb cb, void *userdata)
{
    return workerResolveDomainServiceAsync(wid, domain, NULL, 0, cb, userdata);
}

/**
 * @brief Worker thread routine.
 *
 * This function is the entry point for the worker thread. It runs the worker and returns 0.
 *
 * @param userdata Pointer to the worker.
 * @return 0.
 */
static WTHREAD_ROUTINE(worker_thread) // NOLINT
{
    worker_t *worker = userdata;
    worker->tid      = getTID();
    workerRun(worker);

    return 0;
}

/**
 * @brief Runs the worker in a new thread.
 *
 * This function creates a new thread and runs the worker in it.
 *
 * @param worker Pointer to the worker to run.
 */
void workerSpawn(worker_t *worker)
{
    worker->thread = threadCreate(worker_thread, worker);
}
