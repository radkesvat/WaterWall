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

/**
 * @brief Advance the worker lifecycle to at least @p target. Never goes back.
 */
static void workerLifecycleAdvance(worker_t *worker, worker_lifecycle_e target)
{
    w_atomic_int_value_t current = atomicLoadExplicit(&worker->lifecycle, memory_order_acquire);

    while (current < (w_atomic_int_value_t) target)
    {
        if (atomicCompareExchangeExplicit(&worker->lifecycle,
                                          &current,
                                          (w_atomic_int_value_t) target,
                                          memory_order_acq_rel,
                                          memory_order_acquire))
        {
            return;
        }
    }
}

bool workerStopRequested(const worker_t *worker)
{
    if (worker == NULL)
    {
        return false;
    }

    return atomicLoadExplicit(&((worker_t *) worker)->lifecycle, memory_order_acquire) >=
           (w_atomic_int_value_t) kWorkerLifecycleStopRequested;
}

bool workerRequestStop(worker_t *worker)
{
    if (worker == NULL)
    {
        return false;
    }

    workerLifecycleAdvance(worker, kWorkerLifecycleStopRequested);

    if (! worker->has_event_loop)
    {
        // Pseudo-worker: no loop to wake. Its resources are destroyed explicitly
        // by the shutdown sequence.
        return true;
    }

    /*
     * The loop pointer is only stable while control_mutex is held: the owning
     * thread detaches it under the same lock before destroying it. Waking inside
     * the lock is what makes both orderings safe - either this call wakes a live
     * loop and the owner waits, or the owner already detached and there is
     * nothing left to wake.
     */
    bool woken = true;
    mutexLock(&worker->control_mutex);
    if (worker->loop != NULL)
    {
        woken = wloopRequestStop(worker->loop);
    }
    mutexUnlock(&worker->control_mutex);

    return woken;
}

bool workerPostControlEvent(worker_t *worker, wevent_t *ev)
{
    if (worker == NULL || ev == NULL || ! worker->has_event_loop)
    {
        return false;
    }

    /*
     * Same rule as workerRequestStop(): worker->loop is only stable while
     * control_mutex is held, because the owning thread detaches it under this
     * lock before destroying it. Posting inside the lock is what keeps a control
     * event from reaching a loop that is being torn down.
     */
    bool posted = false;
    mutexLock(&worker->control_mutex);
    if (worker->loop != NULL)
    {
        ev->loop = worker->loop;
        posted   = wloopPostControlEvent(worker->loop, ev);
    }
    mutexUnlock(&worker->control_mutex);

    return posted;
}

void workerDestroyOwnResources(worker_t *worker)
{
    if (worker == NULL)
    {
        return;
    }

    // One-shot: a worker that already tore itself down must not be torn down
    // again by the shutdown sequence.
    if (atomicExchangeExplicit(&worker->resources_destroyed, true, memory_order_acq_rel))
    {
        return;
    }

    // Detach the loop under control_mutex so no concurrent workerRequestStop()
    // can be holding it while it is destroyed below.
    mutexLock(&worker->control_mutex);
    wloop_t *loop = worker->loop;
    worker->loop  = NULL;
    mutexUnlock(&worker->control_mutex);

    if (loop != NULL)
    {
        if (worker->wid == 0)
        {
            globalstateStopSystemLoadSampler();
        }

        /*
         * Keep this order: asyncdnsCleanup() still owns timers and c-ares
         * socket watches registered on the loop, so it must run while the
         * event loop and its wio/timer storage are still alive.
         */
        nodemanagerStopWorkerResources(worker->wid);
        socketmanagerDrainUdpIdleForWorker(worker->wid);
        socketmanagerCloseListenersForLoop(loop);
        asyncdnsCleanup(&worker->dns_resolver);
        workerMessagesCleanupPending(worker);
        wloopDestroy(&loop);
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

    worker->wios_pool    = NULL;
    worker->context_pool = NULL;
    worker->buffer_pool  = NULL;

    workerLifecycleAdvance(worker, kWorkerLifecycleExited);
}

void workerJoin(worker_t *worker)
{
    if (worker->thread_valid)
    {
        safeThreadJoin(worker->thread);
        worker->thread_valid = false;
    }
    workerLifecycleAdvance(worker, kWorkerLifecycleJoined);
}

void workerExitJoin(worker_t *worker)
{

    discard workerRequestStop(worker);
    workerJoin(worker);
}

void workerInit(worker_t *worker, wid_t wid, bool eventloop)
{
    *worker = (worker_t) {.wid = wid, .has_event_loop = eventloop};

    mutexInit(&worker->control_mutex);
    atomicStoreRelaxed(&worker->lifecycle, (w_atomic_int_value_t) kWorkerLifecycleInitialized);
    atomicStoreRelaxed(&worker->resources_destroyed, false);

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

    workerLifecycleAdvance(worker, kWorkerLifecycleRunning);

    while (atomicLoadExplicit(&GSTATE.workers_run_flag, memory_order_acquire) == false)
    {
        if (UNLIKELY(workerStopRequested(worker) || isApplicationTerminating()))
        {
            workerDestroyOwnResources(worker);
            LOGD("Worker %d exited", wid);
            return;
        }
        // wait for the main thread to set the flag
        wwSleepMS(10);
    }

    int loop_result = wloopRun(worker->loop);
    if (UNLIKELY(loop_result != kWLoopRunOk && ! isApplicationTerminating()))
    {
        /*
         * Category B (orderly runtime failure): the loop is gone but this
         * thread's state is structurally valid, so log, request an orderly
         * process shutdown and unwind through the normal cleanup path below.
         * Worker 0 runs the real teardown and joins this thread; terminating
         * here would skip every registered cleanup callback.
         */
        LOGF("Worker %d event loop exited with error %d", wid, loop_result);
        if (! requestProgramShutdown(1))
        {
            // No worker-0 handoff is available: release what this thread owns,
            // then hard-abort rather than continue with a dead event loop.
            workerDestroyOwnResources(worker);
            abortProgramNow(1);
        }
    }

    workerDestroyOwnResources(worker);

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
wthread_error_t workerSpawn(worker_t *worker)
{
    assert(! worker->thread_valid);
    wthread_error_t error = threadCreate(&worker->thread, worker_thread, worker);
    if (error == kWThreadErrorNone)
    {
        worker->thread_valid = true;
    }
    return error;
}
