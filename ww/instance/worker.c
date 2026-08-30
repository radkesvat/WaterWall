#include "worker.h"
#include "application_shutdown.h"
#include "context.h"
#include "global_state.h"
#include "managers/node_manager.h"
#include "managers/signal_manager.h"
#include "managers/socket_manager.h"
#include "tunnel.h"
#include "wevent.h"
#include "wfrand.h"
#include "wloop.h"
#include "worker_messages.h"
#include "wthread.h"

#include "loggers/internal_logger.h"

#include "loggers/dns_logger.h"

thread_local wid_t tl_wid = kInvalidWID;

bool workerWIDIsRegistered(wid_t wid)
{
    if (! GSTATE.flag_initialized || WORKERS == NULL || wid == kInvalidWID)
    {
        return false;
    }
    return wid < getTotalWorkersCount();
}

bool workerWIDIsEventWorker(wid_t wid)
{
    if (! workerWIDIsRegistered(wid))
    {
        return false;
    }
    return WORKERS[wid].has_event_loop;
}

bool currentThreadHasRegisteredWID(void)
{
    return workerWIDIsRegistered(getWID());
}

bool currentThreadIsEventWorker(void)
{
    return workerWIDIsEventWorker(getWID());
}

bool currentThreadIsEventWorkerWID(wid_t wid)
{
    return currentThreadIsEventWorker() && (getWID() == wid);
}

void workerBindCurrentThread(worker_t *worker)
{
    if (UNLIKELY(worker == NULL || ! GSTATE.flag_initialized || WORKERS == NULL))
    {
        LOGF("workerBindCurrentThread: null worker or global state uninitialized");
        abortProgramNow(1);
    }
    wid_t wid = worker->wid;
    if (UNLIKELY(wid >= getTotalWorkersCount() || worker != getWorker(wid)))
    {
        LOGF("workerBindCurrentThread: WID %u is out of bounds or worker pointer mismatch", wid);
        abortProgramNow(1);
    }

    wid_t current = getWID();
    if (current == wid)
    {
        return;
    }
    if (UNLIKELY(current != kInvalidWID))
    {
        LOGF("workerBindCurrentThread: thread already bound to worker %u, cannot rebind to %u", current, wid);
        abortProgramNow(1);
    }

    tl_wid      = wid;
    worker->tid = getTID();
}

void workerUnbindCurrentThread(void)
{
    tl_wid = kInvalidWID;
}

static void workerPublishLifecycleLocked(worker_t *worker, worker_lifecycle_e phase)
{
    condmutexLock(&worker->control_condition_mutex);
    const worker_lifecycle_e current =
        (worker_lifecycle_e) atomicLoadExplicit(&worker->lifecycle, memory_order_relaxed);
    if (current < phase)
    {
        // Publishes the lifecycle context installed before this phase.
        atomicStoreExplicit(&worker->lifecycle, (w_atomic_int_value_t) phase, memory_order_release);
        condvarBroadCast(&worker->control_condition);
    }
    condmutexUnlock(&worker->control_condition_mutex);
}

worker_lifecycle_e workerGetLifecycle(const worker_t *worker)
{
    assert(worker != NULL);
    return (worker_lifecycle_e) atomicLoadExplicit(&((worker_t *) worker)->lifecycle, memory_order_acquire);
}

bool workerQuiesceRequested(const worker_t *worker)
{
    return worker != NULL && workerGetLifecycle(worker) >= kWorkerLifecycleQuiesceRequested;
}

static worker_quiesce_request_result_e workerRequestQuiesceInternal(worker_t                     *worker,
                                                                    const ww_lifecycle_context_t *context,
                                                                    bool application_controller)
{
    if (worker == NULL || context == NULL)
    {
        return kWorkerQuiesceRequestUnavailable;
    }

    if (worker->wid == 0 && ! application_controller)
    {
        return kWorkerQuiesceRequestUnavailable;
    }

    bool               woken = true;
    worker_lifecycle_e lifecycle;
    mutexLock(&worker->control_mutex);
    lifecycle = workerGetLifecycle(worker);
    if (lifecycle >= kWorkerLifecycleTeardownRequested || (worker->has_event_loop && worker->loop == NULL))
    {
        mutexUnlock(&worker->control_mutex);
        return kWorkerQuiesceRequestUnavailable;
    }
    const bool already_requested = lifecycle >= kWorkerLifecycleQuiesceRequested;
    if (already_requested && (! worker->lifecycle_context_set || worker->lifecycle_context.scope != context->scope ||
                              worker->lifecycle_context.close_policy != context->close_policy))
    {
        mutexUnlock(&worker->control_mutex);
        return kWorkerQuiesceRequestUnavailable;
    }
    if (! worker->lifecycle_context_set)
    {
        worker->lifecycle_context     = *context;
        worker->lifecycle_context_set = true;
    }
    workerPublishLifecycleLocked(worker, kWorkerLifecycleQuiesceRequested);
    workerMessagesCloseAdmissionLocked(worker);
    if (worker->loop != NULL)
    {
        woken = wloopRequestQuiesce(worker->loop);
    }
    mutexUnlock(&worker->control_mutex);
    if (already_requested)
    {
        return kWorkerQuiesceRequestAlreadyAccepted;
    }
    return woken ? kWorkerQuiesceRequestAcceptedWakeDelivered : kWorkerQuiesceRequestAcceptedWakeDegraded;
}

worker_quiesce_request_result_e workerRequestQuiesceWithContextResult(worker_t                     *worker,
                                                                      const ww_lifecycle_context_t *context)
{
    return workerRequestQuiesceInternal(worker, context, false);
}

worker_quiesce_request_result_e workerInstallApplicationQuiesceRequest(worker_t                     *worker,
                                                                       const ww_lifecycle_context_t *context)
{
    if (worker == NULL || worker->wid != 0)
    {
        return kWorkerQuiesceRequestUnavailable;
    }
    return workerRequestQuiesceInternal(worker, context, true);
}

bool workerRequestQuiesceWithContext(worker_t *worker, const ww_lifecycle_context_t *context)
{
    return workerRequestQuiesceWithContextResult(worker, context) != kWorkerQuiesceRequestUnavailable;
}

worker_quiesce_request_result_e workerRequestQuiesceResult(worker_t *worker)
{
    return workerRequestQuiesceWithContextResult(worker, wwLifecycleProcessShutdown());
}

bool workerRequestQuiesce(worker_t *worker)
{
    return workerRequestQuiesceResult(worker) != kWorkerQuiesceRequestUnavailable;
}

static bool workerRequestPhase(worker_t *worker, worker_lifecycle_e required, worker_lifecycle_e requested)
{
    if (worker == NULL)
    {
        return false;
    }

    mutexLock(&worker->control_mutex);
    const worker_lifecycle_e current = workerGetLifecycle(worker);
    const bool               valid   = current >= required;
    if (valid)
    {
        workerPublishLifecycleLocked(worker, requested);
    }
    mutexUnlock(&worker->control_mutex);
    return valid;
}

bool workerRequestDrain(worker_t *worker)
{
    return workerRequestPhase(worker, kWorkerLifecycleQuiesced, kWorkerLifecycleDrainRequested);
}

bool workerRequestTeardown(worker_t *worker)
{
    return workerRequestPhase(worker, kWorkerLifecycleDrained, kWorkerLifecycleTeardownRequested);
}

bool workerWaitForPhase(worker_t *worker, worker_lifecycle_e phase, uint32_t timeout_ms)
{
    if (worker == NULL)
    {
        return false;
    }

    const unsigned int started = getTickMS();
    condmutexLock(&worker->control_condition_mutex);
    while (workerGetLifecycle(worker) < phase)
    {
        const unsigned int elapsed = getTickMS() - started;
        if (elapsed >= timeout_ms ||
            ! condvarWaitFor(&worker->control_condition, &worker->control_condition_mutex, timeout_ms - elapsed))
        {
            condmutexUnlock(&worker->control_condition_mutex);
            return workerGetLifecycle(worker) >= phase;
        }
    }
    condmutexUnlock(&worker->control_condition_mutex);
    return true;
}

static void workerWaitForPhaseIndefinite(worker_t *worker, worker_lifecycle_e phase)
{
    condmutexLock(&worker->control_condition_mutex);
    while (workerGetLifecycle(worker) < phase)
    {
        condvarWait(&worker->control_condition, &worker->control_condition_mutex);
    }
    condmutexUnlock(&worker->control_condition_mutex);
}

static void workerPublishLifecycle(worker_t *worker, worker_lifecycle_e phase)
{
    mutexLock(&worker->control_mutex);
    workerPublishLifecycleLocked(worker, phase);
    mutexUnlock(&worker->control_mutex);
}

void workerPerformQuiesce(worker_t *worker, const ww_lifecycle_context_t *context)
{
    assert(worker != NULL);
    assert(worker->has_event_loop);
    assert(currentThreadIsEventWorkerWID(worker->wid));

    if (workerGetLifecycle(worker) >= kWorkerLifecycleQuiesced)
    {
        return;
    }

    if (worker->wid == 0)
    {
        globalstateStopSystemLoadSampler();
        socketmanagerCloseListenersForLoop(worker->loop);
    }
    socketmanagerQuiesceWorker(worker->wid);
    nodemanagerQuiesceWorker(worker->wid, context);
    asyncdnsCleanup(&worker->dns_resolver);
    workerMessagesCleanupPending(worker);
    wloopQuiesceNormalWork(worker->loop);
    workerPublishLifecycle(worker, kWorkerLifecycleQuiesced);
}

void workerPerformDrain(worker_t *worker, const ww_lifecycle_context_t *context)
{
    assert(worker != NULL);
    assert(worker->has_event_loop);
    assert(currentThreadIsEventWorkerWID(worker->wid));
    assert(workerGetLifecycle(worker) >= kWorkerLifecycleDrainRequested);

    if (workerGetLifecycle(worker) >= kWorkerLifecycleDrained)
    {
        return;
    }

    socketmanagerDrainUdpIdleForWorker(worker->wid);
    nodemanagerStopWorkerResources(worker->wid, context);
    workerPublishLifecycle(worker, kWorkerLifecycleDrained);
}

static void workerDestroyPools(worker_t *worker)
{
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
}

void workerPerformTeardown(worker_t *worker)
{
    assert(worker != NULL);
    assert(worker->has_event_loop);
    assert(currentThreadIsEventWorkerWID(worker->wid));
    assert(workerGetLifecycle(worker) >= kWorkerLifecycleTeardownRequested);

    if (atomicExchangeExplicit(&worker->resources_destroyed, true, memory_order_relaxed))
    {
        return;
    }

    wloop_t                *loop  = NULL;
    worker_message_queue_t *queue = NULL;
    workerMessagesCloseAdmissionAndDetach(worker, &loop, &queue);
    workerMessagesDestroyDetached(queue);
    wloopDestroy(&loop);
    workerDestroyPools(worker);
    workerPublishLifecycle(worker, kWorkerLifecycleExited);
}

void workerDestroyPseudoWorkerResources(worker_t *worker)
{
    assert(worker != NULL);
    assert(! worker->has_event_loop);

    if (atomicExchangeExplicit(&worker->resources_destroyed, true, memory_order_relaxed))
    {
        return;
    }

    workerMessagesDestroy(worker);
    workerDestroyPools(worker);
    workerPublishLifecycle(worker, kWorkerLifecycleExited);
}

void workerDestroyUnstartedResources(worker_t *worker)
{
    assert(worker != NULL);
    assert(worker->has_event_loop);
    assert(! worker->thread_valid);
    assert(workerGetLifecycle(worker) == kWorkerLifecycleInitialized);

    if (atomicExchangeExplicit(&worker->resources_destroyed, true, memory_order_relaxed))
    {
        return;
    }

    asyncdnsCleanup(&worker->dns_resolver);
    wloop_t                *loop  = NULL;
    worker_message_queue_t *queue = NULL;
    workerMessagesCloseAdmissionAndDetach(worker, &loop, &queue);
    workerMessagesDestroyDetached(queue);
    wloopDestroy(&loop);
    workerDestroyPools(worker);
    workerPublishLifecycle(worker, kWorkerLifecycleJoined);
}

bool workerJoin(worker_t *worker)
{
    if (worker->thread_valid)
    {
        if (! safeThreadJoin(worker->thread))
        {
            return false;
        }
        worker->thread_valid = false;
    }
    workerPublishLifecycle(worker, kWorkerLifecycleJoined);
    return true;
}

bool workerExitJoin(worker_t *worker)
{
    discard workerRequestQuiesce(worker);
    if (! workerWaitForPhase(worker, kWorkerLifecycleQuiesced, 30000) || ! workerRequestDrain(worker) ||
        ! workerWaitForPhase(worker, kWorkerLifecycleDrained, 30000) || ! workerRequestTeardown(worker))
    {
        return false;
    }
    return workerJoin(worker);
}

bool workerTryCreateCorePools(worker_t *worker)
{
    assert(worker != NULL);

    threadsafe_generic_pool_t *wios_pool =
        threadsafegenericpoolCreateWithDefaultAllocatorAndCapacity(GSTATE.masterpool_wios, sizeof(wio_t), RAM_PROFILE);
    generic_pool_t *context_pool = genericpoolCreateWithDefaultAllocatorAndCapacity(
        GSTATE.masterpool_context_pools, sizeof(context_t), RAM_PROFILE);

    if (UNLIKELY(wios_pool == NULL || context_pool == NULL))
    {
        threadsafegenericpoolDestroy(wios_pool);
        genericpoolDestroy(context_pool);
        return false;
    }

    worker->wios_pool    = wios_pool;
    worker->context_pool = context_pool;
    return true;
}

bool workerTryCreateBufferPool(worker_t *worker)
{
    assert(worker != NULL);
    assert(worker->buffer_pool == NULL);

    buffer_pool_t *pool = bufferpoolCreate(GSTATE.masterpool_buffer_pools_large,
                                           GSTATE.masterpool_buffer_pools_small,
                                           RAM_PROFILE,
                                           PROPER_LARGE_BUFFER_SIZE(RAM_PROFILE),
                                           SMALL_BUFFER_SIZE);
    if (UNLIKELY(pool == NULL))
    {
        return false;
    }

    worker->buffer_pool = pool;
    return true;
}

static void workerRollbackInitialization(worker_t *worker)
{
    if (worker->has_event_loop)
    {
        workerDestroyUnstartedResources(worker);
    }
    else
    {
        workerDestroyPseudoWorkerResources(worker);
    }
}

bool workerInit(worker_t *worker, wid_t wid, bool eventloop)
{
    *worker = (worker_t) {.wid = wid, .has_event_loop = eventloop};

    mutexInit(&worker->control_mutex);
    condmutexInit(&worker->control_condition_mutex);
    condvarInit(&worker->control_condition);
    atomicStoreRelaxed(&worker->lifecycle, (w_atomic_int_value_t) kWorkerLifecycleInitialized);
    atomicStoreRelaxed(&worker->resources_destroyed, false);
    atomicStoreRelaxed(&worker->message_admission_open, false);

    if (UNLIKELY(! workerMessagesInit(worker)))
    {
        LOGF("Worker %d: failed to construct worker-message queue metadata", (int) wid);
        workerRollbackInitialization(worker);
        return false;
    }

    if (UNLIKELY(! workerTryCreateCorePools(worker)))
    {
        LOGF("Worker %d: failed to construct WIO/context pool metadata", (int) wid);
        workerRollbackInitialization(worker);
        return false;
    }

    if (UNLIKELY(! workerTryCreateBufferPool(worker)))
    {
        LOGF("Worker %d: failed to construct buffer-pool metadata", (int) wid);
        workerRollbackInitialization(worker);
        return false;
    }

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
            workerRollbackInitialization(worker);
            return false;
        }
        if (UNLIKELY(! workerMessagesOpenAdmission(worker)))
        {
            LOGF("Worker %d: message admission could not be opened from the initialized state", (int) wid);
            workerRollbackInitialization(worker);
            return false;
        }
    }
    else
    {
        worker->loop = NULL;
    }
    return true;
}

void workerRun(worker_t *worker)
{
    workerBindCurrentThread(worker);
    wid_t wid = worker->wid;
    frandInit();

    workerPublishLifecycle(worker, kWorkerLifecycleRunning);

    bool runtime_published = false;
    // Acquires the fully initialized global and worker registries published by worker 0.
    while (atomicLoadExplicit(&GSTATE.workers_run_flag, memory_order_acquire) == false)
    {
        if (UNLIKELY(workerQuiesceRequested(worker)))
        {
            break;
        }
        wwSleepMS(10);
    }
    runtime_published = atomicLoadExplicit(&GSTATE.workers_run_flag, memory_order_acquire);

    wloop_run_result_e loop_result = kWLoopRunQuiesced;
    if (runtime_published && ! workerQuiesceRequested(worker))
    {
        loop_result = wloopRun(worker->loop);
    }
    if (UNLIKELY(loop_result != kWLoopRunQuiesced))
    {
        LOGF("Worker %d event loop exited with error %d", wid, loop_result);
        if (wid != 0)
        {
            discard workerRequestQuiesceWithContextResult(worker, wwLifecycleProcessShutdown());
        }
        if (applicationShutdownRequestTyped(1, kApplicationShutdownReasonWorkerFailure) ==
            kApplicationShutdownRequestUnavailable)
        {
            abortProgramNow(1);
        }
    }

    if (wid == 0)
    {
        return;
    }

    mutexLock(&worker->control_mutex);
    if (! worker->lifecycle_context_set)
    {
        worker->lifecycle_context     = *wwLifecycleProcessShutdown();
        worker->lifecycle_context_set = true;
    }
    const ww_lifecycle_context_t context = worker->lifecycle_context;
    mutexUnlock(&worker->control_mutex);

    workerPerformQuiesce(worker, &context);
    workerWaitForPhaseIndefinite(worker, kWorkerLifecycleDrainRequested);
    workerPerformDrain(worker, &context);
    workerWaitForPhaseIndefinite(worker, kWorkerLifecycleTeardownRequested);
    workerPerformTeardown(worker);

    LOGD("Worker %d exited", wid);
    frandThreadCleanup();
    workerUnbindCurrentThread();
}

int workerResolveDomainServiceAsync(wid_t wid, const char *domain, const char *service, int socktype, dns_resolve_cb cb,
                                    void *userdata)
{
    /*
     * The resolver channel is worker-local c-ares state with no internal
     * locking, and its socket watches live on this worker's loop. Only the
     * owning event worker may submit to it, and that has to hold in release
     * builds too: a foreign worker or an unregistered device thread reaching
     * another worker's resolver corrupts it silently. Fail with a c-ares status
     * instead of relying on an assertion.
     */
    if (UNLIKELY(wid >= getWorkersCount() || ! currentThreadIsEventWorkerWID(wid)))
    {
        return ARES_ENOTINITIALIZED;
    }

    worker_t *worker = getWorker(wid);
    if (UNLIKELY(worker->loop == NULL || ! wloopNormalDispatchAllowed(worker->loop)))
    {
        // The worker is tearing down; its resolver was already cleaned up.
        return ARES_ECANCELLED;
    }

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
