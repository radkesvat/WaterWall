#include "application_shutdown.h"

#include "global_state.h"
#include "worker.h"

struct application_shutdown_s
{
    wmutex_t                      mutex;
    application_shutdown_phase_e  phase;
    application_shutdown_reason_e reason;
    ww_lifecycle_context_t        cleanup_context;
    int                           exit_code;
    bool                          runtime_committed;
    bool                          cleanup_context_set;
    bool                          status_frozen;
    bool                          coordinator_claimed;
};

static application_shutdown_t *application_shutdown_gstate;
static atomic_int              fatal_exit_status;

#if WW_HAVE_C11_ATOMICS
_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "fatal shutdown status requires an always-lock-free atomic_int");
#elif defined(OS_WIN)
/* The fallback atomic_int is pointer-width and its compare/exchange and load map
 * directly to the lock-free Windows Interlocked pointer primitives. */
_Static_assert(sizeof(atomic_int) == sizeof(void *), "fatal shutdown status must use an Interlocked-width object");
#endif

#ifdef APPLICATION_SHUTDOWN_TEST_HOOKS
static void (*before_publication_hook)(void *);
static void *before_publication_hook_context;

void applicationShutdownTestSetBeforePublicationHook(void (*hook)(void *), void *context)
{
    before_publication_hook         = hook;
    before_publication_hook_context = context;
}
#endif

void applicationShutdownFatalStatusEscalate(int exit_code)
{
    if (exit_code == 0)
    {
        return;
    }

    w_atomic_int_value_t expected = 0;
    discard              atomicCompareExchangeExplicit(
        &fatal_exit_status, &expected, (w_atomic_int_value_t) exit_code, memory_order_relaxed, memory_order_relaxed);
}

int applicationShutdownFatalStatusSnapshot(int fallback_exit_code)
{
    const int recorded = (int) atomicLoadExplicit(&fatal_exit_status, memory_order_relaxed);
    return recorded != 0 ? recorded : fallback_exit_code;
}

static void applicationShutdownArbitrateStatusLocked(application_shutdown_t *controller, int exit_code,
                                                     application_shutdown_reason_e reason)
{
    if (! controller->status_frozen && controller->exit_code == 0 && exit_code != 0)
    {
        controller->exit_code = exit_code;
        applicationShutdownFatalStatusEscalate(exit_code);
    }
    if (controller->reason == kApplicationShutdownReasonNone && reason != kApplicationShutdownReasonNone)
    {
        controller->reason = reason;
    }
}

void applicationShutdownAdvancePhase(application_shutdown_phase_e phase)
{
    application_shutdown_t *controller = application_shutdown_gstate;
    assert(controller != NULL);

    mutexLock(&controller->mutex);
    if (controller->phase < phase)
    {
        controller->phase = phase;
    }
    mutexUnlock(&controller->mutex);
}

bool applicationShutdownBeginFinalizing(application_shutdown_snapshot_t *snapshot)
{
    application_shutdown_t *controller = application_shutdown_gstate;
    if (controller == NULL || snapshot == NULL)
    {
        return false;
    }

    mutexLock(&controller->mutex);
    if (controller->phase != kApplicationShutdownDestroyingWorkers || controller->status_frozen)
    {
        mutexUnlock(&controller->mutex);
        return false;
    }
    controller->phase         = kApplicationShutdownFinalizing;
    controller->status_frozen = true;
    snapshot->reason          = controller->reason;
    snapshot->cleanup_context = controller->cleanup_context;
    snapshot->exit_code       = controller->exit_code;
    mutexUnlock(&controller->mutex);
    return true;
}

application_shutdown_t *applicationShutdownCreate(void)
{
    assert(application_shutdown_gstate == NULL);

    application_shutdown_t *controller = memoryAllocateZero(sizeof(*controller));
    if (controller == NULL)
    {
        return NULL;
    }
    if (! mutexTryInit(&controller->mutex))
    {
        memoryFree(controller);
        return NULL;
    }

    controller->phase           = kApplicationShutdownRunning;
    controller->reason          = kApplicationShutdownReasonNone;
    application_shutdown_gstate = controller;
    return controller;
}

void applicationShutdownSet(application_shutdown_t *controller)
{
    assert(application_shutdown_gstate == NULL);
    application_shutdown_gstate = controller;
}

void applicationShutdownDestroy(void)
{
    application_shutdown_t *controller = application_shutdown_gstate;
    if (controller == NULL)
    {
        return;
    }

    mutexDestroy(&controller->mutex);
    memoryFree(controller);
    application_shutdown_gstate = NULL;
}

static application_shutdown_request_result_e applicationShutdownRequestInternal(int                           exit_code,
                                                                                application_shutdown_reason_e reason,
                                                                                bool update_accepted_status)
{
    application_shutdown_t *controller = application_shutdown_gstate;
    if (controller == NULL)
    {
        return kApplicationShutdownRequestUnavailable;
    }

    mutexLock(&controller->mutex);
    if (controller->phase != kApplicationShutdownRunning)
    {
        if (update_accepted_status)
        {
            applicationShutdownArbitrateStatusLocked(controller, exit_code, reason);
        }
        mutexUnlock(&controller->mutex);
        return kApplicationShutdownRequestAlreadyAccepted;
    }

    if (! GSTATE.flag_initialized || WORKERS == NULL || WORKERS_COUNT <= WORKER_ADDITIONS)
    {
        mutexUnlock(&controller->mutex);
        return kApplicationShutdownRequestUnavailable;
    }

    const ww_lifecycle_context_t *context =
        controller->runtime_committed ? wwLifecycleProcessShutdown() : wwLifecycleStartupRollback();
    /* Controller-to-worker is the shutdown lock order. Worker failure paths
     * release control_mutex before publishing into this controller. */
    const worker_quiesce_request_result_e worker_result = workerInstallApplicationQuiesceRequest(&WORKERS[0], context);
    if (worker_result == kWorkerQuiesceRequestUnavailable)
    {
        mutexUnlock(&controller->mutex);
        return kApplicationShutdownRequestUnavailable;
    }

#ifdef APPLICATION_SHUTDOWN_TEST_HOOKS
    if (before_publication_hook != NULL)
    {
        before_publication_hook(before_publication_hook_context);
    }
#endif

    applicationShutdownArbitrateStatusLocked(controller, exit_code, reason);
    controller->cleanup_context     = *context;
    controller->cleanup_context_set = true;
    controller->phase               = kApplicationShutdownRequested;
    mutexUnlock(&controller->mutex);

    if (worker_result == kWorkerQuiesceRequestAcceptedWakeDelivered)
    {
        return kApplicationShutdownRequestAcceptedWakeDelivered;
    }
    return kApplicationShutdownRequestAcceptedWakeDegraded;
}

bool applicationShutdownCommitRuntime(void)
{
    application_shutdown_t *controller = application_shutdown_gstate;
    if (controller == NULL)
    {
        return false;
    }

    mutexLock(&controller->mutex);
    const bool committed = controller->phase == kApplicationShutdownRunning;
    if (committed)
    {
        controller->runtime_committed = true;
    }
    mutexUnlock(&controller->mutex);
    return committed;
}

bool applicationShutdownGetSelectedContext(ww_lifecycle_context_t *context)
{
    application_shutdown_t *controller = application_shutdown_gstate;
    if (controller == NULL || context == NULL)
    {
        return false;
    }

    mutexLock(&controller->mutex);
    const bool selected = controller->cleanup_context_set;
    if (selected)
    {
        *context = controller->cleanup_context;
    }
    mutexUnlock(&controller->mutex);
    return selected;
}

bool applicationShutdownRuntimeCommitted(void)
{
    application_shutdown_t *controller = application_shutdown_gstate;
    if (controller == NULL)
    {
        return false;
    }

    mutexLock(&controller->mutex);
    const bool committed = controller->runtime_committed;
    mutexUnlock(&controller->mutex);
    return committed;
}

bool applicationShutdownRequest(int exit_code, application_shutdown_reason_e reason)
{
    return applicationShutdownRequestTyped(exit_code, reason) != kApplicationShutdownRequestUnavailable;
}

application_shutdown_request_result_e applicationShutdownRequestTyped(int                           exit_code,
                                                                      application_shutdown_reason_e reason)
{
    return applicationShutdownRequestInternal(exit_code, reason, true);
}

bool applicationShutdownRequestPreservingAcceptedStatus(int exit_code, application_shutdown_reason_e reason)
{
    return applicationShutdownRequestInternal(exit_code, reason, false) != kApplicationShutdownRequestUnavailable;
}

application_shutdown_request_result_e applicationShutdownAcceptSignal(int signum)
{
    return applicationShutdownRequestTyped(128 + signum, kApplicationShutdownReasonSignal);
}

void applicationShutdownRecordFailure(int exit_code, application_shutdown_reason_e reason)
{
    discard applicationShutdownRequestInternal(exit_code, reason, true);
}

application_shutdown_phase_e applicationShutdownGetPhase(void)
{
    application_shutdown_t *controller = application_shutdown_gstate;
    if (controller == NULL)
    {
        return kApplicationShutdownRunning;
    }

    mutexLock(&controller->mutex);
    const application_shutdown_phase_e phase = controller->phase;
    mutexUnlock(&controller->mutex);
    return phase;
}

application_shutdown_reason_e applicationShutdownGetReason(void)
{
    application_shutdown_t *controller = application_shutdown_gstate;
    if (controller == NULL)
    {
        return kApplicationShutdownReasonNone;
    }

    mutexLock(&controller->mutex);
    const application_shutdown_reason_e reason = controller->reason;
    mutexUnlock(&controller->mutex);
    return reason;
}

int applicationShutdownGetExitCode(void)
{
    application_shutdown_t *controller = application_shutdown_gstate;
    if (controller == NULL)
    {
        return 0;
    }

    mutexLock(&controller->mutex);
    const int exit_code = controller->exit_code;
    mutexUnlock(&controller->mutex);
    return exit_code;
}

bool applicationShutdownWasRequested(void)
{
    return applicationShutdownGetPhase() != kApplicationShutdownRunning;
}

void applicationShutdownCoordinate(void)
{
    application_shutdown_t *controller = application_shutdown_gstate;
    if (controller == NULL)
    {
        return;
    }

    if (applicationShutdownGetPhase() == kApplicationShutdownRunning &&
        applicationShutdownRequestTyped(1, kApplicationShutdownReasonWorkerFailure) ==
            kApplicationShutdownRequestUnavailable)
    {
        abortProgramNow(1);
    }

    mutexLock(&controller->mutex);
    if (controller->coordinator_claimed)
    {
        mutexUnlock(&controller->mutex);
        return;
    }
    controller->coordinator_claimed = true;
    assert(controller->phase != kApplicationShutdownRunning);
    assert(controller->cleanup_context_set);
    mutexUnlock(&controller->mutex);

    applicationShutdownAdvancePhase(kApplicationShutdownClosingAdmissions);
    globalstateRunShutdownSequence();

    application_shutdown_snapshot_t snapshot;
    if (! applicationShutdownBeginFinalizing(&snapshot))
    {
        abortProgramNow(1);
    }
    finishGlobalState(&snapshot);
}
