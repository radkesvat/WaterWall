#pragma once

#include "lifecycle.h"
#include "wlibc.h"

typedef enum application_shutdown_phase_e
{
    kApplicationShutdownRunning = 0,
    kApplicationShutdownRequested,
    kApplicationShutdownClosingAdmissions,
    kApplicationShutdownQuiescingWorkers,
    kApplicationShutdownQuiescingExternalProducers,
    kApplicationShutdownDrainingWorkers,
    kApplicationShutdownStoppingComponents,
    kApplicationShutdownDestroyingWorkers,
    kApplicationShutdownFinalizing
} application_shutdown_phase_e;

typedef enum application_shutdown_reason_e
{
    kApplicationShutdownReasonNone = 0,
    kApplicationShutdownReasonProgrammatic,
    kApplicationShutdownReasonSignal,
    kApplicationShutdownReasonWorkerFailure,
    kApplicationShutdownReasonSubsystemFailure,
    kApplicationShutdownReasonStartupFailure
} application_shutdown_reason_e;

typedef enum application_shutdown_request_result_e
{
    kApplicationShutdownRequestUnavailable = 0,
    kApplicationShutdownRequestAcceptedWakeDelivered,
    kApplicationShutdownRequestAcceptedWakeDegraded,
    kApplicationShutdownRequestAlreadyAccepted
} application_shutdown_request_result_e;

typedef struct application_shutdown_snapshot_s
{
    application_shutdown_reason_e reason;
    ww_lifecycle_context_t        cleanup_context;
    int                           exit_code;
} application_shutdown_snapshot_t;

typedef struct application_shutdown_s application_shutdown_t;

application_shutdown_t *applicationShutdownCreate(void);
void                    applicationShutdownDestroy(void);
void                    applicationShutdownSet(application_shutdown_t *controller);

bool applicationShutdownRequest(int exit_code, application_shutdown_reason_e reason);
bool applicationShutdownRequestPreservingAcceptedStatus(int exit_code, application_shutdown_reason_e reason);
application_shutdown_request_result_e applicationShutdownRequestTyped(int                           exit_code,
                                                                      application_shutdown_reason_e reason);
application_shutdown_request_result_e applicationShutdownAcceptSignal(int signum);
void applicationShutdownRecordFailure(int exit_code, application_shutdown_reason_e reason);
bool applicationShutdownCommitRuntime(void);
bool applicationShutdownGetSelectedContext(ww_lifecycle_context_t *context);
bool applicationShutdownRuntimeCommitted(void);

application_shutdown_phase_e  applicationShutdownGetPhase(void);
application_shutdown_reason_e applicationShutdownGetReason(void);
int                           applicationShutdownGetExitCode(void);
bool                          applicationShutdownWasRequested(void);

void applicationShutdownAdvancePhase(application_shutdown_phase_e phase);
bool applicationShutdownBeginFinalizing(application_shutdown_snapshot_t *snapshot);
void applicationShutdownFatalStatusEscalate(int exit_code);
int  applicationShutdownFatalStatusSnapshot(int fallback_exit_code);
void applicationShutdownCoordinate(void);

#ifdef APPLICATION_SHUTDOWN_TEST_HOOKS
void applicationShutdownTestSetBeforePublicationHook(void (*hook)(void *), void *context);
#endif
