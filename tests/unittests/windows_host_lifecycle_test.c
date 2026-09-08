#include "wwapi.h"

#include "global_state_internal.h"
#include "host_lifecycle_windows.h"
#include "startup_options.h"

#include <inttypes.h>

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        ExitProcess(1);
    }
}

static uintptr_t inheritedCopy(HANDLE handle)
{
    HANDLE copy = NULL;
    require(DuplicateHandle(GetCurrentProcess(), handle, GetCurrentProcess(), &copy, 0U, TRUE, DUPLICATE_SAME_ACCESS) !=
                FALSE,
            "could not duplicate inherited event");
    return (uintptr_t) copy;
}

static HANDLE eventCreate(bool signaled)
{
    HANDLE event = CreateEventW(NULL, TRUE, signaled, NULL);
    require(event != NULL, "could not create event");
    return event;
}

static void fixtureCreate(worker_t workers[2], wloop_t *loop)
{
    memoryZero(workers, sizeof(worker_t) * 2U);
    memoryZero(loop, sizeof(*loop));
    workers[0].wid            = 0;
    workers[0].has_event_loop = true;
    workers[0].loop           = loop;
    mutexInit(&workers[0].control_mutex);
    condmutexInit(&workers[0].control_condition_mutex);
    condvarInit(&workers[0].control_condition);
    atomic_init(&workers[0].lifecycle, kWorkerLifecycleInitialized);
    atomic_init(&workers[0].message_admission_open, true);
    mutexInit(&loop->normal_admission_mutex);
    mutexInit(&loop->custom_events_mutex);
    atomic_init(&loop->normal_admission_open, true);
    atomic_init(&loop->stop_requested, false);
    loop->wakeup_pending    = true;
    GSTATE                  = (ww_global_state_t) {0};
    GSTATE.flag_initialized = true;
    GSTATE.workers          = workers;
    GSTATE.workers_count    = 2;
    atomic_init(&GSTATE.workers_run_flag, false);
    GSTATE.application_shutdown = applicationShutdownCreate();
    require(GSTATE.application_shutdown != NULL, "could not create controller");
}

static void fixtureDestroy(worker_t workers[2], wloop_t *loop)
{
    waterwallHostLifecycleDestroy();
    require(waterwallHostLifecycleStopEvent() == 0, "destroy retained an event");
    applicationShutdownDestroy();
    contvarDestroy(&workers[0].control_condition);
    condmutexDestroy(&workers[0].control_condition_mutex);
    mutexDestroy(&workers[0].control_mutex);
    mutexDestroy(&loop->normal_admission_mutex);
    mutexDestroy(&loop->custom_events_mutex);
    GSTATE = (ww_global_state_t) {0};
}

static void testArguments(void)
{
    char                       *valid[] = {"fixture", "--hosted", "--host-stop-event:123", "--host-ready-event:456"};
    waterwall_startup_options_t options = {0};
    require(waterwallStartupOptionsParse(4, valid, &options) == kWaterwallStartupArgumentsRun && options.hosted &&
                options.host_stop_event == 123U && options.host_ready_event == 456U,
            "valid lifecycle arguments rejected");
    require(waterwallStartupOptionsParse(3, valid, &options) == kWaterwallStartupArgumentsRun &&
                options.host_ready_event == 0,
            "optional readiness became mandatory or retained stale state");
    char *invalid[][5] = {
        {"fixture", "--hosted", NULL},
        {"fixture", "--host-stop-event:123", NULL},
        {"fixture", "--hosted", "--host-stop-event:0", NULL},
        {"fixture", "--hosted", "--host-stop-event:-2", NULL},
        {"fixture", "--hosted", "--host-stop-event:", NULL},
        {"fixture", "--hosted", "--host-stop-event:12x", NULL},
        {"fixture", "--hosted", "--host-stop-event:18446744073709551616", NULL},
        {"fixture", "--hosted", "--host-stop-event:123", "--hosted", NULL},
        {"fixture", "--hosted", "--host-stop-event:123", "--host-stop-event:124", NULL},
        {"fixture", "--hosted", "--host-stop-event:123", "--host-ready-event:123", NULL},
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
    {
        int count = 0;
        while (invalid[i][count] != NULL)
        {
            ++count;
        }
        require(waterwallStartupOptionsParse(count, invalid[i], &options) == kWaterwallStartupArgumentsExitFailure,
                "malformed lifecycle arguments accepted");
    }
}

static void testPresignaledStop(bool prior_failure)
{
    worker_t workers[2];
    wloop_t  loop;
    fixtureCreate(workers, &loop);
    if (prior_failure)
    {
        require(requestProgramShutdown(47), "prior failure was refused");
    }
    HANDLE stop  = eventCreate(true);
    HANDLE ready = eventCreate(false);
    require(waterwallHostLifecycleStart(inheritedCopy(stop), inheritedCopy(ready)), "pre-signaled setup failed");
    require(applicationShutdownWasRequested() && ! applicationShutdownCommitRuntime(),
            "pre-signaled stop allowed runtime commit");
    require(applicationShutdownGetExitCode() == (prior_failure ? 47 : 0), "stop replaced selected failure status");
    ww_lifecycle_context_t selected;
    require(applicationShutdownGetSelectedContext(&selected) && selected.scope == wwLifecycleStartupRollback()->scope,
            "precommit stop selected process cleanup");
    waterwallHostLifecycleCheckpoint();
    require(WaitForSingleObject(ready, 0U) == WAIT_TIMEOUT, "startup stop emitted readiness");
    fixtureDestroy(workers, &loop);
    CloseHandle(stop);
    CloseHandle(ready);
}

static void testWaiterAndJoin(bool request_stop)
{
    worker_t workers[2];
    wloop_t  loop;
    fixtureCreate(workers, &loop);
    HANDLE stop = eventCreate(false);
    require(waterwallHostLifecycleStart(inheritedCopy(stop), 0), "stop-only setup failed");
    DWORD flags = 0;
    require(GetHandleInformation((HANDLE) waterwallHostLifecycleStopEvent(), &flags) &&
                (flags & HANDLE_FLAG_INHERIT) == 0U,
            "runtime stop handle remains inheritable");
    require(! SetEvent((HANDLE) waterwallHostLifecycleStopEvent()) && GetLastError() == ERROR_ACCESS_DENIED,
            "runtime retained stop signaling authority");
    if (request_stop)
    {
        require(SetEvent(stop) != FALSE, "host could not request stop");
        const DWORD started = GetTickCount();
        while (! applicationShutdownWasRequested() && (DWORD) (GetTickCount() - started) < 5000U)
        {
            Sleep(1U);
        }
        require(applicationShutdownWasRequested() && applicationShutdownGetExitCode() == 0,
                "waiter did not publish orderly stop");
    }
    waterwallHostLifecycleDestroy();
    require(applicationShutdownWasRequested() == request_stop, "joining idle waiter requested process shutdown");
    fixtureDestroy(workers, &loop);
    CloseHandle(stop);
}

static void testSetupFailure(bool thread_creation)
{
    worker_t workers[2];
    wloop_t  loop;
    fixtureCreate(workers, &loop);
    HANDLE          stop       = eventCreate(false);
    HANDLE          ready      = eventCreate(false);
    const uintptr_t stop_copy  = inheritedCopy(stop);
    const uintptr_t ready_copy = inheritedCopy(ready);
    waterwallHostLifecycleTestFailSetup(thread_creation);
    require(! waterwallHostLifecycleStart(stop_copy, ready_copy), "injected setup failure succeeded");
    DWORD flags = 0;
    require(! GetHandleInformation((HANDLE) stop_copy, &flags) && ! GetHandleInformation((HANDLE) ready_copy, &flags) &&
                waterwallHostLifecycleStopEvent() == 0,
            "failed setup retained owned handles");
    require(! applicationShutdownWasRequested(), "setup failure chose a shutdown result before its owner");
    require(WaitForSingleObject(ready, 0U) == WAIT_TIMEOUT, "failed setup emitted readiness");
    fixtureDestroy(workers, &loop);
    CloseHandle(stop);
    CloseHandle(ready);
}

static DWORD WINAPI abandonMutex(void *context)
{
    require(WaitForSingleObject((HANDLE) context, 0U) == WAIT_OBJECT_0, "fixture could not acquire mutex");
    return 0; /* Native thread exit abandons the owned mutex. */
}

static void testInvalidHandles(void)
{
    worker_t workers[2];
    wloop_t  loop;
    fixtureCreate(workers, &loop);
    require(! waterwallHostLifecycleStart((uintptr_t) 0x12345678U, 0), "invalid stop handle accepted");
    /* A mapping can report signaled on Windows; it is not a dependable wait
     * failure fixture. An abandoned mutex produces a real abnormal wait result. */
    HANDLE mutex = CreateMutexW(NULL, FALSE, NULL);
    require(mutex != NULL, "could not create wait-failure mutex");
    HANDLE thread = CreateThread(NULL, 0, abandonMutex, mutex, 0, NULL);
    require(thread != NULL && WaitForSingleObject(thread, 5000U) == WAIT_OBJECT_0, "fixture did not abandon its mutex");
    CloseHandle(thread);
    require(! waterwallHostLifecycleStart(inheritedCopy(mutex), 0), "abandoned stop wait was accepted");
    require(ReleaseMutex(mutex) != FALSE, "fixture did not receive the abandoned mutex");
    CloseHandle(mutex);
    fixtureDestroy(workers, &loop);
}

static void testReadiness(bool signal_failure)
{
    worker_t workers[2];
    wloop_t  loop;
    fixtureCreate(workers, &loop);
    HANDLE stop  = eventCreate(false);
    HANDLE ready = signal_failure ? CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0U, 4096U, NULL)
                                  : eventCreate(false);
    require(ready != NULL, "could not create readiness handle");
    require(waterwallHostLifecycleStart(inheritedCopy(stop), inheritedCopy(ready)), "ready setup failed");
    require(applicationShutdownCommitRuntime(), "runtime commit refused");
    atomicStoreExplicit(&GSTATE.workers_run_flag, true, memory_order_release);
    waterwallHostLifecyclePublishReady();
    if (signal_failure)
    {
        ww_lifecycle_context_t selected;
        require(applicationShutdownGetExitCode() == 1 && applicationShutdownGetSelectedContext(&selected) &&
                    selected.scope == wwLifecycleProcessShutdown()->scope,
                "readiness failure did not select nonzero process shutdown");
    }
    else
    {
        require(WaitForSingleObject(ready, 0U) == WAIT_OBJECT_0, "readiness was not signaled");
        require(ResetEvent(ready) != FALSE, "could not reset test observer");
        waterwallHostLifecyclePublishReady();
        require(WaitForSingleObject(ready, 0U) == WAIT_TIMEOUT, "readiness was signaled twice");
    }
    fixtureDestroy(workers, &loop);
    CloseHandle(stop);
    CloseHandle(ready);
}

static void readyAfterPublication(void)
{
    require(applicationShutdownRuntimeCommitted() && atomicLoadExplicit(&GSTATE.workers_run_flag, memory_order_acquire),
            "readiness callback preceded runtime commit or worker publication");
    waterwallHostLifecyclePublishReady();
    require(requestProgramShutdown(0), "could not stop integration child");
}

static void runIntegrationChild(uintptr_t stop, uintptr_t ready)
{
    initWLibc();
    ww_construction_data_t data         = {0};
    data.workers_count                  = 2;
    data.ram_profile                    = kRamProfileS1Memory;
    data.mtu_size                       = 1500;
    data.internal_logger_data.log_level = "FATAL";
    data.core_logger_data.log_level     = "FATAL";
    data.network_logger_data.log_level  = "FATAL";
    data.dns_logger_data.log_level      = "FATAL";
    data.application_finalizer          = waterwallHostLifecycleDestroy;
    require(wwStartupSucceeded(createGlobalState(data)), "could not create integration runtime");
    require(waterwallHostLifecycleStart(stop, ready), "could not start integration lifecycle");
    globalstateRunMainThreadWithStartupHooks(waterwallHostLifecycleCheckpoint, readyAfterPublication);
    ExitProcess(2);
}

static void testPublicationIntegration(const char *executable)
{
    HANDLE    stop       = eventCreate(false);
    HANDLE    ready      = eventCreate(false);
    uintptr_t stop_copy  = inheritedCopy(stop);
    uintptr_t ready_copy = inheritedCopy(ready);
    char      command[MAX_PATH * 2U];
    int       count = snprintf(command,
                         sizeof(command),
                         "\"%s\" --integration-child %" PRIuPTR " %" PRIuPTR,
                         executable,
                         stop_copy,
                         ready_copy);
    require(count > 0 && (size_t) count < sizeof(command), "integration command is too long");
    STARTUPINFOA startup      = {0};
    startup.cb                = sizeof(startup);
    PROCESS_INFORMATION child = {0};
    require(CreateProcessA(executable, command, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &startup, &child),
            "could not create hidden integration child");
    CloseHandle((HANDLE) stop_copy);
    CloseHandle((HANDLE) ready_copy);
    require(WaitForSingleObject(child.hProcess, 30000U) == WAIT_OBJECT_0, "integration shutdown did not finish");
    DWORD exit_code = 1;
    require(GetExitCodeProcess(child.hProcess, &exit_code) && exit_code == 0,
            "integration child did not exit through the orderly coordinator");
    require(WaitForSingleObject(ready, 0U) == WAIT_OBJECT_0, "integration child did not publish readiness");
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);
    CloseHandle(stop);
    CloseHandle(ready);
}

int main(int argc, char **argv)
{
    if (argc == 4 && strcmp(argv[1], "--integration-child") == 0)
    {
        runIntegrationChild((uintptr_t) strtoull(argv[2], NULL, 10), (uintptr_t) strtoull(argv[3], NULL, 10));
        return 2;
    }
    testArguments();
    testPresignaledStop(false);
    testPresignaledStop(true);
    testWaiterAndJoin(false);
    testWaiterAndJoin(true);
    testSetupFailure(false);
    testSetupFailure(true);
    testInvalidHandles();
    testReadiness(false);
    testReadiness(true);
    testPublicationIntegration(argv[0]);
    return 0;
}
