#include "wwapi.h"

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        ExitProcess(1);
    }
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
    loop->wakeup_pending = true;

    GSTATE                      = (ww_global_state_t) {0};
    GSTATE.flag_initialized     = true;
    GSTATE.workers              = workers;
    GSTATE.workers_count        = 2;
    GSTATE.application_shutdown = applicationShutdownCreate();
    GSTATE.signal_manager       = signalmanagerCreate();
    require(GSTATE.application_shutdown != NULL && GSTATE.signal_manager != NULL,
            "failed to create the Windows console shutdown fixture");
}

static void fixtureDestroy(worker_t workers[2], wloop_t *loop)
{
    signalmanagerDestroy();
    applicationShutdownDestroy();
    contvarDestroy(&workers[0].control_condition);
    condmutexDestroy(&workers[0].control_condition_mutex);
    mutexDestroy(&workers[0].control_mutex);
    mutexDestroy(&loop->normal_admission_mutex);
    mutexDestroy(&loop->custom_events_mutex);
    GSTATE = (ww_global_state_t) {0};
}

static void runFirstEventCase(void)
{
    worker_t workers[2];
    wloop_t  loop;
    fixtureCreate(workers, &loop);

    require(signalmanagerTestDispatchWindowsConsoleEvent(CTRL_C_EVENT), "Ctrl+C was not handled");
    require(applicationShutdownGetPhase() == kApplicationShutdownRequested,
            "Ctrl+C did not publish a durable shutdown request");
    require(applicationShutdownGetReason() == kApplicationShutdownReasonSignal,
            "Ctrl+C did not preserve the signal request origin");
    require(applicationShutdownGetExitCode() == 130, "Ctrl+C published the wrong exit status");

    fixtureDestroy(workers, &loop);
}

static void runSecondEventChild(void)
{
    worker_t workers[2];
    wloop_t  loop;
    fixtureCreate(workers, &loop);
    require(signalmanagerTestDispatchWindowsConsoleEvent(CTRL_C_EVENT), "first Ctrl+C was not handled");
    signalmanagerTestDispatchWindowsConsoleEvent(CTRL_BREAK_EVENT);
    ExitProcess(2);
}

static void runSecondEventCase(const char *executable)
{
    char command[MAX_PATH * 2U];
    int  command_length = snprintf(command, sizeof(command), "\"%s\" --second-event-child", executable);
    require(command_length > 0 && (size_t) command_length < sizeof(command), "test executable path is too long");

    STARTUPINFOA        startup_info;
    PROCESS_INFORMATION process_info;
    memoryZero(&startup_info, sizeof(startup_info));
    memoryZero(&process_info, sizeof(process_info));
    startup_info.cb = sizeof(startup_info);

    require(CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup_info, &process_info) != FALSE,
            "failed to start the second-event child");
    require(WaitForSingleObject(process_info.hProcess, 15000) == WAIT_OBJECT_0,
            "the second console event did not force a prompt exit");

    DWORD exit_code = 0;
    require(GetExitCodeProcess(process_info.hProcess, &exit_code) != FALSE,
            "failed to read the second-event child status");
    CloseHandle(process_info.hThread);
    CloseHandle(process_info.hProcess);
    require(exit_code == 130, "the second console event used the wrong fatal status");
}

static HANDLE late_entry_started;
static HANDLE late_entry_release;

static void lateEntryHook(void *context)
{
    discard context;
    SetEvent(late_entry_started);
    WaitForSingleObject(late_entry_release, INFINITE);
}

static DWORD WINAPI lateEntryDispatchThread(void *context)
{
    discard context;
    signalmanagerTestDispatchWindowsConsoleEvent(CTRL_C_EVENT);
    return 0;
}

static void runLateEntryChild(void)
{
    worker_t workers[2];
    wloop_t  loop;
    fixtureCreate(workers, &loop);
    require(signalmanagerStart(), "failed to register the console handler");

    late_entry_started = CreateEvent(NULL, TRUE, FALSE, NULL);
    late_entry_release = CreateEvent(NULL, TRUE, FALSE, NULL);
    require(late_entry_started != NULL && late_entry_release != NULL,
            "failed to create late-entry synchronization events");
    signalmanagerTestSetWindowsBeforeEntryHook(lateEntryHook, NULL);

    HANDLE thread = CreateThread(NULL, 0, lateEntryDispatchThread, NULL, 0, NULL);
    require(thread != NULL, "failed to start the late-entry handler thread");
    require(WaitForSingleObject(late_entry_started, 15000) == WAIT_OBJECT_0,
            "the late-entry handler did not reach its barrier");

    signalmanagerDestroy();
    SetEvent(late_entry_release);
    WaitForSingleObject(thread, 15000);
    ExitProcess(3);
}

static void runLateEntryCase(const char *executable)
{
    char command[MAX_PATH * 2U];
    int  command_length = snprintf(command, sizeof(command), "\"%s\" --late-entry-child", executable);
    require(command_length > 0 && (size_t) command_length < sizeof(command), "test executable path is too long");

    STARTUPINFOA        startup_info;
    PROCESS_INFORMATION process_info;
    memoryZero(&startup_info, sizeof(startup_info));
    memoryZero(&process_info, sizeof(process_info));
    startup_info.cb = sizeof(startup_info);

    require(CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup_info, &process_info) != FALSE,
            "failed to start the late-entry child");
    require(WaitForSingleObject(process_info.hProcess, 15000) == WAIT_OBJECT_0,
            "the rejected late-entry handler did not take the bounded fallback");

    DWORD exit_code = 0;
    require(GetExitCodeProcess(process_info.hProcess, &exit_code) != FALSE,
            "failed to read the late-entry child status");
    CloseHandle(process_info.hThread);
    CloseHandle(process_info.hProcess);
    require(exit_code == 130, "the rejected late-entry handler used the wrong fallback status");
}

int main(int argc, char **argv)
{
    if (argc == 2 && stringCompare(argv[1], "--second-event-child") == 0)
    {
        runSecondEventChild();
        return 2;
    }
    if (argc == 2 && stringCompare(argv[1], "--late-entry-child") == 0)
    {
        runLateEntryChild();
        return 3;
    }

    runFirstEventCase();
    runSecondEventCase(argv[0]);
    runLateEntryCase(argv[0]);
    return 0;
}
