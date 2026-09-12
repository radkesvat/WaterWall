#include "wwapi.h"

#include "lifecycle_capabilities_windows.h"
#include "lifecycle_windows.h"

static HANDLE stop_event;
static HANDLE ready_event;
static HANDLE cancel_event;
static HANDLE waiter;
static HANDLE controller_process;

#ifdef WATERWALL_LIFECYCLE_TEST_HOOKS
static int fail_setup;

void waterwallLifecycleTestFailSetup(bool thread_creation)
{
    fail_setup = thread_creation ? 2 : 1;
}
#endif

static void lifecycleRequestShutdown(int exit_code)
{
    if (! requestProgramShutdown(exit_code))
    {
        abortProgramNow(exit_code != 0 ? exit_code : 1);
    }
}

static void lifecycleWaitFailure(DWORD error)
{
    fprintf(stderr, "Lifecycle stop wait failed: Windows error %lu\n", (unsigned long) error);
    lifecycleRequestShutdown(1);
}

static DWORD WINAPI lifecycleWaiterMain(void *context)
{
    (void) context;
    HANDLE events[3] = {cancel_event};
    DWORD  count     = 1;
    if (stop_event != NULL)
        events[count++] = stop_event;
    if (controller_process != NULL)
        events[count++] = controller_process;
    const DWORD result = WaitForMultipleObjects(count, events, FALSE, INFINITE);
    if (result > WAIT_OBJECT_0 && result < WAIT_OBJECT_0 + count)
    {
        lifecycleRequestShutdown(0);
    }
    else if (result != WAIT_OBJECT_0)
    {
        lifecycleWaitFailure(result == WAIT_FAILED ? GetLastError() : ERROR_INVALID_HANDLE);
    }
    return 0;
}

void waterwallLifecycleCheckpoint(void)
{
    HANDLE capabilities[] = {stop_event, controller_process};
    for (size_t i = 0; i < 2; ++i)
    {
        if (capabilities[i] == NULL)
            continue;
        DWORD result = WaitForSingleObject(capabilities[i], 0);
        if (result == WAIT_OBJECT_0)
            lifecycleRequestShutdown(0);
        else if (result != WAIT_TIMEOUT)
            lifecycleWaitFailure(result == WAIT_FAILED ? GetLastError() : ERROR_INVALID_HANDLE);
    }
}

uintptr_t waterwallLifecycleStopEvent(void)
{
    return (uintptr_t) stop_event;
}

void waterwallLifecycleDestroy(void)
{
    if (waiter != NULL)
    {
        if (! SetEvent(cancel_event) || WaitForSingleObject(waiter, INFINITE) != WAIT_OBJECT_0)
        {
            /* A live waiter retains access to both handles and the controller. */
            abortProgramNow(1);
        }
        CloseHandle(waiter);
        waiter = NULL;
    }
    if (cancel_event != NULL)
    {
        CloseHandle(cancel_event);
        cancel_event = NULL;
    }
    if (ready_event != NULL)
    {
        CloseHandle(ready_event);
        ready_event = NULL;
    }
    if (controller_process != NULL)
    {
        CloseHandle(controller_process);
        controller_process = NULL;
    }
    if (stop_event != NULL)
    {
        CloseHandle(stop_event);
        stop_event = NULL;
    }
}

bool waterwallLifecycleStart(uintptr_t supplied_stop, uintptr_t supplied_ready, uintptr_t supplied_controller)
{
    assert(stop_event == NULL && ready_event == NULL && waiter == NULL);
    HANDLE         process    = GetCurrentProcess();
    DWORD          error      = ERROR_SUCCESS;
    HANDLE         supplied[] = {(HANDLE) supplied_stop, (HANDLE) supplied_ready, (HANDLE) supplied_controller};
    HANDLE        *owned[]    = {&stop_event, &ready_event, &controller_process};
    ACCESS_MASK    access[]   = {SYNCHRONIZE, EVENT_MODIFY_STATE, SYNCHRONIZE};
    const wchar_t *types[]    = {L"Event", L"Event", L"Process"};
    for (size_t i = 0; i < 3; ++i)
    {
        if (supplied[i] == NULL)
            continue;
        if (! waterwallCapabilityValidate(supplied[i], types[i], access[i]) ||
            ! DuplicateHandle(process, supplied[i], process, owned[i], access[i], FALSE, 0))
            error = ERROR_INVALID_HANDLE;
    }
    for (size_t i = 0; i < 3; ++i)
        if (supplied[i] != NULL)
            CloseHandle(supplied[i]);
    if (error != ERROR_SUCCESS)
        goto failed;
    waterwallLifecycleCheckpoint();
    if (applicationShutdownWasRequested() || (stop_event == NULL && controller_process == NULL))
        return true;

#ifdef WATERWALL_LIFECYCLE_TEST_HOOKS
    if (fail_setup == 1)
    {
        fail_setup = 0;
        error      = ERROR_NOT_ENOUGH_MEMORY;
        goto failed;
    }
#endif
    cancel_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (cancel_event == NULL)
    {
        error = GetLastError();
        goto failed;
    }
#ifdef WATERWALL_LIFECYCLE_TEST_HOOKS
    if (fail_setup == 2)
    {
        fail_setup = 0;
        error      = ERROR_NOT_ENOUGH_MEMORY;
        goto failed;
    }
#endif
    waiter = CreateThread(NULL, 0, lifecycleWaiterMain, NULL, 0, NULL);
    if (waiter == NULL)
    {
        error = GetLastError();
        goto failed;
    }
    return true;

failed:
    fprintf(stderr, "Could not initialize lifecycle: Windows error %lu\n", (unsigned long) error);
    waterwallLifecycleDestroy();
    return false;
}

void waterwallLifecyclePublishReady(void)
{
    if (ready_event == NULL)
    {
        return;
    }
    waterwallLifecycleCheckpoint();
    if (applicationShutdownWasRequested())
        return;
    /* Runtime commit and worker publication have already happened. A failed
     * notification is an orderly runtime failure, never startup rollback. */
    if (! SetEvent(ready_event))
    {
        fprintf(stderr, "Lifecycle readiness notification failed: Windows error %lu\n", (unsigned long) GetLastError());
        lifecycleRequestShutdown(1);
    }
    CloseHandle(ready_event);
    ready_event = NULL;
}
