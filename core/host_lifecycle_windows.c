#include "wwapi.h"

#include "host_lifecycle_windows.h"

static HANDLE host_stop_event;
static HANDLE host_ready_event;
static HANDLE host_cancel_event;
static HANDLE host_waiter;

#ifdef WATERWALL_HOST_LIFECYCLE_TEST_HOOKS
static int fail_setup;

void waterwallHostLifecycleTestFailSetup(bool thread_creation)
{
    fail_setup = thread_creation ? 2 : 1;
}
#endif

static void hostRequestShutdown(int exit_code)
{
    if (! requestProgramShutdown(exit_code))
    {
        abortProgramNow(exit_code != 0 ? exit_code : 1);
    }
}

static void hostWaitFailure(DWORD error)
{
    fprintf(stderr, "Hosted stop wait failed: Windows error %lu\n", (unsigned long) error);
    hostRequestShutdown(1);
}

static DWORD WINAPI hostWaiterMain(void *context)
{
    (void) context;
    const HANDLE events[] = {host_cancel_event, host_stop_event};
    const DWORD  result   = WaitForMultipleObjects(2U, events, FALSE, INFINITE);
    if (result == WAIT_OBJECT_0 + 1U)
    {
        hostRequestShutdown(0);
    }
    else if (result != WAIT_OBJECT_0)
    {
        hostWaitFailure(result == WAIT_FAILED ? GetLastError() : ERROR_INVALID_HANDLE);
    }
    return 0;
}

void waterwallHostLifecycleCheckpoint(void)
{
    if (host_stop_event == NULL)
    {
        return;
    }
    const DWORD result = WaitForSingleObject(host_stop_event, 0U);
    if (result == WAIT_OBJECT_0)
    {
        hostRequestShutdown(0);
    }
    else if (result != WAIT_TIMEOUT)
    {
        hostWaitFailure(result == WAIT_FAILED ? GetLastError() : ERROR_INVALID_HANDLE);
    }
}

uintptr_t waterwallHostLifecycleStopEvent(void)
{
    return (uintptr_t) host_stop_event;
}

void waterwallHostLifecycleDestroy(void)
{
    if (host_waiter != NULL)
    {
        if (! SetEvent(host_cancel_event) || WaitForSingleObject(host_waiter, INFINITE) != WAIT_OBJECT_0)
        {
            /* A live waiter retains access to both handles and the controller. */
            abortProgramNow(1);
        }
        CloseHandle(host_waiter);
        host_waiter = NULL;
    }
    if (host_cancel_event != NULL)
    {
        CloseHandle(host_cancel_event);
        host_cancel_event = NULL;
    }
    if (host_ready_event != NULL)
    {
        CloseHandle(host_ready_event);
        host_ready_event = NULL;
    }
    if (host_stop_event != NULL)
    {
        CloseHandle(host_stop_event);
        host_stop_event = NULL;
    }
}

bool waterwallHostLifecycleStart(uintptr_t stop_event, uintptr_t ready_event)
{
    assert(host_stop_event == NULL && host_ready_event == NULL && host_waiter == NULL);
    assert(stop_event != 0 && stop_event != ready_event);
    HANDLE process = GetCurrentProcess();
    DWORD  error   = ERROR_SUCCESS;
    if (! DuplicateHandle(process, (HANDLE) stop_event, process, &host_stop_event, SYNCHRONIZE, FALSE, 0U))
    {
        error = GetLastError();
    }
    if (ready_event != 0 &&
        ! DuplicateHandle(process, (HANDLE) ready_event, process, &host_ready_event, EVENT_MODIFY_STATE, FALSE, 0U) &&
        error == ERROR_SUCCESS)
    {
        error = GetLastError();
    }
    CloseHandle((HANDLE) stop_event);
    if (ready_event != 0)
    {
        CloseHandle((HANDLE) ready_event);
    }
    if (error != ERROR_SUCCESS)
    {
        goto failed;
    }

    const DWORD stopped = WaitForSingleObject(host_stop_event, 0U);
    if (stopped != WAIT_OBJECT_0 && stopped != WAIT_TIMEOUT)
    {
        error = stopped == WAIT_FAILED ? GetLastError() : ERROR_INVALID_HANDLE;
        goto failed;
    }
    if (stopped == WAIT_OBJECT_0)
    {
        /* Preserve pre-signaled stop synchronously, before the waiter can race
         * runtime commit. Manual-reset state remains observable at checkpoints. */
        hostRequestShutdown(0);
        return true;
    }

#ifdef WATERWALL_HOST_LIFECYCLE_TEST_HOOKS
    if (fail_setup == 1)
    {
        fail_setup = 0;
        error      = ERROR_NOT_ENOUGH_MEMORY;
        goto failed;
    }
#endif
    host_cancel_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (host_cancel_event == NULL)
    {
        error = GetLastError();
        goto failed;
    }
#ifdef WATERWALL_HOST_LIFECYCLE_TEST_HOOKS
    if (fail_setup == 2)
    {
        fail_setup = 0;
        error      = ERROR_NOT_ENOUGH_MEMORY;
        goto failed;
    }
#endif
    host_waiter = CreateThread(NULL, 0, hostWaiterMain, NULL, 0, NULL);
    if (host_waiter == NULL)
    {
        error = GetLastError();
        goto failed;
    }
    return true;

failed:
    fprintf(stderr, "Could not initialize hosted lifecycle: Windows error %lu\n", (unsigned long) error);
    waterwallHostLifecycleDestroy();
    return false;
}

void waterwallHostLifecyclePublishReady(void)
{
    if (host_ready_event == NULL)
    {
        return;
    }
    /* Runtime commit and worker publication have already happened. A failed
     * notification is an orderly runtime failure, never startup rollback. */
    if (! SetEvent(host_ready_event))
    {
        fprintf(stderr, "Hosted readiness notification failed: Windows error %lu\n", (unsigned long) GetLastError());
        hostRequestShutdown(1);
    }
    CloseHandle(host_ready_event);
    host_ready_event = NULL;
}
