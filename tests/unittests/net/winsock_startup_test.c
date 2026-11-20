/* Exercise Winsock initialization through the runtime startup owner and concurrent standalone callers.
 * Native acquisition and cleanup are substituted so no network access is required.
 * CTest: waterwall.winsock_startup_unit */
#include "global_state.h"
#include "test_assert.h"
#include "wsocket.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static int          startup_error;
static atomic_u32_t starts;
static unsigned     cleanups;
static HANDLE       entered, release_start;

static int fixtureStartup(WORD version, WSADATA *data)
{
    require(version == MAKEWORD(2, 2) && data != NULL, "Winsock version or output changed");
    atomicIncU32Relaxed(&starts);
    if (entered != NULL)
    {
        SetEvent(entered);
        require(WaitForSingleObject(release_start, 5000) == WAIT_OBJECT_0, "startup was never released");
    }
    return startup_error;
}

static int fixtureCleanup(void)
{
    ++cleanups;
    return 0;
}

#define WSAStartup fixtureStartup
#define WSACleanup fixtureCleanup
#include "../../../ww/base/wsocket.c"
#undef WSACleanup
#undef WSAStartup

static DWORD WINAPI initializeWinsock(void *started)
{
    if (started != NULL)
        SetEvent((HANDLE) started);
    return (DWORD) WSATryInit();
}

int main(void)
{
    initWLibc();
    WSADeinit();
    startup_error = WSASYSNOTREADY;
    require(! wwStartupSucceeded(createGlobalState((ww_construction_data_t) {0})),
            "runtime accepted failed Winsock startup");
    require(atomicLoadU32Relaxed(&starts) == 1 && cleanups == 0 && ! GSTATE.flag_initialized &&
                GSTATE.workers == NULL && GSTATE.application_shutdown == NULL,
            "failed Winsock startup retained runtime or released an unacquired reference");

    startup_error         = 0;
    entered               = CreateEventA(NULL, TRUE, FALSE, NULL);
    release_start         = CreateEventA(NULL, TRUE, FALSE, NULL);
    HANDLE second_started = CreateEventA(NULL, TRUE, FALSE, NULL);
    require(entered && release_start && second_started, "could not create fixture events");
    HANDLE first = CreateThread(NULL, 0, initializeWinsock, NULL, 0, NULL);
    require(first && WaitForSingleObject(entered, 5000) == WAIT_OBJECT_0, "first caller did not enter startup");
    HANDLE second = CreateThread(NULL, 0, initializeWinsock, second_started, 0, NULL);
    require(second && WaitForSingleObject(second_started, 5000) == WAIT_OBJECT_0, "second caller did not start");
    require(WaitForSingleObject(second, 50) == WAIT_TIMEOUT, "second caller observed readiness before startup");
    SetEvent(release_start);
    HANDLE threads[] = {first, second};
    require(WaitForMultipleObjects(2, threads, TRUE, 5000) == WAIT_OBJECT_0, "callers failed to finish");
    for (size_t i = 0; i < ARRAY_SIZE(threads); ++i)
    {
        DWORD status;
        require(GetExitCodeThread(threads[i], &status) && status == 0, "concurrent initialization failed");
        CloseHandle(threads[i]);
    }
    CloseHandle(second_started);
    CloseHandle(release_start);
    CloseHandle(entered);
    entered = NULL;
    require(atomicLoadU32Relaxed(&starts) == 2, "concurrent callers acquired multiple Winsock references");
    WSADeinit();
    WSADeinit();
    require(cleanups == 1, "repeated teardown released an extra reference");
    WSAInit();
    WSADeinit();
    require(atomicLoadU32Relaxed(&starts) == 3 && cleanups == 2,
            "startup after teardown did not acquire a new reference");
    return 0;
}
