#include "global_state.h"
#include "worker.h"
#include "wwapi.h"

#if defined(__unix__) || defined(__APPLE__) || defined(UNIX)
#include <pthread.h>
#include <sys/wait.h>
#include <unistd.h>
#define HAS_UNIX_FORK    1
#define HAS_UNIX_PTHREAD 1
#elif defined(_WIN32)
#include <windows.h>
#define HAS_WIN32_THREAD 1
#endif

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static WTHREAD_ROUTINE(plainThreadRoutine)
{
    atomic_bool *ran = userdata;
    require(getWID() == kInvalidWID, "plain threadCreate thread did not observe kInvalidWID");
    require(! currentThreadHasRegisteredWID(), "plain threadCreate thread reported registered WID");
    require(! currentThreadIsEventWorker(), "plain threadCreate thread reported event worker role");
    atomic_store(ran, true);
    return 0;
}

#if defined(HAS_UNIX_PTHREAD)
static void *nativeThreadRoutine(void *arg)
{
    atomic_bool *ran = arg;
    require(getWID() == kInvalidWID, "native pthread did not observe kInvalidWID");
    require(! currentThreadHasRegisteredWID(), "native pthread reported registered WID");
    require(! currentThreadIsEventWorker(), "native pthread reported event worker role");
    atomic_store(ran, true);
    return NULL;
}
#elif defined(HAS_WIN32_THREAD)
static DWORD WINAPI nativeThreadRoutine(LPVOID arg)
{
    atomic_bool *ran = arg;
    require(getWID() == kInvalidWID, "native Win32 thread did not observe kInvalidWID");
    require(! currentThreadHasRegisteredWID(), "native Win32 thread reported registered WID");
    require(! currentThreadIsEventWorker(), "native Win32 thread reported event worker role");
    atomic_store(ran, true);
    return 0;
}
#endif

static void testUnregisteredDefaults(void)
{
    require(getWID() == kInvalidWID, "main test thread did not begin with kInvalidWID");
    require(! currentThreadHasRegisteredWID(), "main test thread reported registered WID before setup");
    require(! currentThreadIsEventWorker(), "main test thread reported event worker before setup");
    require(! workerWIDIsRegistered(kInvalidWID), "kInvalidWID was reported as registered");
    require(! workerWIDIsEventWorker(kInvalidWID), "kInvalidWID was reported as event worker");
}

static void testPlainAndNativeThreadsUnregistered(void)
{
    atomic_bool ran_plain;
    atomic_init(&ran_plain, false);
    wthread_t       thread;
    wthread_error_t error = threadCreate(&thread, plainThreadRoutine, &ran_plain);
    require(error == kWThreadErrorNone, "threadCreate failed");
    require(threadJoin(thread) == 0, "threadJoin failed");
    require(atomic_load(&ran_plain), "plain thread routine did not run");

    atomic_bool ran_native;
    atomic_init(&ran_native, false);

#if defined(HAS_UNIX_PTHREAD)
    pthread_t native_thread;
    require(pthread_create(&native_thread, NULL, nativeThreadRoutine, &ran_native) == 0, "pthread_create failed");
    require(pthread_join(native_thread, NULL) == 0, "pthread_join failed");
    require(atomic_load(&ran_native), "native thread routine did not run");
#elif defined(HAS_WIN32_THREAD)
    HANDLE hThread = CreateThread(NULL, 0, nativeThreadRoutine, &ran_native, 0, NULL);
    require(hThread != NULL, "CreateThread failed");
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    require(atomic_load(&ran_native), "native thread routine did not run");
#endif
}

static void testWorkerBindingAndPredicates(void)
{
    static char            log_off[]         = "OFF";
    ww_construction_data_t init_data         = {0};
    init_data.workers_count                  = 2;
    init_data.ram_profile                    = 4;
    init_data.mtu_size                       = 1500;
    init_data.internal_logger_data.log_level = log_off;
    init_data.core_logger_data.log_level     = log_off;
    init_data.network_logger_data.log_level  = log_off;
    init_data.dns_logger_data.log_level      = log_off;

    createGlobalState(init_data);

    // createGlobalState binds main thread to worker 0
    require(getWID() == 0, "main thread was not bound to worker 0 by createGlobalState");
    require(currentThreadHasRegisteredWID(), "main thread reported no registered WID");
    require(currentThreadIsEventWorker(), "main thread reported not event worker");
    require(currentThreadIsEventWorkerWID(0), "currentThreadIsEventWorkerWID(0) failed");
    require(! currentThreadIsEventWorkerWID(1), "currentThreadIsEventWorkerWID(1) returned true for worker 0");
    require(! currentThreadIsEventWorkerWID(kInvalidWID), "currentThreadIsEventWorkerWID(kInvalidWID) returned true");

    // Re-bind to same worker 0 is idempotent
    workerBindCurrentThread(getWorker(0));
    require(getWID() == 0, "idempotent bind changed WID");

    // Check ordinary event worker predicate
    require(workerWIDIsRegistered(0), "worker 0 not registered");
    require(workerWIDIsEventWorker(0), "worker 0 not event worker");
    require(workerWIDIsRegistered(1), "worker 1 not registered");
    require(workerWIDIsEventWorker(1), "worker 1 not event worker");

    // Check lwIP worker slot semantics
    wid_t lwip_wid = getTotalWorkersCount() - 1;
    require(workerWIDIsRegistered(lwip_wid), "lwIP worker not registered");
    require(! workerWIDIsEventWorker(lwip_wid), "lwIP worker reported as event worker");

    // Unbind restores kInvalidWID
    workerUnbindCurrentThread();
    require(getWID() == kInvalidWID, "unbinding did not restore kInvalidWID");
    require(! currentThreadHasRegisteredWID(), "unbound thread reported registered WID");
    require(! currentThreadIsEventWorker(), "unbound thread reported event worker");
    require(! currentThreadIsEventWorkerWID(0), "unbound thread reported event worker WID 0");

    // Re-bind back to worker 0 for teardown
    workerBindCurrentThread(getWorker(0));

    for (unsigned int wid = 1; wid < getWorkersCount(); ++wid)
    {
        discard workerRequestStop(getWorker(wid));
        discard workerJoin(getWorker(wid));
    }

    destroyGlobalState();

    require(getWID() == kInvalidWID, "destroyGlobalState did not restore kInvalidWID");
}

#if defined(HAS_UNIX_FORK)
static void testRebindingRejection(void)
{
    pid_t pid = fork();
    require(pid >= 0, "fork failed for testRebindingRejection");
    if (pid == 0)
    {
        static char            log_off[]         = "OFF";
        ww_construction_data_t init_data         = {0};
        init_data.workers_count                  = 2;
        init_data.ram_profile                    = 4;
        init_data.mtu_size                       = 1500;
        init_data.internal_logger_data.log_level = log_off;
        init_data.core_logger_data.log_level     = log_off;
        init_data.network_logger_data.log_level  = log_off;
        init_data.dns_logger_data.log_level      = log_off;

        createGlobalState(init_data);
        // Current thread is bound to worker 0; attempt rebinding to worker 1 must fail/abort
        workerBindCurrentThread(getWorker(1));
        // Should not reach here
        exit(0);
    }

    int status = 0;
    require(waitpid(pid, &status, 0) == pid, "waitpid failed for testRebindingRejection");
    require(WIFEXITED(status) && WEXITSTATUS(status) == 1,
            "attempted different-WID rebinding did not exit cleanly via abortProgramNow(1)");
}

static void testInvalidAccessorAssertion(void)
{
    pid_t pid = fork();
    require(pid >= 0, "fork failed for testInvalidAccessorAssertion");
    if (pid == 0)
    {
        static char            log_off[]         = "OFF";
        ww_construction_data_t init_data         = {0};
        init_data.workers_count                  = 2;
        init_data.ram_profile                    = 4;
        init_data.mtu_size                       = 1500;
        init_data.internal_logger_data.log_level = log_off;
        init_data.core_logger_data.log_level     = log_off;
        init_data.network_logger_data.log_level  = log_off;
        init_data.dns_logger_data.log_level      = log_off;

        createGlobalState(init_data);
        workerUnbindCurrentThread();
        // Accessing getWorkerBufferPool with kInvalidWID must assert/abort
        discard getWorkerBufferPool(kInvalidWID);
        exit(0);
    }

    int status = 0;
    require(waitpid(pid, &status, 0) == pid, "waitpid failed for testInvalidAccessorAssertion");
    require(WIFEXITED(status) && WEXITSTATUS(status) == 1,
            "getWorkerBufferPool(kInvalidWID) did not exit cleanly via abortProgramNow(1)");
}
#endif

int main(void)
{
    testUnregisteredDefaults();
    testPlainAndNativeThreadsUnregistered();
    testWorkerBindingAndPredicates();
#if defined(HAS_UNIX_FORK)
    testRebindingRejection();
    testInvalidAccessorAssertion();
#endif
    return 0;
}
