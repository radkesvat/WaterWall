/*
 * Covers: worker identity; the explicit inputs, callbacks and expected results below define this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: testShutdownContext, testUnregisteredDefaults, testWorkerWIDForLog,
 * testPlainAndNativeThreadsUnregistered, testWorkerBindingAndPredicates, testRebindingRejection,
 * testInvalidAccessorAssertion
 * Checks: Assertion labels include: plain threadCreate thread did not observe kInvalidWID; plain
 * threadCreate thread reported registered WID;
 * native pthread did not observe kInvalidWID
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.worker_identity_unit
 */
#include "global_state.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)
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

static const ww_lifecycle_context_t *testShutdownContext(void)
{
    static const ww_lifecycle_context_t context = {
        .scope        = kWwLifecycleProcessShutdown,
        .close_policy = kWwLifecycleCloseGraceful,
    };
    return &context;
}

static WTHREAD_ROUTINE(plainThreadRoutine)
{
    atomic_bool *ran = userdata;
    require(getWID() == kInvalidWID, "plain threadCreate thread did not observe kInvalidWID");
    require(! currentThreadIsWorker(), "plain threadCreate thread reported registered WID");
    require(! currentThreadOwnsWorker(kInvalidWID), "plain thread claimed to own the invalid worker");
    atomic_store(ran, true);
    return 0;
}

#if defined(HAS_UNIX_PTHREAD)
static void *nativeThreadRoutine(void *arg)
{
    atomic_bool *ran = arg;
    require(getWID() == kInvalidWID, "native pthread did not observe kInvalidWID");
    require(! currentThreadIsWorker(), "native pthread reported registered WID");
    atomic_store(ran, true);
    return NULL;
}
#elif defined(HAS_WIN32_THREAD)
static DWORD WINAPI nativeThreadRoutine(LPVOID arg)
{
    atomic_bool *ran = arg;
    require(getWID() == kInvalidWID, "native Win32 thread did not observe kInvalidWID");
    require(! currentThreadIsWorker(), "native Win32 thread reported registered WID");
    atomic_store(ran, true);
    return 0;
}
#endif

static void testUnregisteredDefaults(void)
{
    require(getWID() == kInvalidWID, "main test thread did not begin with kInvalidWID");
    require(! currentThreadIsWorker(), "main test thread reported registered WID before setup");
    require(! workerWIDIsRegistered(kInvalidWID), "kInvalidWID was reported as registered");
    require(! workerWIDIsRegistered(0), "worker 0 was registered before runtime setup");
    require(! currentThreadOwnsWorker(kInvalidWID), "unregistered thread claimed to own the invalid worker");
    require(tryGetCurrentWorker() == NULL, "unregistered thread got a worker before setup");

    testWorkerBindWID(0);
    require(! currentThreadIsWorker() && ! currentThreadOwnsWorker(0) && tryGetCurrentWorker() == NULL,
            "a WID without runtime storage established worker ownership");
    testWorkerUnbindWID();
}

static void testWorkerWIDForLog(void)
{
    require(workerWIDForLog(0) == 0, "workerWIDForLog(0) did not return 0");
    require(workerWIDForLog(1) == 1, "workerWIDForLog(1) did not return 1");
    require(workerWIDForLog(42) == 42, "workerWIDForLog(42) did not return 42");

    const wid_t sample_wid = 99;
    require(workerWIDForLog(sample_wid) == (int) sample_wid, "workerWIDForLog did not preserve sample WID numerically");
    require(workerWIDForLog(sample_wid) != -1, "workerWIDForLog mapped sample WID to -1");

    require(workerWIDForLog(kInvalidWID) == -1, "workerWIDForLog(kInvalidWID) did not return -1");

    require(workerWIDForLog(0) == 0 && workerWIDForLog(2) == 2 && workerWIDForLog(kInvalidWID) == -1,
            "multiple workerWIDForLog calls in single expression failed");
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

    require(wwStartupSucceeded(createGlobalState(init_data)), "failed to create worker-identity fixture");

    // createGlobalState binds main thread to worker 0
    require(getWID() == 0, "main thread was not bound to worker 0 by createGlobalState");
    require(currentThreadIsWorker(), "main thread reported no registered WID");
    require(currentThreadOwnsWorker(0), "currentThreadOwnsWorker(0) failed");
    require(! currentThreadOwnsWorker(1), "currentThreadOwnsWorker(1) returned true for worker 0");
    require(! currentThreadOwnsWorker(kInvalidWID), "currentThreadOwnsWorker(kInvalidWID) returned true");

    // Re-bind to same worker 0 is idempotent
    workerBindCurrentThread(getWorker(0));
    require(getWID() == 0, "idempotent bind changed WID");

    // Every configured worker is registered and owns an event loop.
    require(workerWIDIsRegistered(0), "worker 0 not registered");
    require(workerWIDIsRegistered(1), "worker 1 not registered");
    require(getWorker(0)->loop != NULL && getWorker(1)->loop != NULL, "registered worker lacks an event loop");

    require(getWorkersCount() == init_data.workers_count, "runtime did not preserve the configured worker count");
    require(! workerWIDIsRegistered(getWorkersCount()), "out-of-range worker was registered");

    // Unbind restores kInvalidWID
    workerUnbindCurrentThread();
    require(getWID() == kInvalidWID, "unbinding did not restore kInvalidWID");
    require(! currentThreadIsWorker(), "unbound thread reported registered WID");
    require(! currentThreadOwnsWorker(0), "unbound thread claimed to own worker 0");

    // Re-bind back to worker 0 for teardown
    workerBindCurrentThread(getWorker(0));

    for (unsigned int wid = 1; wid < getWorkersCount(); ++wid)
    {
        require(workerExitJoin(getWorker(wid)), "failed to stop a test worker");
    }

    /* Worker 0 is bound here; release its resources before global teardown. */
    worker_t *worker0 = getWorker(0);
    require(workerInstallApplicationQuiesceRequest(worker0, testShutdownContext()) != kWorkerQuiesceRequestUnavailable,
            "failed to install worker-0 application quiesce request");
    workerPerformQuiesce(worker0, testShutdownContext());
    require(workerRequestDrain(worker0), "failed to request worker-0 drain");
    workerPerformDrain(worker0, testShutdownContext());
    require(workerRequestTeardown(worker0), "failed to request worker-0 teardown");
    workerPerformTeardown(worker0);
    require(worker0->loop == NULL && currentThreadOwnsWorker(0), "loop detachment lost worker identity");
    require(tryGetCurrentWorker() == worker0, "loop detachment lost the current worker");

    destroyGlobalState();

    require(getWID() == kInvalidWID, "destroyGlobalState did not restore kInvalidWID");
    require(! currentThreadIsWorker() && tryGetCurrentWorker() == NULL, "destroyGlobalState left a current worker");
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

        require(wwStartupSucceeded(createGlobalState(init_data)), "failed to create rebinding fixture");
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

        require(wwStartupSucceeded(createGlobalState(init_data)), "failed to create accessor fixture");
        workerUnbindCurrentThread();
        // Accessing getWorkerBufferPool with kInvalidWID must assert/abort
        discard getWorkerBufferPool(kInvalidWID);
        exit(0);
    }

    int status = 0;
    require(waitpid(pid, &status, 0) == pid, "waitpid failed for testInvalidAccessorAssertion");
#if defined(DEBUG)
    require(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT,
            "getWorkerBufferPool(kInvalidWID) did not terminate through its Debug assertion");
#else
    require(WIFEXITED(status) && WEXITSTATUS(status) == 1,
            "getWorkerBufferPool(kInvalidWID) did not exit cleanly via abortProgramNow(1)");
#endif
}
#endif

int main(void)
{
    testCaseSet("worker_identity_test");
    testUnregisteredDefaults();
    testWorkerWIDForLog();
    testPlainAndNativeThreadsUnregistered();
    testWorkerBindingAndPredicates();
#if defined(HAS_UNIX_FORK)
    testRebindingRejection();
    testInvalidAccessorAssertion();
#endif
    return 0;
}
