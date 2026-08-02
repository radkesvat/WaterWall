/*
 * Event-loop shutdown-control stop request.
 *
 * wloopRequestStop() replaced the cross-thread non-atomic write to
 * wloop_t::flags that worker teardown used to perform. These cases pin the
 * contract it has to satisfy for worker shutdown to be reliable:
 *   - a request from another thread wakes a loop blocked in the poller promptly;
 *   - a request issued before wloopRun() started is still honored;
 *   - large and concurrent repeated request sets coalesce without blocking;
 *   - an existing custom-event wake also covers a stop request;
 *   - the first request may race wake-channel initialization during startup;
 *   - a request racing the loop's own exit is safe.
 */

#include "worker_registry_fixture.h"
#include "wwapi.h"

/*
 * Fake worker table for the stubbed GSTATE below. Without it the identity
 * predicates correctly report "not an event worker" and the checked
 * current-worker accessors reject this test.
 */
static test_worker_registry_t g_test_worker_registry;

#define LARGE_STOP_REQUEST_SET 100000U
#define STOP_REQUEST_THREADS   4U
#define STOPS_PER_THREAD       25000U

typedef struct env_s
{
    master_pool_t             *large_master;
    master_pool_t             *small_master;
    master_pool_t             *wio_master;
    threadsafe_generic_pool_t *wio_pool;
    threadsafe_generic_pool_t *wio_pools[1];
} env_t;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void envSetup(env_t *env)
{
    env->large_master = masterpoolCreateWithCapacity(64);
    env->small_master = masterpoolCreateWithCapacity(64);
    env->wio_master   = masterpoolCreateWithCapacity(64);
    env->wio_pool     = threadsafegenericpoolCreateWithDefaultAllocatorAndCapacity(env->wio_master, sizeof(wio_t), 64);
    env->wio_pools[0] = env->wio_pool;

    GSTATE.flag_initialized = true;
    GSTATE.workers_count    = 2;
    testWorkerRegistryInstall(&g_test_worker_registry);
    GSTATE.shortcut_wios_pools = env->wio_pools;
    testWorkerBindWID(0);
}

static void envTeardown(env_t *env)
{
    testWorkerUnbindWID();
    GSTATE.flag_initialized = false;
    GSTATE.workers_count    = 0;
    testWorkerRegistryRestore(&g_test_worker_registry);
    GSTATE.shortcut_wios_pools = NULL;
    threadsafegenericpoolDestroy(env->wio_pool);
    masterpoolMakeEmpty(env->wio_master);
    masterpoolMakeEmpty(env->large_master);
    masterpoolMakeEmpty(env->small_master);
    masterpoolDestroy(env->wio_master);
    masterpoolDestroy(env->large_master);
    masterpoolDestroy(env->small_master);
}

typedef struct loop_runner_s
{
    wloop_t       *loop;
    buffer_pool_t *pool;
    wthread_t      thread;
    atomic_bool    running;
    atomic_bool    finished;
    atomic_bool    start_gate;
    bool           wait_for_start_gate;
    int            result;
} loop_runner_t;

static WTHREAD_ROUTINE(loopRunnerMain) // NOLINT
{
    loop_runner_t *runner = userdata;

    testWorkerBindWID(0);
    atomicStoreExplicit(&runner->running, true, memory_order_release);
    while (runner->wait_for_start_gate && ! atomicLoadExplicit(&runner->start_gate, memory_order_acquire))
    {
    }
    runner->result = wloopRun(runner->loop);
    atomicStoreExplicit(&runner->finished, true, memory_order_release);
    return 0;
}

/*
 * A buffer_pool_t belongs to exactly one thread: it claims whichever thread
 * performs the first buffer operation on it and aborts on any access from
 * another (POOL_THREAD_CHECK, debug builds). Every case here runs its loop on a
 * fresh thread, and wloopRun() takes buffers from the loop's pool, so each
 * runner needs its own pool - sharing one across cases made the second thread
 * trip the check.
 *
 * Creating the pool here on the main thread is safe: nothing touches it until
 * the runner thread's first buffer operation, so the runner is the claimant.
 */
static void runnerCreate(loop_runner_t *runner, env_t *env)
{
    memoryZero(runner, sizeof(*runner));
    runner->pool = bufferpoolCreate(env->large_master, env->small_master, 64, 8192, 1024);
    runner->loop = wloopCreate(0, runner->pool, 0);
    require(runner->loop != NULL, "failed to create the event loop");
}

static void runnerStart(loop_runner_t *runner)
{
    require(threadCreate(&runner->thread, loopRunnerMain, runner) == kWThreadErrorNone,
            "failed to spawn the loop thread");
}

static void runnerJoin(loop_runner_t *runner)
{
    threadJoin(runner->thread);
}

// Must run only after runnerJoin(): the pool is released once its owning thread
// is gone, and bufferpoolDestroy() is the one operation that does not claim it.
static void runnerDestroy(loop_runner_t *runner)
{
    wloopDestroy(&runner->loop);
    bufferpoolDestroy(runner->pool);
    runner->pool = NULL;
}

/* Wait up to `timeout_ms` for `flag` to be published. */
static bool waitForFlag(atomic_bool *flag, unsigned int timeout_ms)
{
    for (unsigned int waited = 0; waited < timeout_ms; waited += 5)
    {
        if (atomicLoadExplicit(flag, memory_order_acquire))
        {
            return true;
        }
        wwSleepMS(5);
    }
    return atomicLoadExplicit(flag, memory_order_acquire);
}

/*
 * A loop blocked in the poller with no pending work must leave promptly when
 * another thread requests a stop. "Promptly" here means without depending on a
 * polling interval: the request writes to the loop's wakeup descriptor.
 */
static void testStopWakesBlockedLoop(env_t *env)
{
    loop_runner_t runner;
    runnerCreate(&runner, env);
    runnerStart(&runner);
    require(waitForFlag(&runner.running, 2000), "the loop thread did not start");

    // Give the loop time to reach its blocking poll before requesting the stop.
    wwSleepMS(50);

    require(! wloopStopRequested(runner.loop), "the loop reported a stop request before one was made");
    require(wloopRequestStop(runner.loop), "wloopRequestStop() failed to wake a blocked loop");
    require(wloopStopRequested(runner.loop), "wloopRequestStop() did not publish the stop request");

    require(waitForFlag(&runner.finished, 2000), "a blocked loop did not stop after a stop request");
    runnerJoin(&runner);

    require(runner.result == kWLoopRunOk, "the stopped loop reported a run error");
    runnerDestroy(&runner);
}

/*
 * Worker 0 may request a stop before the target worker reached wloopRun(); the
 * flag has to survive that ordering instead of being consumed by a wakeup that
 * nobody was waiting for.
 */
static void testStopBeforeRunIsHonored(env_t *env)
{
    loop_runner_t runner;
    runnerCreate(&runner, env);

    require(wloopRequestStop(runner.loop), "wloopRequestStop() failed before the loop started");
    for (size_t i = 1; i < LARGE_STOP_REQUEST_SET; ++i)
    {
        require(wloopRequestStop(runner.loop), "a coalesced pre-start stop request failed");
    }

    runnerStart(&runner);

    require(waitForFlag(&runner.finished, 2000), "a loop started after a stop request kept running");
    runnerJoin(&runner);

    for (size_t i = 0; i < LARGE_STOP_REQUEST_SET; ++i)
    {
        require(wloopRequestStop(runner.loop), "a coalesced post-exit stop request failed");
    }

    runnerDestroy(&runner);
}

/* Repeated requests must coalesce rather than corrupt the loop state. */
static void testRepeatedStopRequests(env_t *env)
{
    loop_runner_t runner;
    runnerCreate(&runner, env);
    runnerStart(&runner);
    require(waitForFlag(&runner.running, 2000), "the loop thread did not start");
    wwSleepMS(50);

    for (size_t i = 0; i < LARGE_STOP_REQUEST_SET; ++i)
    {
        require(wloopRequestStop(runner.loop), "a repeated wloopRequestStop() failed");
    }

    require(waitForFlag(&runner.finished, 2000), "the loop did not stop after repeated stop requests");
    runnerJoin(&runner);

    // Requesting a stop on an already stopped (but not yet destroyed) loop stays
    // safe; this is the shutdown ordering where a worker exits on its own just
    // as worker 0 asks it to stop.
    require(wloopRequestStop(runner.loop), "wloopRequestStop() failed on an already stopped loop");

    runnerDestroy(&runner);
}

typedef struct stop_requester_s
{
    wloop_t  *loop;
    wthread_t thread;
} stop_requester_t;

static WTHREAD_ROUTINE(stopRequesterMain) // NOLINT
{
    stop_requester_t *requester = userdata;

    testWorkerBindWID(0);
    for (size_t i = 0; i < STOPS_PER_THREAD; ++i)
    {
        require(wloopRequestStop(requester->loop), "a concurrent repeated stop request failed");
    }
    return 0;
}

static void testConcurrentRepeatedStopRequests(env_t *env)
{
    loop_runner_t    runner;
    stop_requester_t requesters[STOP_REQUEST_THREADS];
    runnerCreate(&runner, env);
    runnerStart(&runner);
    require(waitForFlag(&runner.running, 2000), "the loop thread did not start");
    wwSleepMS(50);

    for (size_t i = 0; i < STOP_REQUEST_THREADS; ++i)
    {
        requesters[i].loop = runner.loop;
        require(threadCreate(&requesters[i].thread, stopRequesterMain, &requesters[i]) == kWThreadErrorNone,
                "failed to spawn a stop-request thread");
    }
    for (size_t i = 0; i < STOP_REQUEST_THREADS; ++i)
    {
        threadJoin(requesters[i].thread);
    }

    require(waitForFlag(&runner.finished, 2000), "the loop did not stop after concurrent repeated requests");
    runnerJoin(&runner);
    runnerDestroy(&runner);
}

static void testStopCoveredByExistingEventWake(env_t *env)
{
    loop_runner_t runner;
    runnerCreate(&runner, env);

    wevent_t event;
    memoryZero(&event, sizeof(event));
    require(wloopPostControlEvent(runner.loop, &event), "failed to queue the event that arms the shared wake");
    require(runner.loop->wakeup_pending, "custom event did not arm the shared wake");
    require(wloopRequestStop(runner.loop), "existing custom-event wake did not cover the stop request");

    runnerStart(&runner);
    require(waitForFlag(&runner.finished, 2000), "stop covered by an existing event wake was not honored");
    runnerJoin(&runner);
    runnerDestroy(&runner);
}

typedef struct startup_requester_s
{
    wloop_t     *loop;
    atomic_bool  ready;
    atomic_bool *start_gate;
    wthread_t    thread;
    bool         success;
} startup_requester_t;

static WTHREAD_ROUTINE(startupRequesterMain) // NOLINT
{
    startup_requester_t *requester = userdata;

    testWorkerBindWID(0);
    atomicStoreExplicit(&requester->ready, true, memory_order_release);
    while (! atomicLoadExplicit(requester->start_gate, memory_order_acquire))
    {
    }
    requester->success = wloopRequestStop(requester->loop);
    return 0;
}

/*
 * Release wloopRun() and the first stop request from the same gate. This is a
 * functional stress test in normal builds and a regression test for the
 * intern_nevents startup handoff when run under ThreadSanitizer.
 */
static void testFirstStopRacesLoopStartup(env_t *env)
{
    for (int attempt = 0; attempt < 32; ++attempt)
    {
        loop_runner_t       runner;
        startup_requester_t requester;
        runnerCreate(&runner, env);
        runner.wait_for_start_gate = true;
        runnerStart(&runner);
        require(waitForFlag(&runner.running, 2000), "the loop thread did not start");

        memoryZero(&requester, sizeof(requester));
        requester.loop       = runner.loop;
        requester.start_gate = &runner.start_gate;
        require(threadCreate(&requester.thread, startupRequesterMain, &requester) == kWThreadErrorNone,
                "failed to spawn the startup stop-request thread");
        require(waitForFlag(&requester.ready, 2000), "the startup stop-request thread did not start");

        atomicStoreExplicit(&runner.start_gate, true, memory_order_release);
        threadJoin(requester.thread);
        require(requester.success, "the first stop request failed while racing loop startup");
        require(waitForFlag(&runner.finished, 2000), "the loop did not stop after the startup race");
        runnerJoin(&runner);
        runnerDestroy(&runner);
    }
}

/* A stop request racing the loop thread's own exit must be safe both ways. */
static void testStopRacingSelfExit(env_t *env)
{
    for (int attempt = 0; attempt < 32; ++attempt)
    {
        // Each attempt is a new thread, so each attempt gets its own pool.
        loop_runner_t runner;
        runnerCreate(&runner, env);
        runnerStart(&runner);
        require(waitForFlag(&runner.running, 2000), "the loop thread did not start");

        // No settling delay: the request lands anywhere between "not yet in the
        // poller" and "already returning".
        require(wloopRequestStop(runner.loop), "wloopRequestStop() failed while racing the loop thread");

        require(waitForFlag(&runner.finished, 2000), "the loop did not stop while racing its own exit");
        runnerJoin(&runner);
        runnerDestroy(&runner);
    }
}

/* A null loop is rejected instead of dereferenced. */
static void testNullLoop(void)
{
    require(! wloopRequestStop(NULL), "wloopRequestStop(NULL) did not fail");
    require(! wloopStopRequested(NULL), "wloopStopRequested(NULL) did not report false");
}

int main(void)
{
    env_t env;
    envSetup(&env);

    testNullLoop();
    testStopWakesBlockedLoop(&env);
    testStopBeforeRunIsHonored(&env);
    testRepeatedStopRequests(&env);
    testConcurrentRepeatedStopRequests(&env);
    testStopCoveredByExistingEventWake(&env);
    testFirstStopRacesLoopStartup(&env);
    testStopRacingSelfExit(&env);

    envTeardown(&env);
    return 0;
}
