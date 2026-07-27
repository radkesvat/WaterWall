/*
 * Event-loop shutdown-control stop request.
 *
 * wloopRequestStop() replaced the cross-thread non-atomic write to
 * wloop_t::flags that worker teardown used to perform. These cases pin the
 * contract it has to satisfy for worker shutdown to be reliable:
 *   - a request from another thread wakes a loop blocked in the poller promptly;
 *   - a request issued before wloopRun() started is still honored;
 *   - repeated requests are idempotent;
 *   - a request racing the loop's own exit is safe.
 */

#include "global_state.h"
#include "wevent.h" // wio_t layout, for the worker wio pool
#include "wloop.h"
#include "wthread.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct env_s
{
    master_pool_t             *large_master;
    master_pool_t             *small_master;
    master_pool_t             *wio_master;
    buffer_pool_t             *buffer_pool;
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
    env->buffer_pool  = bufferpoolCreate(env->large_master, env->small_master, 64, 8192, 1024);
    env->wio_pool     = threadsafegenericpoolCreateWithDefaultAllocatorAndCapacity(env->wio_master, sizeof(wio_t), 64);
    env->wio_pools[0] = env->wio_pool;

    GSTATE.shortcut_wios_pools = env->wio_pools;
    tl_wid                     = 0;
}

static void envTeardown(env_t *env)
{
    GSTATE.shortcut_wios_pools = NULL;
    threadsafegenericpoolDestroy(env->wio_pool);
    bufferpoolDestroy(env->buffer_pool);
    masterpoolMakeEmpty(env->wio_master);
    masterpoolMakeEmpty(env->large_master);
    masterpoolMakeEmpty(env->small_master);
    masterpoolDestroy(env->wio_master);
    masterpoolDestroy(env->large_master);
    masterpoolDestroy(env->small_master);
}

typedef struct loop_runner_s
{
    wloop_t    *loop;
    atomic_bool running;
    atomic_bool finished;
    int         result;
} loop_runner_t;

static WTHREAD_ROUTINE(loopRunnerMain) // NOLINT
{
    loop_runner_t *runner = userdata;

    tl_wid = 0;
    atomicStoreExplicit(&runner->running, true, memory_order_release);
    runner->result = wloopRun(runner->loop);
    atomicStoreExplicit(&runner->finished, true, memory_order_release);
    return 0;
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
    loop_runner_t runner = {0};
    runner.loop          = wloopCreate(0, env->buffer_pool, 0);
    require(runner.loop != NULL, "failed to create the event loop");

    wthread_t thread;
    require(threadCreate(&thread, loopRunnerMain, &runner) == kWThreadErrorNone, "failed to spawn the loop thread");
    require(waitForFlag(&runner.running, 2000), "the loop thread did not start");

    // Give the loop time to reach its blocking poll before requesting the stop.
    wwSleepMS(50);

    require(! wloopStopRequested(runner.loop), "the loop reported a stop request before one was made");
    require(wloopRequestStop(runner.loop), "wloopRequestStop() failed to wake a blocked loop");
    require(wloopStopRequested(runner.loop), "wloopRequestStop() did not publish the stop request");

    require(waitForFlag(&runner.finished, 2000), "a blocked loop did not stop after a stop request");
    threadJoin(thread);

    require(runner.result == kWLoopRunOk, "the stopped loop reported a run error");
    wloopDestroy(&runner.loop);
}

/*
 * Worker 0 may request a stop before the target worker reached wloopRun(); the
 * flag has to survive that ordering instead of being consumed by a wakeup that
 * nobody was waiting for.
 */
static void testStopBeforeRunIsHonored(env_t *env)
{
    loop_runner_t runner = {0};
    runner.loop          = wloopCreate(0, env->buffer_pool, 0);
    require(runner.loop != NULL, "failed to create the event loop");

    require(wloopRequestStop(runner.loop), "wloopRequestStop() failed before the loop started");

    wthread_t thread;
    require(threadCreate(&thread, loopRunnerMain, &runner) == kWThreadErrorNone, "failed to spawn the loop thread");

    require(waitForFlag(&runner.finished, 2000), "a loop started after a stop request kept running");
    threadJoin(thread);

    wloopDestroy(&runner.loop);
}

/* Repeated requests must coalesce rather than corrupt the loop state. */
static void testRepeatedStopRequests(env_t *env)
{
    loop_runner_t runner = {0};
    runner.loop          = wloopCreate(0, env->buffer_pool, 0);
    require(runner.loop != NULL, "failed to create the event loop");

    wthread_t thread;
    require(threadCreate(&thread, loopRunnerMain, &runner) == kWThreadErrorNone, "failed to spawn the loop thread");
    require(waitForFlag(&runner.running, 2000), "the loop thread did not start");
    wwSleepMS(50);

    for (int i = 0; i < 16; ++i)
    {
        require(wloopRequestStop(runner.loop), "a repeated wloopRequestStop() failed");
    }

    require(waitForFlag(&runner.finished, 2000), "the loop did not stop after repeated stop requests");
    threadJoin(thread);

    // Requesting a stop on an already stopped (but not yet destroyed) loop stays
    // safe; this is the shutdown ordering where a worker exits on its own just
    // as worker 0 asks it to stop.
    require(wloopRequestStop(runner.loop), "wloopRequestStop() failed on an already stopped loop");

    wloopDestroy(&runner.loop);
}

/* A stop request racing the loop thread's own exit must be safe both ways. */
static void testStopRacingSelfExit(env_t *env)
{
    for (int attempt = 0; attempt < 32; ++attempt)
    {
        loop_runner_t runner = {0};
        runner.loop          = wloopCreate(0, env->buffer_pool, 0);
        require(runner.loop != NULL, "failed to create the event loop");

        wthread_t thread;
        require(threadCreate(&thread, loopRunnerMain, &runner) == kWThreadErrorNone, "failed to spawn the loop thread");
        require(waitForFlag(&runner.running, 2000), "the loop thread did not start");

        // No settling delay: the request lands anywhere between "not yet in the
        // poller" and "already returning".
        require(wloopRequestStop(runner.loop), "wloopRequestStop() failed while racing the loop thread");

        require(waitForFlag(&runner.finished, 2000), "the loop did not stop while racing its own exit");
        threadJoin(thread);
        wloopDestroy(&runner.loop);
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
    testStopRacingSelfExit(&env);

    envTeardown(&env);
    return 0;
}
