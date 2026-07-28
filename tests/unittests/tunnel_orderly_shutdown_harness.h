#pragma once

/*
 * Shared scaffolding for the Category-B orderly-shutdown failure-injection
 * tests.
 *
 * A Category-B failure leaves the process structurally valid but unable to
 * continue correctly. The failing worker must release what its own callback
 * owns, hand the shutdown to worker 0 through requestProgramShutdown(), fall
 * back to abortProgramNow() only if that handoff is refused, and then return.
 * This header turns each of those properties into a machine-checkable form:
 *
 *   - the three process APIs are linker-wrapped and recorded instead of being
 *     treated as test failures, so a test can assert the exact call, its exit
 *     code, and that the callback returned afterwards;
 *   - requestProgramShutdown() returns a value the test chooses, so the refused
 *     handoff is reachable without a real signal manager;
 *   - abortProgramNow() and terminateProgram() keep their _Noreturn contract by
 *     leaving the process, which is what makes the refused-handoff case run in a
 *     forked child;
 *   - everything else (buffer ledger, neighbour trace, worker environment, bare
 *     lines) is reused from tunnel_line_failure_harness.h.
 *
 * Like that header, this one deliberately includes no tunnel structure.h.
 *
 * Every test that includes this header must link with:
 *   -Wl,--wrap=terminateProgram -Wl,--wrap=abortProgramNow
 *   -Wl,--wrap=requestProgramShutdown -Wl,--wrap=bufferpoolGetLargeBuffer
 *   -Wl,--wrap=bufferpoolGetSmallBuffer -Wl,--wrap=bufferpoolReuseBuffer
 *   -Wl,--wrap=sbufDestroy
 */

#define TWF_CUSTOM_PROCESS_API_WRAPS 1
#include "tunnel_line_failure_harness.h"

// The worker wios pool is sized from the concrete wio_t, which wwapi.h only
// forward declares.
#include "wevent.h"

#include <sys/wait.h>
#include <unistd.h>

// ---------------------------------------------------------------------------
// exit codes used by the forked sub-cases
// ---------------------------------------------------------------------------

enum
{
    // abortProgramNow(1) reached as the fallback of exactly one refused
    // requestProgramShutdown(1). This is the only shape a Category-B site may
    // use to leave the process.
    kTosChildFallbackAbort = 71,
    // The child reached terminateProgram(), which no converted site may do.
    kTosChildTerminate = 72,
    // The child's production call returned instead of leaving the process.
    kTosChildReturned = 73,
    // abortProgramNow(1) reached without any request first: a Category-D
    // invariant, which must never consult the orderly helper.
    kTosChildDirectAbort = 74,
    // abortProgramNow() reached with an exit code or a request history that
    // matches neither contract.
    kTosChildBadAbort = 75
};

// ---------------------------------------------------------------------------
// process API recorder
// ---------------------------------------------------------------------------

typedef struct tos_process_api_s
{
    uint32_t request_calls;
    int      request_codes[8];
    uint32_t abort_calls;
    uint32_t terminate_calls;
    // What requestProgramShutdown() reports back. A worker-0 handoff that is
    // refused is what forces the hard fallback.
    bool accept_request;
} tos_process_api_t;

static tos_process_api_t g_tos_api = {.accept_request = true};

_Noreturn void __wrap_terminateProgram(int exit_code);
_Noreturn void __wrap_abortProgramNow(int exit_code);
bool           __wrap_requestProgramShutdown(int exit_code);

bool __wrap_requestProgramShutdown(int exit_code)
{
    twfRequire(g_tos_api.request_calls < (sizeof(g_tos_api.request_codes) / sizeof(g_tos_api.request_codes[0])),
               "too many requestProgramShutdown() calls to record");
    g_tos_api.request_codes[g_tos_api.request_calls++] = exit_code;
    return g_tos_api.accept_request;
}

/*
 * The exit code reports which contract this abort satisfied, so a case cannot
 * pass by reaching the right function through the wrong path: a Category-B
 * fallback that never attempted the handoff, and a Category-D invariant that
 * went through the orderly helper first, both land on distinct codes.
 */
_Noreturn void __wrap_abortProgramNow(int exit_code)
{
    ++g_tos_api.abort_calls;
    fprintf(stderr,
            "[%s]: abortProgramNow(%d) after %u request(s)\n",
            g_twf_case,
            exit_code,
            (unsigned) g_tos_api.request_calls);
    fflush(stderr);

    if (exit_code != 1 || g_tos_api.terminate_calls != 0)
    {
        _Exit(kTosChildBadAbort);
    }

    if (g_tos_api.request_calls == 0)
    {
        _Exit(kTosChildDirectAbort);
    }

    // The fallback is only correct after exactly one request that asked for
    // exit code 1 and was refused a worker-0 handoff.
    if (g_tos_api.request_calls == 1 && g_tos_api.request_codes[0] == 1 && ! g_tos_api.accept_request)
    {
        _Exit(kTosChildFallbackAbort);
    }

    _Exit(kTosChildBadAbort);
}

_Noreturn void __wrap_terminateProgram(int exit_code)
{
    ++g_tos_api.terminate_calls;
    fprintf(stderr, "[%s]: terminateProgram(%d)\n", g_twf_case, exit_code);
    fflush(stderr);
    _Exit(kTosChildTerminate);
}

static void tosResetProcessApi(bool accept_request)
{
    memoryZero(&g_tos_api, sizeof(g_tos_api));
    g_tos_api.accept_request = accept_request;
}

/**
 * The whole Category-B contract for an accepted handoff: exactly one request
 * with the expected exit code, no hard abort, and no legacy terminate.
 */
static void tosRequireAcceptedRequest(int expected_code)
{
    twfRequireEqualU32(g_tos_api.request_calls, 1, "expected exactly one requestProgramShutdown() call");
    twfRequireEqualU32((uint32_t) g_tos_api.request_codes[0],
                       (uint32_t) expected_code,
                       "requestProgramShutdown() used the wrong exit code");
    twfRequireEqualU32(g_tos_api.abort_calls, 0, "an accepted handoff must not reach abortProgramNow()");
    twfRequireEqualU32(g_tos_api.terminate_calls, 0, "a converted site must never call terminateProgram()");
}

static void tosRequireNoProcessApiCall(void)
{
    twfRequireEqualU32(g_tos_api.request_calls, 0, "this path must not request a process shutdown");
    twfRequireEqualU32(g_tos_api.abort_calls, 0, "this path must not hard-abort");
    twfRequireEqualU32(g_tos_api.terminate_calls, 0, "this path must not terminate the process");
}

// ---------------------------------------------------------------------------
// worker environment with a real message queue
// ---------------------------------------------------------------------------
//
// Several converted failures live in static worker tasks that onStart only
// enqueues. Reaching them the way the runtime does needs published workers with
// message queues, so this environment builds them and drains one worker's queue
// on demand. Without it those failures are unreachable from a test.

enum
{
    kTosMaxWorkers = 4
};

// One extra slot for the lwIP pseudo-worker: WORKERS_COUNT includes it, and
// getWorkersCount() subtracts it, so a test that wants N event-loop workers has
// to publish N + 1.
typedef struct tos_worker_env_s
{
    master_pool_t             *large_masters[kTosMaxWorkers];
    master_pool_t             *small_masters[kTosMaxWorkers];
    master_pool_t             *message_master;
    master_pool_t             *wios_master;
    buffer_pool_t             *pools[kTosMaxWorkers + 1];
    wloop_t                   *loops[kTosMaxWorkers + 1];
    threadsafe_generic_pool_t *wios_pools[kTosMaxWorkers + 1];
    worker_t                   workers[kTosMaxWorkers + 1];
    wid_t                      count;
} tos_worker_env_t;

/**
 * Publish @p count event-loop workers, each with its own buffer pool, event loop
 * and message queue, through the same GSTATE shortcuts the runtime uses. After
 * this, getWorkersCount() reports exactly @p count.
 */
static void tosWorkerEnvSetup(tos_worker_env_t *env, wid_t count, uint32_t large_buffer_size,
                              uint32_t small_buffer_size)
{
    twfRequire(count > 0 && count <= kTosMaxWorkers, "unsupported test worker count");
    memoryZero(env, sizeof(*env));
    env->count = count;

    env->message_master = masterpoolCreateWithCapacity(16);
    twfRequire(env->message_master != NULL, "failed to create the test message master pool");
    workerMessagesInstallMasterPoolCallbacks(env->message_master);
    GSTATE.masterpool_messages = env->message_master;

    // A queued message wakes its worker through the loop's event fd, and that
    // registration allocates a wio from the worker's pool.
    env->wios_master = masterpoolCreateWithCapacity(16);
    twfRequire(env->wios_master != NULL, "failed to create the test wios master pool");

    for (wid_t wi = 0; wi < count; ++wi)
    {
        env->large_masters[wi] = masterpoolCreateWithCapacity(8);
        env->small_masters[wi] = masterpoolCreateWithCapacity(8);
        twfRequire(env->large_masters[wi] != NULL && env->small_masters[wi] != NULL,
                   "failed to create a test master pool");

        env->pools[wi] =
            bufferpoolCreate(env->large_masters[wi], env->small_masters[wi], 4, large_buffer_size, small_buffer_size);
        twfRequire(env->pools[wi] != NULL, "failed to create a test buffer pool");

        env->wios_pools[wi] =
            threadsafegenericpoolCreateWithDefaultAllocatorAndCapacity(env->wios_master, sizeof(wio_t), 8);
        twfRequire(env->wios_pools[wi] != NULL, "failed to create a test wios pool");

        env->loops[wi] = wloopCreate(WLOOP_FLAG_AUTO_FREE, env->pools[wi], wi);
        twfRequire(env->loops[wi] != NULL, "failed to create a test event loop");

        // wloopRun() is what normally publishes this, and wloopProcessEvents()
        // returns before running pendings while a loop still reads as stopped.
        // The tests step the loop by hand instead of running it on a thread.
        env->loops[wi]->status = WLOOP_STATUS_RUNNING;

        env->workers[wi].wid            = wi;
        env->workers[wi].loop           = env->loops[wi];
        env->workers[wi].buffer_pool    = env->pools[wi];
        env->workers[wi].wios_pool      = env->wios_pools[wi];
        env->workers[wi].has_event_loop = true;
        workerMessagesInit(&env->workers[wi]);
    }

    GSTATE.workers               = env->workers;
    GSTATE.workers_count         = (uint32_t) count + 1U; // + the lwIP pseudo-worker
    GSTATE.shortcut_buffer_pools = env->pools;
    GSTATE.shortcut_loops        = env->loops;
    GSTATE.shortcut_wios_pools   = env->wios_pools;

    twfRequire(getWorkersCount() == count, "the published worker count is not what getWorkersCount() reports");

    twfBufferLedgerReset();
}

/**
 * Adopt @p wid as this thread's worker identity and return the previous one.
 *
 * Each worker thread publishes its own id, and per-worker APIs assert against
 * getWID(). A test that drives one of them has to do the same or it is calling
 * them from the wrong worker.
 */
static wid_t tosSetCurrentWorker(wid_t wid)
{
    const wid_t previous = tl_wid;
    tl_wid               = wid;
    return previous;
}

/**
 * Run everything sendWorkerMessageForceQueue() posted to @p wid, which is what
 * executes a task that onStart only enqueued.
 */
static void tosPumpWorker(tos_worker_env_t *env, wid_t wid)
{
    twfRequire(wid < env->count, "pumping a worker that was never published");

    // The task runs as that worker, exactly as it would on its own thread.
    const wid_t previous = tosSetCurrentWorker(wid);

    // The wakeup travels through the loop's event fd, so reading it and running
    // the callback it dispatches can take more than one iteration.
    for (int i = 0; i < 8; ++i)
    {
        discard wloopProcessEvents(env->loops[wid], 0);
    }

    discard tosSetCurrentWorker(previous);
}

static void tosWorkerEnvTeardown(tos_worker_env_t *env)
{
    for (wid_t wi = 0; wi < env->count; ++wi)
    {
        workerMessagesDestroy(&env->workers[wi]);
    }
}

// ---------------------------------------------------------------------------
// forked sub-cases
// ---------------------------------------------------------------------------
//
// abortProgramNow() and terminateProgram() must not return, so any case that
// can reach one needs its own process. fork() is not wrapped by this harness,
// so the plain libc entry points are the real ones.

/**
 * Run @p body in a child process and require it to end with @p expected_exit.
 *
 * The child inherits the current injection state, so a caller sets
 * tosResetProcessApi(false) first to make the worker-0 handoff refuse.
 */
static void tosRequireChildExit(const char *what, void (*body)(void *), void *argument, int expected_exit)
{
    fflush(stdout);
    fflush(stderr);

    pid_t pid = fork();
    twfRequire(pid >= 0, "fork() failed while starting a sub-case");

    if (pid == 0)
    {
        body(argument);
        // Reached only when the production call returned instead of leaving.
        fflush(stdout);
        fflush(stderr);
        _Exit(kTosChildReturned);
    }

    int status = 0;
    twfRequire(waitpid(pid, &status, 0) == pid, "waitpid() failed while collecting a sub-case");

    if (! WIFEXITED(status))
    {
        fprintf(stderr, "FAIL [%s]: %s did not exit normally (status 0x%x)\n", g_twf_case, what, (unsigned) status);
        fflush(stderr);
        _Exit(1);
    }

    if (WEXITSTATUS(status) != expected_exit)
    {
        fprintf(stderr,
                "FAIL [%s]: %s exited with %d, expected %d%s\n",
                g_twf_case,
                what,
                WEXITSTATUS(status),
                expected_exit,
                WEXITSTATUS(status) == kTosChildReturned ? " (the production call returned instead)" : "");
        fflush(stderr);
        _Exit(1);
    }
}
