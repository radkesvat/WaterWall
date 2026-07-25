// Stop-pipe lifecycle coverage for the Linux capture device.
//
// The stop pipe outlives every BringUp/BringDown cycle, so a wake token left in
// it by one bring-down would be consumed by the next bring-up's reader, which
// would exit immediately while the device still reported success. These tests
// pin the invariant that both lifecycle boundaries leave the pipe empty.
//
// capture_linux.c is compiled directly into this executable and the generic
// process runner is replaced with a linker wrap, so no iptables rule is ever
// installed, no sysctl is written, and root is not required. A synthetic reader
// routine replaces the NFQUEUE reader, so no netlink socket is opened either.

#include "devices/capture/capture.h"
#include "devices/capture/capture_linux_internal.h"
#include "global_state.h"
#include "worker.h"
#include "wproc.h"
#include "wthread.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

enum
{
    kTestCaptureRangeCount = 2,
    kTestQueueNumber       = 77,
    kJoinPollTimeoutMs     = 20,
    kWaitTimeoutMs         = 5000,
    // Long enough for a freshly created reader to actually park inside poll().
    kReaderSettleUs = 50000
};

// ---------------------------------------------------------------------------
// Command seam: nothing may reach a real iptables/sysctl binary.
// ---------------------------------------------------------------------------

static size_t recorded_command_count = 0;
static size_t slow_delete_sleep_us   = 0;
static bool   fail_rule_commands     = false;

bool __wrap_procRunArgvWithDeadline(const char *file, const char *const argv[], const proc_command_options_t *options,
                                    proc_command_result_t *out);
void __real_procCommandResultDrop(proc_command_result_t *out);
void __wrap_procCommandResultDrop(proc_command_result_t *out);

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

bool __wrap_procRunArgvWithDeadline(const char *file, const char *const argv[], const proc_command_options_t *options,
                                    proc_command_result_t *out)
{
    require(file != NULL && argv != NULL && options != NULL && out != NULL,
            "Capture must pass a complete request to the process runner");
    require(strcmp(file, "iptables") == 0 || strcmp(file, "sysctl") == 0,
            "this test must never execute anything but the wrapped iptables/sysctl seams");

    ++recorded_command_count;

    // Rule deletion is deliberately slow in the lifecycle test so the reader can
    // observe running == false and exit before BringDown writes its wake token.
    if (slow_delete_sleep_us > 0 && strcmp(file, "iptables") == 0 && strcmp(argv[3], "-D") == 0)
    {
        usleep((useconds_t) slow_delete_sleep_us);
    }

    memset(out, 0, sizeof(*out));
    if (fail_rule_commands && strcmp(file, "iptables") == 0)
    {
        out->exit_code = 1;
        return false;
    }
    out->exit_code = 0;
    return true;
}

void __wrap_procCommandResultDrop(proc_command_result_t *out)
{
    __real_procCommandResultDrop(out);
}

// ---------------------------------------------------------------------------
// Synthetic reader
// ---------------------------------------------------------------------------

typedef struct reader_probe_s
{
    atomic_int  started;
    atomic_int  exited;
    atomic_int  pipe_events;
    atomic_bool consume_token;
    atomic_bool exit_without_reading;
} reader_probe_t;

static WTHREAD_ROUTINE(probeReader) // NOLINT
{
    capture_device_t *cdev  = userdata;
    reader_probe_t   *probe = cdev->userdata;

    atomicAddExplicit(&probe->started, 1, memory_order_relaxed);

    if (atomicLoadExplicit(&probe->exit_without_reading, memory_order_relaxed))
    {
        // Models the race in the finding: the reader saw running == false during
        // the (slow) rule removal and left before BringDown wrote its token.
        atomicAddExplicit(&probe->exited, 1, memory_order_relaxed);
        return 0;
    }

    struct pollfd fds;
    fds.fd     = cdev->linux_pipe_fds[0];
    fds.events = POLLIN;

    while (atomicLoadExplicit(&cdev->running, memory_order_relaxed))
    {
        fds.revents = 0;
        int ret     = poll(&fds, 1, kJoinPollTimeoutMs);
        if (ret < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            break;
        }
        if (ret > 0 && (fds.revents & POLLIN) != 0)
        {
            atomicAddExplicit(&probe->pipe_events, 1, memory_order_relaxed);
            if (atomicLoadExplicit(&probe->consume_token, memory_order_relaxed))
            {
                char    token = 0;
                ssize_t got   = read(cdev->linux_pipe_fds[0], &token, 1);
                discard got;
            }
            break;
        }
    }

    atomicAddExplicit(&probe->exited, 1, memory_order_relaxed);
    return 0;
}

// ---------------------------------------------------------------------------
// Device scaffolding
// ---------------------------------------------------------------------------

typedef struct test_env_s
{
    master_pool_t *large_master;
    master_pool_t *small_master;
    buffer_pool_t *buffer_pool;
    buffer_pool_t *buffer_pools[1];
} test_env_t;

static void envSetup(test_env_t *env)
{
    env->large_master    = masterpoolCreateWithCapacity(16);
    env->small_master    = masterpoolCreateWithCapacity(16);
    env->buffer_pool     = bufferpoolCreate(env->large_master, env->small_master, 16, 8192, 4096);
    env->buffer_pools[0] = env->buffer_pool;

    GSTATE.shortcut_buffer_pools = env->buffer_pools;
    tl_wid                       = 0;
}

static void envTeardown(test_env_t *env)
{
    GSTATE.shortcut_buffer_pools = NULL;
    bufferpoolDestroy(env->buffer_pool);
    masterpoolMakeEmpty(env->large_master);
    masterpoolMakeEmpty(env->small_master);
    masterpoolDestroy(env->large_master);
    masterpoolDestroy(env->small_master);
}

// Build only the fields BringUp/BringDown touch. caputredeviceCreate() itself
// needs a real netlink socket, which this test deliberately avoids.
static void deviceSetup(capture_device_t *cdev, test_env_t *env, reader_probe_t *probe)
{
    memset(cdev, 0, sizeof(*cdev));
    memset(probe, 0, sizeof(*probe));

    cdev->name                = stringDuplicate("capture-pipe-test");
    cdev->socket              = -1;
    cdev->queue_number        = kTestQueueNumber;
    cdev->capture_range_count = kTestCaptureRangeCount;
    cdev->capture_cidrs       = memoryAllocateZero(kTestCaptureRangeCount * sizeof(char *));
    cdev->capture_cidrs[0]    = stringDuplicate("10.0.0.0/8");
    cdev->capture_cidrs[1]    = stringDuplicate("192.168.0.0/16");
    cdev->reader_buffer_pool  = env->buffer_pool;
    cdev->routine_reader      = probeReader;
    cdev->userdata            = probe;
    cdev->running             = false;
    cdev->up                  = false;

    require(pipe(cdev->linux_pipe_fds) == 0, "test pipe creation failed");
    require(capturedeviceMakeStopPipeNonblocking(cdev->linux_pipe_fds[0]),
            "the production helper failed to make the stop pipe read end nonblocking");
}

static void deviceTeardown(capture_device_t *cdev)
{
    close(cdev->linux_pipe_fds[0]);
    close(cdev->linux_pipe_fds[1]);
    memoryFree(cdev->capture_cidrs[0]);
    memoryFree(cdev->capture_cidrs[1]);
    memoryFree(cdev->capture_cidrs);
    memoryFree(cdev->name);
}

static bool pipeHasReadableData(const capture_device_t *cdev)
{
    struct pollfd fds = {.fd = cdev->linux_pipe_fds[0], .events = POLLIN, .revents = 0};
    int           ret = poll(&fds, 1, 0);
    require(ret >= 0, "poll on the stop pipe failed");
    return ret > 0 && (fds.revents & POLLIN) != 0;
}

static void waitForReaderExits(reader_probe_t *probe, int expected)
{
    for (int waited_ms = 0; waited_ms < kWaitTimeoutMs; waited_ms += 5)
    {
        if (atomicLoadExplicit(&probe->exited, memory_order_relaxed) >= expected)
        {
            return;
        }
        usleep(5000);
    }
    require(false, "a synthetic reader never exited");
}

// ---------------------------------------------------------------------------
// Drain primitive
// ---------------------------------------------------------------------------

static void testDrainEmptiesThePipe(test_env_t *env)
{
    capture_device_t cdev;
    reader_probe_t   probe;
    deviceSetup(&cdev, env, &probe);

    for (int i = 0; i < 5; ++i)
    {
        require(write(cdev.linux_pipe_fds[1], "x", 1) == 1, "failed to write a stop token");
    }
    require(pipeHasReadableData(&cdev), "the test wrote tokens but the pipe reports no readable data");

    require(capturedeviceDrainStopPipe(&cdev), "draining a pipe holding several tokens must succeed");
    require(! pipeHasReadableData(&cdev), "the drain left readable data in the stop pipe");

    // Draining an already-empty pipe must return promptly and successfully; the
    // nonblocking read end is what makes that possible.
    require(capturedeviceDrainStopPipe(&cdev), "draining an already-empty pipe must succeed");
    require(! pipeHasReadableData(&cdev), "draining an empty pipe made it readable");

    deviceTeardown(&cdev);
}

static void testDrainReportsBrokenPipe(test_env_t *env)
{
    capture_device_t cdev;
    reader_probe_t   probe;
    deviceSetup(&cdev, env, &probe);

    // Closing the write end turns every subsequent read into EOF, which is a
    // lifecycle failure rather than "the pipe is empty".
    close(cdev.linux_pipe_fds[1]);
    require(! capturedeviceDrainStopPipe(&cdev), "a stop pipe whose write end is gone must report failure");

    close(cdev.linux_pipe_fds[0]);
    memoryFree(cdev.capture_cidrs[0]);
    memoryFree(cdev.capture_cidrs[1]);
    memoryFree(cdev.capture_cidrs);
    memoryFree(cdev.name);
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

// The exact regression: the first reader exits during the slow rule deletion,
// BringDown then writes a token nobody consumes, and the next BringUp's reader
// must not be terminated by it.
static void testStaleTokenDoesNotKillTheNextReader(test_env_t *env)
{
    capture_device_t cdev;
    reader_probe_t   probe;
    deviceSetup(&cdev, env, &probe);

    atomicStoreExplicit(&probe.exit_without_reading, true, memory_order_relaxed);
    require(caputredeviceBringUp(&cdev), "the first bring-up must succeed");
    require(cdev.up, "the first bring-up did not mark the device up");
    waitForReaderExits(&probe, 1);

    slow_delete_sleep_us = 20000; // let the reader be gone before the wake write
    require(caputredeviceBringDown(&cdev), "the first bring-down must succeed");
    slow_delete_sleep_us = 0;

    require(atomicLoadExplicit(&probe.pipe_events, memory_order_relaxed) == 0,
            "the first reader was supposed to exit without observing the pipe");
    require(! pipeHasReadableData(&cdev), "bring-down left an unread wake token in the stop pipe");

    // Same device object, second cycle: this reader must stay alive.
    atomicStoreExplicit(&probe.exit_without_reading, false, memory_order_relaxed);
    atomicStoreExplicit(&probe.consume_token, true, memory_order_relaxed);
    require(caputredeviceBringUp(&cdev), "the second bring-up on the same device must succeed");

    // Well past several poll intervals: a stale token would have ended it here.
    usleep(120000);
    require(atomicLoadExplicit(&probe.pipe_events, memory_order_relaxed) == 0,
            "the second reader saw a stale stop-pipe event");
    require(atomicLoadExplicit(&probe.exited, memory_order_relaxed) == 1,
            "the second reader exited before the test brought the device down");

    require(caputredeviceBringDown(&cdev), "the second bring-down must succeed");
    waitForReaderExits(&probe, 2);
    require(atomicLoadExplicit(&probe.pipe_events, memory_order_relaxed) == 1,
            "the second reader did not observe exactly one deliberate stop event");
    require(! pipeHasReadableData(&cdev), "the second bring-down left a token in the stop pipe");
    require(! cdev.up, "the device is still marked up after bring-down");

    deviceTeardown(&cdev);
}

// A reader that consumes the token leaves nothing behind either, and the pipe
// stays empty across repeated cycles.
static void testRepeatedCyclesKeepThePipeEmpty(test_env_t *env)
{
    capture_device_t cdev;
    reader_probe_t   probe;
    deviceSetup(&cdev, env, &probe);
    atomicStoreExplicit(&probe.consume_token, true, memory_order_relaxed);

    for (int cycle = 0; cycle < 3; ++cycle)
    {
        require(caputredeviceBringUp(&cdev), "a repeated bring-up must succeed");
        require(caputredeviceBringDown(&cdev), "a repeated bring-down must succeed");
        require(! pipeHasReadableData(&cdev), "a bring-up/bring-down cycle left a token in the stop pipe");
    }
    require(atomicLoadExplicit(&probe.started, memory_order_relaxed) == 3, "every cycle must start a reader");
    require(atomicLoadExplicit(&probe.exited, memory_order_relaxed) == 3, "every reader must be joined");

    deviceTeardown(&cdev);
}

// Pipe and rule failures must both be visible in the return values.
static void testLifecycleReportsInjectedFailures(test_env_t *env)
{
    capture_device_t cdev;
    reader_probe_t   probe;
    deviceSetup(&cdev, env, &probe);
    atomicStoreExplicit(&probe.consume_token, true, memory_order_relaxed);

    // A bring-up whose defensive drain fails must refuse before it installs any
    // rule or starts a reader.
    const size_t commands_before = recorded_command_count;
    close(cdev.linux_pipe_fds[1]);
    require(! caputredeviceBringUp(&cdev), "bring-up must fail when the stop pipe cannot be drained");
    require(recorded_command_count == commands_before, "a failed bring-up must not install any rule");
    require(atomicLoadExplicit(&probe.started, memory_order_relaxed) == 0, "a failed bring-up must not start a reader");
    require(! cdev.up, "a failed bring-up marked the device up");
    close(cdev.linux_pipe_fds[0]);

    // Restore a healthy pipe and show that a rule-removal failure still surfaces.
    require(pipe(cdev.linux_pipe_fds) == 0, "failed to recreate the test pipe");
    require(capturedeviceMakeStopPipeNonblocking(cdev.linux_pipe_fds[0]), "failed to re-arm the nonblocking read end");

    require(caputredeviceBringUp(&cdev), "bring-up on a healthy pipe must succeed");
    fail_rule_commands = true;
    require(! caputredeviceBringDown(&cdev), "a failed rule removal must be reported by bring-down");
    fail_rule_commands = false;
    waitForReaderExits(&probe, 1);
    require(! pipeHasReadableData(&cdev), "a failing bring-down still must leave the stop pipe empty");

    deviceTeardown(&cdev);
}

// ---------------------------------------------------------------------------
// Bounded reader poll
// ---------------------------------------------------------------------------

static atomic_int production_reader_returned;

static WTHREAD_ROUTINE(productionReaderWrapper) // NOLINT
{
    discard captureLinuxReadRoutine(userdata);
    atomicStoreExplicit(&production_reader_returned, 1, memory_order_release);
    return 0;
}

// The production reader must be able to leave poll() on `running == false`
// alone. Without that, a bring-down whose wake write fails would join a thread
// parked in poll() forever. This runs the real routine, never delivers a token,
// and fails on a deadline rather than hanging the suite.
static void testProductionReaderLeavesPollWithoutWakeToken(test_env_t *env)
{
    capture_device_t cdev;
    reader_probe_t   probe;
    deviceSetup(&cdev, env, &probe);

    // A socketpair stands in for the netfilter socket: pollable, and permanently
    // silent, so neither descriptor the reader watches ever becomes readable.
    int pair[2];
    require(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) == 0, "socketpair for the silent capture socket failed");
    cdev.socket = pair[0];

    atomicStoreExplicit(&production_reader_returned, 0, memory_order_relaxed);
    cdev.running = true;
    atomicThreadFence(memory_order_release);

    wthread_t thread;
    require(threadCreate(&thread, productionReaderWrapper, &cdev) == kWThreadErrorNone,
            "failed to start the production reader");

    // Let it settle inside poll(), then withdraw the only other exit condition.
    // Without the settle it could leave through the top-of-loop `running` check
    // and prove nothing about poll() itself.
    usleep(kReaderSettleUs);
    cdev.running = false;
    atomicThreadFence(memory_order_release);

    bool returned = false;
    for (int waited_ms = 0; waited_ms < kWaitTimeoutMs && ! returned; waited_ms += 5)
    {
        returned = atomicLoadExplicit(&production_reader_returned, memory_order_acquire) != 0;
        if (! returned)
        {
            usleep(5000);
        }
    }
    require(returned, "the production reader never left poll() without a wake token; its poll must stay bounded");
    require(safeThreadJoin(thread), "failed to join the production reader");
    require(! pipeHasReadableData(&cdev), "no wake token was written, so the stop pipe must still be empty");

    close(pair[0]);
    close(pair[1]);
    cdev.socket = -1;
    deviceTeardown(&cdev);
}

typedef struct bringdown_task_s
{
    capture_device_t *cdev;
    atomic_int        finished;
    atomic_int        result;
} bringdown_task_t;

static WTHREAD_ROUTINE(bringDownWorker) // NOLINT
{
    bringdown_task_t *task = userdata;
    const bool        ok   = caputredeviceBringDown(task->cdev);
    atomicStoreExplicit(&task->result, ok ? 1 : 0, memory_order_relaxed);
    atomicStoreExplicit(&task->finished, 1, memory_order_release);
    return 0;
}

// End-to-end version of the same hazard: a hard wake-write failure must be
// returned by bring-down instead of deadlocking its join. The production reader
// is used, so the bounded poll is the only thing that can release the join.
// Bring-down runs on its own thread and is awaited with a deadline, so a
// regression fails cleanly here instead of hanging the suite.
static void testWakeWriteFailureIsReportedNotDeadlocked(test_env_t *env)
{
    capture_device_t cdev;
    reader_probe_t   probe;
    deviceSetup(&cdev, env, &probe);

    int pair[2];
    require(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) == 0, "socketpair for the silent capture socket failed");
    cdev.socket         = pair[0];
    cdev.routine_reader = productionReaderWrapper;

    atomicStoreExplicit(&production_reader_returned, 0, memory_order_relaxed);
    require(caputredeviceBringUp(&cdev), "bring-up with the production reader must succeed");

    // The reader must genuinely be parked inside poll() before the wake write is
    // sabotaged; otherwise it would exit through the top-of-loop `running` check
    // and the join would never have been at risk.
    usleep(kReaderSettleUs);

    // Make the wake write fail hard (EBADF). The real write end stays open so the
    // post-join drain still runs against a valid descriptor.
    const int real_write_fd = cdev.linux_pipe_fds[1];
    cdev.linux_pipe_fds[1]  = -1;

    bringdown_task_t task = {.cdev = &cdev};
    wthread_t        down_thread;
    require(threadCreate(&down_thread, bringDownWorker, &task) == kWThreadErrorNone,
            "failed to start the bring-down worker");

    bool finished = false;
    for (int waited_ms = 0; waited_ms < kWaitTimeoutMs && ! finished; waited_ms += 5)
    {
        finished = atomicLoadExplicit(&task.finished, memory_order_acquire) != 0;
        if (! finished)
        {
            usleep(5000);
        }
    }
    require(finished, "bring-down deadlocked joining a reader that never received a wake token");
    require(safeThreadJoin(down_thread), "failed to join the bring-down worker");

    cdev.linux_pipe_fds[1] = real_write_fd;

    require(atomicLoadExplicit(&task.result, memory_order_relaxed) == 0,
            "a hard wake-write failure must be reported by bring-down");
    require(atomicLoadExplicit(&production_reader_returned, memory_order_acquire) != 0,
            "bring-down returned without the reader having exited");
    require(! cdev.up, "a failed bring-down must still mark the device down");
    require(! pipeHasReadableData(&cdev), "a failed wake write must not leave data in the stop pipe");

    // The device must still be reusable afterwards.
    cdev.routine_reader = probeReader;
    atomicStoreExplicit(&probe.consume_token, true, memory_order_relaxed);
    require(caputredeviceBringUp(&cdev), "bring-up after a failed wake write must succeed");
    require(caputredeviceBringDown(&cdev), "bring-down after a recovered wake path must succeed");
    require(! pipeHasReadableData(&cdev), "the recovery cycle left a token in the stop pipe");

    close(pair[0]);
    close(pair[1]);
    cdev.socket = -1;
    deviceTeardown(&cdev);
}

int main(void)
{
    test_env_t env;
    envSetup(&env);

    testDrainEmptiesThePipe(&env);
    testDrainReportsBrokenPipe(&env);
    testStaleTokenDoesNotKillTheNextReader(&env);
    testRepeatedCyclesKeepThePipeEmpty(&env);
    testLifecycleReportsInjectedFailures(&env);
    // Isolated proof that the reader's poll is bounded, ordered before the
    // end-to-end case so a regression is attributed to the primitive first.
    testProductionReaderLeavesPollWithoutWakeToken(&env);
    testWakeWriteFailureIsReportedNotDeadlocked(&env);

    envTeardown(&env);

    printf("capture_linux_pipe_test: all tests passed\n");
    return 0;
}
