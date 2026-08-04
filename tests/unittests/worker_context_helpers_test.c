/*
 * Focused coverage for the checked worker-context helpers and for the
 * worker-message bridge that unregistered, foreign and pseudo-worker threads
 * depend on.
 *
 * The rule under test: nothing except the actual owning event worker may reach
 * worker-local state, and nothing ever silently falls back to worker 0.
 */

#include "global_state.h"
#include "worker.h"
#include "worker_messages.h"
#include "wwapi.h"

#if defined(__unix__) || defined(__APPLE__) || defined(UNIX)
#include <sys/wait.h>
#include <unistd.h>
#define HAS_UNIX_FORK 1
#endif

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void initTestGlobalState(void)
{
    static char            log_off[]         = "OFF";
    ww_construction_data_t init_data         = {0};
    init_data.workers_count                  = 3;
    init_data.ram_profile                    = 4;
    init_data.mtu_size                       = 1500;
    init_data.internal_logger_data.log_level = log_off;
    init_data.core_logger_data.log_level     = log_off;
    init_data.network_logger_data.log_level  = log_off;
    init_data.dns_logger_data.log_level      = log_off;

    createGlobalState(init_data);
}

static void shutdownTestGlobalState(void)
{
    for (unsigned int wid = 1; wid < getWorkersCount(); ++wid)
    {
        discard workerRequestStop(getWorker(wid));
        discard workerJoin(getWorker(wid));
    }
    destroyGlobalState();
}

// ---------------------------------------------------------------------------
// Checked accessors
// ---------------------------------------------------------------------------

static void testAccessorsOnOwningWorker(void)
{
    require(currentThreadIsEventWorkerWID(0), "main thread is not bound to event worker 0");

    require(getCurrentEventWorker() == getWorker(0), "getCurrentEventWorker() did not return worker 0");
    require(tryGetCurrentEventWorker() == getWorker(0), "tryGetCurrentEventWorker() did not return worker 0");
    require(getCurrentEventWorkerWID() == 0, "getCurrentEventWorkerWID() did not return 0");
    require(getCurrentEventWorkerBufferPool() == getWorkerBufferPool(0), "current buffer pool is not worker 0's");
    require(getCurrentEventWorkerContextPool() == getWorkerContextPool(0), "current context pool is not worker 0's");
    require(getCurrentEventWorkerLoop() == getWorkerLoop(0), "current loop is not worker 0's");
    require(getLoopEventWorkerWID(getWorkerLoop(0)) == 0, "getLoopEventWorkerWID() did not resolve worker 0");

    // Another event worker's resources are reachable by explicit id only, and
    // must not be confused with the current worker's.
    require(getWorkerBufferPool(1) != getCurrentEventWorkerBufferPool(),
            "worker 1's pool aliased the current worker's pool");
    require(! currentThreadIsEventWorkerWID(1), "worker 0 claimed to own worker 1");
}

static void testPredicatesRejectUnregisteredAndLwip(void)
{
    const wid_t lwip_wid = getTotalWorkersCount() - 1;

    testWorkerUnbindWID();
    require(tryGetCurrentEventWorker() == NULL, "unregistered thread got an event worker");
    require(! currentThreadIsEventWorker(), "unregistered thread reported event worker role");
    require(! currentThreadIsEventWorkerWID(0), "unregistered thread claimed to own worker 0");

    testWorkerBindWID(lwip_wid);
    require(currentThreadHasRegisteredWID(), "lwIP pseudo-worker is not registered");
    require(! currentThreadIsEventWorker(), "lwIP pseudo-worker reported event worker role");
    require(tryGetCurrentEventWorker() == NULL, "lwIP pseudo-worker got an event worker");
    require(! currentThreadIsEventWorkerWID(0), "lwIP pseudo-worker claimed to own worker 0");
    require(! currentThreadIsEventWorkerWID(lwip_wid), "lwIP pseudo-worker passed an event-worker check");
    require(workerWIDForLog(0) == 0, "workerWIDForLog(0) did not return 0");
    require(workerWIDForLog(1) == 1, "workerWIDForLog(1) did not return 1");
    require(workerWIDForLog(lwip_wid) == (int) lwip_wid, "workerWIDForLog did not preserve lwIP WID numerically");
    require(workerWIDForLog(lwip_wid) != -1, "workerWIDForLog mapped lwIP WID to -1");
    require(workerWIDForLog(kInvalidWID) == -1, "workerWIDForLog(kInvalidWID) did not return -1");

    testWorkerBindWID(0);
}

// ---------------------------------------------------------------------------
// Worker messages
// ---------------------------------------------------------------------------

typedef struct message_probe_s
{
    atomic_int ran;
    atomic_int cleaned;
    wid_t      observed_wid;
} message_probe_t;

static message_probe_t g_probe;

static void probeCallback(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard arg1;
    discard arg2;
    discard arg3;

    g_probe.observed_wid = worker->wid;
    atomicAddExplicit(&g_probe.ran, 1, memory_order_relaxed);
}

static void probeCleanup(void *arg1, void *arg2, void *arg3)
{
    discard arg1;
    discard arg2;
    discard arg3;

    atomicAddExplicit(&g_probe.cleaned, 1, memory_order_relaxed);
}

static void probeReset(void)
{
    atomicStoreRelaxed(&g_probe.ran, 0);
    atomicStoreRelaxed(&g_probe.cleaned, 0);
    g_probe.observed_wid = kInvalidWID;
}

static int probeRuns(void)
{
    return (int) atomicLoadExplicit(&g_probe.ran, memory_order_relaxed);
}

static int probeCleanups(void)
{
    return (int) atomicLoadExplicit(&g_probe.cleaned, memory_order_relaxed);
}

static void testOwningWorkerRunsInline(void)
{
    probeReset();
    sendWorkerMessageWithCleanup(0, (WorkerMessageCallback) probeCallback, probeCleanup, NULL, NULL, NULL);
    require(probeRuns() == 1, "message to the owning worker did not execute inline");
    require(g_probe.observed_wid == 0, "inline callback did not receive its own worker");
    require(probeCleanups() == 0, "inline execution also ran the cleanup callback");
}

static void testOtherEventWorkerQueues(void)
{
    probeReset();
    sendWorkerMessageWithCleanup(1, (WorkerMessageCallback) probeCallback, probeCleanup, NULL, NULL, NULL);
    require(probeRuns() == 0, "message aimed at worker 1 executed inline on worker 0");
    require(probeCleanups() == 0, "queued message ran its cleanup callback");
}

static WTHREAD_ROUTINE(unregisteredPosterRoutine)
{
    discard userdata;

    require(getWID() == kInvalidWID, "poster thread was not unregistered");

    // Same target as the inline case above: an unregistered caller must never
    // take the inline branch, even for worker 0.
    sendWorkerMessageWithCleanup(0, (WorkerMessageCallback) probeCallback, probeCleanup, NULL, NULL, NULL);
    return 0;
}

static void testUnregisteredThreadQueues(void)
{
    probeReset();

    wthread_t thread;
    require(threadCreate(&thread, unregisteredPosterRoutine, NULL) == kWThreadErrorNone,
            "failed to spawn unregistered poster thread");
    require(threadJoin(thread) == 0, "failed to join unregistered poster thread");

    require(probeRuns() == 0, "unregistered thread executed a worker message inline");
    require(probeCleanups() == 0, "queued message from an unregistered thread ran its cleanup");
}

static void testLwipPseudoWorkerQueues(void)
{
    probeReset();

    testWorkerBindWID(getTotalWorkersCount() - 1);
    sendWorkerMessageWithCleanup(0, (WorkerMessageCallback) probeCallback, probeCleanup, NULL, NULL, NULL);
    testWorkerBindWID(0);

    require(probeRuns() == 0, "lwIP pseudo-worker executed a worker message inline");
    require(probeCleanups() == 0, "message queued from lwIP ran its cleanup");
}

static void testInvalidTargetsCleanUpExactlyOnce(void)
{
    const wid_t lwip_wid = getTotalWorkersCount() - 1;

    const wid_t bad_targets[] = {kInvalidWID, (wid_t) getTotalWorkersCount(), lwip_wid};

    for (size_t i = 0; i < ARRAY_SIZE(bad_targets); ++i)
    {
        probeReset();
        require(! sendWorkerMessageForceQueueWithCleanup(
                    bad_targets[i], (WorkerMessageCallback) probeCallback, probeCleanup, NULL, NULL, NULL),
                "posting to an undeliverable target reported success");
        require(probeRuns() == 0, "undeliverable target still ran the callback");
        require(probeCleanups() == 1, "undeliverable target did not run cleanup exactly once");

        probeReset();
        sendWorkerMessageWithCleanup(
            bad_targets[i], (WorkerMessageCallback) probeCallback, probeCleanup, NULL, NULL, NULL);
        require(probeRuns() == 0, "undeliverable target still ran the callback");
        require(probeCleanups() == 1, "undeliverable target did not run cleanup exactly once");

        probeReset();
        discard sendWorkerMessageTimedWithCleanup(
            bad_targets[i], (WorkerMessageCallback) probeCallback, probeCleanup, 25, NULL, NULL, NULL);
        require(probeRuns() == 0, "undeliverable timed target still ran the callback");
        require(probeCleanups() == 1, "undeliverable timed target did not run cleanup exactly once");
    }
}

// ---------------------------------------------------------------------------
// Tunnel-API buffer ownership
// ---------------------------------------------------------------------------

static void testTunnelApiHelpersRejectNonEventWorkers(void)
{
    // A standalone buffer, so the rejection path may destroy it outright.
    sbuf_t *message = sbufCreateWithPadding(64, 0);
    require(message != NULL, "failed to allocate a standalone API message");

    testWorkerUnbindWID();
    api_result_t result = tunnelapiRecycleMessage(message);
    require(result.result_code == kApiResultError, "tunnel API helper accepted an unregistered caller");
    testWorkerBindWID(0);

    message = sbufCreateWithPadding(64, 0);
    require(message != NULL, "failed to allocate a standalone API message");

    testWorkerBindWID(getTotalWorkersCount() - 1);
    result = tunnelapiRecycleMessage(message);
    require(result.result_code == kApiResultError, "tunnel API helper accepted the lwIP pseudo-worker");
    testWorkerBindWID(0);

    // On the owning event worker the buffer goes back to that worker's pool.
    sbuf_t *pooled = bufferpoolGetSmallBuffer(getCurrentEventWorkerBufferPool());
    require(pooled != NULL, "failed to take a buffer from worker 0's pool");
    result = tunnelapiRecycleMessage(pooled);
    require(result.result_code == kApiResultOk, "tunnel API helper rejected the owning event worker");
}

// ---------------------------------------------------------------------------
// Fallible APIs that must reject a bad worker in release builds too
// ---------------------------------------------------------------------------

/*
 * These are the paths where an assertion is not enough: they are reachable from
 * device threads and from cross-worker code, and in a release build an
 * assert-only guard would let a foreign caller reach another worker's state.
 */

static void probeDnsResult(void *userdata, int status, const char *error, const dns_resolved_addr_t *addrs,
                           size_t naddrs)
{
    discard userdata;
    discard status;
    discard error;
    discard addrs;
    discard naddrs;

    require(false, "a rejected resolve request still invoked its callback");
}

static void probeLineDnsResult(tunnel_t *t, line_t *l, void *userdata, int status, const char *error,
                               const dns_resolved_addr_t *addrs, size_t naddrs)
{
    discard t;
    discard l;
    discard userdata;
    discard status;
    discard error;
    discard addrs;
    discard naddrs;

    require(false, "a rejected line resolve request still invoked its callback");
}

static WTHREAD_ROUTINE(unregisteredResolveRoutine)
{
    atomic_int *rc = userdata;

    require(getWID() == kInvalidWID, "resolve probe thread was not unregistered");
    atomicStoreRelaxed(rc, workerResolveDomainAsync(0, "example.invalid", probeDnsResult, NULL));
    return 0;
}

static void testResolverRejectsForeignCallers(void)
{
    // Worker 0 asking worker 1's resolver: rejected, no resolver touched.
    require(workerResolveDomainAsync(1, "example.invalid", probeDnsResult, NULL) == ARES_ENOTINITIALIZED,
            "resolver accepted a foreign worker id");

    // Out of range, and the lwIP pseudo-worker which has no resolver at all.
    require(workerResolveDomainAsync(kInvalidWID, "example.invalid", probeDnsResult, NULL) == ARES_ENOTINITIALIZED,
            "resolver accepted kInvalidWID");
    require(workerResolveDomainAsync(getTotalWorkersCount() - 1, "example.invalid", probeDnsResult, NULL) ==
                ARES_ENOTINITIALIZED,
            "resolver accepted the lwIP pseudo-worker");

    // An unregistered thread must be rejected without touching worker 0.
    atomic_int rc;
    atomicStoreRelaxed(&rc, 0);
    wthread_t thread;
    require(threadCreate(&thread, unregisteredResolveRoutine, &rc) == kWThreadErrorNone,
            "failed to spawn resolve probe thread");
    require(threadJoin(thread) == 0, "failed to join resolve probe thread");
    require(atomicLoadRelaxed(&rc) == ARES_ENOTINITIALIZED, "resolver accepted an unregistered thread");
}

static void testLineResolverRejectsForeignCallers(void)
{
    // A line owned by worker 1, queried from worker 0: rejected before the
    // line is even referenced, so a failed call cannot leak a lock.
    line_t foreign_line = {.wid = 1, .alive = true};
    atomicStoreRelaxed(&foreign_line.refc, 1);

    require(lineResolveDomainAsync(&foreign_line, "example.invalid", probeLineDnsResult, NULL, NULL) ==
                ARES_ENOTINITIALIZED,
            "line resolver accepted a foreign worker");
    require(atomicLoadRelaxed(&foreign_line.refc) == 1, "rejected line resolve leaked a line reference");

    line_t lwip_line = {.wid = (wid_t) (getTotalWorkersCount() - 1), .alive = true};
    atomicStoreRelaxed(&lwip_line.refc, 1);
    require(lineResolveDomainAsync(&lwip_line, "example.invalid", probeLineDnsResult, NULL, NULL) ==
                ARES_ENOTINITIALIZED,
            "line resolver accepted a line owned by the lwIP pseudo-worker");
    require(atomicLoadRelaxed(&lwip_line.refc) == 1, "rejected line resolve leaked a line reference");
}

static line_t *allocateLineForTunnel(tunnel_t *owner, wid_t wid)
{
    line_t *line = memoryAllocateCacheAlignedZero(sizeof(line_t) + tunnelGetLineStateSize(owner));
    require(line != NULL, "failed to allocate a pipe test line");
    atomicStoreRelaxed(&line->refc, 1);
    line->alive = true;
    line->wid   = wid;
    return line;
}

static void testPipeToRejectsBadWorkers(void)
{
    tunnel_t *child = tunnelCreate(NULL, 0, 0);
    require(child != NULL, "failed to create the pipe test child tunnel");

    tunnel_t *pipe_tunnel = pipetunnelCreate(child);
    require(pipe_tunnel != NULL, "failed to create the pipe tunnel");

    // pipeTo() takes the child and reaches its parent through t->prev; the pipe
    // line state sits at the parent's offset.
    child->prev                = pipe_tunnel;
    pipe_tunnel->lstate_offset = 0;

    line_t *owned_line = allocateLineForTunnel(pipe_tunnel, 0);

    /*
     * Self-target, the lwIP pseudo-worker and an out-of-range slot must all be
     * refused. In a release build these used to be unchecked, and pipeTo() would
     * go on to create a pair line for a worker that cannot own it.
     */
    require(! pipeTo(child, owned_line, 0), "pipeTo accepted the current worker as its target");
    require(! pipeTo(child, owned_line, (wid_t) (getTotalWorkersCount() - 1)),
            "pipeTo accepted the lwIP pseudo-worker as its target");
    require(! pipeTo(child, owned_line, kInvalidWID), "pipeTo accepted kInvalidWID as its target");
    require(! pipeTo(child, owned_line, (wid_t) getTotalWorkersCount()),
            "pipeTo accepted an out-of-range target worker");

    // A source line this worker does not own is refused as well.
    line_t *foreign_line = allocateLineForTunnel(pipe_tunnel, 1);
    require(! pipeTo(child, foreign_line, 0), "pipeTo accepted a source line owned by another worker");

    // Every rejection happened before any pair line was built.
    require(atomicLoadRelaxed(&owned_line->refc) == 1, "rejected pipeTo leaked a source line reference");
    require(atomicLoadRelaxed(&foreign_line->refc) == 1, "rejected pipeTo leaked a source line reference");

    memoryFreeAligned(foreign_line);
    memoryFreeAligned(owned_line);
    tunnelDestroy(pipe_tunnel);
}

// ---------------------------------------------------------------------------
// Contract aborts (checked in a child process)
// ---------------------------------------------------------------------------

#if defined(HAS_UNIX_FORK)
typedef enum
{
    kAbortCaseUnregisteredPool = 0,
    kAbortCaseUnregisteredLoop,
    kAbortCaseUnregisteredReuseBuffer,
    kAbortCaseLwipPool,
    kAbortCaseCount
} abort_case_e;

static void runAbortCase(abort_case_e which)
{
    switch (which)
    {
    case kAbortCaseUnregisteredPool:
        testWorkerUnbindWID();
        discard getCurrentEventWorkerBufferPool();
        break;
    case kAbortCaseUnregisteredLoop:
        testWorkerUnbindWID();
        discard getCurrentEventWorkerLoop();
        break;
    case kAbortCaseUnregisteredReuseBuffer: {
        sbuf_t *buf = bufferpoolGetSmallBuffer(getWorkerBufferPool(0));
        testWorkerUnbindWID();
        reuseBuffer(buf);
        break;
    }
    case kAbortCaseLwipPool:
        testWorkerBindWID(getTotalWorkersCount() - 1);
        discard getCurrentEventWorkerBufferPool();
        break;
    case kAbortCaseCount:
    default:
        break;
    }
}

static void testCheckedAccessorsAbortOffEventWorkers(void)
{
    static const char *kNames[kAbortCaseCount] = {
        "getCurrentEventWorkerBufferPool() from an unregistered thread",
        "getCurrentEventWorkerLoop() from an unregistered thread",
        "reuseBuffer() from an unregistered thread",
        "getCurrentEventWorkerBufferPool() from the lwIP pseudo-worker",
    };

    for (int which = 0; which < (int) kAbortCaseCount; ++which)
    {
        pid_t pid = fork();
        require(pid >= 0, "fork failed for a checked-accessor abort case");
        if (pid == 0)
        {
            initTestGlobalState();
            runAbortCase((abort_case_e) which);
            // Reaching here means the accessor silently accepted the caller.
            exit(0);
        }

        int status = 0;
        require(waitpid(pid, &status, 0) == pid, "waitpid failed for a checked-accessor abort case");
        require(WIFEXITED(status) && WEXITSTATUS(status) == 1, kNames[which]);
    }
}
#endif

int main(void)
{
    initTestGlobalState();

    testAccessorsOnOwningWorker();
    testPredicatesRejectUnregisteredAndLwip();

    testOwningWorkerRunsInline();
    testOtherEventWorkerQueues();
    testUnregisteredThreadQueues();
    testLwipPseudoWorkerQueues();
    testInvalidTargetsCleanUpExactlyOnce();

    testTunnelApiHelpersRejectNonEventWorkers();
    testResolverRejectsForeignCallers();
    testLineResolverRejectsForeignCallers();
    testPipeToRejectsBadWorkers();

    shutdownTestGlobalState();

#if defined(HAS_UNIX_FORK)
    testCheckedAccessorsAbortOffEventWorkers();
#endif

    return 0;
}
