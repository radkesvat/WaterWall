/* Owner/foreign identity predicates, worker-local pools, resolver/API refusal and exact-exit accessor death cases.
 * CTest: waterwall.worker_context_helpers_unit; see the driver for ordering and CLI. */
#include "worker_fixture.h"

void testAccessorsOnOwningWorker(void)
{
    require(currentThreadIsEventWorkerWID(0), "main thread is not bound to event worker 0");

    require(getCurrentEventWorker() == getWorker(0), "getCurrentEventWorker() did not return worker 0");
    require(tryGetCurrentEventWorker() == getWorker(0), "tryGetCurrentEventWorker() did not return worker 0");
    require(getCurrentEventWorkerWID() == 0, "getCurrentEventWorkerWID() did not return 0");
    require(getCurrentEventWorkerBufferPool() == getWorkerBufferPool(0), "current buffer pool is not worker 0's");
    sbuf_t *splice = bufferpoolGetSpliceBuffer(getCurrentEventWorkerBufferPool());
#if WW_HAVE_SPLICE
    require(splice != NULL && sbufGetTotalCapacityNoPadding(splice) == SPLICE_BUFFER_STORAGE_SIZE,
            "current worker splice buffer has wrong capacity");
    reuseBuffer(splice);
#else
    require(splice == NULL && errno == ENOSYS, "unsupported splice checkout did not return ENOSYS");
#endif
    require(getCurrentEventWorkerContextPool() == getWorkerContextPool(0), "current context pool is not worker 0's");
    require(getCurrentEventWorkerLoop() == getWorkerLoop(0), "current loop is not worker 0's");
    require(getLoopEventWorkerWID(getWorkerLoop(0)) == 0, "getLoopEventWorkerWID() did not resolve worker 0");

    // Another event worker's resources are reachable by explicit id only, and
    // must not be confused with the current worker's.
    require(getWorkerBufferPool(1) != getCurrentEventWorkerBufferPool(),
            "worker 1's pool aliased the current worker's pool");
    require(! currentThreadIsEventWorkerWID(1), "worker 0 claimed to own worker 1");
}

void testWorkerTimerPools(void)
{
    worker_t *worker = getWorker(0);
    require(worker->timer_pool != NULL && worker->loop->timer_pool == worker->timer_pool,
            "worker loop did not receive its timer pool");
    require(worker->timer_pool->mp == GSTATE.masterpool_timers && worker->timer_pool->cap == 2 * RAM_PROFILE &&
                GSTATE.masterpool_timers->cap == 4 * RAM_PROFILE,
            "timer pool sizes do not follow the memory profile");
    require(getWorker(1)->timer_pool != worker->timer_pool, "workers share a local timer pool");
    require(getTotalWorkersCount() == getWorkersCount(), "unexpected extra worker slot");
}

void testWorkerMessagePoolLocalReuse(void)
{
    generic_pool_t *pool = getWorker(0)->message_pool;
    require(pool != NULL && pool->mp == GSTATE.masterpool_messages && pool->cap == 2 * RAM_PROFILE,
            "worker message pool does not use the shared master and memory profile");
    require(getWorker(1)->message_pool != NULL && getWorker(1)->message_pool != pool,
            "workers do not have separate message caches");
    void *warm = workerMessagePoolAcquire(sizeof(worker_msg_t));
    workerMessagePoolRelease(warm);
    const uint32_t shared      = atomicLoadExplicit(&GSTATE.masterpool_messages->len, memory_order_relaxed);
    const size_t   checked_out = masterpoolGetCheckedOut(GSTATE.masterpool_messages);

    for (unsigned int i = 0; i < 128; ++i)
    {
        void *record = workerMessagePoolAcquire(sizeof(worker_msg_t));
        require(record == warm, "warm message checkout did not reuse its local record");
        require(atomicLoadExplicit(&GSTATE.masterpool_messages->len, memory_order_relaxed) == shared,
                "warm message checkout consumed shared master storage");
        require(masterpoolGetCheckedOut(GSTATE.masterpool_messages) == checked_out + 1,
                "local message checkout lost family accounting");
        workerMessagePoolRelease(record);
        require(atomicLoadExplicit(&GSTATE.masterpool_messages->len, memory_order_relaxed) == shared,
                "warm message return touched shared master storage");
    }
    require(masterpoolGetCheckedOut(GSTATE.masterpool_messages) == checked_out,
            "local message reuse leaked checked-out records");

    const uint32_t local_len = pool->len;
    wthread_t      thread;
    require(threadCreate(&thread, messagePoolForeignRoutine, NULL) == kWThreadErrorNone,
            "failed to start foreign message-pool checkout");
    require(threadJoin(thread) == 0, "failed to join foreign message-pool checkout");
    require(pool->len == local_len, "foreign checkout borrowed a worker-local cache");

    void *foreign_return = workerMessagePoolAcquire(sizeof(worker_msg_t));
    require(threadCreate(&thread, messagePoolForeignRoutine, foreign_return) == kWThreadErrorNone,
            "failed to start foreign message-pool return");
    require(threadJoin(thread) == 0, "failed to join foreign message-pool return");
    require(pool->len == local_len - 1, "foreign return touched its source worker cache");

    while (pool->len != 0)
    {
        genericpoolShrink(pool);
    }
    const uint32_t before_refill = atomicLoadExplicit(&pool->mp->len, memory_order_relaxed);
    require(before_refill >= RAM_PROFILE, "message cache did not return its idle storage to the master");
    void *refilled = workerMessagePoolAcquire(sizeof(worker_msg_t));
    require(pool->len == RAM_PROFILE - 1 &&
                atomicLoadExplicit(&pool->mp->len, memory_order_relaxed) == before_refill - RAM_PROFILE,
            "empty message cache did not refill from the master in a batch");
    workerMessagePoolRelease(refilled);
    require(masterpoolGetCheckedOut(pool->mp) == checked_out, "message transfer leaked checked-out records");
}

void testPredicatesRejectUnregisteredAndOutOfRange(void)
{
    const wid_t unregistered_wid = getTotalWorkersCount();

    testWorkerUnbindWID();
    require(tryGetCurrentEventWorker() == NULL, "unregistered thread got an event worker");
    require(! currentThreadIsEventWorker(), "unregistered thread reported event worker role");
    require(! currentThreadIsEventWorkerWID(0), "unregistered thread claimed to own worker 0");

    testWorkerBindWID(unregistered_wid);
    require(! currentThreadHasRegisteredWID(), "out-of-range identity was registered");
    require(! currentThreadIsEventWorker(), "out-of-range identity reported event worker role");
    require(tryGetCurrentEventWorker() == NULL, "out-of-range identity got an event worker");
    require(! currentThreadIsEventWorkerWID(0), "out-of-range identity claimed to own worker 0");
    require(! currentThreadIsEventWorkerWID(unregistered_wid), "out-of-range identity passed an event-worker check");
    require(workerWIDForLog(0) == 0, "workerWIDForLog(0) did not return 0");
    require(workerWIDForLog(1) == 1, "workerWIDForLog(1) did not return 1");
    require(workerWIDForLog(unregistered_wid) == (int) unregistered_wid,
            "workerWIDForLog did not preserve unregistered WID numerically");
    require(workerWIDForLog(unregistered_wid) != -1, "workerWIDForLog mapped unregistered WID to -1");
    require(workerWIDForLog(kInvalidWID) == -1, "workerWIDForLog(kInvalidWID) did not return -1");

    testWorkerBindWID(0);
}

void testTunnelApiHelpersRejectNonEventWorkers(void)
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

    testWorkerBindWID(getTotalWorkersCount());
    result = tunnelapiRecycleMessage(message);
    require(result.result_code == kApiResultError, "tunnel API helper accepted the out-of-range identity");
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

void testResolverRejectsForeignCallers(void)
{
    // Worker 0 asking worker 1's resolver: rejected, no resolver touched.
    require(workerResolveDomainAsync(1, "example.invalid", probeDnsResult, NULL) == ARES_ENOTINITIALIZED,
            "resolver accepted a foreign worker id");

    // Out of range, and the out-of-range identity which has no resolver at all.
    require(workerResolveDomainAsync(kInvalidWID, "example.invalid", probeDnsResult, NULL) == ARES_ENOTINITIALIZED,
            "resolver accepted kInvalidWID");
    require(workerResolveDomainAsync(getTotalWorkersCount(), "example.invalid", probeDnsResult, NULL) ==
                ARES_ENOTINITIALIZED,
            "resolver accepted the out-of-range identity");

    // An unregistered thread must be rejected without touching worker 0.
    atomic_int rc;
    atomicStoreRelaxed(&rc, 0);
    wthread_t thread;
    require(threadCreate(&thread, unregisteredResolveRoutine, &rc) == kWThreadErrorNone,
            "failed to spawn resolve probe thread");
    require(threadJoin(thread) == 0, "failed to join resolve probe thread");
    require(atomicLoadRelaxed(&rc) == ARES_ENOTINITIALIZED, "resolver accepted an unregistered thread");
}

void testLineResolverRejectsForeignCallers(void)
{
    // A line owned by worker 1, queried from worker 0: rejected before the
    // line is even referenced, so a failed call cannot leak a line reference.
    line_t foreign_line = {.wid = 1, .alive = true};
    atomicStoreU32Relaxed(&foreign_line.refc, 1);

    require(lineResolveDomainAsync(&foreign_line, "example.invalid", probeLineDnsResult, NULL, NULL) ==
                ARES_ENOTINITIALIZED,
            "line resolver accepted a foreign worker");
    require(atomicLoadU32Relaxed(&foreign_line.refc) == 1, "rejected line resolve leaked a line reference");

    line_t unregistered_line = {.wid = (wid_t) (getTotalWorkersCount()), .alive = true};
    atomicStoreU32Relaxed(&unregistered_line.refc, 1);
    require(lineResolveDomainAsync(&unregistered_line, "example.invalid", probeLineDnsResult, NULL, NULL) ==
                ARES_ENOTINITIALIZED,
            "line resolver accepted a line owned by the out-of-range identity");
    require(atomicLoadU32Relaxed(&unregistered_line.refc) == 1, "rejected line resolve leaked a line reference");
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
    kAbortCaseOutOfRangePool,
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
    case kAbortCaseOutOfRangePool:
        testWorkerBindWID(getTotalWorkersCount());
        discard getCurrentEventWorkerBufferPool();
        break;
    case kAbortCaseCount:
    default:
        break;
    }
}

void testCheckedAccessorsAbortOffEventWorkers(void)
{
    static const char *kNames[kAbortCaseCount] = {
        "getCurrentEventWorkerBufferPool() from an unregistered thread",
        "getCurrentEventWorkerLoop() from an unregistered thread",
        "reuseBuffer() from an unregistered thread",
        "getCurrentEventWorkerBufferPool() from the out-of-range identity",
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
