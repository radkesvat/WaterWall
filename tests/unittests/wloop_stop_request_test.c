/*
 * Event-loop shutdown-control stop request.
 *
 * wloopRequestQuiesce() replaced the cross-thread non-atomic write to
 * wloop_t::flags that worker teardown used to perform. These cases pin the
 * contract it has to satisfy for worker shutdown to be reliable:
 *   - a request from another thread wakes a loop blocked in the poller promptly;
 *   - a request issued before wloopRun() started is still honored;
 *   - large and concurrent repeated request sets coalesce without blocking;
 *   - an existing custom-event wake also covers a stop request;
 *   - the first request may race wake-channel initialization during startup;
 *   - a request racing the loop's own exit is safe.
 */

#include "buffer_pool_internal.h"
#include "wloop_internal.h"
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
    bufferpoolDestroy(env->buffer_pool);
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

static uint32_t largeBufferCacheCount(buffer_pool_t *pool)
{
    uint32_t large_count = 0;
    uint32_t small_count = 0;
    bufferpoolCachedTierCountsForTest(pool, &large_count, &small_count);
    discard small_count;
    return large_count;
}

static void warmLargeBufferCache(buffer_pool_t *pool, uint32_t count)
{
    sbuf_t *buffers[4];
    require(count <= ARRAY_SIZE(buffers), "unsupported buffer-cache warm count");
    for (uint32_t i = 0; i < count; ++i)
    {
        buffers[i] = bufferpoolGetLargeBuffer(pool);
    }
    for (uint32_t i = 0; i < count; ++i)
    {
        bufferpoolReuseBuffer(pool, buffers[i]);
    }
}

static sbuf_t *makeWriteBuffer(buffer_pool_t *pool, uint32_t length)
{
    sbuf_t *buf = bufferpoolGetLargeBuffer(pool);
    memorySet(sbufGetMutablePtr(buf), 'w', length);
    sbufSetLength(buf, length);
    return buf;
}

typedef struct cross_loop_write_probe_s
{
    wio_t  *target;
    sbuf_t *buf;
    int     result;
    int     write_callbacks;
    int     close_callbacks;
} cross_loop_write_probe_t;

static void crossLoopWriteCallback(wio_t *io)
{
    cross_loop_write_probe_t *probe = weventGetUserdata(io);
    probe->write_callbacks++;
}

static void crossLoopCloseCallback(wio_t *io)
{
    cross_loop_write_probe_t *probe = weventGetUserdata(io);
    probe->close_callbacks++;
}

static void crossLoopWriteEvent(wevent_t *event)
{
    cross_loop_write_probe_t *probe = weventGetUserdata(event);
    probe->result                   = wioWrite(probe->target, probe->buf);
    probe->buf                      = NULL;
}

static wio_t *createSocketPairIO(wloop_t *loop, int *peer_fd)
{
    int sockets[2];
    require(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0, "failed to create a stream socket pair");
    wio_t *io = wioGet(loop, sockets[0]);
    require(io != NULL, "failed to create a WIO for the stream socket pair");
    *peer_fd = sockets[1];
    return io;
}

static void testCrossLoopCallbackCannotBorrowAdmission(env_t *env)
{
    wloop_t *loop_a = wloopCreate(0, env->buffer_pool, 0);
    wloop_t *loop_b = wloopCreate(0, env->buffer_pool, 0);
    require(loop_a != NULL && loop_b != NULL, "failed to create the cross-loop write fixtures");

    int                      peer_fd = -1;
    wio_t                   *target  = createSocketPairIO(loop_b, &peer_fd);
    cross_loop_write_probe_t probe   = {.target = target};
    weventSetUserData(target, &probe);
    wioSetCallBackWrite(target, crossLoopWriteCallback);
    wioSetCallBackClose(target, crossLoopCloseCallback);

    warmLargeBufferCache(env->buffer_pool, 1);
    const uint32_t cached_before = largeBufferCacheCount(env->buffer_pool);
    probe.buf                    = makeWriteBuffer(env->buffer_pool, 1);

    require(wloopCloseNormalAdmission(loop_b), "failed to close the target loop admission");
    wevent_t event;
    memoryZero(&event, sizeof(event));
    event.loop = loop_a;
    event.cb   = crossLoopWriteEvent;
    weventSetUserData(&event, &probe);
    require(wloopPostEvent(loop_a, &event), "failed to post the cross-loop write callback");
    discard wloopProcessEvents(loop_a, 0);

    require(probe.result == -1, "a callback on loop A bypassed loop B's closed admission gate");
    require(probe.write_callbacks == 0 && probe.close_callbacks == 0,
            "a rejected cross-loop write invoked a user callback");
    require(write_queue_empty(&target->write_queue), "a rejected cross-loop write published queued data");
    require(largeBufferCacheCount(env->buffer_pool) == cached_before,
            "a rejected cross-loop write did not recycle its buffer exactly once");

    wioClose(target);
    close(peer_fd);
    wloopDestroy(&loop_a);
    wloopDestroy(&loop_b);
}

typedef struct accepted_cross_loop_probe_s
{
    wloop_t       *loop_a;
    wloop_t       *loop_b;
    wio_t         *target_a;
    wio_t         *target_b;
    buffer_pool_t *pool;
    int            outer_write_result;
    int            nested_a_write_result;
    unsigned int   target_b_callbacks;
    bool           target_b_saw_b;
    bool           target_b_saw_a;
    bool           outer_restored_a;
    bool           outer_retained_b;
} accepted_cross_loop_probe_t;

static void acceptedCrossLoopWriteCallback(wio_t *io)
{
    accepted_cross_loop_probe_t *probe = weventGetUserdata(io);
    probe->target_b_callbacks++;
    probe->target_b_saw_b = wloopCurrentThreadInNormalCallback(probe->loop_b);
    probe->target_b_saw_a = wloopCurrentThreadInNormalCallback(probe->loop_a);

    require(wloopCloseNormalAdmission(probe->loop_a), "failed to close loop A from loop B's callback");
    probe->nested_a_write_result = wioWrite(probe->target_a, makeWriteBuffer(probe->pool, 1));
}

static void acceptedCrossLoopOuterEvent(wevent_t *event)
{
    accepted_cross_loop_probe_t *probe = weventGetUserdata(event);
    probe->outer_write_result          = wioWrite(probe->target_b, makeWriteBuffer(probe->pool, 1));
    probe->outer_restored_a            = wloopCurrentThreadInNormalCallback(probe->loop_a);
    probe->outer_retained_b            = wloopCurrentThreadInNormalCallback(probe->loop_b);
}

static void testAcceptedCrossLoopWriteBindsTargetAuthority(env_t *env)
{
    wloop_t *loop_a = wloopCreate(0, env->buffer_pool, 0);
    wloop_t *loop_b = wloopCreate(0, env->buffer_pool, 0);
    require(loop_a != NULL && loop_b != NULL, "failed to create accepted cross-loop fixtures");

    int    peer_a   = -1;
    int    peer_b   = -1;
    wio_t *target_a = createSocketPairIO(loop_a, &peer_a);
    wio_t *target_b = createSocketPairIO(loop_b, &peer_b);

    accepted_cross_loop_probe_t probe = {
        .loop_a = loop_a, .loop_b = loop_b, .target_a = target_a, .target_b = target_b, .pool = env->buffer_pool};
    weventSetUserData(target_b, &probe);
    wioSetCallBackWrite(target_b, acceptedCrossLoopWriteCallback);

    wevent_t event;
    memoryZero(&event, sizeof(event));
    event.cb       = acceptedCrossLoopOuterEvent;
    event.userdata = &probe;
    require(wloopPostEvent(loop_a, &event), "failed to post the accepted cross-loop event");
    discard wloopProcessEvents(loop_a, 0);

    require(probe.outer_write_result == 1 && probe.target_b_callbacks == 1,
            "accepted cross-loop write did not complete its synchronous callback once");
    require(probe.target_b_saw_b && ! probe.target_b_saw_a,
            "loop B's synchronous write callback inherited loop A authority");
    require(probe.nested_a_write_result == -1,
            "loop B's callback borrowed loop A authority after loop A admission closed");
    require(probe.outer_restored_a && ! probe.outer_retained_b,
            "returning from loop B's callback did not restore loop A authority");

    wioClose(target_a);
    wioClose(target_b);
    close(peer_a);
    close(peer_b);
    wloopDestroy(&loop_a);
    wloopDestroy(&loop_b);
}

typedef struct event_authority_probe_s
{
    wloop_t *loop_a;
    wloop_t *loop_b;
    bool     saw_a;
    bool     saw_b;
    bool     metadata_is_a;
} event_authority_probe_t;

static void recordEventAuthority(wevent_t *event)
{
    event_authority_probe_t *probe = weventGetUserdata(event);
    probe->saw_a                   = wloopCurrentThreadInNormalCallback(probe->loop_a);
    probe->saw_b                   = wloopCurrentThreadInNormalCallback(probe->loop_b);
    probe->metadata_is_a           = event->loop == probe->loop_a;
}

static void testCustomEventAuthorityUsesDestinationLoop(env_t *env)
{
    wloop_t *loop_a = wloopCreate(0, env->buffer_pool, 0);
    wloop_t *loop_b = wloopCreate(0, env->buffer_pool, 0);
    require(loop_a != NULL && loop_b != NULL, "failed to create custom-event authority fixtures");

    event_authority_probe_t probe = {.loop_a = loop_a, .loop_b = loop_b};
    wevent_t                event;
    memoryZero(&event, sizeof(event));
    event.loop     = loop_b;
    event.cb       = recordEventAuthority;
    event.userdata = &probe;
    require(wloopPostEvent(loop_a, &event), "failed to post the stale-metadata custom event");
    require(event.loop == loop_b, "posting a custom event mutated caller storage");
    discard wloopProcessEvents(loop_a, 0);

    require(probe.saw_a && ! probe.saw_b && probe.metadata_is_a,
            "custom-event authority did not derive from its destination loop");

    wloopDestroy(&loop_a);
    wloopDestroy(&loop_b);
}

typedef struct control_authority_probe_s
{
    wloop_t       *loop;
    wio_t         *target;
    buffer_pool_t *pool;
    bool           saw_normal_authority;
    bool           metadata_matches;
    int            write_result;
    unsigned int   write_callbacks;
} control_authority_probe_t;

static void unexpectedControlWriteCallback(wio_t *io)
{
    control_authority_probe_t *probe = weventGetUserdata(io);
    probe->write_callbacks++;
}

static void controlAuthorityCallback(wevent_t *event)
{
    control_authority_probe_t *probe = weventGetUserdata(event);
    probe->saw_normal_authority      = wloopCurrentThreadInNormalCallback(probe->loop);
    probe->metadata_matches          = event->loop == probe->loop;
    require(wloopCloseNormalAdmission(probe->loop), "failed to close normal admission from control cleanup");
    probe->write_result = wioWrite(probe->target, makeWriteBuffer(probe->pool, 1));
}

static void testWakeControlCallbackClearsNormalAuthority(env_t *env)
{
    wloop_t *loop = wloopCreate(0, env->buffer_pool, 0);
    require(loop != NULL, "failed to create the control-authority loop");
    int    peer_fd = -1;
    wio_t *target  = createSocketPairIO(loop, &peer_fd);

    control_authority_probe_t probe = {.loop = loop, .target = target, .pool = env->buffer_pool};
    weventSetUserData(target, &probe);
    wioSetCallBackWrite(target, unexpectedControlWriteCallback);

    wevent_t event;
    memoryZero(&event, sizeof(event));
    event.loop     = NULL;
    event.cb       = controlAuthorityCallback;
    event.userdata = &probe;
    require(wloopPostControlEvent(loop, &event), "failed to post the control-authority callback");
    discard wloopProcessEvents(loop, 0);

    require(! probe.saw_normal_authority && probe.metadata_matches,
            "control cleanup inherited the surrounding wake callback's normal authority");
    require(probe.write_result == -1 && probe.write_callbacks == 0,
            "control cleanup started normal work after closing admission");

    wioClose(target);
    close(peer_fd);
    wloopDestroy(&loop);
}

static void testClosedAdmissionRejectsExistingQueueWrite(env_t *env)
{
    wloop_t *loop = wloopCreate(0, env->buffer_pool, 0);
    require(loop != NULL, "failed to create the queued-write loop");
    int    peer_fd = -1;
    wio_t *io      = createSocketPairIO(loop, &peer_fd);

    warmLargeBufferCache(env->buffer_pool, 2);
    const uint32_t cached_before = largeBufferCacheCount(env->buffer_pool);
    sbuf_t        *queued        = makeWriteBuffer(env->buffer_pool, 1);
    write_queue_init(&io->write_queue, 4);
    write_queue_push_back(&io->write_queue, &queued);
    io->write_bufsize = 1;

    require(wloopCloseNormalAdmission(loop), "failed to close the queued-write loop admission");
    require(wioWrite(io, makeWriteBuffer(env->buffer_pool, 1)) == -1,
            "a write joined an existing queue after admission closed");
    require(*write_queue_front(&io->write_queue) == queued && io->write_bufsize == 1,
            "a rejected write mutated the existing stream queue");
    require(largeBufferCacheCount(env->buffer_pool) == cached_before - 1U,
            "a rejected queued write leaked or duplicated its transferred buffer");

    wioDone(io);
    require(largeBufferCacheCount(env->buffer_pool) == cached_before,
            "queued-write cleanup did not settle the pre-existing buffer once");
    wioClose(io);
    close(peer_fd);
    wloopDestroy(&loop);
}

typedef struct partial_write_race_s
{
    wloop_t    *loop;
    wthread_t   closer;
    atomic_bool send_entered;
    atomic_bool closer_entered;
    bool        close_result;
} partial_write_race_t;

static partial_write_race_t *partial_write_race;
static bool                  force_partial_send;

ssize_t __real_send(int socket, const void *buffer, size_t length, int flags);
ssize_t __wrap_send(int socket, const void *buffer, size_t length, int flags);

ssize_t __wrap_send(int socket, const void *buffer, size_t length, int flags)
{
    if (! force_partial_send)
    {
        return __real_send(socket, buffer, length, flags);
    }
    discard socket;
    discard buffer;
    discard flags;
    require(length > 1, "the partial-send fixture received an undersized write");
    atomicStoreExplicit(&partial_write_race->send_entered, true, memory_order_release);
    require(waitForFlag(&partial_write_race->closer_entered, 2000), "the admission closer did not enter");
    return 1;
}

static WTHREAD_ROUTINE(partialWriteCloserMain) // NOLINT
{
    partial_write_race_t *race = userdata;
    require(waitForFlag(&race->send_entered, 2000), "the partial send did not reach the injected boundary");
    atomicStoreExplicit(&race->closer_entered, true, memory_order_release);
    race->close_result = wloopCloseNormalAdmission(race->loop);
    return 0;
}

static void testAdmittedPartialWritePublishesBeforeClosure(env_t *env)
{
    wloop_t *loop = wloopCreate(0, env->buffer_pool, 0);
    require(loop != NULL, "failed to create the partial-write loop");
    int    peer_fd = -1;
    wio_t *io      = createSocketPairIO(loop, &peer_fd);

    partial_write_race_t race;
    memoryZero(&race, sizeof(race));
    race.loop = loop;
    atomic_init(&race.send_entered, false);
    atomic_init(&race.closer_entered, false);
    partial_write_race = &race;

    warmLargeBufferCache(env->buffer_pool, 1);
    const uint32_t cached_before = largeBufferCacheCount(env->buffer_pool);
    require(threadCreate(&race.closer, partialWriteCloserMain, &race) == kWThreadErrorNone,
            "failed to start the partial-write admission closer");
    force_partial_send = true;
    require(wioWrite(io, makeWriteBuffer(env->buffer_pool, 4)) == 1, "the injected partial write returned incorrectly");
    force_partial_send = false;
    threadJoin(race.closer);
    partial_write_race = NULL;

    require(race.close_result && ! wloopNormalDispatchAllowed(loop),
            "the racing admission closure did not complete after write publication");
    require(! write_queue_empty(&io->write_queue) && io->write_bufsize == 3,
            "an admitted partial write lost its queued remainder during closure");
    require(largeBufferCacheCount(env->buffer_pool) == cached_before - 1U,
            "the admitted partial write settled its queued buffer incorrectly");

    wioDone(io);
    require(largeBufferCacheCount(env->buffer_pool) == cached_before,
            "partial-write cleanup did not reclaim the queued remainder exactly once");
    wioClose(io);
    close(peer_fd);
    wloopDestroy(&loop);
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

    require(! wloopQuiesceRequested(runner.loop), "the loop reported a stop request before one was made");
    require(wloopRequestQuiesce(runner.loop), "wloopRequestQuiesce() failed to wake a blocked loop");
    require(wloopQuiesceRequested(runner.loop), "wloopRequestQuiesce() did not publish the stop request");

    require(waitForFlag(&runner.finished, 2000), "a blocked loop did not stop after a stop request");
    runnerJoin(&runner);

    require(runner.result == kWLoopRunQuiesced, "the stopped loop reported a run error");
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

    require(wloopRequestQuiesce(runner.loop), "wloopRequestQuiesce() failed before the loop started");
    for (size_t i = 1; i < LARGE_STOP_REQUEST_SET; ++i)
    {
        require(wloopRequestQuiesce(runner.loop), "a coalesced pre-start stop request failed");
    }

    runnerStart(&runner);

    require(waitForFlag(&runner.finished, 2000), "a loop started after a stop request kept running");
    runnerJoin(&runner);

    for (size_t i = 0; i < LARGE_STOP_REQUEST_SET; ++i)
    {
        require(wloopRequestQuiesce(runner.loop), "a coalesced post-exit stop request failed");
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
        require(wloopRequestQuiesce(runner.loop), "a repeated wloopRequestQuiesce() failed");
    }

    require(waitForFlag(&runner.finished, 2000), "the loop did not stop after repeated stop requests");
    runnerJoin(&runner);

    // Requesting a stop on an already stopped (but not yet destroyed) loop stays
    // safe; this is the shutdown ordering where a worker exits on its own just
    // as worker 0 asks it to stop.
    require(wloopRequestQuiesce(runner.loop), "wloopRequestQuiesce() failed on an already stopped loop");

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
        require(wloopRequestQuiesce(requester->loop), "a concurrent repeated stop request failed");
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
    require(wloopPostEvent(runner.loop, &event), "failed to queue the event that arms the shared wake");
    require(runner.loop->wakeup_pending, "custom event did not arm the shared wake");
    require(wloopRequestQuiesce(runner.loop), "existing custom-event wake did not cover the stop request");

    runnerStart(&runner);
    require(waitForFlag(&runner.finished, 2000), "stop covered by an existing event wake was not honored");
    runnerJoin(&runner);
    runnerDestroy(&runner);
}

typedef struct timer_quiesce_probe_s
{
    loop_runner_t runner;
    wtimer_t     *victim;
    atomic_bool   stop_ran;
    atomic_bool   victim_ran;
} timer_quiesce_probe_t;

static void victimTimerCallback(wtimer_t *timer)
{
    timer_quiesce_probe_t *probe = weventGetUserdata(timer);
    atomicStoreExplicit(&probe->victim_ran, true, memory_order_release);
}

static void stopTimerCallback(wtimer_t *timer)
{
    timer_quiesce_probe_t *probe = weventGetUserdata(timer);
    atomicStoreExplicit(&probe->stop_ran, true, memory_order_release);
    require(wloopRequestQuiesce(probe->runner.loop), "timer callback could not request quiescence");
}

static WTHREAD_ROUTINE(timerQuiesceRunnerMain) // NOLINT
{
    timer_quiesce_probe_t *probe = userdata;

    testWorkerBindWID(0);
    probe->runner.result = wloopRun(probe->runner.loop);
    wloopQuiesceNormalWork(probe->runner.loop);
    wtimerDelete(probe->victim);
    probe->victim = NULL;
    return 0;
}

static void testSuppressedPendingTimerRemainsDeletable(env_t *env)
{
    timer_quiesce_probe_t probe;
    memoryZero(&probe, sizeof(probe));
    runnerCreate(&probe.runner, env);

    probe.victim         = wtimerAdd(probe.runner.loop, victimTimerCallback, 1, 1);
    wtimer_t *stop_timer = wtimerAdd(probe.runner.loop, stopTimerCallback, 1, 1);
    require(probe.victim != NULL && stop_timer != NULL, "failed to create timer quiesce fixtures");
    weventSetUserData(probe.victim, &probe);
    weventSetUserData(stop_timer, &probe);

    require(threadCreate(&probe.runner.thread, timerQuiesceRunnerMain, &probe) == kWThreadErrorNone,
            "failed to spawn timer quiesce runner");
    runnerJoin(&probe.runner);

    require(probe.runner.result == kWLoopRunQuiesced, "timer quiesce did not stop the loop normally");
    require(atomicLoadExplicit(&probe.stop_ran, memory_order_acquire), "the quiesce timer did not run");
    require(! atomicLoadExplicit(&probe.victim_ran, memory_order_acquire),
            "a pending timer ran after quiescence closed normal dispatch");
    require(probe.victim == NULL, "the suppressed pending timer was not deletable during drain");
    runnerDestroy(&probe.runner);
}

typedef struct readiness_batch_probe_s
{
    loop_runner_t runner;
    wio_t        *stop_io;
    wio_t        *victim_io;
    int           stop_peer;
    int           victim_peer;
    atomic_bool   stop_ran;
    atomic_bool   victim_ran;
} readiness_batch_probe_t;

static void readinessBatchVictimRead(wio_t *io, sbuf_t *buf)
{
    readiness_batch_probe_t *probe = weventGetUserdata(io);
    atomicStoreExplicit(&probe->victim_ran, true, memory_order_release);
    bufferpoolReuseBuffer(probe->runner.pool, buf);
}

static void readinessBatchStopRead(wio_t *io, sbuf_t *buf)
{
    readiness_batch_probe_t *probe = weventGetUserdata(io);
    bufferpoolReuseBuffer(probe->runner.pool, buf);
    atomicStoreExplicit(&probe->stop_ran, true, memory_order_release);
    require(wloopRequestQuiesce(probe->runner.loop), "readiness callback could not request quiescence");
}

static void testReadinessBatchStopsAtQuiescence(env_t *env)
{
    readiness_batch_probe_t probe;
    int                     stop_pair[2];
    int                     victim_pair[2];

    memoryZero(&probe, sizeof(probe));
    runnerCreate(&probe.runner, env);
    require(socketpair(AF_UNIX, SOCK_STREAM, 0, stop_pair) == 0, "failed to create stop readiness pair");
    require(socketpair(AF_UNIX, SOCK_STREAM, 0, victim_pair) == 0, "failed to create victim readiness pair");

    probe.stop_peer   = stop_pair[1];
    probe.victim_peer = victim_pair[1];
    probe.stop_io     = wioGet(probe.runner.loop, stop_pair[0]);
    probe.victim_io   = wioGet(probe.runner.loop, victim_pair[0]);
    require(probe.stop_io != NULL && probe.victim_io != NULL, "failed to create readiness io fixtures");

    weventSetUserData(probe.stop_io, &probe);
    weventSetUserData(probe.victim_io, &probe);
    weventSetPriority(probe.stop_io, WEVENT_HIGH_PRIORITY);
    weventSetPriority(probe.victim_io, WEVENT_NORMAL_PRIORITY);
    wioSetCallBackRead(probe.stop_io, readinessBatchStopRead);
    wioSetCallBackRead(probe.victim_io, readinessBatchVictimRead);
    require(wioRead(probe.stop_io) == 0 && wioRead(probe.victim_io) == 0, "failed to register readiness fixtures");
    require(send(probe.stop_peer, "s", 1, 0) == 1 && send(probe.victim_peer, "v", 1, 0) == 1,
            "failed to make both readiness fixtures ready");

    runnerStart(&probe.runner);
    require(waitForFlag(&probe.runner.finished, 2000), "readiness batch did not stop the loop");
    runnerJoin(&probe.runner);

    require(probe.runner.result == kWLoopRunQuiesced, "readiness quiesce did not stop the loop normally");
    require(atomicLoadExplicit(&probe.stop_ran, memory_order_acquire), "the first readiness callback did not run");
    require(! atomicLoadExplicit(&probe.victim_ran, memory_order_acquire),
            "a captured readiness callback ran after quiescence");
    require(! probe.victim_io->pending, "suppressed readiness remained pending");

    closesocket(probe.stop_peer);
    closesocket(probe.victim_peer);
    runnerDestroy(&probe.runner);
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
    requester->success = wloopRequestQuiesce(requester->loop);
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
        require(wloopRequestQuiesce(runner.loop), "wloopRequestQuiesce() failed while racing the loop thread");

        require(waitForFlag(&runner.finished, 2000), "the loop did not stop while racing its own exit");
        runnerJoin(&runner);
        runnerDestroy(&runner);
    }
}

/* A null loop is rejected instead of dereferenced. */
static void testNullLoop(void)
{
    require(! wloopRequestQuiesce(NULL), "wloopRequestQuiesce(NULL) did not fail");
    require(! wloopQuiesceRequested(NULL), "wloopQuiesceRequested(NULL) did not report false");
}

static void controlCleanupCallback(wevent_t *event)
{
    unsigned int *runs = weventGetUserdata(event);
    ++*runs;
}

static void testControlCleanupDrainsAfterNormalAdmissionCloses(env_t *env)
{
    loop_runner_t runner;
    runnerCreate(&runner, env);

    require(wloopRequestQuiesce(runner.loop), "failed to close normal admission for control cleanup");

    unsigned int runs = 0;
    wevent_t     event;
    memoryZero(&event, sizeof(event));
    event.cb       = controlCleanupCallback;
    event.userdata = &runs;

    require(! wloopPostEvent(runner.loop, &event), "normal custom work was accepted after closure");
    require(wloopPostControlEvent(runner.loop, &event), "control cleanup was rejected after normal closure");
    wloopQuiesceNormalWork(runner.loop);
    require(runs == 1, "accepted control cleanup did not run exactly once before Quiesced");
    require(! wloopPostControlEvent(runner.loop, &event), "control cleanup was accepted after the drain boundary");

    runnerDestroy(&runner);
}

int main(void)
{
    env_t env;
    envSetup(&env);

    testCrossLoopCallbackCannotBorrowAdmission(&env);
    testAcceptedCrossLoopWriteBindsTargetAuthority(&env);
    testCustomEventAuthorityUsesDestinationLoop(&env);
    testWakeControlCallbackClearsNormalAuthority(&env);
    testClosedAdmissionRejectsExistingQueueWrite(&env);
    testAdmittedPartialWritePublishesBeforeClosure(&env);

    testNullLoop();
    testControlCleanupDrainsAfterNormalAdmissionCloses(&env);
    testStopWakesBlockedLoop(&env);
    testStopBeforeRunIsHonored(&env);
    testRepeatedStopRequests(&env);
    testConcurrentRepeatedStopRequests(&env);
    testStopCoveredByExistingEventWake(&env);
    testSuppressedPendingTimerRemainsDeletable(&env);
    testReadinessBatchStopsAtQuiescence(&env);
    testFirstStopRacesLoopStartup(&env);
    testStopRacingSelfExit(&env);

    envTeardown(&env);
    return 0;
}
