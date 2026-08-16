/*
 * Forced-backend coverage for the event-loop wake channel. CMake builds this
 * source once with the pipe backend and once with the socketpair backend.
 */

#include "wloop_internal.h"
#include "wwapi.h"

#include "worker_registry_fixture.h"
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

/*
 * Fake worker table for the stubbed GSTATE below. Without it the identity
 * predicates correctly report "not an event worker" and the checked
 * current-worker accessors reject this test.
 */
static test_worker_registry_t g_test_worker_registry;

#define MANY_PRESTART_EVENTS 20000U
#define RECURSIVE_EVENTS     1000U
#define PRODUCER_COUNT       4U
#define EVENTS_PER_PRODUCER  2000U
#define REPEATED_STOPS       50000U

typedef struct env_s
{
    master_pool_t             *large_master;
    master_pool_t             *small_master;
    master_pool_t             *wio_master;
    threadsafe_generic_pool_t *wio_pool;
    threadsafe_generic_pool_t *wio_pools[1];
} env_t;

typedef struct loop_runner_s
{
    wloop_t       *loop;
    buffer_pool_t *pool;
    wthread_t      thread;
    atomic_bool    running;
    atomic_bool    finished;
    int            result;
} loop_runner_t;

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

static WTHREAD_ROUTINE(loopRunnerMain) // NOLINT
{
    loop_runner_t *runner = userdata;

    testWorkerBindWID(0);
    atomicStoreExplicit(&runner->running, true, memory_order_release);
    runner->result = wloopRun(runner->loop);
    atomicStoreExplicit(&runner->finished, true, memory_order_release);
    return 0;
}

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

static void runnerDestroy(loop_runner_t *runner)
{
    wloopDestroy(&runner->loop);
    bufferpoolDestroy(runner->pool);
    runner->pool = NULL;
}

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

static int countOpenDescriptors(void)
{
    DIR           *directory = opendir("/proc/self/fd");
    struct dirent *entry;
    int            count = 0;

    require(directory != NULL, "failed to inspect open descriptors");
    while ((entry = readdir(directory)) != NULL)
    {
        if (entry->d_name[0] != '.')
        {
            ++count;
        }
    }
    closedir(directory);
    return count;
}

static void postEvent(wloop_t *loop, wevent_cb callback, void *userdata, uintptr_t id)
{
    wevent_t event;

    memoryZero(&event, sizeof(event));
    event.cb       = callback;
    event.userdata = userdata;
    event.privdata = (void *) id;
    require(wloopPostEvent(loop, &event), "custom event post was rejected");
}

static void testDescriptorConfigurationAndCoalescing(env_t *env)
{
    loop_runner_t runner;
    runnerCreate(&runner, env);

#ifdef WLOOP_TEST_PIPE_BACKEND
    require(wloopTestWakeBackend() == kWLoopTestWakeBackendPipe, "test did not select the pipe wake backend");
#else
    require(wloopTestWakeBackend() == kWLoopTestWakeBackendSocketPair,
            "test did not select the socketpair wake backend");
#endif

    uint64_t attempts_before = wloopTestWakeWriteAttempts();
    postEvent(runner.loop, NULL, NULL, 0);

    require(runner.loop->eventfds[0] >= 0 && runner.loop->eventfds[1] >= 0, "wake descriptors were not created");
    for (size_t i = 0; i < 2; ++i)
    {
        int status_flags = fcntl(runner.loop->eventfds[i], F_GETFL, 0);
        int fd_flags     = fcntl(runner.loop->eventfds[i], F_GETFD, 0);
        require(status_flags >= 0 && (status_flags & O_NONBLOCK) != 0, "wake descriptor is blocking");
        require(fd_flags >= 0 && (fd_flags & FD_CLOEXEC) != 0, "wake descriptor is not close-on-exec");
    }

    postEvent(runner.loop, NULL, NULL, 1);
    require(wloopTestWakeupPending(runner.loop), "accepted events did not leave an armed wake");
    require(wloopTestWakeWriteAttempts() - attempts_before == 1,
            "posts covered by one pending batch emitted multiple wake tokens");

    require(wloopRequestQuiesce(runner.loop), "stop request was not covered by the existing event wake");
    require(wloopTestWakeWriteAttempts() - attempts_before == 1,
            "stop request emitted a token despite an already-pending event wake");

    runnerStart(&runner);
    require(waitForFlag(&runner.finished, 2000), "pre-start stop request was not honored");
    runnerJoin(&runner);
    runnerDestroy(&runner);
}

static void testWakeWriteErrors(env_t *env)
{
    loop_runner_t runner;
    uint64_t      attempts_before;

    runnerCreate(&runner, env);
    attempts_before = wloopTestWakeWriteAttempts();
    wloopTestSetNextWakeWriteError(EINTR);
    postEvent(runner.loop, NULL, NULL, 0);
    require(wloopTestWakeWriteAttempts() - attempts_before == 2, "interrupted wake write was not retried once");
    require(runner.loop->custom_events.size == 1, "event was lost after an interrupted wake write");
    runnerDestroy(&runner);

    runnerCreate(&runner, env);
    attempts_before = wloopTestWakeWriteAttempts();
    wloopTestSetNextWakeWriteError(EAGAIN);
    postEvent(runner.loop, NULL, NULL, 0);
    require(wloopTestWakeWriteAttempts() - attempts_before == 1, "would-block wake write was unexpectedly retried");
    require(wloopTestWakeupPending(runner.loop), "would-block wake write did not arm the wake state");
    require(runner.loop->custom_events.size == 1, "would-block wake write did not accept the covered event");
    runnerDestroy(&runner);

    runnerCreate(&runner, env);
    attempts_before = wloopTestWakeWriteAttempts();
    wloopTestSetNextWakeWriteError(EIO);
    wevent_t event;
    memoryZero(&event, sizeof(event));
    require(! wloopPostEvent(runner.loop, &event), "hard wake error accepted a custom event");
    require(wloopTestWakeWriteAttempts() - attempts_before == 1, "hard wake error had an unexpected retry");
    require(! wloopTestWakeupPending(runner.loop), "hard wake error armed the wake state");
    require(runner.loop->custom_events.size == 0, "hard wake error queued a custom event");
    postEvent(runner.loop, NULL, NULL, 0);
    require(runner.loop->custom_events.size == 1, "wake channel did not recover after a hard write error");
    runnerDestroy(&runner);
}

static void testDescriptorConfigurationFailure(env_t *env)
{
    loop_runner_t runner;
    runnerCreate(&runner, env);

    const int descriptors_before = countOpenDescriptors();
    wloopTestSetNextWakeConfigError(EIO);

    wevent_t event;
    memoryZero(&event, sizeof(event));
    require(! wloopPostEvent(runner.loop, &event), "descriptor configuration failure accepted an event");
    require(runner.loop->eventfds[0] == -1 && runner.loop->eventfds[1] == -1,
            "descriptor configuration failure retained a wake endpoint");
    require(runner.loop->custom_events.size == 0, "descriptor configuration failure queued an event");
    require(! wloopTestWakeupPending(runner.loop), "descriptor configuration failure armed the wake state");
    require(countOpenDescriptors() == descriptors_before, "descriptor configuration failure leaked an endpoint");

    postEvent(runner.loop, NULL, NULL, 0);
    runnerDestroy(&runner);
}

static void testDescriptorRegistrationRejection(env_t *env)
{
    loop_runner_t runner;
    runnerCreate(&runner, env);

    const int descriptors_before = countOpenDescriptors();
    wloopTestRejectNextWakeRegistration();

    wevent_t event;
    memoryZero(&event, sizeof(event));
    require(! wloopPostEvent(runner.loop, &event), "descriptor registration rejection accepted an event");
    require(runner.loop->eventfds[0] == -1 && runner.loop->eventfds[1] == -1,
            "descriptor registration rejection retained a wake endpoint");
    require(runner.loop->custom_events.size == 0, "descriptor registration rejection queued an event");
    require(! wloopTestWakeupPending(runner.loop), "descriptor registration rejection armed the wake state");
    require(countOpenDescriptors() == descriptors_before, "descriptor registration rejection leaked an endpoint");

    postEvent(runner.loop, NULL, NULL, 0);
    runnerDestroy(&runner);
}

static void testStopPublicationAfterWakeFailure(env_t *env)
{
    loop_runner_t runner;
    runnerCreate(&runner, env);

    uint64_t attempts_before = wloopTestWakeWriteAttempts();
    wloopTestSetNextWakeWriteError(EIO);
    require(! wloopRequestQuiesce(runner.loop), "hard wake error was reported as an immediate stop wake");
    require(wloopQuiesceRequested(runner.loop), "hard wake error retracted the level-triggered stop condition");
    require(wloopTestWakeWriteAttempts() - attempts_before == 1, "failed stop wake had an unexpected retry");

    for (size_t i = 0; i < REPEATED_STOPS; ++i)
    {
        require(wloopRequestQuiesce(runner.loop), "repeated published stop request failed");
    }
    require(wloopTestWakeWriteAttempts() - attempts_before == 1, "repeated stop requests emitted more wake tokens");

    runnerStart(&runner);
    require(waitForFlag(&runner.finished, 2000), "published stop was not honored after its immediate wake failed");
    runnerJoin(&runner);
    runnerDestroy(&runner);
}

typedef struct ordered_delivery_s
{
    wloop_t *loop;
    size_t   next;
    size_t   total;
    bool     failed;
} ordered_delivery_t;

static void orderedDeliveryCallback(wevent_t *event)
{
    ordered_delivery_t *delivery = event->userdata;
    size_t              id       = (size_t) (uintptr_t) event->privdata;

    if (id != delivery->next)
    {
        delivery->failed = true;
    }
    ++delivery->next;
    if (delivery->next == delivery->total)
    {
        require(wloopRequestQuiesce(delivery->loop), "final ordered callback could not request a stop");
    }
}

static void testManyPostsBeforeRun(env_t *env)
{
    loop_runner_t      runner;
    ordered_delivery_t delivery;
    runnerCreate(&runner, env);

    memoryZero(&delivery, sizeof(delivery));
    delivery.loop  = runner.loop;
    delivery.total = MANY_PRESTART_EVENTS;

    uint64_t attempts_before = wloopTestWakeWriteAttempts();
    for (size_t i = 0; i < delivery.total; ++i)
    {
        postEvent(runner.loop, orderedDeliveryCallback, &delivery, i);
    }
    require(wloopTestWakeWriteAttempts() - attempts_before == 1,
            "many pre-start posts were not covered by one coalesced wake");

    runnerStart(&runner);
    require(waitForFlag(&runner.finished, 5000), "loop did not deliver the pre-start event batch");
    runnerJoin(&runner);

    require(! delivery.failed, "pre-start event batch was not delivered in FIFO order");
    require(delivery.next == delivery.total, "pre-start event batch lost callbacks");
    runnerDestroy(&runner);
}

static void recursiveDeliveryCallback(wevent_t *event)
{
    ordered_delivery_t *delivery = event->userdata;
    size_t              id       = (size_t) (uintptr_t) event->privdata;

    if (id != delivery->next)
    {
        delivery->failed = true;
    }
    ++delivery->next;

    if (delivery->next < delivery->total)
    {
        postEvent(delivery->loop, recursiveDeliveryCallback, delivery, delivery->next);
    }
    else
    {
        require(wloopRequestQuiesce(delivery->loop), "recursive callback chain could not request a stop");
    }
}

static void testRecursivePosting(env_t *env)
{
    loop_runner_t      runner;
    ordered_delivery_t delivery;
    runnerCreate(&runner, env);

    memoryZero(&delivery, sizeof(delivery));
    delivery.loop  = runner.loop;
    delivery.total = RECURSIVE_EVENTS;
    postEvent(runner.loop, recursiveDeliveryCallback, &delivery, 0);

    runnerStart(&runner);
    require(waitForFlag(&runner.finished, 5000), "recursive event chain did not finish");
    runnerJoin(&runner);

    require(! delivery.failed, "recursive event chain was delivered out of order");
    require(delivery.next == delivery.total, "recursive event chain lost callbacks");
    runnerDestroy(&runner);
}

typedef struct batch_delivery_s
{
    wloop_t *loop;
    size_t   stage;
    bool     failed;
} batch_delivery_t;

static void batchDeliveryCallback(wevent_t *event)
{
    batch_delivery_t *delivery = event->userdata;
    size_t            id       = (size_t) (uintptr_t) event->privdata;

    if (id == 0)
    {
        if (delivery->stage != 0 || wloopTestWakeupPending(delivery->loop))
        {
            delivery->failed = true;
        }
        delivery->stage = 1;
        postEvent(delivery->loop, batchDeliveryCallback, delivery, 2);
        return;
    }

    if (id == 1)
    {
        if (delivery->stage != 1 || ! wloopTestWakeupPending(delivery->loop))
        {
            delivery->failed = true;
        }
        delivery->stage = 2;
        return;
    }

    if (id != 2 || delivery->stage != 2 || wloopTestWakeupPending(delivery->loop))
    {
        delivery->failed = true;
    }
    delivery->stage = 3;
    require(wloopRequestQuiesce(delivery->loop), "subsequent wake batch could not request a stop");
}

static void testPostDuringCallbackUsesNextBatch(env_t *env)
{
    loop_runner_t    runner;
    batch_delivery_t delivery;
    runnerCreate(&runner, env);

    memoryZero(&delivery, sizeof(delivery));
    delivery.loop = runner.loop;
    postEvent(runner.loop, batchDeliveryCallback, &delivery, 0);
    postEvent(runner.loop, batchDeliveryCallback, &delivery, 1);

    runnerStart(&runner);
    require(waitForFlag(&runner.finished, 2000), "post-during-callback batch did not finish");
    runnerJoin(&runner);

    require(! delivery.failed, "post during callback was consumed by the wrong wake batch");
    require(delivery.stage == 3, "post during callback was not delivered");
    runnerDestroy(&runner);
}

typedef struct concurrent_delivery_s
{
    wloop_t    *loop;
    uint8_t    *seen;
    size_t      total;
    atomic_uint delivered;
    atomic_bool failed;
} concurrent_delivery_t;

typedef struct producer_s
{
    concurrent_delivery_t *delivery;
    size_t                 begin;
    size_t                 count;
    wthread_t              thread;
} producer_t;

static void concurrentDeliveryCallback(wevent_t *event)
{
    concurrent_delivery_t *delivery = event->userdata;
    size_t                 id       = (size_t) (uintptr_t) event->privdata;

    if (id >= delivery->total || delivery->seen[id] != 0)
    {
        atomicStoreExplicit(&delivery->failed, true, memory_order_release);
    }
    else
    {
        delivery->seen[id] = 1;
    }

    unsigned int previous = atomicAddExplicit(&delivery->delivered, 1, memory_order_acq_rel);
    if ((size_t) previous + 1 == delivery->total)
    {
        require(wloopRequestQuiesce(delivery->loop), "concurrent delivery could not request a stop");
    }
}

static WTHREAD_ROUTINE(producerMain) // NOLINT
{
    producer_t *producer = userdata;

    testWorkerBindWID(0);
    for (size_t i = 0; i < producer->count; ++i)
    {
        postEvent(producer->delivery->loop, concurrentDeliveryCallback, producer->delivery, producer->begin + i);
    }
    return 0;
}

static void testConcurrentProducers(env_t *env)
{
    loop_runner_t         runner;
    concurrent_delivery_t delivery;
    producer_t            producers[PRODUCER_COUNT];
    runnerCreate(&runner, env);

    memoryZero(&delivery, sizeof(delivery));
    delivery.loop  = runner.loop;
    delivery.total = PRODUCER_COUNT * EVENTS_PER_PRODUCER;
    delivery.seen  = calloc(delivery.total, sizeof(*delivery.seen));
    require(delivery.seen != NULL, "failed to allocate concurrent delivery bitmap");

    runnerStart(&runner);
    require(waitForFlag(&runner.running, 2000), "loop did not start for concurrent producers");

    for (size_t i = 0; i < PRODUCER_COUNT; ++i)
    {
        producers[i].delivery = &delivery;
        producers[i].begin    = i * EVENTS_PER_PRODUCER;
        producers[i].count    = EVENTS_PER_PRODUCER;
        require(threadCreate(&producers[i].thread, producerMain, &producers[i]) == kWThreadErrorNone,
                "failed to start an event producer");
    }
    for (size_t i = 0; i < PRODUCER_COUNT; ++i)
    {
        threadJoin(producers[i].thread);
    }

    require(waitForFlag(&runner.finished, 5000), "loop did not deliver all concurrently posted events");
    runnerJoin(&runner);

    require(! atomicLoadExplicit(&delivery.failed, memory_order_acquire),
            "concurrent producers caused a duplicate or invalid delivery");
    require((size_t) atomicLoadExplicit(&delivery.delivered, memory_order_acquire) == delivery.total,
            "concurrent producers lost an accepted event");
    for (size_t i = 0; i < delivery.total; ++i)
    {
        require(delivery.seen[i] == 1, "concurrent producer event was not delivered exactly once");
    }

    free(delivery.seen);
    runnerDestroy(&runner);
}

int main(void)
{
    env_t env;
    envSetup(&env);

    testDescriptorConfigurationAndCoalescing(&env);
    testWakeWriteErrors(&env);
    testDescriptorConfigurationFailure(&env);
    testDescriptorRegistrationRejection(&env);
    testStopPublicationAfterWakeFailure(&env);
    testManyPostsBeforeRun(&env);
    testRecursivePosting(&env);
    testPostDuringCallbackUsesNextBatch(&env);
    testConcurrentProducers(&env);

    envTeardown(&env);
    return 0;
}
