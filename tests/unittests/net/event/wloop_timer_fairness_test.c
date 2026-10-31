/*
 * Covers: due/overdue timer polling, socket/custom-event/worker-message progress,
 * timer priority, wait rounding, backend errors and quiescence.
 * Setup: Real Linux epoll/eventfd, socketpairs and a registered worker with its
 * real message queue. Controlled clocks make timer overruns deterministic;
 * link wrappers observe epoll/sleep arguments without inferring waits from timing.
 * Limits: No throughput claim or runtime coverage of other poller backends.
 * CTest: waterwall.wloop_timer_fairness_unit
 */
#include "wevent.h"

#include "fixtures/worker_registry_fixture.h"
#include "test_assert.h"
#include "wloop_internal.h"
#include "worker_messages.h"

#include <sys/epoll.h>

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static thread_local uint64_t clock_us;
static thread_local time_t   clock_seconds;
static thread_local bool     clock_frozen;
static unsigned int          poll_calls;
static int                   poll_timeout;
static unsigned int          sleep_calls;
static useconds_t            sleep_us;
static bool                  fail_poll;

unsigned long long __real_getHRTimeUs(void);
unsigned long long __wrap_getHRTimeUs(void);
time_t             __real_time(time_t *value);
time_t             __wrap_time(time_t *value);
int                __real_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
int                __wrap_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
int                __real_usleep(useconds_t usec);
int                __wrap_usleep(useconds_t usec);

unsigned long long __wrap_getHRTimeUs(void)
{
    return clock_frozen ? clock_us : __real_getHRTimeUs();
}

time_t __wrap_time(time_t *value)
{
    if (! clock_frozen)
    {
        return __real_time(value);
    }
    if (value != NULL)
    {
        *value = clock_seconds;
    }
    return clock_seconds;
}

int __wrap_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
    ++poll_calls;
    poll_timeout = timeout;
    if (fail_poll)
    {
        fail_poll = false;
        errno     = EIO;
        return -1;
    }
    return __real_epoll_wait(epfd, events, maxevents, timeout);
}

int __wrap_usleep(useconds_t usec)
{
    ++sleep_calls;
    sleep_us = usec;
    return clock_frozen ? 0 : __real_usleep(usec);
}

typedef struct fixture_s
{
    test_worker_registry_t     registry;
    master_pool_t             *masters[4];
    threadsafe_generic_pool_t *wio_pools[1];
    buffer_pool_t             *buffers;
    worker_t                  *worker;
    wloop_t                   *loop;
} fixture_t;

static void fixtureInit(fixture_t *fix)
{
    memoryZero(fix, sizeof(*fix));
    clock_us      = __real_getHRTimeUs();
    clock_seconds = __real_time(NULL);
    clock_frozen  = true;
    poll_calls = sleep_calls = 0;
    poll_timeout             = -1;
    sleep_us                 = 0;
    GSTATE.workers_count     = 1;
    testWorkerRegistryInstall(&fix->registry);
    testWorkerBindWID(0);

    for (size_t i = 0; i < ARRAY_SIZE(fix->masters); ++i)
    {
        fix->masters[i] = masterpoolCreateWithCapacity(64);
    }
    fix->buffers = bufferpoolCreate(
        fix->masters[0], fix->masters[1], fix->masters[2], 64, 8192, MEDIUM_BUFFER_SIZE_RAM_HIGH, 1024, 8192, 8192);
    fix->wio_pools[0] = threadsafegenericpoolCreateWithDefaultAllocatorAndCapacity(fix->masters[3], sizeof(wio_t), 64);
    GSTATE.shortcut_wios_pools = fix->wio_pools;
    fix->loop                  = wloopCreate(0, fix->buffers, 0);
    /* Exact calendar deadlines must not race a real wall-clock second boundary. */
    fix->loop->start_ms = (uint64_t) clock_seconds * 1000U;
    wloopUpdateTime(fix->loop);
    atomicStoreExplicit(&fix->loop->status, WLOOP_STATUS_RUNNING, memory_order_release);
    fix->worker              = getWorker(0);
    fix->worker->loop        = fix->loop;
    fix->worker->buffer_pool = fix->buffers;
    mutexInit(&fix->worker->control_mutex);
    workerMessagesInit(fix->worker);
    require(workerMessagesOpenAdmission(fix->worker), "failed to open worker-message admission");
    require(strcmp(wioGetEngine(), "epoll") == 0, "fixture must exercise native epoll");
}

static void fixtureCleanup(fixture_t *fix)
{
    workerMessagesCloseAdmission(fix->worker);
    require(wloopCloseNormalAdmission(fix->loop), "failed to close loop admission");
    workerMessagesCleanupPending(fix->worker);
    wloopQuiesceNormalWork(fix->loop);
    workerMessagesDestroy(fix->worker);
    wloopDestroy(&fix->loop);
    mutexDestroy(&fix->worker->control_mutex);
    bufferpoolDestroy(fix->buffers);
    threadsafegenericpoolDestroy(fix->wio_pools[0]);
    for (size_t i = 0; i < ARRAY_SIZE(fix->masters); ++i)
    {
        require(masterpoolGetCheckedOut(fix->masters[i]) == 0, "fixture leaked pooled storage");
        masterpoolMakeEmpty(fix->masters[i]);
        masterpoolDestroy(fix->masters[i]);
    }
    GSTATE.shortcut_wios_pools = NULL;
    testWorkerUnbindWID();
    testWorkerRegistryRestore(&fix->registry);
    GSTATE.workers_count = 0;
    clock_frozen         = false;
}

typedef struct progress_s
{
    unsigned int expected_timers;
    unsigned int timers;
    unsigned int sockets;
    unsigned int custom_events;
    unsigned int messages;
    unsigned int cleanups;
    bool         overrun;
    bool         quiesce;
} progress_t;

static void timerCallback(wtimer_t *timer)
{
    progress_t *progress = weventGetUserdata(timer);
    ++progress->timers;
    if (progress->overrun)
    {
        /* A finite 2 ms callback outlasts the repeating timer's 1 ms interval. */
        clock_us += 2000;
    }
    if (progress->quiesce)
    {
        require(wloopRequestQuiesce(timer->loop), "timer could not request quiescence");
    }
}

static void socketCallback(wio_t *io, sbuf_t *buf)
{
    progress_t *progress = weventGetUserdata(io);
    require(progress->timers == progress->expected_timers, "socket ran before due timer");
    require(sbufGetLength(buf) == 1 && *(const char *) sbufGetRawPtr(buf) == 'x', "socket payload changed");
    ++progress->sockets;
    bufferpoolReuseBuffer(io->loop->bufpool, buf);
}

static int registerSocket(fixture_t *fix, progress_t *progress)
{
    int pair[2];
    require(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0, "socketpair failed");
    wio_t *io = wRead(fix->loop, pair[0], socketCallback);
    require(io != NULL, "socket registration failed");
    weventSetUserData(io, progress);
    return pair[1];
}

static void customCallback(wevent_t *event)
{
    progress_t *progress = weventGetUserdata(event);
    require(progress->timers == progress->expected_timers, "custom event ran before due timer");
    ++progress->custom_events;
}

static void messageCallback(void *owner, void *arg1, void *arg2, void *arg3)
{
    worker_t   *worker   = owner;
    progress_t *progress = arg1;
    discard     arg3;
    require(currentThreadOwnsWorker(worker->wid), "message ran off its owner worker");
    require(progress->timers == progress->expected_timers, "message ran before due timer");
    require(*(unsigned int *) arg2 == progress->expected_timers, "message lost its owned payload");
    ++progress->messages;
    memoryFree(arg2);
}

static void messageCleanup(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    progress_t *progress = arg1;
    discard     arg3;
    require(reason == kWorkerMessageCancelQuiesced, "unexpected message cancellation");
    ++progress->cleanups;
    memoryFree(arg2);
}

static WTHREAD_ROUTINE(postMessage)
{
    progress_t   *progress = userdata;
    unsigned int *payload  = memoryAllocate(sizeof(*payload));
    *payload               = progress->expected_timers;
    require(! currentThreadIsWorker(), "poster unexpectedly owns worker state");
    require(sendWorkerMessageForceQueueWithCleanup(0, messageCallback, messageCleanup, progress, payload, NULL) ==
                kWorkerMessageSubmitAccepted,
            "worker message was not accepted");
    return 0;
}

static void queueReadyWork(fixture_t *fix, progress_t *progress, int peer)
{
    require(send(peer, "x", 1, 0) == 1, "failed to make socket readable");
    wevent_t event = {.cb = customCallback, .userdata = progress};
    require(wloopPostEvent(fix->loop, &event), "custom event was not accepted");
    require(fix->loop->eventfds[0] >= 0 && fix->loop->eventfds[0] == fix->loop->eventfds[1],
            "fixture must exercise the native eventfd wake path");
    wthread_t thread;
    require(threadCreate(&thread, postMessage, progress) == kWThreadErrorNone, "message poster did not start");
    require(threadJoin(thread) == 0, "message poster did not join");
}

static void setDeadline(wloop_t *loop, wtimer_t *timer, int64_t offset_us)
{
    wloopUpdateTime(loop);
    const bool     realtime = timer->event_type == WEVENT_TYPE_PERIOD;
    struct heap   *heap     = realtime ? &loop->realtimers : &loop->timers;
    const uint64_t now      = realtime ? wloopNowUS(loop) : loop->cur_hrtime;
    heap_remove(heap, &timer->node);
    timer->next_timeout = (uint64_t) ((int64_t) now + offset_us);
    heap_insert(heap, &timer->node);
}

static void testOverdueProgress(bool quiesce)
{
    fixture_t fix;
    fixtureInit(&fix);
    progress_t progress = {.overrun = true, .quiesce = quiesce};
    int        peer     = registerSocket(&fix, &progress);
    wtimer_t  *timer    = wtimerAdd(fix.loop, timerCallback, 1, INFINITE);
    require(timer != NULL, "repeating timer was not installed");
    weventSetUserData(timer, &progress);
    setDeadline(fix.loop, timer, -1000);

    const unsigned int rounds = quiesce ? 1 : 4;
    for (unsigned int round = 1; round <= rounds; ++round)
    {
        progress.expected_timers = round;
        queueReadyWork(&fix, &progress, peer);
        require(timer->next_timeout < clock_us, "timer overrun did not persist into the next round");
        require(wloopProcessEvents(fix.loop, 100) >= 0, "event processing failed");
        require(progress.timers == round, "overdue timer did not progress");
        require(progress.sockets == (quiesce ? 0 : round), "overdue timer starved ready socket work");
        require(progress.custom_events == (quiesce ? 0 : round), "overdue timer starved custom events");
        require(progress.messages == (quiesce ? 0 : round), "overdue timer starved accepted worker messages");
        require(poll_calls == round && poll_timeout == 0, "overdue timer must poll with timeout zero");
        require(sleep_calls == 0, "loop slept despite registered I/O");
        require(timer->active && timer->repeat == INFINITE, "progress depended on stopping the timer");
    }
    closesocket(peer);
    fixtureCleanup(&fix);
    require(progress.cleanups == (quiesce ? 1U : 0U), "worker message was not settled exactly once");
}

static void testWaitSelection(bool realtime, bool with_io, int64_t offset_us, int expected_ms)
{
    fixture_t fix;
    fixtureInit(&fix);
    progress_t progress = {.expected_timers = offset_us <= 0 ? 1U : 0U};
    int        peer     = with_io ? registerSocket(&fix, &progress) : -1;
    wtimer_t  *timer    = realtime ? wtimerAddPeriod(fix.loop, timerCallback, -1, -1, -1, -1, -1, INFINITE)
                                   : wtimerAdd(fix.loop, timerCallback, 1, INFINITE);
    require(timer != NULL, "wait-selection timer was not installed");
    weventSetUserData(timer, &progress);
    setDeadline(fix.loop, timer, offset_us);
    if (with_io)
    {
        require(send(peer, "x", 1, 0) == 1, "wait-selection socket was not made readable");
    }
    require(wloopProcessEvents(fix.loop, 100) >= 0, "wait-selection processing failed");
    require(progress.timers == progress.expected_timers, "timer expiration changed");
    if (with_io)
    {
        require(poll_calls == 1 && poll_timeout == expected_ms, "incorrect backend timeout");
        require(progress.sockets == 1 && sleep_calls == 0, "ready socket did not progress through polling");
        closesocket(peer);
    }
    else
    {
        require(poll_calls == 0, "empty loop attempted to poll");
        require(sleep_calls <= 1 && sleep_us == (useconds_t) expected_ms * 1000U, "incorrect no-I/O sleep");
        require(expected_ms == 0 || sleep_calls == 1, "future timer skipped its wait");
    }
    fixtureCleanup(&fix);
}

static void testOverdueBackendError(void)
{
    fixture_t fix;
    fixtureInit(&fix);
    progress_t progress = {0};
    int        peer     = registerSocket(&fix, &progress);
    wtimer_t  *timer    = wtimerAdd(fix.loop, timerCallback, 1, INFINITE);
    require(timer != NULL, "backend-error timer was not installed");
    weventSetUserData(timer, &progress);
    setDeadline(fix.loop, timer, -1000);
    fail_poll = true;
    require(wloopProcessEvents(fix.loop, 100) == kWLoopRunErrorBackend, "overdue timer hid backend failure");
    require(poll_calls == 1 && poll_timeout == 0, "backend failure did not follow a nonblocking poll");
    require(progress.timers == 0 && progress.sockets == 0, "callbacks ran after backend failure");
    closesocket(peer);
    fixtureCleanup(&fix);
}

int main(void)
{
    testCaseSet("wloop_timer_fairness_test");
    testOverdueProgress(false);
    testOverdueProgress(true);
    const int64_t offsets[] = {-1000, 0, 2500, 250000};
    const int     waits[]   = {0, 0, 3, 100};
    for (unsigned int realtime = 0; realtime < 2; ++realtime)
    {
        for (unsigned int with_io = 0; with_io < 2; ++with_io)
        {
            for (size_t i = 0; i < ARRAY_SIZE(offsets); ++i)
            {
                testWaitSelection(realtime != 0, with_io != 0, offsets[i], waits[i]);
            }
        }
    }
    testOverdueBackendError();
    return 0;
}
