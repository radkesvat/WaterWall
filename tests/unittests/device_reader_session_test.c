#include "wwapi.h"

#include "devices/device_reader_session.h"

#include "worker_messages.h"

#include <poll.h>
#include <pthread.h>

#if defined(OS_UNIX)
#include "worker_registry_fixture.h"
#include <sys/wait.h>
#include <unistd.h>

/*
 * Fake worker table for the stubbed GSTATE below. Without it the identity
 * predicates correctly report "not an event worker" and the checked
 * current-worker accessors reject this test.
 */
static test_worker_registry_t g_test_worker_registry;
#endif

enum
{
    kCapturedMessageMax = 128
};

typedef struct captured_message_s
{
    wid_t                        wid;
    WorkerMessageCallback        callback;
    WorkerMessageCleanupCallback cleanup;
    void                        *arg1;
    void                        *arg2;
    void                        *arg3;
} captured_message_t;

typedef struct reader_probe_s
{
    unsigned int        delivered;
    unsigned int        prepared;
    sbuf_t             *last_prepared;
    bool                check_prepare_order;
    const unsigned int *required_work_steps;
    unsigned int        expected_work_steps;
    atomic_bool         block_delivery;
    atomic_bool         delivery_entered;
    atomic_bool         release_delivery;
} reader_probe_t;

typedef struct end_wait_probe_s
{
    device_reader_session_t *session;
    atomic_uint              hook_calls;
    atomic_bool              first_hook_entered;
    atomic_bool              first_hook_release;
    atomic_bool              second_hook_entered;
    atomic_bool              second_hook_release;
    atomic_bool              completed;
} end_wait_probe_t;

typedef struct test_env_s
{
    master_pool_t *large_master;
    master_pool_t *small_master;
    master_pool_t *medium_master;
    master_pool_t *splice_master;
    buffer_pool_t *worker_buffer_pool;
    buffer_pool_t *second_worker_buffer_pool;
    buffer_pool_t *buffer_pools[2];
    wloop_t       *loops[2];
} test_env_t;

static captured_message_t       captured_messages[kCapturedMessageMax];
static unsigned int             captured_message_count;
static bool                     fail_post;
static device_reader_session_t *tracked_session;
static master_pool_t           *tracked_message_pool;
static unsigned int             tracked_session_free_count;
static unsigned int             tracked_pool_destroy_count;
static buffer_pool_t           *tracked_reuse_pool;
static sbuf_t                  *tracked_reuse_buffer;
static unsigned int             tracked_reuse_count;
static reader_probe_t          *active_prepare_probe;
static device_reader_session_t *active_prepare_session;

worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *arg1, void *arg2, void *arg3);
void                           __real_memoryFree(void *ptr);
void                           __wrap_memoryFree(void *ptr);
void                           __real_masterpoolDestroy(master_pool_t *pool);
void                           __wrap_masterpoolDestroy(master_pool_t *pool);
void                           __real_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buf);
void                           __wrap_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buf);

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *arg1, void *arg2, void *arg3)
{
    if (fail_post)
    {
        cleanup(arg1, arg2, arg3, kWorkerMessageCancelEnqueueFailure);
        return false;
    }

    require(captured_message_count < kCapturedMessageMax, "captured-message queue overflow");
    captured_messages[captured_message_count++] = (captured_message_t) {
        .wid      = wid,
        .callback = callback,
        .cleanup  = cleanup,
        .arg1     = arg1,
        .arg2     = arg2,
        .arg3     = arg3,
    };
    return true;
}

void __wrap_memoryFree(void *ptr)
{
    if (tracked_session != NULL && ptr == tracked_session)
    {
        require(atomic_load_explicit(&tracked_session->output_charge, memory_order_acquire) == 0,
                "reader session was destroyed with output allocation charge reserved");
        require(atomic_load_explicit(&tracked_session->output_packets, memory_order_acquire) == 0,
                "reader session was destroyed with output packet reservations");
        tracked_session_free_count++;
    }
    __real_memoryFree(ptr);
}

void __wrap_masterpoolDestroy(master_pool_t *pool)
{
    if (pool == tracked_message_pool)
    {
        tracked_pool_destroy_count++;
    }
    __real_masterpoolDestroy(pool);
}

void __wrap_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buf)
{
    if (pool == tracked_reuse_pool && (tracked_reuse_buffer == NULL || buf == tracked_reuse_buffer))
    {
        tracked_reuse_count++;
    }
    __real_bufferpoolReuseBuffer(pool, buf);
}

static void deliverPacket(void *device, sbuf_t *buf, wid_t wid)
{
    reader_probe_t *probe = device;
    if (probe->required_work_steps != NULL)
    {
        require(*probe->required_work_steps == probe->expected_work_steps,
                "ordinary packet overtook unfinished worker work");
    }
    if (probe->check_prepare_order)
    {
        require(currentThreadIsEventWorkerWID(wid), "prepared output did not reach its selected event worker");
        require(probe->last_prepared == buf && probe->prepared == probe->delivered + 1 &&
                    ((const uint8_t *) sbufGetRawPtr(buf))[0] == 0xA5,
                "output reached the device before its worker-side prepare callback");
    }
    probe->delivered++;

    if (atomicLoadRelaxed(&probe->block_delivery))
    {
        atomicStoreExplicit(&probe->delivery_entered, true, memory_order_release);
        while (! atomicLoadExplicit(&probe->release_delivery, memory_order_acquire))
        {
            YIELD_THREAD();
        }
        sbufDestroy(buf);
        return;
    }
    bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
}

static void prepareReaderOutput(sbuf_t *buf)
{
    require(active_prepare_probe != NULL && active_prepare_session != NULL, "prepare callback lost its test owner");
    require(currentThreadIsEventWorkerWID(0), "prepare callback ran outside the receiving event worker");
    require(atomic_load_explicit(&active_prepare_session->output_packets, memory_order_acquire) > 0 &&
                atomic_load_explicit(&active_prepare_session->output_charge, memory_order_acquire) > 0,
            "prepare callback ran after its output reservation was released");
    require(((const uint8_t *) sbufGetRawPtr(buf))[0] == 0x5A,
            "prepare callback saw changed reader-owned output bytes");
    ((uint8_t *) sbufGetMutablePtr(buf))[0] = 0xA5;
    active_prepare_probe->last_prepared     = buf;
    active_prepare_probe->prepared++;
}

static void writeIpv4Checksum(uint8_t *packet)
{
    uint32_t sum = 0;
    PUT_BE16(packet + 10, 0);
    for (uint32_t offset = 0; offset < 20; offset += 2)
    {
        sum += GET_BE16(packet + offset);
    }
    while ((sum >> 16U) != 0)
    {
        sum = (sum & UINT32_C(0xFFFF)) + (sum >> 16U);
    }
    PUT_BE16(packet + 10, (uint16_t) ~sum);
}

static sbuf_t *makeCompletePacket(device_reader_session_t *session, buffer_pool_t *pool, uint16_t id)
{
    device_frag_affinity_result_t result;
    for (unsigned part = 0; part < 2; ++part)
    {
        sbuf_t  *buf   = bufferpoolGetSmallBuffer(pool);
        uint8_t *bytes = sbufGetMutablePtr(buf);
        memoryZero(bytes, 84);
        bytes[0] = 0x45;
        bytes[8] = 64;
        bytes[9] = 17;
        PUT_BE16(bytes + 2, 84);
        PUT_BE16(bytes + 4, id);
        PUT_BE16(bytes + 6, part ? 8 : 0x2000);
        PUT_BE32(bytes + 12, 0x0a000001);
        PUT_BE32(bytes + 16, 0xc0000201);
        writeIpv4Checksum(bytes);
        sbufSetLength(buf, 84);
        require(deviceFragAffinityOffer(session->frag_affinity, bytes, 84, buf, &result) ==
                    (part ? kDeviceFragAffinityComplete : kDeviceFragAffinityStaged),
                "normalized offer failed");
    }
    return result.completed;
}

static void envSetup(test_env_t *env)
{
    memoryZero(env, sizeof(*env));
    env->large_master              = masterpoolCreateWithCapacity(16);
    env->small_master              = masterpoolCreateWithCapacity(16);
    env->medium_master             = masterpoolCreateWithCapacity(16);
    env->splice_master             = masterpoolCreateWithCapacity(16);
    env->worker_buffer_pool        = bufferpoolCreate(env->large_master,
                                               env->medium_master,
                                               env->small_master,
                                               env->splice_master,
                                               16,
                                               8192,
                                               MEDIUM_BUFFER_SIZE_RAM_HIGH,
                                               4096,
                                               8192,
                                               8192);
    env->second_worker_buffer_pool = bufferpoolCreate(env->large_master,
                                                      env->medium_master,
                                                      env->small_master,
                                                      env->splice_master,
                                                      16,
                                                      8192,
                                                      MEDIUM_BUFFER_SIZE_RAM_HIGH,
                                                      4096,
                                                      8192,
                                                      8192);
    env->buffer_pools[0]           = env->worker_buffer_pool;
    env->buffer_pools[1]           = env->second_worker_buffer_pool;
    env->loops[0]                  = (wloop_t *) (void *) env;
    env->loops[1]                  = (wloop_t *) (void *) env;

    GSTATE.shortcut_buffer_pools          = env->buffer_pools;
    GSTATE.shortcut_loops                 = env->loops;
    GSTATE.masterpool_buffer_pools_large  = env->large_master;
    GSTATE.masterpool_buffer_pools_small  = env->small_master;
    GSTATE.masterpool_buffer_pools_medium = env->medium_master;
    GSTATE.masterpool_buffer_pools_splice = env->splice_master;
    GSTATE.workers_count                  = 2;
    testWorkerRegistryInstall(&g_test_worker_registry);
    testWorkerBindWID(0);
}

static void envTeardown(test_env_t *env)
{
    GSTATE.shortcut_buffer_pools          = NULL;
    GSTATE.shortcut_loops                 = NULL;
    GSTATE.masterpool_buffer_pools_large  = NULL;
    GSTATE.masterpool_buffer_pools_small  = NULL;
    GSTATE.masterpool_buffer_pools_medium = NULL;
    GSTATE.masterpool_buffer_pools_splice = NULL;
    GSTATE.workers_count                  = 0;
    testWorkerRegistryRestore(&g_test_worker_registry);

    bufferpoolDestroy(env->worker_buffer_pool);
    bufferpoolDestroy(env->second_worker_buffer_pool);
    masterpoolMakeEmpty(env->large_master);
    masterpoolMakeEmpty(env->small_master);
    masterpoolMakeEmpty(env->medium_master);
    masterpoolMakeEmpty(env->splice_master);
    masterpoolDestroy(env->large_master);
    masterpoolDestroy(env->small_master);
    masterpoolDestroy(env->medium_master);
    masterpoolDestroy(env->splice_master);
}

static device_reader_session_t *createSession(test_env_t *env, reader_probe_t *probe, uint16_t batch_capacity)
{
    return deviceReaderSessionCreate(
        4, batch_capacity, probe, deliverPacket, env->worker_buffer_pool, kDeviceFragmentReassemble);
}

static void resetCapturedMessages(void)
{
    memoryZero(captured_messages, sizeof(captured_messages));
    captured_message_count = 0;
    fail_post              = false;
    tracked_reuse_pool     = NULL;
    tracked_reuse_buffer   = NULL;
    tracked_reuse_count    = 0;
}

static void deliverMessage(unsigned int index)
{
    worker_t            receiver = {.wid = 0};
    captured_message_t *message  = &captured_messages[index];
    message->callback(&receiver, message->arg1, message->arg2, message->arg3);
}

static void cleanupMessage(unsigned int index)
{
    captured_message_t *message = &captured_messages[index];
    message->cleanup(message->arg1, message->arg2, message->arg3, kWorkerMessageCancelQuiesced);
}

static void *deliverFirstMessageRoutine(void *userdata)
{
    discard userdata;
    deliverMessage(0);
    return NULL;
}

static void waitForEndWaitFlag(const atomic_bool *flag, const char *message)
{
    const uint64_t deadline_us = getHRTimeUs() + UINT64_C(2000000);
    while (! atomicLoadExplicit(flag, memory_order_acquire))
    {
        require(getHRTimeUs() < deadline_us, message);
        YIELD_THREAD();
    }
}

static void waitForSecondEndWaitHook(const end_wait_probe_t *probe, const char *message)
{
    const uint64_t deadline_us = getHRTimeUs() + UINT64_C(2000000);
    while (! atomicLoadExplicit(&probe->second_hook_entered, memory_order_acquire))
    {
        require(! atomicLoadExplicit(&probe->completed, memory_order_acquire),
                "reader-session EndWait completed before its second non-quiesced observation");
        require(getHRTimeUs() < deadline_us, message);
        YIELD_THREAD();
    }
}

static void readerSessionEndWaitYieldHook(device_reader_session_t *session, void *context)
{
    end_wait_probe_t *probe = context;
    require(session == probe->session, "reader EndWait seam reported the wrong session");
    const unsigned int hook_call = atomicAddExplicit(&probe->hook_calls, 1, memory_order_relaxed);
    if (hook_call == 0)
    {
        atomicStoreExplicit(&probe->first_hook_entered, true, memory_order_release);
        waitForEndWaitFlag(&probe->first_hook_release, "reader-session EndWait first hook was never released");
        return;
    }
    if (hook_call == 1)
    {
        atomicStoreExplicit(&probe->second_hook_entered, true, memory_order_release);
        waitForEndWaitFlag(&probe->second_hook_release, "reader-session EndWait second hook was never released");
        return;
    }
    require(false, "reader-session EndWait hook ran more than twice while the test held admission");
}

static void *endWaitRoutine(void *userdata)
{
    end_wait_probe_t *probe = userdata;
    deviceReaderSessionEndWait(probe->session);
    atomicStoreExplicit(&probe->completed, true, memory_order_release);
    return NULL;
}

static void testQueuedCleanupOutlivesDeviceReference(test_env_t *env)
{
    resetCapturedMessages();
    reader_probe_t           probe   = {0};
    device_reader_session_t *session = createSession(env, &probe, 1);

    tracked_session            = session;
    tracked_message_pool       = session->message_pool;
    tracked_session_free_count = 0;
    tracked_pool_destroy_count = 0;

    deviceReaderSessionBegin(session);
    sbuf_t *buf = sbufCreate(64);
    deviceReaderSessionPost(session, 0, &buf, 1);
    require(captured_message_count == 1, "singleton post did not queue exactly one message");
    require(atomicLoadExplicit(&session->refcount, memory_order_acquire) == 2,
            "posting did not retain the reader session");

    deviceReaderSessionEnd(session);
    deviceReaderSessionUnref(session);
    require(tracked_session_free_count == 0 && tracked_pool_destroy_count == 0,
            "dropping the device reference destroyed a queued-message session");

    cleanupMessage(0);
    require(tracked_session_free_count == 1, "queued cleanup did not free the session exactly once");
    require(tracked_pool_destroy_count == 1, "queued cleanup did not destroy the message pool exactly once");

    tracked_session      = NULL;
    tracked_message_pool = NULL;
}

static void testClosedAndStaleDeliveriesAreDropped(test_env_t *env)
{
    resetCapturedMessages();
    reader_probe_t           probe   = {0};
    device_reader_session_t *session = createSession(env, &probe, 1);
    deviceReaderSessionBegin(session);

    sbuf_t *closed_buf = bufferpoolGetSmallBuffer(env->worker_buffer_pool);
    sbuf_t *stale_buf  = bufferpoolGetSmallBuffer(env->worker_buffer_pool);
    deviceReaderSessionPost(session, 0, &closed_buf, 1);
    deviceReaderSessionPost(session, 0, &stale_buf, 1);
    require(captured_message_count == 2, "singleton posts did not queue both deliveries");

    deviceReaderSessionEnd(session);
    deliverMessage(0);
    require(probe.delivered == 0, "a closed-session message reached the device");

    deviceReaderSessionBegin(session);
    deliverMessage(1);
    require(probe.delivered == 0, "a stale-generation message reached the device");

    deviceReaderSessionEnd(session);
    deviceReaderSessionUnref(session);
}

static void testSingleAndBatchedMessagesRoundTrip(test_env_t *env)
{
    const uint16_t capacities[] = {1, 4};
    for (unsigned int capacity_index = 0; capacity_index < ARRAY_SIZE(capacities); capacity_index++)
    {
        resetCapturedMessages();
        reader_probe_t           probe    = {0};
        const uint16_t           capacity = capacities[capacity_index];
        device_reader_session_t *session  = createSession(env, &probe, capacity);
        sbuf_t                  *bufs[4];

        for (uint16_t i = 0; i < capacity; i++)
        {
            bufs[i] = bufferpoolGetSmallBuffer(env->worker_buffer_pool);
        }

        deviceReaderSessionBegin(session);
        deviceReaderSessionPost(session, 0, bufs, capacity);
        require(captured_message_count == 1, "round-trip post did not queue exactly one message");
        deliverMessage(0);
        require(probe.delivered == capacity, "round-trip delivery lost a single or batched buffer");

        deviceReaderSessionEnd(session);
        deviceReaderSessionUnref(session);
    }
}

static void testFailedPostBalancesReference(test_env_t *env)
{
    resetCapturedMessages();
    reader_probe_t           probe   = {0};
    device_reader_session_t *session = createSession(env, &probe, 1);
    deviceReaderSessionBegin(session);

    fail_post   = true;
    sbuf_t *buf = sbufCreate(64);
    deviceReaderSessionPost(session, 0, &buf, 1);
    require(captured_message_count == 0, "a failed post remained queued");
    require(atomicLoadExplicit(&session->refcount, memory_order_acquire) == 1,
            "a failed post leaked or over-released its session reference");

    deviceReaderSessionEnd(session);
    deviceReaderSessionUnref(session);
    fail_post = false;
}

static void testTrackedSingletonSettlement(test_env_t *env)
{
    resetCapturedMessages();
    reader_probe_t           probe   = {0};
    device_reader_session_t *session = createSession(env, &probe, 1);
    require(deviceReaderSessionBegin(session) != 0, "failed to begin tracked singleton session");

    sbuf_t *buf = makeCompletePacket(session, env->worker_buffer_pool, 30001);
    require(deviceReaderSessionPost(session, 0, &buf, 1), "tracked singleton post was unexpectedly refused");
    require(captured_message_count == 1, "tracked singleton did not queue a message");
    deliverMessage(0);
    require(probe.delivered == 1, "normalized packet was not delivered");
    deviceReaderSessionEnd(session);
    deviceReaderSessionUnref(session);
}

static void testOversizedBatchIsRejectedAndRecycled(test_env_t *env)
{
    resetCapturedMessages();
    reader_probe_t           probe   = {0};
    device_reader_session_t *session = createSession(env, &probe, 1);
    sbuf_t                  *bufs[2] = {
        bufferpoolGetSmallBuffer(env->worker_buffer_pool),
        bufferpoolGetSmallBuffer(env->worker_buffer_pool),
    };

    tracked_reuse_pool  = env->worker_buffer_pool;
    tracked_reuse_count = 0;
    deviceReaderSessionBegin(session);
    deviceReaderSessionPost(session, 0, bufs, ARRAY_SIZE(bufs));
    tracked_reuse_pool = NULL;

    require(captured_message_count == 0, "an oversized batch was queued");
    require(tracked_reuse_count == ARRAY_SIZE(bufs), "an oversized batch did not recycle every buffer");
    require(atomicLoadExplicit(&session->refcount, memory_order_acquire) == 1,
            "an oversized batch changed the reader-session reference count");

    deviceReaderSessionEnd(session);
    deviceReaderSessionUnref(session);
}

static void testEndWaitsForEnteredDelivery(test_env_t *env)
{
    resetCapturedMessages();
    reader_probe_t probe = {
        .block_delivery = true,
    };
    device_reader_session_t *session = createSession(env, &probe, 1);
    require(deviceReaderSessionBegin(session) != 0, "failed to begin blocking reader session");

    sbuf_t *buf = bufferpoolGetSmallBuffer(env->worker_buffer_pool);
    deviceReaderSessionPost(session, 0, &buf, 1);

    pthread_t delivery_thread;
    require(pthread_create(&delivery_thread, NULL, deliverFirstMessageRoutine, NULL) == 0,
            "failed to create blocking delivery thread");
    waitForEndWaitFlag(&probe.delivery_entered, "blocking reader delivery did not enter");

    deviceReaderSessionEndRequest(session);
    require(! quiescenceGateIsActive(&session->delivery_gate), "reader EndRequest left delivery admission open");
    require(! quiescenceGateIsClosedAndQuiesced(&session->delivery_gate),
            "reader EndRequest quiesced while a delivery callback was still active");

    end_wait_probe_t end_probe = {.session = session};
    pthread_t        end_thread;
    deviceReaderSessionInstallEndWaitYieldHook(readerSessionEndWaitYieldHook, &end_probe);
    require(pthread_create(&end_thread, NULL, endWaitRoutine, &end_probe) == 0,
            "failed to create reader-session end thread");
    waitForEndWaitFlag(&end_probe.first_hook_entered, "reader-session EndWait did not enter its first hook");
    require(! atomicLoadExplicit(&end_probe.completed, memory_order_acquire),
            "reader-session EndWait returned during active delivery");
    require(! quiescenceGateIsClosedAndQuiesced(&session->delivery_gate),
            "reader EndWait first observation saw a quiesced gate during active delivery");

    atomicStoreExplicit(&end_probe.first_hook_release, true, memory_order_release);
    waitForSecondEndWaitHook(&end_probe, "reader-session EndWait did not make a second observation");
    require(! atomicLoadExplicit(&end_probe.completed, memory_order_acquire),
            "reader-session EndWait returned at its second active-delivery observation");
    require(! quiescenceGateIsClosedAndQuiesced(&session->delivery_gate),
            "reader EndWait second observation saw a quiesced gate during active delivery");

    atomicStoreExplicit(&probe.release_delivery, true, memory_order_release);
    require(pthread_join(delivery_thread, NULL) == 0, "failed to join blocking delivery thread");
    require(quiescenceGateIsClosedAndQuiesced(&session->delivery_gate),
            "reader delivery did not quiesce before releasing EndWait's second hook");
    atomicStoreExplicit(&end_probe.second_hook_release, true, memory_order_release);
    require(pthread_join(end_thread, NULL) == 0, "failed to join reader-session end thread");
    deviceReaderSessionInstallEndWaitYieldHook(NULL, NULL);
    require(atomicLoadExplicit(&end_probe.completed, memory_order_acquire),
            "reader-session EndWait did not complete after delivery left");

    deviceReaderSessionUnref(session);
}

static void testTrackedEnvelopeStaleAfterReopenIsRejected(test_env_t *env)
{
    resetCapturedMessages();
    reader_probe_t           probe   = {0};
    device_reader_session_t *session = createSession(env, &probe, 1);
    require(deviceReaderSessionBegin(session) != 0, "failed to begin tracked stale-generation session");

    sbuf_t *buf = makeCompletePacket(session, env->worker_buffer_pool, 30002);
    require(deviceReaderSessionPost(session, 0, &buf, 1), "tracked stale-generation post was unexpectedly refused");
    require(captured_message_count == 1, "tracked stale-generation singleton was not queued");

    deviceReaderSessionEnd(session);
    require(deviceReaderSessionBegin(session) != 0, "failed to reopen tracked stale-generation session");
    deliverMessage(0);
    require(probe.delivered == 0, "stale tracked envelope reached the device after reopen");

    deviceReaderSessionEnd(session);
    deviceReaderSessionUnref(session);
}

static void testReferenceOverflowFailsBeforeWrap(test_env_t *env)
{
#if defined(OS_UNIX)
    reader_probe_t           probe   = {0};
    device_reader_session_t *session = createSession(env, &probe, 1);
    atomicStoreRelaxed(&session->refcount, W_ATOMIC_UINT_VALUE_MAX);

    const pid_t child = fork();
    require(child >= 0, "failed to fork reader-reference overflow test");
    if (child == 0)
    {
        deviceReaderSessionRef(session);
        _Exit(0);
    }

    int status;
    require(waitpid(child, &status, 0) == child, "failed to wait for reader-reference overflow child");
    require(WIFEXITED(status) && WEXITSTATUS(status) != 0,
            "reader-reference overflow returned or wrapped instead of aborting");

    atomicStoreRelaxed(&session->refcount, 1);
    deviceReaderSessionUnref(session);
#else
    discard env;
#endif
}

static void requireOutputBudgetEmpty(const device_reader_session_t *session)
{
    require(atomic_load_explicit(&session->output_charge, memory_order_acquire) == 0,
            "output budget leaked allocation charge");
    require(atomic_load_explicit(&session->output_packets, memory_order_acquire) == 0,
            "output budget leaked packet count");
}

static void requireOutputWake(device_reader_session_t *session)
{
    const int fd = deviceReaderSessionOutputWakeFd(session);
    require(fd >= 0, "configured output budget lacks a wake descriptor");
    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    require(poll(&pfd, 1, 0) == 1 && (pfd.revents & POLLIN), "settlement did not wake the blocked reader");
    deviceReaderSessionDrainOutputWake(session);
    pfd.revents = 0;
    require(poll(&pfd, 1, 0) == 0, "output wake was not fully drained");
}

static void testOutputBudgetStalledDeliveryAndCancellation(test_env_t *env)
{
    resetCapturedMessages();
    reader_probe_t           probe   = {0};
    device_reader_session_t *session = createSession(env, &probe, 1);
    buffer_pool_fit_t        fit;
    require(bufferpoolQueryBestFit(env->worker_buffer_pool, 64, 0, &fit), "failed to query output packet charge");
    const size_t charge = fit.allocation_charge;
    require(deviceReaderSessionConfigureOutputBudget(session, 2 * charge, 2), "failed to configure output budget");
    require(deviceReaderSessionBegin(session) != 0, "failed to begin budgeted reader session");

    for (unsigned int i = 0; i < 2; ++i)
    {
        require(deviceReaderSessionTryReserveOutput(session, charge), "failed to reserve initial output packet");
        sbuf_t *buf = bufferpoolGetBestFit(env->worker_buffer_pool, 64, 0);
        require(sbufGetAllocationCharge(buf) == charge, "pre-allocation charge did not match actual buffer");
        require(deviceReaderSessionPostReserved(session, 0, &buf, &charge, 1, NULL), "initial budgeted post failed");
    }
    require(atomic_load_explicit(&session->output_charge, memory_order_acquire) == 2 * charge,
            "stalled messages exceeded or lost the output charge budget");
    require(atomic_load_explicit(&session->output_packets, memory_order_acquire) == 2,
            "stalled messages exceeded or lost the output packet budget");
    require(! deviceReaderSessionTryReserveOutput(session, charge), "stalled worker did not backpressure the reader");

    cleanupMessage(0);
    requireOutputWake(session);
    require(deviceReaderSessionTryReserveOutput(session, charge), "cancelled delivery did not return one credit");
    sbuf_t *third = bufferpoolGetBestFit(env->worker_buffer_pool, 64, 0);
    require(deviceReaderSessionPostReserved(session, 0, &third, &charge, 1, NULL), "post after credit return failed");
    require(! deviceReaderSessionTryReserveOutput(session, charge), "repeated output exceeded the bounded budget");

    deliverMessage(1);
    requireOutputWake(session);
    deliverMessage(2);
    require(probe.delivered == 2, "budgeted delivery count was incorrect");
    requireOutputBudgetEmpty(session);
    deviceReaderSessionEnd(session);
    deviceReaderSessionUnref(session);
}

static void testOutputBudgetLocalAndRejectedSettlement(test_env_t *env)
{
    resetCapturedMessages();
    reader_probe_t           probe   = {0};
    device_reader_session_t *session = createSession(env, &probe, 1);
    buffer_pool_fit_t        fit;
    require(bufferpoolQueryBestFit(env->worker_buffer_pool, 64, 0, &fit), "failed to query output packet charge");
    const size_t charge = fit.allocation_charge;
    require(deviceReaderSessionConfigureOutputBudget(session, 3 * charge, 1),
            "failed to configure packet-count budget");
    require(deviceReaderSessionBegin(session) != 0, "failed to begin packet-count budget session");
    require(deviceReaderSessionTryReserveOutput(session, charge), "failed to reserve local output");
    require(! deviceReaderSessionTryReserveOutput(session, charge), "packet-count budget allowed a second output");
    deviceReaderSessionReleaseOutput(session, charge);
    requireOutputWake(session);
    requireOutputBudgetEmpty(session);

    require(deviceReaderSessionTryReserveOutput(session, charge), "failed to reserve refused-post output");
    sbuf_t *buf = bufferpoolGetBestFit(env->worker_buffer_pool, 64, 0);
    fail_post   = true;
    require(! deviceReaderSessionPostReserved(session, 0, &buf, &charge, 1, NULL),
            "refused budgeted post reported acceptance");
    fail_post = false;
    requireOutputBudgetEmpty(session);
    require(atomic_load_explicit(&session->refcount, memory_order_acquire) == 1,
            "refused budgeted post leaked the session reference");

    require(deviceReaderSessionTryReserveOutput(session, charge), "failed to reserve stale-generation output");
    buf = bufferpoolGetBestFit(env->worker_buffer_pool, 64, 0);
    require(deviceReaderSessionPostReserved(session, 0, &buf, &charge, 1, NULL), "stale-generation setup post failed");
    deviceReaderSessionEnd(session);
    require(deviceReaderSessionBegin(session) != 0, "failed to reopen budgeted session");
    deliverMessage(0);
    require(probe.delivered == 0, "stale budgeted delivery reached the device");
    requireOutputBudgetEmpty(session);
    deviceReaderSessionEnd(session);
    deviceReaderSessionUnref(session);
}

static void testOutputBudgetCancellationOutlivesDevice(test_env_t *env)
{
    resetCapturedMessages();
    reader_probe_t           probe   = {0};
    device_reader_session_t *session = createSession(env, &probe, 1);
    buffer_pool_fit_t        fit;
    require(bufferpoolQueryBestFit(env->worker_buffer_pool, 64, 0, &fit), "failed to query output packet charge");
    const size_t charge = fit.allocation_charge;
    require(deviceReaderSessionConfigureOutputBudget(session, charge, 1), "failed to configure retained budget");
    require(deviceReaderSessionBegin(session) != 0, "failed to begin retained budget session");
    require(deviceReaderSessionTryReserveOutput(session, charge), "failed to reserve retained output");
    sbuf_t *buf = bufferpoolGetBestFit(env->worker_buffer_pool, 64, 0);
    require(deviceReaderSessionPostReserved(session, 0, &buf, &charge, 1, NULL), "failed to queue retained output");

    tracked_session            = session;
    tracked_message_pool       = session->message_pool;
    tracked_session_free_count = 0;
    tracked_pool_destroy_count = 0;
    deviceReaderSessionEnd(session);
    deviceReaderSessionRetireProducerBuffers(session);
    deviceReaderSessionUnref(session);
    require(tracked_session_free_count == 0, "queued output did not retain its budget and session");
    cleanupMessage(0);
    require(tracked_session_free_count == 1 && tracked_pool_destroy_count == 1,
            "queued output cancellation did not settle and destroy its session once");
    tracked_session      = NULL;
    tracked_message_pool = NULL;
}

static void testPreparedOutputRunsOnlyOnLiveWorkerDelivery(test_env_t *env)
{
    resetCapturedMessages();
    reader_probe_t           probe   = {.check_prepare_order = true};
    device_reader_session_t *session = createSession(env, &probe, 2);
    buffer_pool_fit_t        fit;
    require(bufferpoolQueryBestFit(env->worker_buffer_pool, 64, 0, &fit), "failed to query prepared output charge");
    const size_t charge = fit.allocation_charge;
    require(deviceReaderSessionConfigureOutputBudget(session, 2 * charge, 2),
            "failed to configure prepared output budget");
    require(deviceReaderSessionBegin(session) != 0, "failed to begin prepared output session");
    active_prepare_probe   = &probe;
    active_prepare_session = session;

    sbuf_t      *bufs[2];
    const size_t charges[2] = {charge, charge};
    for (unsigned int i = 0; i < ARRAY_SIZE(bufs); ++i)
    {
        require(deviceReaderSessionTryReserveOutput(session, charge), "failed to reserve prepared output");
        bufs[i] = bufferpoolGetBestFit(env->worker_buffer_pool, 64, 0);
        sbufSetLength(bufs[i], 1);
        ((uint8_t *) sbufGetMutablePtr(bufs[i]))[0] = 0x5A;
    }
    testWorkerUnbindWID();
    require(deviceReaderSessionPostReserved(session, 0, bufs, charges, 2, prepareReaderOutput),
            "prepared output batch was refused");
    require(probe.prepared == 0 && probe.delivered == 0, "prepared output ran during producer-side posting");
    testWorkerBindWID(0);
    deliverMessage(0);
    require(probe.prepared == 2 && probe.delivered == 2, "worker did not prepare both batched outputs in order");
    requireOutputBudgetEmpty(session);

    require(deviceReaderSessionTryReserveOutput(session, charge), "failed to reserve stale prepared output");
    sbuf_t *buf = bufferpoolGetBestFit(env->worker_buffer_pool, 64, 0);
    sbufSetLength(buf, 1);
    ((uint8_t *) sbufGetMutablePtr(buf))[0] = 0x5A;
    require(deviceReaderSessionPostReserved(session, 0, &buf, &charge, 1, prepareReaderOutput),
            "failed to queue stale prepared output");
    deviceReaderSessionEnd(session);
    require(deviceReaderSessionBegin(session) != 0, "failed to reopen prepared output session");
    deliverMessage(1);
    require(probe.prepared == 2 && probe.delivered == 2, "stale generation ran output preparation");
    requireOutputBudgetEmpty(session);

    require(deviceReaderSessionTryReserveOutput(session, charge), "failed to reserve cancelled prepared output");
    buf = bufferpoolGetBestFit(env->worker_buffer_pool, 64, 0);
    sbufSetLength(buf, 1);
    ((uint8_t *) sbufGetMutablePtr(buf))[0] = 0x5A;
    require(deviceReaderSessionPostReserved(session, 0, &buf, &charge, 1, prepareReaderOutput),
            "failed to queue cancelled prepared output");
    cleanupMessage(2);
    require(probe.prepared == 2 && probe.delivered == 2, "cancelled output ran preparation");
    requireOutputBudgetEmpty(session);

    require(deviceReaderSessionTryReserveOutput(session, charge), "failed to reserve refused prepared output");
    buf = bufferpoolGetBestFit(env->worker_buffer_pool, 64, 0);
    sbufSetLength(buf, 1);
    ((uint8_t *) sbufGetMutablePtr(buf))[0] = 0x5A;
    fail_post                               = true;
    require(! deviceReaderSessionPostReserved(session, 0, &buf, &charge, 1, prepareReaderOutput),
            "refused prepared output reported acceptance");
    fail_post = false;
    require(probe.prepared == 2 && probe.delivered == 2, "refused output ran preparation");
    requireOutputBudgetEmpty(session);

    active_prepare_probe   = NULL;
    active_prepare_session = NULL;
    deviceReaderSessionEnd(session);
    deviceReaderSessionUnref(session);
}

/* Generic work models an aggregate that stays at the queue head while its
 * bounded worker steps execute. TUN-specific segment bytes are checked by the
 * Linux lifetime fixture; this fixture exercises FIFO and ownership settlement. */
typedef struct worker_work_probe_s
{
    unsigned int steps;
    unsigned int target_steps;
    unsigned int cleanups;
    uint32_t     step_bytes;
    wid_t        target_wid;
} worker_work_probe_t;

static bool stepWorkerWork(device_reader_session_t *session, void *context, wid_t wid,
                           device_reader_work_budget_t *budget)
{
    worker_work_probe_t *probe = context;
    require(wid == probe->target_wid && currentThreadIsEventWorkerWID(wid),
            "aggregate work ran outside its selected event worker");
    require(atomic_load_explicit(&session->output_charge, memory_order_acquire) > 0 &&
                atomic_load_explicit(&session->output_packets, memory_order_acquire) >= 2,
            "aggregate work ran without its retained input and output allowance");
    require(probe->steps < probe->target_steps && probe->cleanups == 0,
            "aggregate work ran after completion or cleanup");
    const uint32_t bytes = probe->step_bytes != 0 ? probe->step_bytes : 1;
    if (budget->bytes < bytes)
    {
        return false;
    }
    require(budget->packets > 0, "aggregate work ran without callback packet capacity");
    --budget->packets;
    budget->bytes -= bytes;
    return ++probe->steps == probe->target_steps;
}

static void cleanupWorkerWork(void *context)
{
    worker_work_probe_t *probe = context;
    require(++probe->cleanups == 1, "aggregate work cleanup ran more than once");
}

static device_reader_session_t *createWorkerQueueSession(test_env_t *env, reader_probe_t *probe)
{
    device_reader_session_t *session = createSession(env, probe, 4);
    require(deviceReaderSessionConfigureOutputBudget(session, 1024 * 1024, 8),
            "failed to configure worker-queue budget");
    require(deviceReaderSessionEnableWorkerQueue(session), "failed to enable ordered worker queue");
    require(deviceReaderSessionBegin(session) != 0, "failed to begin ordered worker queue");
    return session;
}

static bool postWorkerWork(device_reader_session_t *session, worker_work_probe_t *probe)
{
    const size_t charge = 256;
    require(deviceReaderSessionTryReserveWork(session, charge, 2), "failed to reserve aggregate work");
    return deviceReaderSessionPostWork(session, probe->target_wid, probe, stepWorkerWork, cleanupWorkerWork, charge, 2);
}

static void deliverWorkerQueueMessage(unsigned int index)
{
    captured_message_t *message = &captured_messages[index];
    testWorkerBindWID(message->wid);
    worker_t receiver = {.wid = message->wid};
    message->callback(&receiver, message->arg1, message->arg2, message->arg3);
    testWorkerBindWID(0);
}

static void testWorkerQueueContinuationAndOrdinaryFifo(test_env_t *env)
{
    resetCapturedMessages();
    worker_work_probe_t      first   = {.target_steps = 3, .target_wid = 0};
    worker_work_probe_t      other   = {.target_steps = 1, .target_wid = 1};
    reader_probe_t           probe   = {.required_work_steps = &first.steps, .expected_work_steps = 3};
    device_reader_session_t *session = createWorkerQueueSession(env, &probe);
    require(postWorkerWork(session, &first), "first aggregate work was refused");
    require(postWorkerWork(session, &other), "other-worker aggregate work was refused");
    sbuf_t *ordinary = bufferpoolGetSmallBuffer(env->worker_buffer_pool);
    require(deviceReaderSessionPost(session, 0, &ordinary, 1), "ordinary packet behind aggregate was refused");
    require(captured_message_count == 2 && first.steps == 0 && other.steps == 0,
            "posting expanded work or scheduled duplicate FIFO drain tokens");
    const size_t retained_charge = atomic_load_explicit(&session->output_charge, memory_order_acquire);
    require(retained_charge > 512 && atomic_load_explicit(&session->output_packets, memory_order_acquire) == 5,
            "ordinary backlog was not included in the aggregate queue budget");
    require(! deviceReaderSessionTryReserveWork(session, 128, 4),
            "stalled workers exceeded the aggregate packet budget");

    deliverWorkerQueueMessage(0);
    require(first.steps == 1 && first.cleanups == 0 && probe.delivered == 0,
            "one drain callback did not yield after one bounded aggregate step");
    require(atomic_load_explicit(&session->output_charge, memory_order_acquire) == retained_charge,
            "partial aggregate released its ownership reservation");
    deliverWorkerQueueMessage(1);
    require(other.steps == 1 && other.cleanups == 1 && first.steps == 1,
            "unfinished aggregate prevented another worker from progressing");
    for (unsigned int i = 2; i < captured_message_count; ++i)
    {
        deliverWorkerQueueMessage(i);
    }
    require(first.steps == 3 && first.cleanups == 1 && probe.delivered == 1,
            "continuation failed to finish aggregate and its following ordinary packet");
    requireOutputBudgetEmpty(session);
    deviceReaderSessionEnd(session);
    deviceReaderSessionUnref(session);
}

static void testWorkerQueueBatchesCompletedAggregates(test_env_t *env)
{
    /* Small records share one callback, but combined packet and byte limits
     * still force a continuation. This also catches yielding once per record. */
    const unsigned int counts[]          = {3, 65, 2};
    const uint32_t     sizes[]           = {100, 100, 40000};
    const unsigned int first_completed[] = {3, 64, 1};
    for (unsigned int test = 0; test < ARRAY_SIZE(counts); ++test)
    {
        resetCapturedMessages();
        reader_probe_t           probe   = {0};
        device_reader_session_t *session = createSession(env, &probe, 4);
        require(deviceReaderSessionConfigureOutputBudget(session, 1024 * 1024, 256) &&
                    deviceReaderSessionEnableWorkerQueue(session) && deviceReaderSessionBegin(session) != 0,
                "failed to initialize aggregate batching fixture");
        worker_work_probe_t work[65] = {0};
        for (unsigned int i = 0; i < counts[test]; ++i)
        {
            work[i].target_steps = 1;
            work[i].step_bytes   = sizes[test];
            require(postWorkerWork(session, &work[i]), "small aggregate admission failed");
        }
        sbuf_t *ordinary = bufferpoolGetSmallBuffer(env->worker_buffer_pool);
        sbufSetLength(ordinary, 100);
        require(deviceReaderSessionPost(session, 0, &ordinary, 1), "trailing ordinary admission failed");
        require(captured_message_count == 1, "aggregate admission scheduled duplicate drain tokens");
        deliverWorkerQueueMessage(0);
        for (unsigned int i = 0; i < counts[test]; ++i)
        {
            const unsigned int expected = i < first_completed[test] ? 1 : 0;
            require(work[i].steps == expected && work[i].cleanups == expected,
                    "callback failed to batch small work or exceeded its combined quantum");
        }
        require(probe.delivered == (test == 0 ? 1U : 0U),
                "ordinary packet overtook work or failed to share remaining callback capacity");
        require(captured_message_count == (test == 0 ? 1U : 2U),
                "FIFO scheduled an unnecessary continuation or failed to yield at its bound");
        if (test != 0)
        {
            deliverWorkerQueueMessage(1);
        }
        require(probe.delivered == 1 && captured_message_count == (test == 0 ? 1U : 2U),
                "continuation failed to drain the remaining aggregate and ordinary packet");
        requireOutputBudgetEmpty(session);
        deviceReaderSessionEnd(session);
        deviceReaderSessionUnref(session);
    }
}

static void testWorkerQueueStaleContinuationAndRefusal(test_env_t *env)
{
    resetCapturedMessages();
    reader_probe_t           probe   = {0};
    device_reader_session_t *session = createWorkerQueueSession(env, &probe);
    worker_work_probe_t      stale   = {.target_steps = 3};
    require(postWorkerWork(session, &stale), "stale aggregate setup failed");
    deliverWorkerQueueMessage(0);
    require(stale.steps == 1 && captured_message_count == 2, "aggregate failed to retain continuation");
    deviceReaderSessionEnd(session);
    require(deviceReaderSessionBegin(session) != 0, "failed to reopen queue with stale continuation");
    worker_work_probe_t fresh = {.target_steps = 1};
    require(postWorkerWork(session, &fresh), "fresh generation aggregate was refused");
    for (unsigned int i = 1; i < captured_message_count; ++i)
    {
        deliverWorkerQueueMessage(i);
    }
    require(stale.steps == 1 && stale.cleanups == 1 && fresh.steps == 1 && fresh.cleanups == 1,
            "stale continuation reached new generation or blocked new work");
    requireOutputBudgetEmpty(session);

    worker_work_probe_t refused = {.target_steps = 1};
    fail_post                   = true;
    require(! postWorkerWork(session, &refused), "initial queue refusal reported acceptance");
    fail_post = false;
    require(refused.steps == 0 && refused.cleanups == 1, "refused work ran or lost its cleanup");
    requireOutputBudgetEmpty(session);

    worker_work_probe_t cancelled = {.target_steps = 3};
    const unsigned int  next      = captured_message_count;
    require(postWorkerWork(session, &cancelled), "continuation-refusal setup failed");
    sbuf_t *ordinary = bufferpoolGetSmallBuffer(env->worker_buffer_pool);
    require(deviceReaderSessionPost(session, 0, &ordinary, 1), "continuation-refusal ordinary setup failed");
    fail_post = true;
    deliverWorkerQueueMessage(next);
    fail_post = false;
    require(cancelled.steps == 1 && cancelled.cleanups == 1 && probe.delivered == 0,
            "refused continuation ran later output or leaked pending FIFO ownership");
    requireOutputBudgetEmpty(session);
    deviceReaderSessionEnd(session);
    deviceReaderSessionUnref(session);
}

static void testWorkerQueueCancellationOutlivesDevice(test_env_t *env)
{
    resetCapturedMessages();
    reader_probe_t           probe   = {0};
    device_reader_session_t *session = createWorkerQueueSession(env, &probe);
    worker_work_probe_t      work    = {.target_steps = 3};
    require(postWorkerWork(session, &work), "retained aggregate setup failed");
    deliverWorkerQueueMessage(0);
    sbuf_t *ordinary = bufferpoolGetSmallBuffer(env->worker_buffer_pool);
    require(deviceReaderSessionPost(session, 0, &ordinary, 1), "retained ordinary setup failed");
    tracked_session            = session;
    tracked_message_pool       = session->message_pool;
    tracked_session_free_count = 0;
    tracked_pool_destroy_count = 0;
    deviceReaderSessionEnd(session);
    deviceReaderSessionRetireProducerBuffers(session);
    deviceReaderSessionUnref(session);
    require(tracked_session_free_count == 0, "partial aggregate failed to retain its session");
    testWorkerUnbindWID();
    cleanupMessage(1);
    testWorkerBindWID(0);
    require(work.steps == 1 && work.cleanups == 1 && probe.delivered == 0,
            "foreign cancellation delivered work or failed to settle retained input");
    require(tracked_session_free_count == 1 && tracked_pool_destroy_count == 1,
            "foreign cancellation failed to destroy the retired session exactly once");
    tracked_session      = NULL;
    tracked_message_pool = NULL;
}

typedef struct ordinary_wait_probe_s
{
    device_reader_session_t *session;
    buffer_pool_t           *reader_pool;
    atomic_bool              completed;
    bool                     accepted;
} ordinary_wait_probe_t;

static void *postOrdinaryWhileFull(void *context)
{
    ordinary_wait_probe_t *probe = context;
    require(! currentThreadIsEventWorker(), "ordinary producer fixture unexpectedly owns an event worker");
    sbuf_t *buf = bufferpoolGetSmallBuffer(probe->reader_pool);
    sbufSetLength(buf, 64);
    probe->accepted = deviceReaderSessionPost(probe->session, 0, &buf, 1);
    atomic_store_explicit(&probe->completed, true, memory_order_release);
    return NULL;
}

static void testWorkerQueueStopWakesOrdinaryCapacityWait(test_env_t *env)
{
    resetCapturedMessages();
    reader_probe_t           delivered   = {0};
    buffer_pool_t           *reader_pool = bufferpoolCreate(env->large_master,
                                                  env->medium_master,
                                                  env->small_master,
                                                  env->splice_master,
                                                  4,
                                                  8192,
                                                  MEDIUM_BUFFER_SIZE_RAM_HIGH,
                                                  4096,
                                                  8192,
                                                  8192);
    device_reader_session_t *session =
        deviceReaderSessionCreate(4, 1, &delivered, deliverPacket, reader_pool, kDeviceFragmentReassemble);
    require(deviceReaderSessionConfigureOutputBudget(session, 1024 * 1024, 2) &&
                deviceReaderSessionEnableWorkerQueue(session) && deviceReaderSessionBegin(session) != 0,
            "failed to initialize ordinary capacity-wait fixture");
    worker_work_probe_t aggregate = {.target_steps = 3};
    require(postWorkerWork(session, &aggregate), "failed to fill ordinary capacity-wait budget");
    tracked_reuse_pool             = reader_pool;
    ordinary_wait_probe_t producer = {.session = session, .reader_pool = reader_pool};
    pthread_t             thread;
    require(pthread_create(&thread, NULL, postOrdinaryWhileFull, &producer) == 0,
            "failed to start blocked ordinary producer");
    waitForEndWaitFlag(&session->output_waiting, "ordinary producer never waited for aggregate capacity");
    require(! atomic_load_explicit(&producer.completed, memory_order_acquire) && captured_message_count == 1 &&
                atomic_load_explicit(&session->output_packets, memory_order_acquire) == 2,
            "ordinary producer exceeded budget instead of waiting behind stalled worker");

    deviceReaderSessionEndRequest(session);
    waitForEndWaitFlag(&producer.completed, "stop did not wake ordinary capacity waiter");
    require(pthread_join(thread, NULL) == 0, "failed to join stopped ordinary producer");
    deviceReaderSessionEndWait(session);
    require(! producer.accepted && tracked_reuse_count == 1 && delivered.delivered == 0,
            "stopped ordinary post was accepted, delivered, or failed to recycle exactly once");
    tracked_reuse_pool = NULL;
    cleanupMessage(0);
    require(aggregate.steps == 0 && aggregate.cleanups == 1,
            "stopping ordinary capacity wait incorrectly ran or lost retained aggregate");
    requireOutputBudgetEmpty(session);
    bufferpoolResetThreadOwnership(reader_pool);
    deviceReaderSessionRetireProducerBuffers(session);
    deviceReaderSessionUnref(session);
    bufferpoolDestroy(reader_pool);
}

int main(void)
{
    test_env_t env;
    envSetup(&env);
    testQueuedCleanupOutlivesDeviceReference(&env);
    testClosedAndStaleDeliveriesAreDropped(&env);
    testSingleAndBatchedMessagesRoundTrip(&env);
    testFailedPostBalancesReference(&env);
    testTrackedSingletonSettlement(&env);
    testOversizedBatchIsRejectedAndRecycled(&env);
    testEndWaitsForEnteredDelivery(&env);
    testTrackedEnvelopeStaleAfterReopenIsRejected(&env);
    testReferenceOverflowFailsBeforeWrap(&env);
    testOutputBudgetStalledDeliveryAndCancellation(&env);
    testOutputBudgetLocalAndRejectedSettlement(&env);
    testOutputBudgetCancellationOutlivesDevice(&env);
    testPreparedOutputRunsOnlyOnLiveWorkerDelivery(&env);
    testWorkerQueueContinuationAndOrdinaryFifo(&env);
    testWorkerQueueBatchesCompletedAggregates(&env);
    testWorkerQueueStaleContinuationAndRefusal(&env);
    testWorkerQueueCancellationOutlivesDevice(&env);
    testWorkerQueueStopWakesOrdinaryCapacityWait(&env);
    envTeardown(&env);
    puts("device reader session tests passed");
    return 0;
}
