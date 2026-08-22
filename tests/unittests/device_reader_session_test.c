#include "wwapi.h"

#include "devices/device_reader_session.h"

#include "worker_messages.h"

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
    kCapturedMessageMax = 8
};

typedef struct captured_message_s
{
    WorkerMessageCallback        callback;
    WorkerMessageCleanupCallback cleanup;
    void                        *arg1;
    void                        *arg2;
    void                        *arg3;
} captured_message_t;

typedef struct reader_probe_s
{
    unsigned int delivered;
    unsigned int delivered_with_claim;
    atomic_bool  block_delivery;
    atomic_bool  delivery_entered;
    atomic_bool  release_delivery;
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

typedef struct stack_use_probe_s
{
    sbuf_t              *buf;
    atomic_bool          entered;
    atomic_bool          release;
    atomic_bool          completed;
    bool                 entered_stack;
    device_frag_claim_t *claim;
} stack_use_probe_t;

typedef struct test_env_s
{
    master_pool_t *large_master;
    master_pool_t *small_master;
    buffer_pool_t *worker_buffer_pool;
    buffer_pool_t *buffer_pools[1];
    wloop_t       *loops[1];
} test_env_t;

static captured_message_t                 captured_messages[kCapturedMessageMax];
static unsigned int                       captured_message_count;
static bool                               fail_post;
static device_reader_session_t           *tracked_session;
static master_pool_t                     *tracked_message_pool;
static unsigned int                       tracked_session_free_count;
static unsigned int                       tracked_pool_destroy_count;
static buffer_pool_t                     *tracked_reuse_pool;
static sbuf_t                            *tracked_reuse_buffer;
static unsigned int                       tracked_reuse_count;
static bool                               observe_settlement;
static device_frag_affinity_publication_t observed_publication;
static unsigned int                       observed_settlement_count;
static unsigned int                       observed_unknown_settlement_count;

worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *arg1, void *arg2, void *arg3);
void                           __real_memoryFree(void *ptr);
void                           __wrap_memoryFree(void *ptr);
void                           __real_masterpoolDestroy(master_pool_t *pool);
void                           __wrap_masterpoolDestroy(master_pool_t *pool);
void                           __real_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buf);
void                           __wrap_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buf);
void                           __real_deviceFragAffinitySettlePublication(device_frag_affinity_table_t             *table,
                                                                          const device_frag_affinity_publication_t *publication,
                                                                          device_frag_settlement_t                  settlement);
void                           __wrap_deviceFragAffinitySettlePublication(device_frag_affinity_table_t             *table,
                                                                          const device_frag_affinity_publication_t *publication,
                                                                          device_frag_settlement_t                  settlement);

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
    discard wid;
    if (fail_post)
    {
        cleanup(arg1, arg2, arg3, kWorkerMessageCancelEnqueueFailure);
        return false;
    }

    require(captured_message_count < kCapturedMessageMax, "captured-message queue overflow");
    captured_messages[captured_message_count++] = (captured_message_t) {
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
    if (ptr == tracked_session)
    {
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

static bool publicationsMatch(const device_frag_affinity_publication_t *left,
                              const device_frag_affinity_publication_t *right)
{
    return left != NULL && right != NULL && left->valid == right->valid && left->serial == right->serial &&
           left->slot == right->slot && left->count == right->count;
}

void __wrap_deviceFragAffinitySettlePublication(device_frag_affinity_table_t             *table,
                                                const device_frag_affinity_publication_t *publication,
                                                device_frag_settlement_t                  settlement)
{
    if (observe_settlement && publicationsMatch(publication, &observed_publication))
    {
        observed_settlement_count++;
        if (settlement == kDeviceFragSettlementUnknown)
        {
            observed_unknown_settlement_count++;
        }
    }
    __real_deviceFragAffinitySettlePublication(table, publication, settlement);
}

static void deliverPacket(void *device, sbuf_t *buf, wid_t wid)
{
    reader_probe_t *probe = device;
    probe->delivered++;
    if (sbufGetLifetime(buf) != NULL)
    {
        probe->delivered_with_claim++;
    }
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

static device_frag_affinity_publication_t makeTrackedFragment(device_reader_session_t *session, buffer_pool_t *pool,
                                                              uint16_t identification, sbuf_t **buf_out)
{
    enum
    {
        kPayloadBytes = 64,
        kPacketBytes  = 20 + kPayloadBytes,
    };

    sbuf_t *buf = bufferpoolGetSmallBuffer(pool);
    sbufSetLength(buf, kPacketBytes);

    uint8_t *packet = sbufGetMutablePtr(buf);
    memoryZero(packet, kPacketBytes);
    packet[0] = 0x45;
    packet[8] = 64;
    packet[9] = 17;
    PUT_BE16(packet + 2, kPacketBytes);
    PUT_BE16(packet + 4, identification);
    PUT_BE16(packet + 6, UINT16_C(0x2000));
    PUT_BE32(packet + 12, UINT32_C(0x0A000001));
    PUT_BE32(packet + 16, UINT32_C(0xC0000201));
    PUT_BE16(packet + 20, 5900);
    PUT_BE16(packet + 22, 53);
    writeIpv4Checksum(packet);

    device_frag_affinity_result_t result;
    require(deviceFragAffinityOffer(session->frag_affinity, packet, kPacketBytes, buf, &result) ==
                kDeviceFragAffinityDispatch,
            "tracked fragment did not create a real publication");
    require(result.publication.valid, "tracked fragment publication was invalid");
    *buf_out = buf;
    return result.publication;
}

static void envSetup(test_env_t *env)
{
    memoryZero(env, sizeof(*env));
    env->large_master       = masterpoolCreateWithCapacity(16);
    env->small_master       = masterpoolCreateWithCapacity(16);
    env->worker_buffer_pool = bufferpoolCreate(env->large_master, env->small_master, 16, 8192, 4096);
    env->buffer_pools[0]    = env->worker_buffer_pool;
    env->loops[0]           = (wloop_t *) (void *) env;

    GSTATE.shortcut_buffer_pools         = env->buffer_pools;
    GSTATE.shortcut_loops                = env->loops;
    GSTATE.masterpool_buffer_pools_large = env->large_master;
    GSTATE.masterpool_buffer_pools_small = env->small_master;
    GSTATE.workers_count                 = 2;
    testWorkerRegistryInstall(&g_test_worker_registry);
    testWorkerBindWID(0);
}

static void envTeardown(test_env_t *env)
{
    GSTATE.shortcut_buffer_pools         = NULL;
    GSTATE.shortcut_loops                = NULL;
    GSTATE.masterpool_buffer_pools_large = NULL;
    GSTATE.masterpool_buffer_pools_small = NULL;
    GSTATE.workers_count                 = 0;
    testWorkerRegistryRestore(&g_test_worker_registry);

    bufferpoolDestroy(env->worker_buffer_pool);
    masterpoolMakeEmpty(env->large_master);
    masterpoolMakeEmpty(env->small_master);
    masterpoolDestroy(env->large_master);
    masterpoolDestroy(env->small_master);
}

static device_reader_session_t *createSession(test_env_t *env, reader_probe_t *probe, uint16_t batch_capacity)
{
    return deviceReaderSessionCreate(4, batch_capacity, probe, deliverPacket, env->worker_buffer_pool);
}

static void resetCapturedMessages(void)
{
    memoryZero(captured_messages, sizeof(captured_messages));
    captured_message_count            = 0;
    fail_post                         = false;
    tracked_reuse_pool                = NULL;
    tracked_reuse_buffer              = NULL;
    tracked_reuse_count               = 0;
    observe_settlement                = false;
    observed_publication              = (device_frag_affinity_publication_t) {0};
    observed_settlement_count         = 0;
    observed_unknown_settlement_count = 0;
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

static void *holdStackUseRoutine(void *userdata)
{
    stack_use_probe_t *probe = userdata;
    probe->entered_stack     = deviceFragClaimBeginStackUse(probe->buf, &probe->claim);
    atomicStoreExplicit(&probe->entered, true, memory_order_release);
    if (! probe->entered_stack)
    {
        return NULL;
    }

    while (! atomicLoadExplicit(&probe->release, memory_order_acquire))
    {
        YIELD_THREAD();
    }
    deviceFragClaimEndStackUse(probe->claim);
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

    sbuf_t                                  *buf;
    const device_frag_affinity_publication_t publication =
        makeTrackedFragment(session, env->worker_buffer_pool, 30001, &buf);
    require(deviceReaderSessionPostTracked(session, 0, &buf, &publication, 1),
            "tracked singleton post was unexpectedly refused");
    require(captured_message_count == 1, "tracked singleton did not queue a message");
    deliverMessage(0);
    require(probe.delivered == 1 && probe.delivered_with_claim == 1,
            "tracked singleton was not delivered with an attached lifetime claim");
    require(! deviceFragAffinityPublicationMayEnter(session->frag_affinity, &publication),
            "tracked singleton delivery did not settle its publication exactly once");
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

    sbuf_t                                  *buf;
    const device_frag_affinity_publication_t publication =
        makeTrackedFragment(session, env->worker_buffer_pool, 30002, &buf);
    require(deviceReaderSessionPostTracked(session, 0, &buf, &publication, 1),
            "tracked stale-generation post was unexpectedly refused");
    require(captured_message_count == 1, "tracked stale-generation singleton was not queued");

    deviceReaderSessionEnd(session);
    require(deviceReaderSessionBegin(session) != 0, "failed to reopen tracked stale-generation session");
    deliverMessage(0);
    require(probe.delivered == 0, "stale tracked envelope reached the device after reopen");
    require(! deviceFragAffinityPublicationMayEnter(session->frag_affinity, &publication),
            "stale tracked envelope did not settle its publication");

    deviceReaderSessionEnd(session);
    deviceReaderSessionUnref(session);
}

static void testFragmentClaimGenerationAndPoisonAdmission(test_env_t *env)
{
    resetCapturedMessages();
    reader_probe_t           probe      = {0};
    device_reader_session_t *session    = createSession(env, &probe, 1);
    const uint32_t           generation = deviceReaderSessionBegin(session);
    require(generation != 0, "failed to begin claim-admission session");

    sbuf_t                                  *buf;
    const device_frag_affinity_publication_t publication =
        makeTrackedFragment(session, env->worker_buffer_pool, 30003, &buf);
    require(deviceFragClaimAttach(session, generation, &publication, buf), "failed to attach a real fragment claim");

    device_frag_claim_t *claim = NULL;
    require(deviceFragClaimBeginStackUse(buf, &claim), "current-generation claim failed final stack admission");
    require(claim != NULL, "tracked claim did not return its stack-use token");
    deviceFragClaimEndStackUse(claim);

    deviceReaderSessionEnd(session);
    require(deviceReaderSessionBegin(session) != 0, "failed to reopen claim-admission session");
    claim = NULL;
    require(! deviceFragClaimBeginStackUse(buf, &claim), "rolled-over claim passed final stack admission");
    require(claim == NULL, "rejected rolled-over claim returned a stack-use token");
    deviceFragClaimResolveBuffer(buf, kDeviceFragSettlementUnknown);
    bufferpoolReuseBuffer(env->worker_buffer_pool, buf);

    deviceReaderSessionEnd(session);
    deviceReaderSessionUnref(session);
}

static void testPoisonedPendingClaimIsRejected(test_env_t *env)
{
    resetCapturedMessages();
    reader_probe_t           probe      = {0};
    device_reader_session_t *session    = createSession(env, &probe, 1);
    const uint32_t           generation = deviceReaderSessionBegin(session);
    require(generation != 0, "failed to begin poisoned-claim session");

    sbuf_t                                  *buf;
    const device_frag_affinity_publication_t publication =
        makeTrackedFragment(session, env->worker_buffer_pool, 30004, &buf);
    require(deviceFragClaimAttach(session, generation, &publication, buf),
            "failed to attach a pending claim before poisoning");

    require(quiescenceGateIsActive(&session->delivery_gate) &&
                ! quiescenceGateIsClosedAndQuiesced(&session->delivery_gate),
            "poisoned-publication fixture did not keep delivery admission open");

    /* Same reassembly identity but a conflicting fragment-zero flow hash. The
     * public affinity API owns and recycles this consumed drop. */
    sbuf_t *conflicting = bufferpoolGetSmallBuffer(env->worker_buffer_pool);
    sbufSetLength(conflicting, sbufGetLength(buf));
    memoryCopy(sbufGetMutablePtr(conflicting), sbufGetRawPtr(buf), sbufGetLength(buf));
    PUT_BE16(sbufGetMutablePtr(conflicting) + 20, 5901);

    device_frag_affinity_result_t conflict_result;
    tracked_reuse_pool   = env->worker_buffer_pool;
    tracked_reuse_buffer = conflicting;
    tracked_reuse_count  = 0;
    require(deviceFragAffinityOffer(session->frag_affinity,
                                    sbufGetRawPtr(conflicting),
                                    sbufGetLength(conflicting),
                                    conflicting,
                                    &conflict_result) == kDeviceFragAffinityConsumedDrop,
            "conflicting fragment was not consumed as a drop");
    tracked_reuse_pool   = NULL;
    tracked_reuse_buffer = NULL;
    require(tracked_reuse_count == 1, "conflicting fragment was not recycled exactly once by affinity");
    require(! deviceFragAffinityPublicationMayEnter(session->frag_affinity, &publication),
            "conflicting fragment did not poison the original open-generation publication");

    device_frag_claim_t *claim = NULL;
    require(! deviceFragClaimBeginStackUse(buf, &claim),
            "open-generation poisoned claim reached final stack admission");
    require(claim == NULL, "poisoned claim returned a stack-use token");
    observe_settlement                = true;
    observed_publication              = publication;
    observed_settlement_count         = 0;
    observed_unknown_settlement_count = 0;
    deviceFragClaimResolveBuffer(buf, kDeviceFragSettlementUnknown);
    require(observed_settlement_count == 1 && observed_unknown_settlement_count == 1,
            "poisoned original publication did not settle exactly once as Unknown");
    require(atomicLoadExplicit(&session->refcount, memory_order_acquire) == 1,
            "poisoned claim did not return the reader session to its owner-only reference");
    tracked_reuse_pool   = env->worker_buffer_pool;
    tracked_reuse_buffer = buf;
    tracked_reuse_count  = 0;
    bufferpoolReuseBuffer(env->worker_buffer_pool, buf);
    require(tracked_reuse_count == 1, "poisoned original buffer was not recycled exactly once after settlement");
    tracked_reuse_pool   = NULL;
    tracked_reuse_buffer = NULL;
    observe_settlement   = false;

    deviceReaderSessionEnd(session);
    deviceReaderSessionUnref(session);
}

static void testEndWaitsForEnteredStackClaim(test_env_t *env)
{
    resetCapturedMessages();
    reader_probe_t           reader_probe = {0};
    device_reader_session_t *session      = createSession(env, &reader_probe, 1);
    const uint32_t           generation   = deviceReaderSessionBegin(session);
    require(generation != 0, "failed to begin stack-claim wait session");

    sbuf_t                                  *buf;
    const device_frag_affinity_publication_t publication =
        makeTrackedFragment(session, env->worker_buffer_pool, 30005, &buf);
    require(deviceFragClaimAttach(session, generation, &publication, buf), "failed to attach stack-claim wait fixture");

    stack_use_probe_t stack_probe = {
        .buf       = buf,
        .entered   = false,
        .release   = false,
        .completed = false,
    };
    pthread_t stack_thread;
    require(pthread_create(&stack_thread, NULL, holdStackUseRoutine, &stack_probe) == 0,
            "failed to create stack-claim helper thread");
    waitForEndWaitFlag(&stack_probe.entered, "stack-claim helper did not enter final admission");
    require(stack_probe.entered_stack, "stack-claim helper failed final stack admission");

    deviceReaderSessionEndRequest(session);
    require(! quiescenceGateIsActive(&session->delivery_gate), "stack-claim EndRequest left delivery admission open");
    require(! quiescenceGateIsClosedAndQuiesced(&session->delivery_gate),
            "stack-claim EndRequest quiesced while final admission was held");

    end_wait_probe_t end_probe = {.session = session};
    pthread_t        end_thread;
    deviceReaderSessionInstallEndWaitYieldHook(readerSessionEndWaitYieldHook, &end_probe);
    require(pthread_create(&end_thread, NULL, endWaitRoutine, &end_probe) == 0,
            "failed to create stack-claim End waiter");
    waitForEndWaitFlag(&end_probe.first_hook_entered, "stack-claim EndWait did not enter its first hook");
    require(! atomicLoadExplicit(&end_probe.completed, memory_order_acquire),
            "EndWait returned while a helper held final stack admission");
    require(! quiescenceGateIsClosedAndQuiesced(&session->delivery_gate),
            "stack-claim EndWait first observation saw a quiesced gate");

    atomicStoreExplicit(&end_probe.first_hook_release, true, memory_order_release);
    waitForSecondEndWaitHook(&end_probe, "stack-claim EndWait did not make a second observation");
    require(! atomicLoadExplicit(&end_probe.completed, memory_order_acquire),
            "stack-claim EndWait returned at its second active observation");
    require(! quiescenceGateIsClosedAndQuiesced(&session->delivery_gate),
            "stack-claim EndWait second observation saw a quiesced gate");

    atomicStoreExplicit(&stack_probe.release, true, memory_order_release);
    require(pthread_join(stack_thread, NULL) == 0, "failed to join stack-claim helper thread");
    require(atomicLoadExplicit(&stack_probe.completed, memory_order_acquire),
            "stack-claim helper did not leave final stack admission");
    require(quiescenceGateIsClosedAndQuiesced(&session->delivery_gate),
            "stack-claim helper did not quiesce before releasing EndWait's second hook");
    atomicStoreExplicit(&end_probe.second_hook_release, true, memory_order_release);
    require(pthread_join(end_thread, NULL) == 0, "failed to join stack-claim End waiter");
    deviceReaderSessionInstallEndWaitYieldHook(NULL, NULL);
    require(atomicLoadExplicit(&end_probe.completed, memory_order_acquire),
            "EndWait did not complete after final stack admission left");

    deviceFragClaimResolveBuffer(buf, kDeviceFragSettlementUnknown);
    bufferpoolReuseBuffer(env->worker_buffer_pool, buf);
    deviceReaderSessionUnref(session);
}

static void testTrackedRefusalAndQueuedCleanupSettleOnce(test_env_t *env)
{
    resetCapturedMessages();
    reader_probe_t           probe   = {0};
    device_reader_session_t *session = createSession(env, &probe, 1);
    require(deviceReaderSessionBegin(session) != 0, "failed to begin tracked-refusal session");

    sbuf_t                                  *refused_buf;
    const device_frag_affinity_publication_t refused_publication =
        makeTrackedFragment(session, env->worker_buffer_pool, 30006, &refused_buf);
    fail_post = true;
    require(! deviceReaderSessionPostTracked(session, 0, &refused_buf, &refused_publication, 1),
            "immediate tracked-message refusal reported success");
    fail_post = false;
    require(captured_message_count == 0, "immediate tracked-message refusal remained queued");
    require(! deviceFragAffinityPublicationMayEnter(session->frag_affinity, &refused_publication),
            "immediate tracked-message refusal did not settle its publication");

    sbuf_t                                  *queued_buf;
    const device_frag_affinity_publication_t queued_publication =
        makeTrackedFragment(session, env->worker_buffer_pool, 30007, &queued_buf);
    require(deviceReaderSessionPostTracked(session, 0, &queued_buf, &queued_publication, 1),
            "queued tracked-message cleanup fixture was unexpectedly refused");
    require(captured_message_count == 1, "queued tracked-message cleanup fixture was not submitted");
    cleanupMessage(0);
    require(probe.delivered == 0, "queued cleanup delivered a tracked packet");
    require(! deviceFragAffinityPublicationMayEnter(session->frag_affinity, &queued_publication),
            "queued tracked-message cleanup did not settle its publication");
    require(atomicLoadExplicit(&session->refcount, memory_order_acquire) == 1,
            "tracked refusal or queued cleanup leaked a reader-session reference");

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
    testFragmentClaimGenerationAndPoisonAdmission(&env);
    testPoisonedPendingClaimIsRejected(&env);
    testEndWaitsForEnteredStackClaim(&env);
    testTrackedRefusalAndQueuedCleanupSettleOnce(&env);
    testReferenceOverflowFailsBeforeWrap(&env);
    envTeardown(&env);
    puts("device reader session tests passed");
    return 0;
}
