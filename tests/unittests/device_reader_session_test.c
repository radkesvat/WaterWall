#include "devices/device_reader_session.h"

#include "global_state.h"
#include "worker_messages.h"

#include <stdio.h>
#include <stdlib.h>

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
} reader_probe_t;

typedef struct test_env_s
{
    master_pool_t *large_master;
    master_pool_t *small_master;
    buffer_pool_t *worker_buffer_pool;
    buffer_pool_t *buffer_pools[1];
    wloop_t       *loops[1];
} test_env_t;

static captured_message_t       captured_messages[kCapturedMessageMax];
static unsigned int             captured_message_count;
static bool                     fail_post;
static device_reader_session_t *tracked_session;
static master_pool_t           *tracked_message_pool;
static unsigned int             tracked_session_free_count;
static unsigned int             tracked_pool_destroy_count;
static buffer_pool_t           *tracked_reuse_pool;
static unsigned int             tracked_reuse_count;

bool __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                   WorkerMessageCleanupCallback cleanup, void *arg1, void *arg2,
                                                   void *arg3);
void __real_memoryFree(void *ptr);
void __wrap_memoryFree(void *ptr);
void __real_masterpoolDestroy(master_pool_t *pool);
void __wrap_masterpoolDestroy(master_pool_t *pool);
void __real_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buf);
void __wrap_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buf);

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

bool __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                   WorkerMessageCleanupCallback cleanup, void *arg1, void *arg2,
                                                   void *arg3)
{
    discard wid;
    if (fail_post)
    {
        cleanup(arg1, arg2, arg3);
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
    if (pool == tracked_reuse_pool)
    {
        tracked_reuse_count++;
    }
    __real_bufferpoolReuseBuffer(pool, buf);
}

static void deliverPacket(void *device, sbuf_t *buf, wid_t wid)
{
    reader_probe_t *probe = device;
    probe->delivered++;
    bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
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
    atomicStoreExplicit(&GSTATE.application_stopping_flag, false, memory_order_release);
    tl_wid = 0;
}

static void envTeardown(test_env_t *env)
{
    GSTATE.shortcut_buffer_pools         = NULL;
    GSTATE.shortcut_loops                = NULL;
    GSTATE.masterpool_buffer_pools_large = NULL;
    GSTATE.masterpool_buffer_pools_small = NULL;
    GSTATE.workers_count                 = 0;

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
    captured_message_count = 0;
    fail_post              = false;
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
    message->cleanup(message->arg1, message->arg2, message->arg3);
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
    require(captured_message_count == 1, "posting did not queue a reader message");
    require(atomicLoadExplicit(&session->refcount, memory_order_acquire) == 2,
            "posting did not retain the reader session");

    deviceReaderSessionEnd(session);
    deviceReaderSessionUnref(session, NULL, NULL);
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

    deviceReaderSessionEnd(session);
    deliverMessage(0);
    require(probe.delivered == 0, "a closed-session message reached the device");

    deviceReaderSessionBegin(session);
    deliverMessage(1);
    require(probe.delivered == 0, "a stale-generation message reached the device");

    deviceReaderSessionEnd(session);
    deviceReaderSessionUnref(session, NULL, NULL);
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
        deviceReaderSessionUnref(session, NULL, NULL);
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
    deviceReaderSessionUnref(session, NULL, NULL);
    fail_post = false;
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
    deviceReaderSessionUnref(session, NULL, NULL);
}

int main(void)
{
    test_env_t env;
    envSetup(&env);
    testQueuedCleanupOutlivesDeviceReference(&env);
    testClosedAndStaleDeliveriesAreDropped(&env);
    testSingleAndBatchedMessagesRoundTrip(&env);
    testFailedPostBalancesReference(&env);
    testOversizedBatchIsRejectedAndRecycled(&env);
    envTeardown(&env);
    puts("device reader session tests passed");
    return 0;
}
