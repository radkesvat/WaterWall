#include "devices/raw/raw.h"

#include "global_state.h"
#include "wchan.h"

#include <errno.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct test_env_s
{
    master_pool_t *large_master;
    master_pool_t *small_master;
    buffer_pool_t *worker_buffer_pool;
    buffer_pool_t *buffer_pools[1];
} test_env_t;

typedef struct writer_probe_s
{
    raw_device_t *rdev;
    sbuf_t      **buffers;
    unsigned int  buffer_count;
    atomic_bool   start;
    atomic_bool   running;
    atomic_uint   next_buffer;
    atomic_uint   started;
    atomic_uint   attempts;
} writer_probe_t;

typedef struct consumer_probe_s
{
    sbuf_t     **buffers;
    unsigned int buffer_capacity;
    atomic_uint  buffer_count;
} consumer_probe_t;

static bool fail_next_thread_join;

int __real_pthread_join(pthread_t thread, void **retval);
int __wrap_pthread_join(pthread_t thread, void **retval);
int __wrap_pthread_join(pthread_t thread, void **retval)
{
    if (fail_next_thread_join)
    {
        fail_next_thread_join = false;
        return EBUSY;
    }
    return __real_pthread_join(thread, retval);
}

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void envSetup(test_env_t *env)
{
    env->large_master       = masterpoolCreateWithCapacity(16);
    env->small_master       = masterpoolCreateWithCapacity(16);
    env->worker_buffer_pool = bufferpoolCreate(env->large_master, env->small_master, 16, 8192, 4096);
    env->buffer_pools[0]    = env->worker_buffer_pool;

    GSTATE.shortcut_buffer_pools = env->buffer_pools;
    GSTATE.ram_profile           = 1;
    tl_wid                       = 0;
}

static void envTeardown(test_env_t *env)
{
    GSTATE.shortcut_buffer_pools = NULL;
    bufferpoolDestroy(env->worker_buffer_pool);
    masterpoolMakeEmpty(env->large_master);
    masterpoolMakeEmpty(env->small_master);
    masterpoolDestroy(env->large_master);
    masterpoolDestroy(env->small_master);
}

static WTHREAD_ROUTINE(testWriterRoutine)
{
    raw_device_t     *rdev  = userdata;
    consumer_probe_t *probe = rdev->userdata;
    sbuf_t           *buf;
    struct wchan_s   *writer_channel = deviceWriterChannelGetConsumerChannel(&rdev->writer_channel);

    while (atomicLoadRelaxed(&rdev->running))
    {
        if (! chanRecv(writer_channel, &buf))
        {
            break;
        }
        const unsigned int index = atomicAddExplicit(&probe->buffer_count, 1, memory_order_relaxed);
        require(index < probe->buffer_capacity, "raw writer consumed more buffers than the test allocated");
        probe->buffers[index] = buf;
    }
    return 0;
}

static void *senderRoutine(void *userdata)
{
    writer_probe_t *probe = userdata;
    atomicAddExplicit(&probe->started, 1, memory_order_release);

    while (! atomicLoadExplicit(&probe->start, memory_order_acquire))
    {
        YIELD_THREAD();
    }

    while (atomicLoadExplicit(&probe->running, memory_order_acquire))
    {
        const unsigned int index = atomicAddExplicit(&probe->next_buffer, 1, memory_order_relaxed);
        if (index >= probe->buffer_count)
        {
            break;
        }

        sbuf_t *buf = probe->buffers[index];
        if (rawdeviceWrite(probe->rdev, buf))
        {
            probe->buffers[index] = NULL;
        }
        atomicAddExplicit(&probe->attempts, 1, memory_order_release);
    }
    return NULL;
}

static void testRawBringDownQuiescesConcurrentWriters(test_env_t *env)
{
    enum
    {
        kWriterThreads = 4,
        kWriterBuffers = 2048
    };

    raw_device_t rdev;
    memoryZero(&rdev, sizeof(rdev));
    sbuf_t          *consumed_buffers[kWriterBuffers];
    consumer_probe_t consumer = {
        .buffers         = consumed_buffers,
        .buffer_capacity = ARRAY_SIZE(consumed_buffers),
    };
    rdev.name               = stringDuplicate("raw-writer-test");
    rdev.writer_buffer_pool = bufferpoolCreate(env->large_master, env->small_master, 16, 8192, 4096);
    rdev.routine_writer     = testWriterRoutine;
    rdev.userdata           = &consumer;
    deviceWriterChannelInit(&rdev.writer_channel);

    require(rawdeviceBringUp(&rdev), "production rawdeviceBringUp failed");

    sbuf_t *buffers[kWriterBuffers];
    for (unsigned int i = 0; i < ARRAY_SIZE(buffers); i++)
    {
        buffers[i] = bufferpoolGetSmallBuffer(rdev.writer_buffer_pool);
        sbufSetLength(buffers[i], sizeof(struct iphdr) + 1);
    }

    writer_probe_t probe = {
        .rdev         = &rdev,
        .buffers      = buffers,
        .buffer_count = ARRAY_SIZE(buffers),
        .start        = false,
        .running      = true,
    };
    pthread_t threads[kWriterThreads];
    for (unsigned int i = 0; i < ARRAY_SIZE(threads); i++)
    {
        require(pthread_create(&threads[i], NULL, senderRoutine, &probe) == 0, "failed to create a raw writer thread");
    }

    while (atomicLoadExplicit(&probe.started, memory_order_acquire) < ARRAY_SIZE(threads))
    {
        YIELD_THREAD();
    }
    atomicStoreExplicit(&probe.start, true, memory_order_release);
    while (atomicLoadExplicit(&probe.attempts, memory_order_acquire) < ARRAY_SIZE(threads))
    {
        YIELD_THREAD();
    }

    require(rawdeviceBringDown(&rdev), "production rawdeviceBringDown failed");
    atomicStoreExplicit(&probe.running, false, memory_order_release);
    for (unsigned int i = 0; i < ARRAY_SIZE(threads); i++)
    {
        require(pthread_join(threads[i], NULL) == 0, "failed to join a raw writer thread");
    }

    sbuf_t *after_down = bufferpoolGetSmallBuffer(rdev.writer_buffer_pool);
    sbufSetLength(after_down, sizeof(struct iphdr) + 1);
    require(! rawdeviceWrite(&rdev, after_down), "rawdeviceWrite accepted a buffer after bring-down");
    bufferpoolReuseBuffer(rdev.writer_buffer_pool, after_down);

    for (unsigned int i = 0; i < ARRAY_SIZE(buffers); i++)
    {
        if (buffers[i] != NULL)
        {
            bufferpoolReuseBuffer(rdev.writer_buffer_pool, buffers[i]);
        }
    }
    const unsigned int consumed_count = atomicLoadExplicit(&consumer.buffer_count, memory_order_acquire);
    for (unsigned int i = 0; i < consumed_count; i++)
    {
        bufferpoolReuseBuffer(rdev.writer_buffer_pool, consumed_buffers[i]);
    }

    require(deviceWriterChannelDestroy(&rdev.writer_channel), "failed to destroy retired raw writer generations");
    memoryFree(rdev.name);
    bufferpoolDestroy(rdev.writer_buffer_pool);
}

static void testRawJoinFailureRetainsOwnership(test_env_t *env)
{
    raw_device_t rdev;
    memoryZero(&rdev, sizeof(rdev));
    sbuf_t          *consumed_buffers[1];
    consumer_probe_t consumer = {
        .buffers         = consumed_buffers,
        .buffer_capacity = ARRAY_SIZE(consumed_buffers),
    };
    rdev.name               = stringDuplicate("raw-join-retry-test");
    rdev.writer_buffer_pool = bufferpoolCreate(env->large_master, env->small_master, 16, 8192, 4096);
    rdev.routine_writer     = testWriterRoutine;
    rdev.userdata           = &consumer;
    deviceWriterChannelInit(&rdev.writer_channel);

    require(rawdeviceBringUp(&rdev), "raw join-retry bring-up failed");
    fail_next_thread_join = true;
    require(! rawdeviceBringDown(&rdev), "injected raw writer join failure reported success");
    require(rdev.writer_joinable, "raw writer join failure discarded thread ownership");
    require(deviceWriterChannelHasCurrent(&rdev.writer_channel),
            "raw writer join failure retired a generation still owned by the thread");
    require(! rawdeviceBringUp(&rdev), "raw writer restarted while failed-join ownership remained");

    require(rawdeviceBringDown(&rdev), "raw writer join retry failed");
    require(! rdev.writer_joinable, "raw writer join retry retained thread ownership");
    require(! deviceWriterChannelHasCurrent(&rdev.writer_channel),
            "raw writer join retry did not retire its closed generation");

    require(deviceWriterChannelDestroy(&rdev.writer_channel), "failed to destroy raw join-retry generations");
    memoryFree(rdev.name);
    bufferpoolDestroy(rdev.writer_buffer_pool);
}

int main(void)
{
    test_env_t env;
    envSetup(&env);
    testRawBringDownQuiescesConcurrentWriters(&env);
    testRawJoinFailureRetainsOwnership(&env);
    envTeardown(&env);
    puts("Linux raw writer lifetime tests passed");
    return 0;
}
