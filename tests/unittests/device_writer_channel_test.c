#include "devices/device_writer_channel.h"

#include "global_state.h"
#include "wchan.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct test_env_s
{
    master_pool_t *large_master;
    master_pool_t *small_master;
    buffer_pool_t *buffer_pool;
} test_env_t;

typedef struct sender_probe_s
{
    device_writer_channel_t *writer_channel;
    sbuf_t                 **buffers;
    unsigned int             buffer_count;
    atomic_bool              start;
    atomic_bool              running;
    atomic_uint              next_buffer;
    atomic_uint              started;
    atomic_uint              attempts;
} sender_probe_t;

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
    env->large_master = masterpoolCreateWithCapacity(16);
    env->small_master = masterpoolCreateWithCapacity(16);
    env->buffer_pool  = bufferpoolCreate(env->large_master, env->small_master, 16, 8192, 4096);
}

static void envTeardown(test_env_t *env)
{
    bufferpoolDestroy(env->buffer_pool);
    masterpoolMakeEmpty(env->large_master);
    masterpoolMakeEmpty(env->small_master);
    masterpoolDestroy(env->large_master);
    masterpoolDestroy(env->small_master);
}

static void testAllSendResultsAndIdempotentClose(test_env_t *env)
{
    device_writer_channel_t writer_channel;
    deviceWriterChannelInit(&writer_channel);

    sbuf_t *down_buf = bufferpoolGetSmallBuffer(env->buffer_pool);
    require(deviceWriterChannelTrySend(&writer_channel, down_buf) == kDeviceWriterSendDown,
            "a closed gate did not report the writer as down");
    bufferpoolReuseBuffer(env->buffer_pool, down_buf);

    require(deviceWriterChannelOpen(&writer_channel, 1), "failed to open a writer channel");
    sbuf_t *sent_buf = bufferpoolGetSmallBuffer(env->buffer_pool);
    sbuf_t *full_buf = bufferpoolGetSmallBuffer(env->buffer_pool);
    require(deviceWriterChannelTrySend(&writer_channel, sent_buf) == kDeviceWriterSendOk,
            "an empty writer channel rejected a buffer");
    require(deviceWriterChannelTrySend(&writer_channel, full_buf) == kDeviceWriterSendFull,
            "a full writer channel did not report ring-full");
    bufferpoolReuseBuffer(env->buffer_pool, full_buf);

    chanClose(writer_channel.channel);
    writer_channel.closed = true;
    sbuf_t *closed_buf    = bufferpoolGetSmallBuffer(env->buffer_pool);
    require(deviceWriterChannelTrySend(&writer_channel, closed_buf) == kDeviceWriterSendClosed,
            "a closed channel did not report channel-closed");
    bufferpoolReuseBuffer(env->buffer_pool, closed_buf);

    deviceWriterChannelCloseAndQuiesce(&writer_channel);
    deviceWriterChannelCloseAndQuiesce(&writer_channel);
    deviceWriterChannelFree(&writer_channel);
    deviceWriterChannelFree(&writer_channel);
    require(writer_channel.channel == NULL, "free retained the writer channel pointer");
}

static void *senderRoutine(void *userdata)
{
    sender_probe_t *probe = userdata;
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
        if (deviceWriterChannelTrySend(probe->writer_channel, buf) == kDeviceWriterSendOk)
        {
            probe->buffers[index] = NULL;
        }
        atomicAddExplicit(&probe->attempts, 1, memory_order_release);
    }
    return NULL;
}

static void testConcurrentSendersQuiesceBeforeFree(test_env_t *env)
{
    enum
    {
        kSenderThreads = 4,
        kSenderBuffers = 2048
    };

    device_writer_channel_t writer_channel;
    deviceWriterChannelInit(&writer_channel);
    require(deviceWriterChannelOpen(&writer_channel, 64), "failed to open the concurrent writer channel");

    sbuf_t *buffers[kSenderBuffers];
    for (unsigned int i = 0; i < ARRAY_SIZE(buffers); i++)
    {
        buffers[i] = bufferpoolGetSmallBuffer(env->buffer_pool);
    }

    sender_probe_t probe = {
        .writer_channel = &writer_channel,
        .buffers        = buffers,
        .buffer_count   = ARRAY_SIZE(buffers),
        .start          = false,
        .running        = true,
    };
    pthread_t threads[kSenderThreads];
    for (unsigned int i = 0; i < ARRAY_SIZE(threads); i++)
    {
        require(pthread_create(&threads[i], NULL, senderRoutine, &probe) == 0,
                "failed to create a writer sender thread");
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

    deviceWriterChannelCloseAndQuiesce(&writer_channel);
    deviceWriterChannelFree(&writer_channel);
    atomicStoreExplicit(&probe.running, false, memory_order_release);

    for (unsigned int i = 0; i < ARRAY_SIZE(threads); i++)
    {
        require(pthread_join(threads[i], NULL) == 0, "failed to join a writer sender thread");
    }
    require(atomicLoadExplicit(&probe.attempts, memory_order_acquire) >= ARRAY_SIZE(threads),
            "concurrent senders did not exercise the writer gate");

    for (unsigned int i = 0; i < ARRAY_SIZE(buffers); i++)
    {
        if (buffers[i] != NULL)
        {
            bufferpoolReuseBuffer(env->buffer_pool, buffers[i]);
        }
    }
}

int main(void)
{
    test_env_t env;
    envSetup(&env);
    testAllSendResultsAndIdempotentClose(&env);
    testConcurrentSendersQuiesceBeforeFree(&env);
    envTeardown(&env);
    puts("device writer channel tests passed");
    return 0;
}
