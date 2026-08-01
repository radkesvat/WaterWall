#include "wwapi.h"

#include "devices/device_writer_channel.h"

#include <pthread.h>

typedef struct test_env_s
{
    master_pool_t *large_master;
    master_pool_t *small_master;
    buffer_pool_t *buffer_pool;
} test_env_t;

typedef struct selected_generation_probe_s
{
    device_writer_channel_t    *writer_channel;
    device_writer_generation_t *generation;
    sbuf_t                     *buffer;
    atomic_bool                 selected;
    atomic_bool                 resume;
    device_writer_send_result_t result;
} selected_generation_probe_t;

typedef struct before_selection_probe_s
{
    device_writer_channel_t    *writer_channel;
    sbuf_t                     *buffer;
    atomic_bool                 resume;
    device_writer_send_result_t result;
} before_selection_probe_t;

typedef struct sender_probe_s
{
    device_writer_channel_t *writer_channel;
    sbuf_t                 **buffers;
    unsigned int             buffer_count;
    atomic_bool              start;
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

static void closeSelectedGenerationHook(device_writer_channel_t *writer_channel, device_writer_generation_t *generation,
                                        void *context)
{
    discard generation;
    discard context;
    deviceWriterChannelClose(writer_channel);
}

static void testAllSendResultsAndIdempotentClose(test_env_t *env)
{
    device_writer_channel_t writer_channel;
    deviceWriterChannelInit(&writer_channel);

    sbuf_t *down_buf = bufferpoolGetSmallBuffer(env->buffer_pool);
    require(deviceWriterChannelTrySend(&writer_channel, down_buf) == kDeviceWriterSendDown,
            "an unpublished writer did not report down");
    bufferpoolReuseBuffer(env->buffer_pool, down_buf);

    require(deviceWriterChannelOpen(&writer_channel, 1), "failed to open a writer channel");
    sbuf_t *sent_buf = bufferpoolGetSmallBuffer(env->buffer_pool);
    sbuf_t *full_buf = bufferpoolGetSmallBuffer(env->buffer_pool);
    require(deviceWriterChannelTrySend(&writer_channel, sent_buf) == kDeviceWriterSendOk,
            "an empty writer channel rejected a buffer");
    require(deviceWriterChannelTrySend(&writer_channel, full_buf) == kDeviceWriterSendFull,
            "a full writer channel did not report ring-full");
    bufferpoolReuseBuffer(env->buffer_pool, full_buf);

    sbuf_t *received = NULL;
    require(chanRecv(deviceWriterChannelGetConsumerChannel(&writer_channel), &received),
            "failed to consume the successful-send buffer");
    bufferpoolReuseBuffer(env->buffer_pool, received);

    // Pause after generation selection by closing from the test hook. The real
    // TrySend then continues against that selected generation and must map the
    // channel result to Closed.
    deviceWriterChannelInstallAfterSelectHook(closeSelectedGenerationHook, NULL);
    sbuf_t *closed_buf = bufferpoolGetSmallBuffer(env->buffer_pool);
    require(deviceWriterChannelTrySend(&writer_channel, closed_buf) == kDeviceWriterSendClosed,
            "a selected closed channel did not report channel-closed");
    deviceWriterChannelInstallAfterSelectHook(NULL, NULL);
    bufferpoolReuseBuffer(env->buffer_pool, closed_buf);

    deviceWriterChannelClose(&writer_channel);
    deviceWriterChannelClose(&writer_channel);
    require(deviceWriterChannelRetireCurrent(&writer_channel), "failed to retire closed writer generation");
    require(deviceWriterChannelDestroy(&writer_channel), "failed to destroy retired writer generation");
    require(deviceWriterChannelDestroy(&writer_channel), "repeated writer destroy was not idempotent");
}

static void *selectedGenerationRoutine(void *userdata)
{
    selected_generation_probe_t *probe = userdata;
    probe->result                      = deviceWriterChannelTrySend(probe->writer_channel, probe->buffer);
    return NULL;
}

static void pauseSelectedGenerationHook(device_writer_channel_t *writer_channel, device_writer_generation_t *generation,
                                        void *context)
{
    selected_generation_probe_t *probe = context;
    require(writer_channel == probe->writer_channel, "selection hook received the wrong writer channel");
    probe->generation = generation;
    atomicStoreRelaxed(&probe->selected, true);

    while (! atomicLoadRelaxed(&probe->resume))
    {
        YIELD_THREAD();
    }
}

static void testSelectedOldGenerationNeverReachesReopen(test_env_t *env)
{
    device_writer_channel_t writer_channel;
    deviceWriterChannelInit(&writer_channel);
    require(deviceWriterChannelOpen(&writer_channel, 8), "failed to open old writer generation");

    selected_generation_probe_t probe = {
        .writer_channel = &writer_channel,
        .buffer         = bufferpoolGetSmallBuffer(env->buffer_pool),
        .selected       = false,
        .resume         = false,
    };
    deviceWriterChannelInstallAfterSelectHook(pauseSelectedGenerationHook, &probe);
    pthread_t sender;
    require(pthread_create(&sender, NULL, selectedGenerationRoutine, &probe) == 0,
            "failed to create selected-generation sender");
    while (! atomicLoadRelaxed(&probe.selected))
    {
        YIELD_THREAD();
    }

    deviceWriterChannelClose(&writer_channel);
    require(deviceWriterChannelRetireCurrent(&writer_channel), "failed to retire selected old generation");
    require(deviceWriterChannelOpen(&writer_channel, 8), "failed to publish replacement generation");

    atomicStoreRelaxed(&probe.resume, true);
    require(pthread_join(sender, NULL) == 0, "failed to join selected-generation sender");
    deviceWriterChannelInstallAfterSelectHook(NULL, NULL);
    require(probe.result == kDeviceWriterSendClosed, "old selected generation did not remain safely closed");

    bool    closed = false;
    sbuf_t *unexpected;
    require(! chanTryRecv(deviceWriterChannelGetConsumerChannel(&writer_channel), &unexpected, &closed),
            "an old-generation packet reached the replacement queue");
    bufferpoolReuseBuffer(env->buffer_pool, probe.buffer);

    deviceWriterChannelClose(&writer_channel);
    require(deviceWriterChannelRetireCurrent(&writer_channel), "failed to retire replacement generation");
    require(writer_channel.retired_generation_count == 2, "restart did not retain both closed generations");
    require(deviceWriterChannelDestroy(&writer_channel), "failed to destroy retained generations");
}

static void *beforeSelectionRoutine(void *userdata)
{
    before_selection_probe_t *probe = userdata;
    while (! atomicLoadRelaxed(&probe->resume))
    {
        YIELD_THREAD();
    }
    probe->result = deviceWriterChannelTrySend(probe->writer_channel, probe->buffer);
    return NULL;
}

static void testCallPausedBeforeSelectionMayUseReopen(test_env_t *env)
{
    device_writer_channel_t writer_channel;
    deviceWriterChannelInit(&writer_channel);
    require(deviceWriterChannelOpen(&writer_channel, 8), "failed to open initial selection generation");

    before_selection_probe_t probe = {
        .writer_channel = &writer_channel,
        .buffer         = bufferpoolGetSmallBuffer(env->buffer_pool),
        .resume         = false,
        .result         = kDeviceWriterSendDown,
    };
    pthread_t sender;
    require(pthread_create(&sender, NULL, beforeSelectionRoutine, &probe) == 0,
            "failed to create pre-selection sender");

    deviceWriterChannelClose(&writer_channel);
    require(deviceWriterChannelRetireCurrent(&writer_channel), "failed to retire pre-selection generation");
    require(deviceWriterChannelOpen(&writer_channel, 8), "failed to reopen before producer selection");
    atomicStoreRelaxed(&probe.resume, true);
    require(pthread_join(sender, NULL) == 0, "failed to join pre-selection sender");
    require(probe.result == kDeviceWriterSendOk, "call paused before selection did not select the reopened generation");

    sbuf_t *received = NULL;
    require(chanRecv(deviceWriterChannelGetConsumerChannel(&writer_channel), &received),
            "reopened generation did not receive selected packet");
    require(received == probe.buffer, "reopened generation received the wrong packet");
    bufferpoolReuseBuffer(env->buffer_pool, received);

    deviceWriterChannelClose(&writer_channel);
    require(deviceWriterChannelRetireCurrent(&writer_channel), "failed to retire reopened generation");
    require(deviceWriterChannelDestroy(&writer_channel), "failed to destroy selection generations");
}

static void *senderRoutine(void *userdata)
{
    sender_probe_t *probe = userdata;
    atomicIncRelaxed(&probe->started);

    while (! atomicLoadRelaxed(&probe->start))
    {
        YIELD_THREAD();
    }

    for (;;)
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
        atomicIncRelaxed(&probe->attempts);
    }
    return NULL;
}

static void testConcurrentSendersRemainSafeThroughRetire(test_env_t *env)
{
    enum
    {
        kSenderThreads = 4,
        kSenderBuffers = 2048
    };

    device_writer_channel_t writer_channel;
    deviceWriterChannelInit(&writer_channel);
    require(deviceWriterChannelOpen(&writer_channel, 64), "failed to open concurrent writer channel");

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
    };
    pthread_t threads[kSenderThreads];
    for (unsigned int i = 0; i < ARRAY_SIZE(threads); i++)
    {
        require(pthread_create(&threads[i], NULL, senderRoutine, &probe) == 0,
                "failed to create a writer sender thread");
    }

    while (atomicLoadRelaxed(&probe.started) < ARRAY_SIZE(threads))
    {
        YIELD_THREAD();
    }
    atomicStoreRelaxed(&probe.start, true);
    while (atomicLoadRelaxed(&probe.attempts) < ARRAY_SIZE(threads))
    {
        YIELD_THREAD();
    }

    deviceWriterChannelClose(&writer_channel);
    require(deviceWriterChannelRetireCurrent(&writer_channel), "failed to retire while producers were active");

    for (unsigned int i = 0; i < ARRAY_SIZE(threads); i++)
    {
        require(pthread_join(threads[i], NULL) == 0, "failed to join a writer sender thread");
    }
    require(atomicLoadRelaxed(&probe.attempts) == ARRAY_SIZE(buffers),
            "concurrent senders did not attempt every buffer");

    for (unsigned int i = 0; i < ARRAY_SIZE(buffers); i++)
    {
        if (buffers[i] != NULL)
        {
            bufferpoolReuseBuffer(env->buffer_pool, buffers[i]);
        }
    }
    require(deviceWriterChannelDestroy(&writer_channel), "failed to destroy after producer quiescence");
}

static void testRepeatedGenerationsAndDestroyPrecondition(void)
{
    device_writer_channel_t writer_channel;
    deviceWriterChannelInit(&writer_channel);

    for (unsigned int i = 0; i < 12; i++)
    {
        require(deviceWriterChannelOpen(&writer_channel, 4), "repeated writer open failed");
        require(! deviceWriterChannelDestroy(&writer_channel), "destroy reclaimed a published generation");
        deviceWriterChannelClose(&writer_channel);
        require(deviceWriterChannelRetireCurrent(&writer_channel), "repeated generation retire failed");
    }
    require(writer_channel.retired_generation_count == 12, "retired-generation count was incorrect");
    require(deviceWriterChannelDestroy(&writer_channel), "failed to destroy repeated retired generations");
}

int main(void)
{
    test_env_t env;
    envSetup(&env);
    testAllSendResultsAndIdempotentClose(&env);
    testSelectedOldGenerationNeverReachesReopen(&env);
    testCallPausedBeforeSelectionMayUseReopen(&env);
    testConcurrentSendersRemainSafeThroughRetire(&env);
    testRepeatedGenerationsAndDestroyPrecondition();
    envTeardown(&env);
    puts("device writer channel tests passed");
    return 0;
}
