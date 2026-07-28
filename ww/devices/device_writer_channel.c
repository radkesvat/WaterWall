#include "devices/device_writer_channel.h"

#include "loggers/internal_logger.h"
#include "wchan.h"

enum
{
    kDeviceWriterRetiredGenerationWarningThreshold = 8
};

#ifdef DEVICE_WRITER_CHANNEL_TEST_HOOKS
static DeviceWriterChannelAfterSelectHook device_writer_channel_after_select_hook;
static void                              *device_writer_channel_after_select_context;

void deviceWriterChannelInstallAfterSelectHook(DeviceWriterChannelAfterSelectHook hook, void *context)
{
    device_writer_channel_after_select_hook    = hook;
    device_writer_channel_after_select_context = context;
}
#endif

static void deviceWriterGenerationDrain(device_writer_generation_t *generation)
{
    sbuf_t *buf;
    while (chanRecv(generation->channel, &buf))
    {
        // The writer pool belongs to the joined writer thread; sbufDestroy() is
        // thread-agnostic and keeps drain ownership unambiguous.
        sbufDestroy(buf);
    }
}

void deviceWriterChannelInit(device_writer_channel_t *writer_channel)
{
    *writer_channel = (device_writer_channel_t) {
        .current                  = NULL,
        .retired                  = NULL,
        .retired_generation_count = 0,
        .current_closed           = false,
    };
    atomicStoreRelaxed(&writer_channel->published_generation, (uintptr_t) NULL);
}

bool deviceWriterChannelOpen(device_writer_channel_t *writer_channel, size_t queue_capacity)
{
    if (writer_channel->current != NULL || queue_capacity > UINT32_MAX)
    {
        return false;
    }

    device_writer_generation_t *generation = memoryAllocate(sizeof(*generation));
    generation->channel                    = chanOpen(sizeof(void *), (uint32_t) queue_capacity);
    if (generation->channel == NULL)
    {
        memoryFree(generation);
        return false;
    }

    generation->next               = NULL;
    generation->queue_capacity     = queue_capacity;
    writer_channel->current        = generation;
    writer_channel->current_closed = false;

    // Publishes the immutable generation and channel fields to producers.
    atomicStoreExplicit(&writer_channel->published_generation, (uintptr_t) generation, memory_order_release);
    return true;
}

device_writer_send_result_t deviceWriterChannelTrySend(device_writer_channel_t *writer_channel, sbuf_t *buf)
{
    // Selects one fully initialized immutable generation for this send attempt.
    const uintptr_t published = atomicLoadExplicit(&writer_channel->published_generation, memory_order_acquire);
    if (UNLIKELY(published == (uintptr_t) NULL))
    {
        return kDeviceWriterSendDown;
    }

    device_writer_generation_t *generation = (device_writer_generation_t *) published;
#ifdef DEVICE_WRITER_CHANNEL_TEST_HOOKS
    if (device_writer_channel_after_select_hook != NULL)
    {
        device_writer_channel_after_select_hook(writer_channel, generation, device_writer_channel_after_select_context);
    }
#endif
    bool       closed = false;
    const bool sent   = chanTrySend(generation->channel, &buf, &closed);

    if (sent)
    {
        return kDeviceWriterSendOk;
    }
    return closed ? kDeviceWriterSendClosed : kDeviceWriterSendFull;
}

void deviceWriterChannelClose(device_writer_channel_t *writer_channel)
{
    const uintptr_t published = (uintptr_t) atomicExchangeExplicit(
        &writer_channel->published_generation, (uintptr_t) NULL, memory_order_relaxed);
    if (published == (uintptr_t) NULL)
    {
        return;
    }

    device_writer_generation_t *generation = (device_writer_generation_t *) published;
    assert(generation == writer_channel->current);
    assert(! writer_channel->current_closed);

    chanClose(generation->channel);
    writer_channel->current_closed = true;
}

struct wchan_s *deviceWriterChannelGetConsumerChannel(const device_writer_channel_t *writer_channel)
{
    assert(writer_channel->current != NULL);
    return writer_channel->current->channel;
}

bool deviceWriterChannelHasCurrent(const device_writer_channel_t *writer_channel)
{
    return writer_channel->current != NULL;
}

bool deviceWriterChannelCurrentIsClosed(const device_writer_channel_t *writer_channel)
{
    return writer_channel->current != NULL && writer_channel->current_closed;
}

bool deviceWriterChannelRetireCurrent(device_writer_channel_t *writer_channel)
{
    device_writer_generation_t *generation = writer_channel->current;
    if (generation == NULL)
    {
        return true;
    }
    if (UNLIKELY(! writer_channel->current_closed))
    {
        LOGE("DeviceWriterChannel: refusing to drain and retire an open generation");
        return false;
    }

    deviceWriterGenerationDrain(generation);
    generation->next        = writer_channel->retired;
    writer_channel->retired = generation;
    writer_channel->retired_generation_count++;
    writer_channel->current        = NULL;
    writer_channel->current_closed = false;

    if (writer_channel->retired_generation_count >= kDeviceWriterRetiredGenerationWarningThreshold &&
        writer_channel->retired_generation_count % kDeviceWriterRetiredGenerationWarningThreshold == 0)
    {
        LOGW("DeviceWriterChannel: %zu closed queue generations are retained until device destruction "
             "(latest capacity=%zu pointers)",
             writer_channel->retired_generation_count,
             generation->queue_capacity);
    }
    return true;
}

bool deviceWriterChannelDestroy(device_writer_channel_t *writer_channel)
{
    if (UNLIKELY(atomicLoadRelaxed(&writer_channel->published_generation) != (uintptr_t) NULL))
    {
        LOGE("DeviceWriterChannel: refusing to destroy a published generation");
        return false;
    }

    if (writer_channel->current != NULL)
    {
        // Defensive cleanup is safe only under Destroy's joined-writer
        // precondition. Normal Stop already closed this generation.
        if (! writer_channel->current_closed)
        {
            chanClose(writer_channel->current->channel);
            writer_channel->current_closed = true;
        }
        if (! deviceWriterChannelRetireCurrent(writer_channel))
        {
            return false;
        }
    }

    device_writer_generation_t *generation = writer_channel->retired;
    while (generation != NULL)
    {
        device_writer_generation_t *next = generation->next;
        chanFree(generation->channel);
        memoryFree(generation);
        generation = next;
    }

    writer_channel->retired                  = NULL;
    writer_channel->retired_generation_count = 0;
    return true;
}
