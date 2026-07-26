#include "devices/device_writer_channel.h"

#include "wchan.h"

void deviceWriterChannelInit(device_writer_channel_t *writer_channel, buffer_pool_t *buffer_pool)
{
    *writer_channel = (device_writer_channel_t) {
        .channel     = NULL,
        .buffer_pool = buffer_pool,
        .closed      = false,
    };
    deviceLifetimeGateInit(&writer_channel->gate);
}

bool deviceWriterChannelOpen(device_writer_channel_t *writer_channel, size_t queue_capacity)
{
    if (writer_channel->channel != NULL || queue_capacity > UINT32_MAX)
    {
        return false;
    }

    writer_channel->channel = chanOpen(sizeof(void *), (uint32_t) queue_capacity);
    if (writer_channel->channel == NULL)
    {
        return false;
    }

    writer_channel->closed = false;
    deviceLifetimeGateOpen(&writer_channel->gate);
    return true;
}

device_writer_send_result_t deviceWriterChannelTrySend(device_writer_channel_t *writer_channel, sbuf_t *buf)
{
    if (UNLIKELY(! deviceLifetimeGateEnter(&writer_channel->gate)))
    {
        return kDeviceWriterSendDown;
    }

    struct wchan_s *channel = writer_channel->channel;
    if (UNLIKELY(channel == NULL))
    {
        deviceLifetimeGateLeave(&writer_channel->gate);
        return kDeviceWriterSendDown;
    }

    bool       closed = false;
    const bool sent   = chanTrySend(channel, &buf, &closed);
    deviceLifetimeGateLeave(&writer_channel->gate);

    if (sent)
    {
        return kDeviceWriterSendOk;
    }
    return closed ? kDeviceWriterSendClosed : kDeviceWriterSendFull;
}

void deviceWriterChannelCloseAndQuiesce(device_writer_channel_t *writer_channel)
{
    deviceLifetimeGateCloseAndQuiesce(&writer_channel->gate, deviceLifetimeYieldThread, NULL);

    if (writer_channel->channel == NULL || writer_channel->closed)
    {
        return;
    }

    chanClose(writer_channel->channel);
    writer_channel->closed = true;
}

void deviceWriterChannelDrain(device_writer_channel_t *writer_channel)
{
    if (writer_channel->channel == NULL)
    {
        return;
    }

    if (UNLIKELY(! writer_channel->closed))
    {
        LOGE("DeviceWriterChannel: refusing to drain an open channel");
        assert(writer_channel->closed);
        return;
    }

    sbuf_t *buf;
    while (chanRecv(writer_channel->channel, &buf))
    {
        bufferpoolReuseBuffer(writer_channel->buffer_pool, buf);
    }
}

void deviceWriterChannelFree(device_writer_channel_t *writer_channel)
{
    if (writer_channel->channel == NULL)
    {
        return;
    }

    deviceWriterChannelCloseAndQuiesce(writer_channel);
    deviceWriterChannelDrain(writer_channel);
    chanFree(writer_channel->channel);
    writer_channel->channel = NULL;
    writer_channel->closed  = false;
}
