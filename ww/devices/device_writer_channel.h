#pragma once

/*
 * A writer queue whose publication and teardown are protected by a lifetime
 * gate. The device-specific writer thread remains the sole consumer.
 */

#include "buffer_pool.h"
#include "devices/device_lifetime.h"

typedef enum device_writer_send_result_e
{
    kDeviceWriterSendOk = 0,
    kDeviceWriterSendDown,
    kDeviceWriterSendClosed,
    kDeviceWriterSendFull
} device_writer_send_result_t;

typedef struct device_writer_channel_s
{
    struct wchan_s        *channel;
    device_lifetime_gate_t gate;
    buffer_pool_t         *buffer_pool;
    bool                   closed;
} device_writer_channel_t;

void deviceWriterChannelInit(device_writer_channel_t *writer_channel, buffer_pool_t *buffer_pool);
bool deviceWriterChannelOpen(device_writer_channel_t *writer_channel, size_t queue_capacity);
device_writer_send_result_t deviceWriterChannelTrySend(device_writer_channel_t *writer_channel, sbuf_t *buf);
void                        deviceWriterChannelCloseAndQuiesce(device_writer_channel_t *writer_channel);
/* The channel must be closed; receiving from an open, empty channel would block. */
void deviceWriterChannelDrain(device_writer_channel_t *writer_channel);
void deviceWriterChannelFree(device_writer_channel_t *writer_channel);
