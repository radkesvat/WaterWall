#pragma once

/*
 * A writer queue whose publication and teardown are protected by a lifetime
 * gate. The device-specific writer thread remains the sole consumer.
 *
 * Teardown runs on the lifetime owner's thread, not on the writer thread, so
 * the drain cannot return leftover buffers to the writer's buffer pool: those
 * pools are thread-affine and the writer thread claims them the first time it
 * recycles a packet. The drain destroys them instead, which is thread-agnostic
 * and costs at most one queue's worth of allocator churn per device shutdown.
 */

#include "devices/device_lifetime.h"
#include "shiftbuffer.h"

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
    bool                   closed;
} device_writer_channel_t;

void deviceWriterChannelInit(device_writer_channel_t *writer_channel);
bool deviceWriterChannelOpen(device_writer_channel_t *writer_channel, size_t queue_capacity);
device_writer_send_result_t deviceWriterChannelTrySend(device_writer_channel_t *writer_channel, sbuf_t *buf);
void                        deviceWriterChannelCloseAndQuiesce(device_writer_channel_t *writer_channel);
/*
 * The channel must be closed; receiving from an open, empty channel would block.
 * The writer thread must already be joined: it is the only other consumer, and
 * draining alongside it would race on the queue. Leftover buffers are destroyed,
 * not pooled -- see the note at the top of this file.
 */
void deviceWriterChannelDrain(device_writer_channel_t *writer_channel);
void deviceWriterChannelFree(device_writer_channel_t *writer_channel);
