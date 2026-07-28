#pragma once

/*
 * Single-consumer device writer queue with immutable producer generations.
 *
 * Producers select a generation with one acquire load and may use that record
 * until their send attempt returns. Stop therefore closes and retires a
 * generation but never frees it. Final Destroy may reclaim retired generations
 * only after every external producer context (workers, the lwIP pseudo-worker,
 * and device callbacks) is stopped or detached.
 *
 * The lifecycle owner closes the queue, joins the writer thread, then drains and
 * retires it. Drain destroys leftover buffers rather than returning them to the
 * writer thread's thread-affine pool.
 */

#include "shiftbuffer.h"
#include "watomic.h"

typedef enum device_writer_send_result_e
{
    kDeviceWriterSendOk = 0,
    kDeviceWriterSendDown,
    kDeviceWriterSendClosed,
    kDeviceWriterSendFull
} device_writer_send_result_t;

typedef struct device_writer_generation_s
{
    struct wchan_s                    *channel;
    struct device_writer_generation_s *next;
    size_t                             queue_capacity;
} device_writer_generation_t;

typedef struct device_writer_channel_s
{
    atomic_uintptr_t            published_generation;
    device_writer_generation_t *current;
    device_writer_generation_t *retired;
    size_t                      retired_generation_count;
    bool                        current_closed;
} device_writer_channel_t;

void                        deviceWriterChannelInit(device_writer_channel_t *writer_channel);
bool                        deviceWriterChannelOpen(device_writer_channel_t *writer_channel, size_t queue_capacity);
device_writer_send_result_t deviceWriterChannelTrySend(device_writer_channel_t *writer_channel, sbuf_t *buf);

/*
 * Unpublishes and closes the current generation. This is idempotent and does
 * not wait for producers; a producer that already selected this generation
 * safely observes either its pre-close send or the channel's Closed result.
 */
void deviceWriterChannelClose(device_writer_channel_t *writer_channel);

/*
 * Owner-only access for the writer thread. Thread creation publishes the
 * current generation installed before the thread was started.
 */
struct wchan_s *deviceWriterChannelGetConsumerChannel(const device_writer_channel_t *writer_channel);

bool deviceWriterChannelHasCurrent(const device_writer_channel_t *writer_channel);
bool deviceWriterChannelCurrentIsClosed(const device_writer_channel_t *writer_channel);

/*
 * Requires a closed current generation and a confirmed writer-thread join.
 * Drains remaining buffers and retains the generation for final destruction.
 */
bool deviceWriterChannelRetireCurrent(device_writer_channel_t *writer_channel);

/*
 * Requires external producer quiescence and a joined writer thread. Frees every
 * retained generation. Returns false instead of reclaiming a still-published
 * generation.
 */
bool deviceWriterChannelDestroy(device_writer_channel_t *writer_channel);

#ifdef DEVICE_WRITER_CHANNEL_TEST_HOOKS
typedef void (*DeviceWriterChannelAfterSelectHook)(device_writer_channel_t    *writer_channel,
                                                   device_writer_generation_t *generation, void *context);
void deviceWriterChannelInstallAfterSelectHook(DeviceWriterChannelAfterSelectHook hook, void *context);
#endif
