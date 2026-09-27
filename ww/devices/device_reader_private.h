#pragma once
#include "devices/device_reader_session.h"

/* One lifecycle owner retains the initial session reference. Every admitted
 * message owns another, and each scheduled FIFO token owns one until drain or
 * cancellation (continuation transfers that token reference). Message cleanup
 * settles unconsumed buffers or the work context and its reservation exactly
 * once, even on refusal, stale generation or foreign cancellation after device
 * destruction. Budget notification, queue storage and the message pool survive
 * until the final reference. The delivery gate alone permits device access.
 * Reader scratch/fragment storage remains separately owned until reader join;
 * failed joins retain the device and its owner reference. */
typedef struct device_reader_message_s
{
    device_reader_session_t        *session;
    struct device_reader_message_s *next;
    DeviceReaderPrepareFn           prepare;
    DeviceReaderWorkFn              work;
    DeviceReaderWorkCleanupFn       work_cleanup;
    void                           *work_context;
    size_t                          work_charge;
    unsigned int                    work_packets;
    uint32_t                        generation;
    uint16_t                        count;
    uint16_t                        consumed;
    sbuf_t                         *bufs[];
} device_reader_message_t;

typedef struct device_reader_worker_queue_s
{
    wmutex_t                 lock;
    device_reader_session_t *session;
    device_reader_message_t *head;
    device_reader_message_t *tail;
    wid_t                    wid;
    bool                     scheduled;
} device_reader_worker_queue_t;

/* Raw readers need only pointers. A budgeted session allocates a parallel
 * charge array after those pointers; configuration is fixed before first Post. */
static inline size_t *deviceReaderMessageCharges(device_reader_message_t *message)
{
    assert(message->session->output_wake_fd >= 0);
    return (size_t *) (message->bufs + message->session->batch_capacity);
}

static inline uint32_t deviceReaderSessionGeneration(const device_reader_session_t *session)
{
    // The generation is only a tag; the delivery gate publishes session fields.
    return (uint32_t) atomicLoadRelaxed(&session->generation);
}

static inline bool deviceReaderSessionMatchesGeneration(const device_reader_session_t *session, uint32_t generation)
{
    return generation == deviceReaderSessionGeneration(session);
}
