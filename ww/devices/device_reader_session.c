#include "devices/device_reader_session.h"

#include "global_state.h"
#include "worker_messages.h"

typedef struct device_reader_message_s
{
    device_reader_session_t *session;
    uint32_t                 generation;
    uint16_t                 count;
    sbuf_t                  *bufs[];
} device_reader_message_t;

static master_pool_item_t *deviceReaderMessageCreate(void *userdata)
{
    const device_reader_session_t *session = userdata;
    const size_t size = sizeof(device_reader_message_t) + (size_t) session->batch_capacity * sizeof(sbuf_t *);
    return memoryAllocate(size);
}

static void deviceReaderMessageDestroy(master_pool_item_t *item)
{
    memoryFree(item);
}

static void deviceReaderSessionReuseReaderBuffers(device_reader_session_t *session, sbuf_t **bufs, unsigned int count)
{
    for (unsigned int i = 0; i < count; i++)
    {
        bufferpoolReuseBuffer(session->reader_buffer_pool, bufs[i]);
    }
}

static void deviceReaderSessionCleanupMessage(device_reader_message_t *message)
{
    if (message == NULL)
    {
        return;
    }

    device_reader_session_t *session = message->session;
    for (unsigned int i = 0; i < message->count; i++)
    {
        sbufDestroy(message->bufs[i]);
    }
    masterpoolReuseItems(session->message_pool, (void **) &message, 1);
    deviceReaderSessionUnref(session);
}

device_reader_session_t *deviceReaderSessionCreate(uint32_t pool_capacity, uint16_t batch_capacity, void *device,
                                                   DeviceReaderDeliverFn deliver, buffer_pool_t *reader_buffer_pool)
{
    assert(batch_capacity > 0);
    assert(device != NULL);
    assert(deliver != NULL);
    assert(reader_buffer_pool != NULL);

    device_reader_session_t *session = memoryAllocate(sizeof(*session));
    *session                         = (device_reader_session_t) {
                                .refcount           = 1,
                                .generation         = 0,
                                .message_pool       = masterpoolCreateWithCapacity(pool_capacity),
                                .batch_capacity     = batch_capacity,
                                .device             = device,
                                .deliver            = deliver,
                                .reader_buffer_pool = reader_buffer_pool,
    };
    deviceLifetimeGateInit(&session->delivery_gate);
    masterpoolInstallCallBacks(session->message_pool, deviceReaderMessageCreate, deviceReaderMessageDestroy);
    return session;
}

void deviceReaderSessionRef(device_reader_session_t *session)
{
    w_atomic_uint_value_t previous = atomicLoadRelaxed(&session->refcount);
    for (;;)
    {
        if (UNLIKELY(previous == 0 || previous >= W_ATOMIC_UINT_VALUE_MAX))
        {
            LOGF("DeviceReaderSession: reference count overflow or resurrection attempt");
            abortProgramNow(1);
        }

        if (atomic_compare_exchange_weak_explicit(
                &session->refcount, &previous, previous + 1, memory_order_relaxed, memory_order_relaxed))
        {
            return;
        }
    }
}

static void deviceReaderSessionDestroyInternal(device_reader_session_t *session)
{
    masterpoolMakeEmpty(session->message_pool);
    masterpoolDestroy(session->message_pool);
    memoryFree(session);
}

void deviceReaderSessionUnref(device_reader_session_t *session)
{
    // Release publishes all work performed through this reference.
    const w_atomic_uint_value_t previous = atomicSubExplicit(&session->refcount, 1, memory_order_release);
    assert(previous > 0);
    if (previous != 1)
    {
        return;
    }

    // Pairs with prior reference releases before final destruction.
    atomicThreadFence(memory_order_acquire);
    deviceReaderSessionDestroyInternal(session);
}

uint32_t deviceReaderSessionBegin(device_reader_session_t *session)
{
    if (UNLIKELY(! deviceLifetimeGateIsClosedAndQuiesced(&session->delivery_gate)))
    {
        LOGE("DeviceReaderSession: begin requires the previous generation to be closed and quiesced");
        return 0;
    }

    const uint32_t previous = (uint32_t) atomicLoadRelaxed(&session->generation);
    if (UNLIKELY(previous == UINT32_MAX))
    {
        LOGE("DeviceReaderSession: generation space exhausted; refusing to reopen delivery");
        return 0;
    }

    const uint32_t generation = previous + UINT32_C(1);
    atomicStoreRelaxed(&session->generation, (w_atomic_uint_value_t) generation);
    if (UNLIKELY(! deviceLifetimeGateOpen(&session->delivery_gate)))
    {
        // One lifecycle owner makes rollback safe; no entrant could pass a gate
        // whose Open CAS failed.
        atomicStoreRelaxed(&session->generation, (w_atomic_uint_value_t) previous);
        return 0;
    }
    return generation;
}

void deviceReaderSessionEnd(device_reader_session_t *session)
{
    deviceLifetimeGateCloseAndQuiesce(&session->delivery_gate, deviceLifetimeYieldThread, NULL);
}

uint32_t deviceReaderSessionGeneration(const device_reader_session_t *session)
{
    // The generation is only a tag; the delivery gate publishes session fields.
    return (uint32_t) atomicLoadRelaxed(&session->generation);
}

bool deviceReaderSessionMatchesGeneration(const device_reader_session_t *session, uint32_t generation)
{
    return generation == deviceReaderSessionGeneration(session);
}

void deviceReaderSessionMessageReceived(void *worker, void *arg1, void *arg2, void *arg3)
{
    device_reader_message_t *message    = arg1;
    device_reader_session_t *session    = message->session;
    const uint32_t           generation = message->generation;
    const wid_t              wid        = ((worker_t *) worker)->wid;
    discard                  arg2;
    discard                  arg3;

    const bool entered = deviceLifetimeGateEnter(&session->delivery_gate);
    if (entered && deviceReaderSessionMatchesGeneration(session, generation))
    {
        for (unsigned int i = 0; i < message->count; i++)
        {
            session->deliver(session->device, message->bufs[i], wid);
        }
        deviceLifetimeGateLeave(&session->delivery_gate);
    }
    else
    {
        if (entered)
        {
            deviceLifetimeGateLeave(&session->delivery_gate);
        }
        for (unsigned int i = 0; i < message->count; i++)
        {
            bufferpoolReuseBuffer(getWorkerBufferPool(wid), message->bufs[i]);
        }
    }

    masterpoolReuseItems(session->message_pool, (void **) &message, 1);
    deviceReaderSessionUnref(session);
}

void deviceReaderSessionCleanupPostedMessage(void *arg1, void *arg2, void *arg3)
{
    device_reader_message_t *message = arg1;
    discard                  arg2;
    discard                  arg3;

    deviceReaderSessionCleanupMessage(message);
}

void deviceReaderSessionPost(device_reader_session_t *session, wid_t target_wid, sbuf_t **bufs, unsigned int count)
{
    if (UNLIKELY(count == 0 || count > session->batch_capacity))
    {
        LOGE("DeviceReaderSession: refusing to post %u buffer(s); batch capacity is %u",
             count,
             (unsigned int) session->batch_capacity);
        deviceReaderSessionReuseReaderBuffers(session, bufs, count);
        return;
    }

    assert(count > 0);
    assert(count <= session->batch_capacity);

    if (UNLIKELY(isApplicationTerminating() || GSTATE.shortcut_loops == NULL))
    {
        deviceReaderSessionReuseReaderBuffers(session, bufs, count);
        return;
    }

    device_reader_message_t *message;
    masterpoolGetItems(session->message_pool, (const void **) &message, 1, session);

    message->session    = session;
    message->generation = deviceReaderSessionGeneration(session);
    message->count      = (uint16_t) count;
    for (unsigned int i = 0; i < count; i++)
    {
        message->bufs[i] = bufs[i];
    }

    deviceReaderSessionRef(session);
    discard sendWorkerMessageForceQueueWithCleanup(
        target_wid, deviceReaderSessionMessageReceived, deviceReaderSessionCleanupPostedMessage, message, NULL, NULL);
}
