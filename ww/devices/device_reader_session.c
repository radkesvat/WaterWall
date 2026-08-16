#include "devices/device_reader_session.h"

#include "devices/device_frag_affinity.h"
#include "global_state.h"
#include "worker_messages.h"

typedef struct device_reader_message_s
{
    device_reader_session_t *session;
    uint32_t                 generation;
    uint16_t                 count;
    struct
    {
        sbuf_t                            *buf;
        device_frag_affinity_publication_t publication;
    } items[];
} device_reader_message_t;

static master_pool_item_t *deviceReaderMessageCreate(void *userdata)
{
    const device_reader_session_t *session = userdata;
    const size_t                   size    = sizeof(device_reader_message_t) +
                        (size_t) session->batch_capacity * sizeof(((device_reader_message_t *) NULL)->items[0]);
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
        deviceFragAffinitySettlePublication(
            session->frag_affinity, &message->items[i].publication, kDeviceFragSettlementUnknown);
        sbufDestroy(message->items[i].buf);
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
    if (UNLIKELY(session == NULL))
    {
        return NULL;
    }

    master_pool_t *message_pool = masterpoolCreateWithCapacity(pool_capacity);
    if (UNLIKELY(message_pool == NULL))
    {
        memoryFree(session);
        return NULL;
    }
    device_frag_affinity_table_t *frag_affinity = deviceFragAffinityCreate(reader_buffer_pool);
    if (UNLIKELY(frag_affinity == NULL))
    {
        masterpoolDestroy(message_pool);
        memoryFree(session);
        return NULL;
    }

    *session = (device_reader_session_t) {
        .refcount           = 1,
        .generation         = 0,
        .producer_admission = false,
        .message_pool       = message_pool,
        .batch_capacity     = batch_capacity,
        .device             = device,
        .deliver            = deliver,
        .reader_buffer_pool = reader_buffer_pool,
        .frag_affinity      = frag_affinity,
    };
    atomic_init(&session->producer_admission, false);
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
    /* Device teardown retires staged buffers before its pool dies. A session
     * used outside a device may still own a live pool at its final reference. */
    deviceFragAffinityDestroy(session->frag_affinity);
    session->frag_affinity = NULL;
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

    /* Poisoned identities survive a reopen until their post-settlement quarantine ends. */
    bufferpoolResetThreadOwnership(session->reader_buffer_pool);

    const uint32_t generation = previous + UINT32_C(1);
    atomicStoreRelaxed(&session->generation, (w_atomic_uint_value_t) generation);
    if (UNLIKELY(! deviceLifetimeGateOpen(&session->delivery_gate)))
    {
        // One lifecycle owner makes rollback safe; no entrant could pass a gate
        // whose Open CAS failed.
        atomicStoreRelaxed(&session->generation, (w_atomic_uint_value_t) previous);
        return 0;
    }
    deviceFragAffinityBeginGeneration(session->frag_affinity);
    atomicStoreExplicit(&session->producer_admission, true, memory_order_release);
    return generation;
}

/* Convenience form for callers that are allowed to wait for admitted delivery. */
void deviceReaderSessionEnd(device_reader_session_t *session)
{
    deviceReaderSessionEndRequest(session);
    deviceReaderSessionEndWait(session);
}

void deviceReaderSessionEndRequest(device_reader_session_t *session)
{
    atomicStoreExplicit(&session->producer_admission, false, memory_order_relaxed);
    deviceLifetimeGateClose(&session->delivery_gate);
}

void deviceReaderSessionEndWait(device_reader_session_t *session)
{
    deviceLifetimeGateWaitQuiesced(&session->delivery_gate, deviceLifetimeYieldThread, NULL);
    /* A late receipt holds the delivery gate across its final admission, lwIP
     * input, and exact residue query. Closing the fragment generation only after
     * those entrants leave makes "may enter" atomic with generation shutdown. */
    deviceFragAffinityEndGeneration(session->frag_affinity);
}

void deviceReaderSessionRetireGenerationBuffers(device_reader_session_t *session)
{
    assert(deviceLifetimeGateIsClosedAndQuiesced(&session->delivery_gate));

    if (session->reader_buffer_pool == NULL)
    {
        return;
    }

    deviceFragAffinityReleaseStagedBuffers(session->frag_affinity);
}

void deviceReaderSessionRetireProducerBuffers(device_reader_session_t *session)
{
    assert(deviceLifetimeGateIsClosedAndQuiesced(&session->delivery_gate));
    assert(session->reader_buffer_pool != NULL);

    deviceFragAffinityRetireReleasePool(session->frag_affinity);
    assert(deviceFragAffinityStagedCount(session->frag_affinity) == 0);
    assert(deviceFragAffinityStagedBytes(session->frag_affinity) == 0);
    session->reader_buffer_pool = NULL;
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
            const bool tracked = message->items[i].publication.valid;
            if (tracked &&
                ! deviceFragClaimAttach(session, generation, &message->items[i].publication, message->items[i].buf))
            {
                /* Without a persistent receipt, a delaying transform could let
                 * this packet enter lwIP after the fallback quarantine ended. */
                deviceFragAffinitySettlePublication(
                    session->frag_affinity, &message->items[i].publication, kDeviceFragSettlementUnknown);
                bufferpoolReuseBuffer(getWorkerBufferPool(wid), message->items[i].buf);
                continue;
            }

            session->deliver(session->device, message->items[i].buf, wid);
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
            deviceFragAffinitySettlePublication(
                session->frag_affinity, &message->items[i].publication, kDeviceFragSettlementUnknown);
            bufferpoolReuseBuffer(getWorkerBufferPool(wid), message->items[i].buf);
        }
    }

    masterpoolReuseItems(session->message_pool, (void **) &message, 1);
    deviceReaderSessionUnref(session);
}

void deviceReaderSessionCleanupPostedMessage(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard                  reason;
    device_reader_message_t *message = arg1;
    discard                  arg2;
    discard                  arg3;

    deviceReaderSessionCleanupMessage(message);
}

bool deviceReaderSessionPost(device_reader_session_t *session, wid_t target_wid, sbuf_t **bufs, unsigned int count)
{
    return deviceReaderSessionPostTracked(session, target_wid, bufs, NULL, count);
}

bool deviceReaderSessionPostTracked(device_reader_session_t *session, wid_t target_wid, sbuf_t **bufs,
                                    const device_frag_affinity_publication_t *publications, unsigned int count)
{
    assert(session->reader_buffer_pool != NULL);
    if (UNLIKELY(count == 0 || count > session->batch_capacity))
    {
        LOGE("DeviceReaderSession: refusing to post %u buffer(s); batch capacity is %u",
             count,
             (unsigned int) session->batch_capacity);
        for (unsigned int i = 0; i < count; ++i)
        {
            if (publications != NULL)
            {
                deviceFragAffinitySettlePublication(
                    session->frag_affinity, &publications[i], kDeviceFragSettlementUnknown);
            }
        }
        deviceReaderSessionReuseReaderBuffers(session, bufs, count);
        return false;
    }

    assert(count > 0);
    assert(count <= session->batch_capacity);

    // Acquires the generation and affinity state published when admission opened.
    if (UNLIKELY(! atomicLoadExplicit(&session->producer_admission, memory_order_acquire) ||
                 GSTATE.shortcut_loops == NULL))
    {
        for (unsigned int i = 0; i < count; ++i)
        {
            if (publications != NULL)
            {
                deviceFragAffinitySettlePublication(
                    session->frag_affinity, &publications[i], kDeviceFragSettlementUnknown);
            }
        }
        deviceReaderSessionReuseReaderBuffers(session, bufs, count);
        return false;
    }

    master_pool_item_t      *pool_item;
    device_reader_message_t *message;
    masterpoolGetItems(session->message_pool, &pool_item, 1, session);
    message = pool_item;

    message->session    = session;
    message->generation = deviceReaderSessionGeneration(session);
    message->count      = (uint16_t) count;
    for (unsigned int i = 0; i < count; i++)
    {
        message->items[i].buf = bufs[i];
        message->items[i].publication =
            publications != NULL ? publications[i] : (device_frag_affinity_publication_t) {0};
    }

    deviceReaderSessionRef(session);
    return sendWorkerMessageForceQueueWithCleanup(target_wid,
                                                  deviceReaderSessionMessageReceived,
                                                  deviceReaderSessionCleanupPostedMessage,
                                                  message,
                                                  NULL,
                                                  NULL) == kWorkerMessageSubmitAccepted;
}
