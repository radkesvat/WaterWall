#include "devices/device_reader_budget.h"
#include "devices/device_reader_dispatch.h"
#include "devices/device_reader_private.h"
#include "global_state.h"
#include "loggers/internal_logger.h"

#ifdef DEVICE_READER_SESSION_TEST_HOOKS
static DeviceReaderSessionEndWaitYieldHook device_reader_session_end_wait_yield_hook;
static void                               *device_reader_session_end_wait_yield_context;

void deviceReaderSessionInstallEndWaitYieldHook(DeviceReaderSessionEndWaitYieldHook hook, void *context)
{
    device_reader_session_end_wait_yield_hook    = hook;
    device_reader_session_end_wait_yield_context = context;
}

static void deviceReaderSessionEndWaitYield(void *context)
{
    device_reader_session_t *session = context;
    if (device_reader_session_end_wait_yield_hook != NULL)
    {
        device_reader_session_end_wait_yield_hook(session, device_reader_session_end_wait_yield_context);
    }
    quiescenceGateYieldThread(NULL);
}
#endif

static master_pool_item_t *deviceReaderMessageCreate(void *userdata)
{
    const device_reader_session_t *session = userdata;
    const size_t                   slot    = sizeof(sbuf_t *) + (session->output_wake_fd >= 0 ? sizeof(size_t) : 0);
    const size_t                   size    = sizeof(device_reader_message_t) + (size_t) session->batch_capacity * slot;
    return memoryAllocate(size);
}

static void deviceReaderMessageDestroy(master_pool_item_t *item)
{
    memoryFree(item);
}

device_reader_session_t *deviceReaderSessionCreate(uint32_t pool_capacity, uint16_t batch_capacity, void *device,
                                                   DeviceReaderDeliverFn deliver, buffer_pool_t *reader_buffer_pool,
                                                   device_fragment_policy_t policy)
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
    device_frag_affinity_table_t *frag_affinity = deviceFragAffinityCreate(reader_buffer_pool, policy);
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
        .output_wake_fd     = -1,
        .frag_affinity      = frag_affinity,
    };
    atomic_init(&session->producer_admission, false);
    atomic_init(&session->output_charge, 0);
    atomic_init(&session->output_packets, 0);
    atomic_init(&session->output_waiting, false);
    quiescenceGateInit(&session->delivery_gate);
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
    deviceReaderDispatchDestroy(session);
    /* Device teardown retires staged buffers before its pool dies. A session
     * used outside a device may still own a live pool at its final reference. */
    deviceFragAffinityDestroy(session->frag_affinity);
    session->frag_affinity = NULL;
    masterpoolMakeEmpty(session->message_pool);
    masterpoolDestroy(session->message_pool);
    deviceReaderBudgetDestroy(session);
    memoryFree(session);
}

void deviceReaderSessionUnref(device_reader_session_t *session)
{
    // Release publishes all work performed through this reference.
    const w_atomic_uint_value_t previous = atomicSubExplicit(&session->refcount, 1, memory_order_release);
    assert(previous > 0);
    if (UNLIKELY(previous == 0))
    {
        LOGF("deviceReaderSessionUnref: reader session refcount underflow");
        abortProgramNow(1);
    }
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
    if (UNLIKELY(! quiescenceGateIsClosedAndQuiesced(&session->delivery_gate)))
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

    /* Poisoned identities survive a reopen until their local poison interval ends. */
    bufferpoolResetThreadOwnership(session->reader_buffer_pool);

    const uint32_t generation = previous + UINT32_C(1);
    atomicStoreRelaxed(&session->generation, (w_atomic_uint_value_t) generation);
    if (UNLIKELY(! quiescenceGateOpen(&session->delivery_gate)))
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
    atomicStoreExplicit(&session->producer_admission, false, memory_order_release);
    quiescenceGateClose(&session->delivery_gate);
    deviceReaderSessionSignalOutputCapacity(session);
}

void deviceReaderSessionEndWait(device_reader_session_t *session)
{
#ifdef DEVICE_READER_SESSION_TEST_HOOKS
    quiescenceGateWaitQuiesced(&session->delivery_gate, deviceReaderSessionEndWaitYield, session);
#else
    quiescenceGateWaitQuiesced(&session->delivery_gate, quiescenceGateYieldThread, NULL);
#endif
    /* Delivery admission protects the callback root, not downstream retention. */
    deviceFragAffinityEndGeneration(session->frag_affinity);
}

void deviceReaderSessionRetireGenerationBuffers(device_reader_session_t *session)
{
    assert(quiescenceGateIsClosedAndQuiesced(&session->delivery_gate));

    if (session->reader_buffer_pool == NULL)
    {
        return;
    }

    deviceFragAffinityReleaseStagedBuffers(session->frag_affinity);
}

void deviceReaderSessionRetireProducerBuffers(device_reader_session_t *session)
{
    assert(quiescenceGateIsClosedAndQuiesced(&session->delivery_gate));
    assert(session->reader_buffer_pool != NULL);

    deviceFragAffinityRetireReleasePool(session->frag_affinity);
    session->reader_buffer_pool = NULL;
}
