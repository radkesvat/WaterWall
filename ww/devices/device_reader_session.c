#include "devices/device_reader_session.h"

#include "devices/device_frag_affinity.h"
#include "global_state.h"
#include "loggers/internal_logger.h"
#include "worker_messages.h"

#ifdef OS_LINUX
#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>
#endif

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

enum
{
    kDeviceReaderWorkerPacketQuantum = 64,
    kDeviceReaderWorkerByteQuantum   = 64 * 1024,
    kDeviceReaderCapacityPollMs      = 100,
};

/* Raw readers need only pointers. A budgeted session allocates a parallel
 * charge array after those pointers; configuration is fixed before first Post. */
static size_t *deviceReaderMessageCharges(device_reader_message_t *message)
{
    assert(message->session->output_wake_fd >= 0);
    return (size_t *) (message->bufs + message->session->batch_capacity);
}

static void deviceReaderSessionSignalOutputCapacity(device_reader_session_t *session)
{
#ifdef OS_LINUX
    if (session->output_wake_fd >= 0 && atomic_exchange_explicit(&session->output_waiting, false, memory_order_acq_rel))
    {
        const uint64_t one = 1;
        for (;;)
        {
            const ssize_t written = write(session->output_wake_fd, &one, sizeof(one));
            if (written == (ssize_t) sizeof(one) || (written < 0 && errno == EAGAIN))
            {
                return;
            }
            if (written < 0 && errno == EINTR)
            {
                continue;
            }
            LOGF("DeviceReaderSession: failed to signal output capacity: %s", strerror(errno));
            abortProgramNow(1);
        }
    }
#else
    discard session;
#endif
}

void deviceReaderSessionReleaseWork(device_reader_session_t *session, size_t exact_charge, unsigned int packets)
{
    assert(session != NULL);
    assert(exact_charge > 0);
    assert(packets > 0);
    const size_t previous_charge =
        atomic_fetch_sub_explicit(&session->output_charge, exact_charge, memory_order_acq_rel);
    const unsigned int previous_count =
        atomic_fetch_sub_explicit(&session->output_packets, packets, memory_order_acq_rel);
    if (UNLIKELY(previous_charge < exact_charge || previous_count < packets))
    {
        LOGF("DeviceReaderSession: output-budget reservation underflow");
        abortProgramNow(1);
    }
    deviceReaderSessionSignalOutputCapacity(session);
}

void deviceReaderSessionReleaseOutput(device_reader_session_t *session, size_t exact_charge)
{
    deviceReaderSessionReleaseWork(session, exact_charge, 1);
}

bool deviceReaderSessionConfigureOutputBudget(device_reader_session_t *session, size_t max_charge, uint32_t max_packets)
{
    assert(session != NULL);
    assert(max_charge > 0 && max_packets > 0);
    assert(session->output_wake_fd < 0);
    assert(atomic_load_explicit(&session->generation, memory_order_relaxed) == 0);
#ifdef OS_LINUX
    const int fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (fd < 0)
    {
        return false;
    }
    session->output_charge_limit = max_charge;
    session->output_packet_limit = max_packets;
    session->output_wake_fd      = fd;
    return true;
#else
    discard session;
    discard max_charge;
    discard max_packets;
    return false;
#endif
}

bool deviceReaderSessionTryReserveWork(device_reader_session_t *session, size_t exact_charge, unsigned int packets)
{
    assert(session != NULL);
    assert(session->output_wake_fd >= 0);
    assert(exact_charge > 0 && exact_charge <= session->output_charge_limit);
    assert(packets > 0 && packets <= session->output_packet_limit);
    if (UNLIKELY(! atomic_load_explicit(&session->producer_admission, memory_order_acquire)))
    {
        return false;
    }

    /* Publish the waiter before observing credits; a foreign-thread release
     * between this point and a failed reservation must leave a wake event.
     * The exchange's acquire half observes a release that completed just
     * before it, so stale credit loads cannot strand an unnotified waiter. */
    discard atomic_exchange_explicit(&session->output_waiting, true, memory_order_acq_rel);

    w_atomic_uint_value_t count = atomic_load_explicit(&session->output_packets, memory_order_relaxed);
    for (;;)
    {
        if (packets > session->output_packet_limit - count)
        {
            return false;
        }
        if (atomic_compare_exchange_weak_explicit(
                &session->output_packets, &count, count + packets, memory_order_acq_rel, memory_order_relaxed))
        {
            break;
        }
    }

    /* The Windows fallback's atomic_size_t stores intptr_t; its CAS expected
     * pointer must match that type as well as its width. C11 uses size_t. */
#if WW_HAVE_C11_ATOMICS
    size_t charge = atomic_load_explicit(&session->output_charge, memory_order_relaxed);
#else
    w_atomic_uint_value_t charge = atomic_load_explicit(&session->output_charge, memory_order_relaxed);
#endif
    for (;;)
    {
        if (exact_charge > session->output_charge_limit - charge)
        {
            const unsigned int previous =
                atomic_fetch_sub_explicit(&session->output_packets, packets, memory_order_acq_rel);
            if (UNLIKELY(previous < packets))
            {
                LOGF("DeviceReaderSession: output-budget packet reservation underflow");
                abortProgramNow(1);
            }
            return false;
        }
        if (atomic_compare_exchange_weak_explicit(
                &session->output_charge, &charge, charge + exact_charge, memory_order_acq_rel, memory_order_relaxed))
        {
            atomic_store_explicit(&session->output_waiting, false, memory_order_release);
            return true;
        }
    }
}

bool deviceReaderSessionTryReserveOutput(device_reader_session_t *session, size_t exact_charge)
{
    return deviceReaderSessionTryReserveWork(session, exact_charge, 1);
}

bool deviceReaderSessionEnableWorkerQueue(device_reader_session_t *session)
{
    assert(session != NULL);
    assert(session->output_wake_fd >= 0);
    assert(session->worker_queues == NULL);
    assert(atomicLoadRelaxed(&session->generation) == 0);
    const uint16_t count = getWorkersCount();
    assert(count > 0);
    device_reader_worker_queue_t *queues = memoryAllocateZero((size_t) count * sizeof(*queues));
    if (queues == NULL)
    {
        return false;
    }
    for (uint16_t i = 0; i < count; ++i)
    {
        if (! mutexTryInit(&queues[i].lock))
        {
            for (uint16_t j = 0; j < i; ++j)
            {
                mutexDestroy(&queues[j].lock);
            }
            memoryFree(queues);
            return false;
        }
        queues[i].session = session;
        queues[i].wid     = (wid_t) i;
    }
    session->worker_queue_count = count;
    session->worker_queues      = queues;
    return true;
}

int deviceReaderSessionOutputWakeFd(const device_reader_session_t *session)
{
    assert(session != NULL);
    return session->output_wake_fd;
}

void deviceReaderSessionDrainOutputWake(device_reader_session_t *session)
{
    assert(session != NULL);
#ifdef OS_LINUX
    if (session->output_wake_fd < 0)
    {
        return;
    }
    uint64_t count;
    for (;;)
    {
        const ssize_t nread = read(session->output_wake_fd, &count, sizeof(count));
        if (nread == (ssize_t) sizeof(count))
        {
            continue;
        }
        if (nread < 0 && errno == EINTR)
        {
            continue;
        }
        if (nread < 0 && errno == EAGAIN)
        {
            return;
        }
        LOGF("DeviceReaderSession: failed to drain output-capacity notification: %s", strerror(errno));
        abortProgramNow(1);
    }
#else
    discard session;
#endif
}

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

static void deviceReaderSessionReuseReaderBuffers(device_reader_session_t *session, sbuf_t **bufs, unsigned int count)
{
    for (unsigned int i = 0; i < count; i++)
    {
        bufferpoolReuseBuffer(session->reader_buffer_pool, bufs[i]);
    }
}

static void deviceReaderSessionReuseReservedBuffers(device_reader_session_t *session, sbuf_t **bufs,
                                                    const size_t *charges, unsigned int count)
{
    for (unsigned int i = 0; i < count; i++)
    {
        const size_t charge = charges == NULL ? sbufGetAllocationCharge(bufs[i]) : charges[i];
        bufferpoolReuseBuffer(session->reader_buffer_pool, bufs[i]);
        deviceReaderSessionReleaseOutput(session, charge);
    }
}

static void deviceReaderSessionCleanupMessage(device_reader_message_t *message)
{
    if (message == NULL)
    {
        return;
    }

    device_reader_session_t *session = message->session;
    if (message->work != NULL)
    {
        message->work_cleanup(message->work_context);
        deviceReaderSessionReleaseWork(session, message->work_charge, message->work_packets);
    }
    else
    {
        size_t *charges = session->output_wake_fd >= 0 ? deviceReaderMessageCharges(message) : NULL;
        for (unsigned int i = message->consumed; i < message->count; i++)
        {
            sbufDestroy(message->bufs[i]);
            if (charges != NULL && charges[i] != 0)
            {
                deviceReaderSessionReleaseOutput(session, charges[i]);
            }
        }
    }
    masterpoolReuseItems(session->message_pool, (void **) &message, 1);
    deviceReaderSessionUnref(session);
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
    for (uint16_t i = 0; i < session->worker_queue_count; ++i)
    {
        assert(session->worker_queues[i].head == NULL);
        assert(! session->worker_queues[i].scheduled);
        mutexDestroy(&session->worker_queues[i].lock);
    }
    memoryFree(session->worker_queues);
    /* Device teardown retires staged buffers before its pool dies. A session
     * used outside a device may still own a live pool at its final reference. */
    deviceFragAffinityDestroy(session->frag_affinity);
    session->frag_affinity = NULL;
    masterpoolMakeEmpty(session->message_pool);
    masterpoolDestroy(session->message_pool);
#ifdef OS_LINUX
    if (session->output_wake_fd >= 0)
    {
        close(session->output_wake_fd);
    }
#endif
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

static uint32_t deviceReaderSessionGeneration(const device_reader_session_t *session)
{
    // The generation is only a tag; the delivery gate publishes session fields.
    return (uint32_t) atomicLoadRelaxed(&session->generation);
}

static bool deviceReaderSessionMatchesGeneration(const device_reader_session_t *session, uint32_t generation)
{
    return generation == deviceReaderSessionGeneration(session);
}

static void deviceReaderWorkerQueueDrain(void *worker, void *arg1, void *arg2, void *arg3);

/* The sole queued token owns this lane until callback-or-cleanup settlement.
 * A producer may append while cancellation detaches the old FIFO; subsequent
 * work then schedules its own token. Neither path touches an owner-only pool. */
static void deviceReaderWorkerQueueCancel(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard                       reason;
    discard                       arg2;
    discard                       arg3;
    device_reader_worker_queue_t *queue   = arg1;
    device_reader_session_t      *session = queue->session;
    mutexLock(&queue->lock);
    device_reader_message_t *message = queue->head;
    queue->head                      = NULL;
    queue->tail                      = NULL;
    queue->scheduled                 = false;
    mutexUnlock(&queue->lock);
    while (message != NULL)
    {
        device_reader_message_t *next = message->next;
        deviceReaderSessionCleanupMessage(message);
        message = next;
    }
    deviceReaderSessionUnref(session);
}

static bool deviceReaderWorkerQueueSchedule(device_reader_worker_queue_t *queue)
{
    return sendWorkerMessageForceQueueWithCleanup(
               queue->wid, deviceReaderWorkerQueueDrain, deviceReaderWorkerQueueCancel, queue, NULL, NULL) ==
           kWorkerMessageSubmitAccepted;
}

static bool deviceReaderWorkerQueueAppend(device_reader_message_t *message, wid_t target_wid)
{
    device_reader_session_t *session = message->session;
    assert(target_wid < session->worker_queue_count);
    device_reader_worker_queue_t *queue = &session->worker_queues[target_wid];
    mutexLock(&queue->lock);
    if (queue->tail != NULL)
    {
        queue->tail->next = message;
    }
    else
    {
        queue->head = message;
    }
    queue->tail         = message;
    const bool schedule = ! queue->scheduled;
    if (schedule)
    {
        queue->scheduled = true;
        deviceReaderSessionRef(session);
    }
    mutexUnlock(&queue->lock);
    return ! schedule || deviceReaderWorkerQueueSchedule(queue);
}

static void deviceReaderWorkerQueueDrain(void *worker, void *arg1, void *arg2, void *arg3)
{
    discard                       arg2;
    discard                       arg3;
    device_reader_worker_queue_t *queue   = arg1;
    device_reader_session_t      *session = queue->session;
    const wid_t                   wid     = ((worker_t *) worker)->wid;
    assert(wid == queue->wid);
    device_reader_work_budget_t budget = {.packets = kDeviceReaderWorkerPacketQuantum,
                                          .bytes   = kDeviceReaderWorkerByteQuantum};

    while (budget.packets > 0 && budget.bytes > 0)
    {
        mutexLock(&queue->lock);
        device_reader_message_t *message = queue->head;
        if (message == NULL)
        {
            queue->scheduled = false;
            mutexUnlock(&queue->lock);
            deviceReaderSessionUnref(session);
            return;
        }
        mutexUnlock(&queue->lock);

        const bool entered  = quiescenceGateEnter(&session->delivery_gate);
        const bool admitted = entered && deviceReaderSessionMatchesGeneration(session, message->generation);
        bool       done     = true;
        if (message->work != NULL)
        {
            if (admitted)
            {
                const device_reader_work_budget_t before = budget;
                done                                     = message->work(session, message->work_context, wid, &budget);
                assert(budget.packets <= before.packets && budget.bytes <= before.bytes);
                assert(! done || budget.packets < before.packets);
                discard before;
            }
            else
            {
                /* Bound stale disposal too, even though no output is built. */
                --budget.packets;
            }
        }
        else
        {
            size_t *charges = deviceReaderMessageCharges(message);
            while (message->consumed < message->count && budget.packets > 0 && budget.bytes > 0)
            {
                const uint32_t length = sbufGetLength(message->bufs[message->consumed]);
                /* An ordinary packet larger than the byte quantum travels
                 * alone; it must not become a permanently blocked FIFO head. */
                if (length > budget.bytes && budget.packets != kDeviceReaderWorkerPacketQuantum)
                {
                    break;
                }
                const unsigned int index = message->consumed++;
                if (admitted)
                {
                    if (message->prepare != NULL)
                    {
                        message->prepare(message->bufs[index]);
                    }
                    session->deliver(session->device, message->bufs[index], wid);
                }
                else
                {
                    sbufDestroy(message->bufs[index]);
                }
                deviceReaderSessionReleaseOutput(session, charges[index]);
                --budget.packets;
                budget.bytes -= min(length, budget.bytes);
            }
            done = message->consumed == message->count;
        }
        if (entered)
        {
            quiescenceGateLeave(&session->delivery_gate);
        }

        if (! done)
        {
            break;
        }
        mutexLock(&queue->lock);
        assert(queue->head == message);
        queue->head = message->next;
        if (queue->head == NULL)
        {
            queue->tail = NULL;
        }
        mutexUnlock(&queue->lock);
        deviceReaderSessionCleanupMessage(message);
    }

    mutexLock(&queue->lock);
    const bool more = queue->head != NULL;
    if (! more)
    {
        queue->scheduled = false;
    }
    mutexUnlock(&queue->lock);
    if (more)
    {
        /* Ownership of the existing token reference passes to callback or
         * cleanup, including synchronous refusal. Touch nothing afterwards. */
        discard deviceReaderWorkerQueueSchedule(queue);
    }
    else
    {
        deviceReaderSessionUnref(session);
    }
}

static void deviceReaderSessionMessageReceived(void *worker, void *arg1, void *arg2, void *arg3)
{
    device_reader_message_t *message    = arg1;
    device_reader_session_t *session    = message->session;
    const uint32_t           generation = message->generation;
    const wid_t              wid        = ((worker_t *) worker)->wid;
    size_t                  *charges    = session->output_wake_fd >= 0 ? deviceReaderMessageCharges(message) : NULL;
    discard                  arg2;
    discard                  arg3;

    const bool entered = quiescenceGateEnter(&session->delivery_gate);
    if (entered && deviceReaderSessionMatchesGeneration(session, generation))
    {
        for (unsigned int i = 0; i < message->count; i++)
        {
            if (message->prepare != NULL)
            {
                message->prepare(message->bufs[i]);
            }
            session->deliver(session->device, message->bufs[i], wid);
            if (charges != NULL && charges[i] != 0)
            {
                deviceReaderSessionReleaseOutput(session, charges[i]);
            }
        }
        quiescenceGateLeave(&session->delivery_gate);
    }
    else
    {
        if (entered)
        {
            quiescenceGateLeave(&session->delivery_gate);
        }
        for (unsigned int i = 0; i < message->count; i++)
        {
            bufferpoolReuseBuffer(getWorkerBufferPool(wid), message->bufs[i]);
            if (charges != NULL && charges[i] != 0)
            {
                deviceReaderSessionReleaseOutput(session, charges[i]);
            }
        }
    }

    masterpoolReuseItems(session->message_pool, (void **) &message, 1);
    deviceReaderSessionUnref(session);
}

static void deviceReaderSessionCleanupPostedMessage(void *arg1, void *arg2, void *arg3,
                                                    worker_message_cancel_reason_e reason)
{
    discard                  reason;
    device_reader_message_t *message = arg1;
    discard                  arg2;
    discard                  arg3;

    deviceReaderSessionCleanupMessage(message);
}

static bool deviceReaderSessionPostInternal(device_reader_session_t *session, wid_t target_wid, sbuf_t **bufs,
                                            const size_t *charges, unsigned int count, DeviceReaderPrepareFn prepare)
{
    assert(session->reader_buffer_pool != NULL);
    if (UNLIKELY(count == 0 || count > session->batch_capacity))
    {
        LOGE("DeviceReaderSession: refusing to post %u buffer(s); batch capacity is %u",
             count,
             (unsigned int) session->batch_capacity);
        if (charges != NULL)
        {
            deviceReaderSessionReuseReservedBuffers(session, bufs, charges, count);
        }
        else
        {
            deviceReaderSessionReuseReaderBuffers(session, bufs, count);
        }
        return false;
    }

    assert(count > 0);
    assert(count <= session->batch_capacity);

    // Acquires the generation and affinity state published when admission opened.
    if (UNLIKELY(! atomicLoadExplicit(&session->producer_admission, memory_order_acquire) ||
                 GSTATE.shortcut_loops == NULL))
    {
        if (charges != NULL || session->worker_queues != NULL)
        {
            deviceReaderSessionReuseReservedBuffers(session, bufs, charges, count);
        }
        else
        {
            deviceReaderSessionReuseReaderBuffers(session, bufs, count);
        }
        return false;
    }

    master_pool_item_t      *pool_item;
    device_reader_message_t *message;
    masterpoolGetItems(session->message_pool, &pool_item, 1, session);
    message = pool_item;

    *message = (device_reader_message_t) {
        .session    = session,
        .prepare    = prepare,
        .generation = deviceReaderSessionGeneration(session),
        .count      = (uint16_t) count,
    };
    size_t *message_charges = session->output_wake_fd >= 0 ? deviceReaderMessageCharges(message) : NULL;
    for (unsigned int i = 0; i < count; i++)
    {
        message->bufs[i] = bufs[i];
        if (message_charges != NULL)
        {
            message_charges[i] =
                charges != NULL ? charges[i] : (session->worker_queues != NULL ? sbufGetAllocationCharge(bufs[i]) : 0);
        }
    }

    deviceReaderSessionRef(session);
    if (session->worker_queues != NULL)
    {
        return deviceReaderWorkerQueueAppend(message, target_wid);
    }
    return sendWorkerMessageForceQueueWithCleanup(target_wid,
                                                  deviceReaderSessionMessageReceived,
                                                  deviceReaderSessionCleanupPostedMessage,
                                                  message,
                                                  NULL,
                                                  NULL) == kWorkerMessageSubmitAccepted;
}

static bool deviceReaderSessionWaitReserveWork(device_reader_session_t *session, size_t charge, unsigned int packets,
                                               uint32_t generation)
{
    for (;;)
    {
        if (! atomicLoadExplicit(&session->producer_admission, memory_order_acquire) ||
            ! deviceReaderSessionMatchesGeneration(session, generation))
        {
            return false;
        }
        if (deviceReaderSessionTryReserveWork(session, charge, packets))
        {
            return true;
        }
#ifdef OS_LINUX
        struct pollfd fd     = {.fd = session->output_wake_fd, .events = POLLIN};
        const int     result = poll(&fd, 1, kDeviceReaderCapacityPollMs);
        if (result > 0)
        {
            if (UNLIKELY((fd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0))
            {
                LOGF("DeviceReaderSession: invalid output-capacity notification descriptor");
                abortProgramNow(1);
            }
            deviceReaderSessionDrainOutputWake(session);
        }
        else if (result < 0 && errno != EINTR)
        {
            LOGE("DeviceReaderSession: output-capacity wait failed: %s", strerror(errno));
            return false;
        }
#else
        return false;
#endif
    }
}

bool deviceReaderSessionPost(device_reader_session_t *session, wid_t target_wid, sbuf_t **bufs, unsigned int count)
{
    if (session->worker_queues == NULL || count == 0 || count > session->batch_capacity)
    {
        return deviceReaderSessionPostInternal(session, target_wid, bufs, NULL, count, NULL);
    }

    /* The producer owns only this bounded read/fragment-release batch outside
     * the queue budget. Reserve a whole fitting chunk at once so a producer
     * cannot hold partial credits while waiting for the rest of its own batch. */
    const uint32_t generation = deviceReaderSessionGeneration(session);
    unsigned int   first      = 0;
    while (first < count)
    {
        unsigned int chunk  = 0;
        size_t       charge = 0;
        while (first + chunk < count && chunk < session->output_packet_limit)
        {
            const size_t next = sbufGetAllocationCharge(bufs[first + chunk]);
            if (UNLIKELY(next > session->output_charge_limit))
            {
                LOGF("DeviceReaderSession: ordinary packet exceeds configured queue budget");
                abortProgramNow(1);
            }
            if (next > session->output_charge_limit - charge)
            {
                break;
            }
            charge += next;
            ++chunk;
        }
        assert(chunk > 0);
        if (! deviceReaderSessionWaitReserveWork(session, charge, chunk, generation))
        {
            deviceReaderSessionReuseReaderBuffers(session, bufs + first, count - first);
            return false;
        }

        /* Ordered PostInternal derives each already-reserved ordinary charge
         * directly from the buffer into its message's parallel charge array. */
        if (! deviceReaderSessionPostInternal(session, target_wid, bufs + first, NULL, chunk, NULL))
        {
            deviceReaderSessionReuseReaderBuffers(session, bufs + first + chunk, count - first - chunk);
            return false;
        }
        first += chunk;
    }
    return true;
}

bool deviceReaderSessionPostWork(device_reader_session_t *session, wid_t target_wid, void *context,
                                 DeviceReaderWorkFn step, DeviceReaderWorkCleanupFn cleanup, size_t charge,
                                 unsigned int packets)
{
    assert(session != NULL && session->worker_queues != NULL);
    assert(step != NULL && cleanup != NULL);
    assert(charge > 0 && packets > 0);
    if (! atomicLoadExplicit(&session->producer_admission, memory_order_acquire) || GSTATE.shortcut_loops == NULL)
    {
        cleanup(context);
        deviceReaderSessionReleaseWork(session, charge, packets);
        return false;
    }
    master_pool_item_t *pool_item;
    masterpoolGetItems(session->message_pool, &pool_item, 1, session);
    device_reader_message_t *message = pool_item;
    *message                         = (device_reader_message_t) {
                                .session      = session,
                                .work         = step,
                                .work_cleanup = cleanup,
                                .work_context = context,
                                .work_charge  = charge,
                                .work_packets = packets,
                                .generation   = deviceReaderSessionGeneration(session),
    };
    deviceReaderSessionRef(session);
    return deviceReaderWorkerQueueAppend(message, target_wid);
}

bool deviceReaderSessionPostReserved(device_reader_session_t *session, wid_t target_wid, sbuf_t **bufs,
                                     const size_t *charges, unsigned int count, DeviceReaderPrepareFn prepare)
{
    assert(charges != NULL);
    assert(session->output_wake_fd >= 0);
    for (unsigned int i = 0; i < count; i++)
    {
        if (UNLIKELY(charges[i] != sbufGetAllocationCharge(bufs[i])))
        {
            LOGF("DeviceReaderSession: output reservation does not match packet allocation charge");
            abortProgramNow(1);
        }
    }
    return deviceReaderSessionPostInternal(session, target_wid, bufs, charges, count, prepare);
}
