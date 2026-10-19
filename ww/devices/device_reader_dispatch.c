#include "devices/device_reader_dispatch.h"
#include "devices/device_reader_budget.h"
#include "devices/device_reader_private.h"
#include "global_state.h"
#include "loggers/internal_logger.h"
#include "packet_batch.h"
#include "worker_messages.h"

enum
{
    kDeviceReaderWorkerPacketQuantum = 64,
    kDeviceReaderWorkerByteQuantum   = 64 * 1024
};

bool deviceReaderSessionEnableWorkerQueue(device_reader_session_t *session)
{
    assert(session != NULL);
    assert(session->output_charge_limit != 0);
    assert(session->worker_queues == NULL);
    assert(atomicLoadRelaxed(&session->generation) == 0);
    const uint16_t count = getWorkersCount();
    assert(count > 0);
    device_reader_worker_queue_t *queues = memoryAllocateZero((size_t) count * sizeof(*queues));
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

static void deviceReaderSessionReuseReaderBuffers(device_reader_session_t *session, sbuf_t **bufs, unsigned int count)
{
    for (unsigned int i = 0; i < count; i++)
    {
        bufferpoolReuseBuffer(session->reader_buffer_pool, bufs[i]);
    }
}

static void deviceReaderSessionReuseReservedBuffers(device_reader_session_t *session, sbuf_t **bufs,
                                                    const size_t *charges, unsigned int count, bool detached)
{
    for (unsigned int i = 0; i < count; i++)
    {
        const size_t charge = charges == NULL ? sbufGetAllocationCharge(bufs[i]) : charges[i];
        if (detached)
            sbufDestroy(bufs[i]);
        else
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
        size_t *charges = session->output_charge_limit != 0 ? deviceReaderMessageCharges(message) : NULL;
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

static void deviceReaderWorkerQueueDrain(void *worker, void *arg1, void *arg2, void *arg3);

bool deviceReaderSessionTryBeginBurst(device_reader_session_t *session, worker_t *worker, device_reader_burst_t *burst)
{
    assert(session != NULL && session->worker_queues != NULL && worker != NULL && burst != NULL);
    assert(worker->wid < session->worker_queue_count);
    *burst = (device_reader_burst_t) {0};
    if (worker != tryGetCurrentEventWorker() || ! wloopCurrentThreadInNormalCallback(worker->loop))
        return false;

    device_reader_worker_queue_t *queue = &session->worker_queues[worker->wid];
    mutexLock(&queue->lock);
    assert(queue->producer_burst == NULL);
    *burst                = (device_reader_burst_t) {.queue = queue, .worker = worker};
    queue->producer_burst = burst;
    mutexUnlock(&queue->lock);
    return true;
}

void deviceReaderSessionEndBurst(device_reader_burst_t *burst)
{
    assert(burst != NULL && burst->queue != NULL && burst->worker != NULL);
    device_reader_worker_queue_t *queue  = burst->queue;
    worker_t                     *worker = burst->worker;
    assert(worker == tryGetCurrentEventWorker() && wloopCurrentThreadInNormalCallback(worker->loop));
    mutexLock(&queue->lock);
    assert(queue->producer_burst == burst);
    const bool owns_drain = burst->owns_drain;
    queue->producer_burst = NULL;
    mutexUnlock(&queue->lock);
    *burst = (device_reader_burst_t) {0};
    /* Clear the scope before callbacks: recursive input joins the existing
     * token, and any unfinished quantum keeps its normal queued continuation. */
    if (owns_drain)
        deviceReaderWorkerQueueDrain(worker, queue, NULL, NULL);
}

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
    bool       local    = false;
    if (schedule)
    {
        queue->scheduled = true;
        deviceReaderSessionRef(session);
        device_reader_burst_t *burst = queue->producer_burst;
        if (burst != NULL && currentThreadIsEventWorkerWID(target_wid) &&
            wloopCurrentThreadInNormalCallback(burst->worker->loop))
        {
            assert(! burst->owns_drain);
            burst->owns_drain = true;
            local             = true;
        }
    }
    mutexUnlock(&queue->lock);
    /* A newly claimed local token belongs to the producer's EndBurst. Every
     * other token remains queued; no packet is delivered during collection. */
    return ! schedule || local || deviceReaderWorkerQueueSchedule(queue);
}

static void deviceReaderWorkerQueueDrain(void *worker, void *arg1, void *arg2, void *arg3)
{
    discard                       arg2;
    discard                       arg3;
    device_reader_worker_queue_t *queue   = arg1;
    device_reader_session_t      *session = queue->session;
    const wid_t                   wid     = ((worker_t *) worker)->wid;
    assert(wid == queue->wid);
    device_reader_work_budget_t budget    = {.packets = kDeviceReaderWorkerPacketQuantum,
                                             .bytes   = kDeviceReaderWorkerByteQuantum};
    packet_batch_t              batch;
    packetBatchBegin(&batch);

    while (budget.packets > 0 && budget.bytes > 0)
    {
        mutexLock(&queue->lock);
        device_reader_message_t *message = queue->head;
        if (message == NULL)
        {
            queue->scheduled = false;
            mutexUnlock(&queue->lock);
            packetBatchEnd(&batch);
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

    /* Participants flush before yielding or publishing the continuation. */
    packetBatchEnd(&batch);
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
    size_t                  *charges = session->output_charge_limit != 0 ? deviceReaderMessageCharges(message) : NULL;
    discard                  arg2;
    discard                  arg3;

    const bool entered = quiescenceGateEnter(&session->delivery_gate);
    if (entered && deviceReaderSessionMatchesGeneration(session, generation))
    {
        packet_batch_t batch;
        packetBatchBegin(&batch);
        unsigned int batch_packets = 0;
        size_t       batch_bytes   = 0;
        for (unsigned int i = 0; i < message->count; i++)
        {
            const uint32_t length = sbufGetLength(message->bufs[i]);
            if (batch_packets != 0 &&
                (batch_packets == kDeviceReaderWorkerPacketQuantum ||
                 length > kDeviceReaderWorkerByteQuantum - min(batch_bytes, (size_t) kDeviceReaderWorkerByteQuantum)))
            {
                packetBatchEnd(&batch);
                packetBatchBegin(&batch);
                batch_packets = 0;
                batch_bytes   = 0;
            }
            if (message->prepare != NULL)
            {
                message->prepare(message->bufs[i]);
            }
            session->deliver(session->device, message->bufs[i], wid);
            ++batch_packets;
            batch_bytes += length;
            if (charges != NULL && charges[i] != 0)
            {
                deviceReaderSessionReleaseOutput(session, charges[i]);
            }
        }
        packetBatchEnd(&batch);
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
                                            const size_t *charges, unsigned int count, DeviceReaderPrepareFn prepare,
                                            bool detached)
{
    assert(detached || session->reader_buffer_pool != NULL);
    if (UNLIKELY(count == 0 || count > session->batch_capacity))
    {
        LOGE("DeviceReaderSession: refusing to post %u buffer(s); batch capacity is %u",
             count,
             (unsigned int) session->batch_capacity);
        if (charges != NULL)
        {
            deviceReaderSessionReuseReservedBuffers(session, bufs, charges, count, detached);
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
            deviceReaderSessionReuseReservedBuffers(session, bufs, charges, count, detached);
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
    size_t *message_charges = session->output_charge_limit != 0 ? deviceReaderMessageCharges(message) : NULL;
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

bool deviceReaderSessionPost(device_reader_session_t *session, wid_t target_wid, sbuf_t **bufs, unsigned int count)
{
    if (session->worker_queues == NULL || count == 0 || count > session->batch_capacity)
    {
        return deviceReaderSessionPostInternal(session, target_wid, bufs, NULL, count, NULL, false);
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
        if (! deviceReaderSessionPostInternal(session, target_wid, bufs + first, NULL, chunk, NULL, false))
        {
            deviceReaderSessionReuseReaderBuffers(session, bufs + first + chunk, count - first - chunk);
            return false;
        }
        first += chunk;
    }
    return true;
}

device_reader_post_result_e deviceReaderSessionTryPost(device_reader_session_t *session, wid_t target_wid,
                                                       sbuf_t **bufs, unsigned int count)
{
    assert(session != NULL && session->worker_queues != NULL && bufs != NULL);
    assert(count > 0 && count <= session->batch_capacity && count <= session->output_packet_limit);
    assert(target_wid < session->worker_queue_count);

    size_t charge = 0;
    for (unsigned int i = 0; i < count; ++i)
    {
        const size_t next = sbufGetAllocationCharge(bufs[i]);
        if (UNLIKELY(next > session->output_charge_limit - charge))
        {
            LOGF("DeviceReaderSession: nonblocking batch exceeds configured queue budget");
            abortProgramNow(1);
        }
        charge += next;
    }
    if (deviceReaderSessionTryReserveWork(session, charge, count))
    {
        return deviceReaderSessionPostInternal(session, target_wid, bufs, NULL, count, NULL, true)
                   ? kDeviceReaderPostAccepted
                   : kDeviceReaderPostClosed;
    }
    if (atomicLoadExplicit(&session->producer_admission, memory_order_acquire))
    {
        return kDeviceReaderPostCapacity;
    }
    for (unsigned int i = 0; i < count; ++i)
    {
        sbufDestroy(bufs[i]);
    }
    return kDeviceReaderPostClosed;
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
    assert(session->output_charge_limit != 0);
    for (unsigned int i = 0; i < count; i++)
    {
        if (UNLIKELY(charges[i] != sbufGetAllocationCharge(bufs[i])))
        {
            LOGF("DeviceReaderSession: output reservation does not match packet allocation charge");
            abortProgramNow(1);
        }
    }
    return deviceReaderSessionPostInternal(session, target_wid, bufs, charges, count, prepare, false);
}

void deviceReaderDispatchDestroy(device_reader_session_t *session)
{
    for (uint16_t i = 0; i < session->worker_queue_count; ++i)
    {
        assert(session->worker_queues[i].head == NULL);
        assert(! session->worker_queues[i].scheduled);
        assert(session->worker_queues[i].producer_burst == NULL);
        mutexDestroy(&session->worker_queues[i].lock);
    }
    memoryFree(session->worker_queues);
}
