#include "devices/tun/tun_writer.h"

#include "global_state.h"
#include "loggers/internal_logger.h"
#include "quiescence_gate.h"
#include "worker_messages.h"

#define i_type tun_writer_buffers_t
#define i_key  sbuf_t *
#include "stc/deque.h"

typedef struct tun_writer_queue_s
{
    tun_writer_buffers_t buffers;
    bool                 scheduled; /* Owner worker, or closed and quiesced. */
    atomic_bool          cancelled;
} tun_writer_queue_t;

struct tun_writer_generation_s
{
    tun_writer_generation_t *next;
    quiescence_gate_t        gate;
    atomic_uint              references;
    atomic_bool              failed;
    atomic_size_t            packets;
    atomic_size_t            charge;
    size_t                   packet_limit;
    size_t                   charge_limit;
    size_t                   worker_count;
    void                    *context;
    tun_writer_batch_fn      write_batch;
    tun_writer_queue_t       queues[];
};

static void tunWriterGenerationUnref(tun_writer_generation_t *generation)
{
    const w_atomic_uint_value_t before = atomicSubExplicit(&generation->references, 1, memory_order_acq_rel);
    assert(before > 0);
    if (before == 1)
    {
        assert(quiescenceGateIsClosedAndQuiesced(&generation->gate));
        assert(atomicLoadRelaxed(&generation->packets) == 0);
        memoryFree(generation);
    }
}

static bool tunWriterReserve(atomic_size_t *used, size_t limit, size_t amount)
{
#if WW_HAVE_C11_ATOMICS
    size_t current = atomicLoadRelaxed(used);
#else
    w_atomic_uint_value_t current = atomicLoadRelaxed(used);
#endif
    for (;;)
    {
        if (amount > limit - (size_t) current)
            return false;
        if (atomic_compare_exchange_weak_explicit(
                used, &current, (size_t) current + amount, memory_order_relaxed, memory_order_relaxed))
            return true;
    }
}

static void tunWriterReleaseBudget(tun_writer_generation_t *generation, size_t packets, size_t charge)
{
    const size_t old_packets = (size_t) atomicSubExplicit(&generation->packets, packets, memory_order_relaxed);
    const size_t old_charge  = (size_t) atomicSubExplicit(&generation->charge, charge, memory_order_relaxed);
    assert(old_packets >= packets && old_charge >= charge);
    discard old_packets;
    discard old_charge;
}

static void tunWriterDiscardQueue(tun_writer_generation_t *generation, tun_writer_queue_t *queue)
{
    while (! tun_writer_buffers_t_is_empty(&queue->buffers))
    {
        sbuf_t      *buffer = tun_writer_buffers_t_pull_front(&queue->buffers);
        const size_t charge = sbufGetAllocationCharge(buffer);
        sbufDestroy(buffer);
        tunWriterReleaseBudget(generation, 1, charge);
    }
}

static void tunWriterDrain(worker_t *worker, void *arg1, void *arg2, void *arg3);

static void tunWriterDrainCancelled(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard                  arg3;
    discard                  reason;
    tun_writer_generation_t *generation = arg1;
    tun_writer_queue_t      *queue      = arg2;
    /* Cancellation may run on a foreign thread. Only independently atomic
     * notification and generation ownership are touched; CloseWait owns FIFO
     * cleanup after closing and waiting for the operation gate. */
    atomicStoreExplicit(&queue->cancelled, true, memory_order_release);
    tunWriterGenerationUnref(generation);
}

static bool tunWriterSchedule(tun_writer_generation_t *generation, tun_writer_queue_t *queue, wid_t wid)
{
    queue->scheduled = true;
    discard                              atomicIncExplicit(&generation->references, memory_order_relaxed);
    const worker_message_submit_result_e result = sendWorkerMessageForceQueueWithCleanup(
        wid, (WorkerMessageCallback) tunWriterDrain, tunWriterDrainCancelled, generation, queue, NULL);
    if (result == kWorkerMessageSubmitAccepted)
        return true;
    assert(result == kWorkerMessageSubmitRejectedCleanupRan);
    queue->scheduled = false;
    return false;
}

static void tunWriterDrain(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard                  arg3;
    tun_writer_generation_t *generation = arg1;
    tun_writer_queue_t      *queue      = arg2;
    assert(currentThreadOwnsWorker(worker->wid));

    if (! quiescenceGateEnter(&generation->gate))
    {
        tunWriterGenerationUnref(generation);
        return;
    }

    assert(queue == &generation->queues[worker->wid]);
    queue->scheduled = false;
    if (atomicLoadExplicit(&generation->failed, memory_order_acquire) ||
        atomicLoadExplicit(&queue->cancelled, memory_order_acquire))
    {
        tunWriterDiscardQueue(generation, queue);
        quiescenceGateLeave(&generation->gate);
        tunWriterGenerationUnref(generation);
        return;
    }

    sbuf_t *buffers[kTunWriterBatchPackets];
    size_t  count  = 0;
    size_t  charge = 0;
    while (count < ARRAY_SIZE(buffers) && ! tun_writer_buffers_t_is_empty(&queue->buffers))
    {
        sbuf_t      *buffer      = *tun_writer_buffers_t_front(&queue->buffers);
        const size_t next_charge = sbufGetAllocationCharge(buffer);
        /* An oversized retained allocation still makes progress alone. */
        if (count != 0 && next_charge > kTunWriterBatchCharge - min(charge, (size_t) kTunWriterBatchCharge))
            break;
        buffers[count++] = tun_writer_buffers_t_pull_front(&queue->buffers);
        charge += next_charge;
    }

    bool failed = false;
    if (count != 0)
    {
        if (! generation->write_batch(generation->context, worker, buffers, count))
            failed = ! atomicExchangeExplicit(&generation->failed, true, memory_order_acq_rel);
        tunWriterReleaseBudget(generation, count, charge);
    }

    if (! atomicLoadExplicit(&generation->failed, memory_order_acquire) &&
        ! tun_writer_buffers_t_is_empty(&queue->buffers) && ! tunWriterSchedule(generation, queue, worker->wid))
        tunWriterDiscardQueue(generation, queue);

    quiescenceGateLeave(&generation->gate);
    tunWriterGenerationUnref(generation);
    if (failed && ! requestProgramShutdown(1))
        abortProgramNow(1);
}

void tunWriterInit(tun_writer_t *writer)
{
    *writer = (tun_writer_t) {0};
    atomicStoreRelaxed(&writer->published_generation, (uintptr_t) NULL);
}

bool tunWriterOpen(tun_writer_t *writer, size_t packet_limit, size_t charge_limit, void *context,
                   tun_writer_batch_fn write_batch)
{
    assert(write_batch != NULL);
    assert(GSTATE.flag_initialized);
    if (writer->current != NULL || packet_limit == 0 || charge_limit == 0)
        return false;
    const size_t worker_count = getWorkersCount();
    if (worker_count == 0 || packet_limit > (size_t) PTRDIFF_MAX / (2U * sizeof(sbuf_t *)))
        return false;

    tun_writer_generation_t *generation =
        memoryAllocateZero(sizeof(*generation) + worker_count * sizeof(generation->queues[0]));
    generation->packet_limit = packet_limit;
    generation->charge_limit = charge_limit;
    generation->worker_count = worker_count;
    generation->context      = context;
    generation->write_batch  = write_batch;
    atomicStoreRelaxed(&generation->references, 1);
    quiescenceGateInit(&generation->gate);
    if (! quiescenceGateOpen(&generation->gate))
    {
        tunWriterGenerationUnref(generation);
        return false;
    }
    writer->current = generation;
    atomicStoreExplicit(&writer->published_generation, (uintptr_t) generation, memory_order_release);
    return true;
}

void tunWriterCloseRequest(tun_writer_t *writer)
{
    tun_writer_generation_t *generation = (tun_writer_generation_t *) atomicExchangeExplicit(
        &writer->published_generation, (uintptr_t) NULL, memory_order_acq_rel);
    if (generation != NULL)
    {
        assert(generation == writer->current);
        quiescenceGateClose(&generation->gate);
    }
}

void tunWriterCloseWait(tun_writer_t *writer)
{
    tunWriterCloseRequest(writer);
    tun_writer_generation_t *generation = writer->current;
    if (generation == NULL)
        return;
    quiescenceGateWaitQuiesced(&generation->gate, quiescenceGateYieldThread, NULL);
    for (size_t i = 0; i < generation->worker_count; ++i)
    {
        tun_writer_queue_t *queue = &generation->queues[i];
        tunWriterDiscardQueue(generation, queue);
        tun_writer_buffers_t_drop(&queue->buffers);
    }
    generation->context = NULL;
    generation->next    = writer->retired;
    writer->retired     = generation;
    writer->current     = NULL;
}

void tunWriterDestroy(tun_writer_t *writer)
{
    tunWriterCloseWait(writer);
    tun_writer_generation_t *generation = writer->retired;
    writer->retired                     = NULL;
    while (generation != NULL)
    {
        tun_writer_generation_t *next = generation->next;
        tunWriterGenerationUnref(generation);
        generation = next;
    }
}

tun_writer_send_result_t tunWriterTrySend(tun_writer_t *writer, sbuf_t *buffer)
{
    worker_t                *worker = getCurrentWorker();
    tun_writer_generation_t *generation =
        (tun_writer_generation_t *) atomicLoadExplicit(&writer->published_generation, memory_order_acquire);
    if (generation == NULL)
        return kTunWriterSendDown;
    if (! quiescenceGateEnter(&generation->gate))
        return kTunWriterSendClosed;

    assert(worker->wid < generation->worker_count);
    tun_writer_queue_t      *queue  = &generation->queues[worker->wid];
    tun_writer_send_result_t result = kTunWriterSendClosed;
    if (atomicLoadExplicit(&generation->failed, memory_order_acquire) ||
        atomicLoadExplicit(&queue->cancelled, memory_order_acquire))
        goto done;

    result = kTunWriterSendFull;
    if (! tunWriterReserve(&generation->packets, generation->packet_limit, 1))
        goto done;
    const size_t charge = sbufGetAllocationCharge(buffer);
    if (! tunWriterReserve(&generation->charge, generation->charge_limit, charge))
    {
        discard atomicSubExplicit(&generation->packets, 1, memory_order_relaxed);
        goto done;
    }
    discard tun_writer_buffers_t_push_back(&queue->buffers, buffer);
    if (! queue->scheduled && ! tunWriterSchedule(generation, queue, worker->wid))
    {
        assert(tun_writer_buffers_t_size(&queue->buffers) == 1);
        discard tun_writer_buffers_t_pull_back(&queue->buffers);
        atomicStoreExplicit(&queue->cancelled, false, memory_order_release);
        tunWriterReleaseBudget(generation, 1, charge);
        result = kTunWriterSendClosed;
        goto done;
    }
    result = kTunWriterSendOk;
done:
    quiescenceGateLeave(&generation->gate);
    return result;
}
