#include "devices/raw/raw_writer.h"

#include "global_state.h"
#include "loggers/internal_logger.h"
#include "quiescence_gate.h"
#include "worker_messages.h"

#define i_type raw_writer_buffers_t
#define i_key  sbuf_t *
#include "stc/deque.h"

struct raw_writer_lane_s
{
    raw_writer_generation_t *generation;
    wid_t                    wid;
    atomic_bool              cancelled;
    bool                     scheduled; /* Owner worker: token pending, or native notification awaited. */
    raw_writer_buffers_t     buffers;
    sbuf_t                  *batch[kRawWriterBatchPackets];
    size_t                   batch_count;
    size_t                   batch_offset;
};

struct raw_writer_generation_s
{
    raw_writer_generation_t *next;
    quiescence_gate_t        gate;
    atomic_uint              references;
    atomic_bool              failed;
    atomic_size_t            packets;
    size_t                   packet_limit;
    size_t                   worker_count;
    uint32_t                 retry_delay_ms;
    void                    *context;
    raw_writer_batch_fn      write_batch;
    raw_writer_stop_fn       stop_worker;
    raw_writer_lane_t        lanes[];
};

static void rawWriterGenerationUnref(raw_writer_generation_t *generation)
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

static bool rawWriterReservePacket(raw_writer_generation_t *generation)
{
#if WW_HAVE_C11_ATOMICS
    size_t current = atomicLoadRelaxed(&generation->packets);
#else
    w_atomic_uint_value_t current = atomicLoadRelaxed(&generation->packets);
#endif
    for (;;)
    {
        if ((size_t) current >= generation->packet_limit)
            return false;
        if (atomic_compare_exchange_weak_explicit(
                &generation->packets, &current, current + 1, memory_order_relaxed, memory_order_relaxed))
            return true;
    }
}

static void rawWriterReleasePackets(raw_writer_generation_t *generation, size_t count)
{
    const size_t before = (size_t) atomicSubExplicit(&generation->packets, count, memory_order_relaxed);
    assert(before >= count);
    discard before;
}

static void rawWriterDiscardLane(raw_writer_lane_t *lane)
{
    size_t count = 0;
    while (lane->batch_offset < lane->batch_count)
    {
        sbufDestroy(lane->batch[lane->batch_offset++]);
        count++;
    }
    lane->batch_offset = lane->batch_count = 0;
    while (! raw_writer_buffers_t_is_empty(&lane->buffers))
    {
        sbufDestroy(raw_writer_buffers_t_pull_front(&lane->buffers));
        count++;
    }
    rawWriterReleasePackets(lane->generation, count);
}

static void rawWriterDrain(worker_t *worker, void *arg1, void *arg2, void *arg3);

static void rawWriterTokenCancelled(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard                  arg3;
    discard                  reason;
    raw_writer_generation_t *generation = arg1;
    raw_writer_lane_t       *lane       = arg2;
    /* FIFO and native borrows remain intact until CloseWait retires native
     * roots. Cancellation is notification only, even on a foreign thread. */
    atomicStoreExplicit(&lane->cancelled, true, memory_order_release);
    rawWriterGenerationUnref(generation);
}

static bool rawWriterPostToken(raw_writer_generation_t *generation, raw_writer_lane_t *lane, uint32_t delay_ms)
{
    discard                              atomicIncExplicit(&generation->references, memory_order_relaxed);
    const worker_message_submit_result_e result =
        delay_ms == 0
            ? sendWorkerMessageForceQueueWithCleanup(
                  lane->wid, (WorkerMessageCallback) rawWriterDrain, rawWriterTokenCancelled, generation, lane, NULL)
            : sendWorkerMessageTimedWithCleanup(lane->wid,
                                                (WorkerMessageCallback) rawWriterDrain,
                                                rawWriterTokenCancelled,
                                                delay_ms,
                                                generation,
                                                lane,
                                                NULL);
    assert(result == kWorkerMessageSubmitAccepted || result == kWorkerMessageSubmitRejectedCleanupRan);
    return result == kWorkerMessageSubmitAccepted;
}

static bool rawWriterSchedule(raw_writer_generation_t *generation, raw_writer_lane_t *lane, uint32_t delay_ms)
{
    lane->scheduled = true;
    if (rawWriterPostToken(generation, lane, delay_ms))
        return true;
    lane->scheduled = false;
    return false;
}

static void rawWriterDrain(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard                  arg3;
    raw_writer_generation_t *generation = arg1;
    raw_writer_lane_t       *lane       = arg2;
    assert(currentThreadOwnsWorker(worker->wid));
    if (! quiescenceGateEnter(&generation->gate))
    {
        rawWriterGenerationUnref(generation);
        return;
    }
    assert(lane == &generation->lanes[worker->wid]);
    lane->scheduled = false;
    if (atomicLoadExplicit(&generation->failed, memory_order_acquire) ||
        atomicLoadExplicit(&lane->cancelled, memory_order_acquire))
    {
        /* A different worker may still have an outstanding native borrow.
         * Uniformly leave disposal to CloseWait's native-retirement boundary. */
        quiescenceGateLeave(&generation->gate);
        rawWriterGenerationUnref(generation);
        return;
    }

    if (lane->batch_count == 0)
    {
        while (lane->batch_count < ARRAY_SIZE(lane->batch) && ! raw_writer_buffers_t_is_empty(&lane->buffers))
            lane->batch[lane->batch_count++] = raw_writer_buffers_t_pull_front(&lane->buffers);
    }

    bool failed = false;
    if (lane->batch_count != 0)
    {
        const size_t                    remaining = lane->batch_count - lane->batch_offset;
        const raw_writer_batch_result_t result =
            generation->write_batch(generation->context, worker, lane, &lane->batch[lane->batch_offset], remaining);
        if (UNLIKELY(result.consumed > remaining || result.status > kRawWriterBatchFailed))
        {
            LOGF("RawWriter: native callback returned invalid batch ownership");
            abortProgramNow(1);
        }
        lane->batch_offset += result.consumed;
        rawWriterReleasePackets(generation, result.consumed);
        if (lane->batch_offset == lane->batch_count)
            lane->batch_count = lane->batch_offset = 0;

        if (result.status == kRawWriterBatchFailed)
            failed = ! atomicExchangeExplicit(&generation->failed, true, memory_order_acq_rel);
        else if (lane->batch_count != 0 || ! raw_writer_buffers_t_is_empty(&lane->buffers))
        {
            if (result.status == kRawWriterBatchBlocked && generation->retry_delay_ms == 0)
                lane->scheduled = true; /* Exactly one native completion will Notify. */
            else
            {
                const uint32_t delay = result.status == kRawWriterBatchBlocked ? generation->retry_delay_ms : 0;
                /* Refused continuation retains ownership for native retirement,
                 * including an externally borrowed buffer in another lane. */
                discard rawWriterSchedule(generation, lane, delay);
            }
        }
    }
    quiescenceGateLeave(&generation->gate);
    rawWriterGenerationUnref(generation);
    if (failed && ! requestProgramShutdown(1))
        abortProgramNow(1);
}

void rawWriterInit(raw_writer_t *writer)
{
    *writer = (raw_writer_t) {0};
    atomicStoreRelaxed(&writer->published_generation, (uintptr_t) NULL);
}

bool rawWriterOpen(raw_writer_t *writer, size_t packet_limit, uint32_t retry_delay_ms, void *context,
                   raw_writer_batch_fn write_batch, raw_writer_stop_fn stop_worker)
{
    assert(write_batch != NULL);
    assert(GSTATE.flag_initialized);
    if (writer->current != NULL || packet_limit == 0 || packet_limit > (size_t) PTRDIFF_MAX / (2U * sizeof(sbuf_t *)))
        return false;
    const size_t worker_count = getWorkersCount();
    assert(worker_count > 0);
    raw_writer_generation_t *generation =
        memoryAllocateZero(sizeof(*generation) + worker_count * sizeof(generation->lanes[0]));
    generation->packet_limit   = packet_limit;
    generation->worker_count   = worker_count;
    generation->retry_delay_ms = retry_delay_ms;
    generation->context        = context;
    generation->write_batch    = write_batch;
    generation->stop_worker    = stop_worker;
    atomicStoreRelaxed(&generation->references, 1);
    for (wid_t wid = 0; wid < worker_count; ++wid)
    {
        generation->lanes[wid].generation = generation;
        generation->lanes[wid].wid        = wid;
    }
    quiescenceGateInit(&generation->gate);
    if (! quiescenceGateOpen(&generation->gate))
    {
        rawWriterGenerationUnref(generation);
        return false;
    }
    writer->current = generation;
    atomicStoreExplicit(&writer->published_generation, (uintptr_t) generation, memory_order_release);
    return true;
}

void rawWriterCloseRequest(raw_writer_t *writer)
{
    raw_writer_generation_t *generation = (raw_writer_generation_t *) atomicExchangeExplicit(
        &writer->published_generation, (uintptr_t) NULL, memory_order_acq_rel);
    if (generation != NULL)
    {
        assert(generation == writer->current);
        quiescenceGateClose(&generation->gate);
    }
}

void rawWriterCloseWait(raw_writer_t *writer)
{
    rawWriterCloseRequest(writer);
    raw_writer_generation_t *generation = writer->current;
    if (generation == NULL)
        return;
    quiescenceGateWaitQuiesced(&generation->gate, quiescenceGateYieldThread, NULL);
    if (generation->stop_worker != NULL)
        for (wid_t wid = 0; wid < generation->worker_count; ++wid)
            generation->stop_worker(generation->context, wid);
    for (size_t i = 0; i < generation->worker_count; ++i)
    {
        rawWriterDiscardLane(&generation->lanes[i]);
        raw_writer_buffers_t_drop(&generation->lanes[i].buffers);
    }
    generation->context = NULL;
    generation->next    = writer->retired;
    writer->retired     = generation;
    writer->current     = NULL;
}

void rawWriterDestroy(raw_writer_t *writer)
{
    rawWriterCloseWait(writer);
    raw_writer_generation_t *generation = writer->retired;
    writer->retired                     = NULL;
    while (generation != NULL)
    {
        raw_writer_generation_t *next = generation->next;
        rawWriterGenerationUnref(generation);
        generation = next;
    }
}

raw_writer_send_result_t rawWriterTrySend(raw_writer_t *writer, sbuf_t *buffer)
{
    worker_t                *worker = getCurrentWorker();
    raw_writer_generation_t *generation =
        (raw_writer_generation_t *) atomicLoadExplicit(&writer->published_generation, memory_order_acquire);
    if (generation == NULL)
        return kRawWriterSendDown;
    if (! quiescenceGateEnter(&generation->gate))
        return kRawWriterSendClosed;
    assert(worker->wid < generation->worker_count);
    raw_writer_lane_t       *lane   = &generation->lanes[worker->wid];
    raw_writer_send_result_t result = kRawWriterSendClosed;
    if (atomicLoadExplicit(&generation->failed, memory_order_acquire) ||
        atomicLoadExplicit(&lane->cancelled, memory_order_acquire))
        goto done;
    result = kRawWriterSendFull;
    if (! rawWriterReservePacket(generation))
        goto done;
    discard raw_writer_buffers_t_push_back(&lane->buffers, buffer);
    if (! lane->scheduled && ! rawWriterSchedule(generation, lane, 0))
    {
        assert(lane->batch_count == 0 && raw_writer_buffers_t_size(&lane->buffers) == 1);
        discard raw_writer_buffers_t_pull_back(&lane->buffers);
        atomicStoreExplicit(&lane->cancelled, false, memory_order_release);
        rawWriterReleasePackets(generation, 1);
        result = kRawWriterSendClosed;
        goto done;
    }
    result = kRawWriterSendOk;
done:
    quiescenceGateLeave(&generation->gate);
    return result;
}

bool rawWriterNotify(raw_writer_lane_t *lane)
{
    raw_writer_generation_t *generation = lane->generation;
    assert(generation->retry_delay_ms == 0);
    if (! quiescenceGateEnter(&generation->gate))
        return false;
    const bool accepted = ! atomicLoadExplicit(&generation->failed, memory_order_acquire) &&
                          ! atomicLoadExplicit(&lane->cancelled, memory_order_acquire) &&
                          rawWriterPostToken(generation, lane, 0);
    quiescenceGateLeave(&generation->gate);
    return accepted;
}
