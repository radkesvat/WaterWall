// Regression tests for wchan close semantics.
//
// chanClose() used to signal its waiters without removing them from the wait queues, and
// chanSend() ignored the cancellation flag afterwards. A sender blocked at close therefore
// reported success for a message that was never delivered, the closed channel kept handing
// out that canceled message through a Thr that had already returned to its caller, and the
// cancellation flag stayed set on the thread forever, breaking the next channel it used.

#include "wwapi.h"

enum
{
    kParkWaitMs              = 5000, // ceiling for a worker to reach its blocking call
    kMpscMessagesPerProducer = 2048,
};

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

// Waits until a worker is really parked on c. Closing on a timer instead would race the
// worker on a loaded machine, and a send that arrives after the close aborts the process
// by design rather than exercising cancellation.
static void waitUntilParked(wchan_t *c, bool senders)
{
    for (unsigned int i = 0; i < kParkWaitMs; i++)
    {
        if (chanWaiterCount(c, senders) > 0)
        {
            return;
        }
        wwSleepMS(1);
    }
    require(false, "timed out waiting for the worker to park on the channel");
}

typedef struct sender_worker_s
{
    wchan_t *canceled_channel; // full channel this worker blocks on until it is closed
    wchan_t *fresh_channel;    // channel the worker uses after being canceled
    int      message;
    bool     send_result;
    bool     fresh_recv_result;
    int      fresh_recv_value;
} sender_worker_t;

typedef struct receiver_worker_s
{
    wchan_t *canceled_channel; // empty channel this worker blocks on until it is closed
    wchan_t *fresh_channel;
    bool     recv_result;
    int      recv_value;
    bool     fresh_recv_result;
    int      fresh_recv_value;
} receiver_worker_t;

static WTHREAD_ROUTINE(senderWorkerMain) // NOLINT
{
    sender_worker_t *worker = userdata;

    // Blocks: the channel buffer is full and no receiver is coming. Only the close wakes it.
    worker->send_result = chanSend(worker->canceled_channel, &worker->message);

    // The same thread now waits on an unrelated channel that is open and has a message coming.
    worker->fresh_recv_value  = -1;
    worker->fresh_recv_result = chanRecv(worker->fresh_channel, &worker->fresh_recv_value);
    return (HTHREAD_RETTYPE) 0;
}

static WTHREAD_ROUTINE(receiverWorkerMain) // NOLINT
{
    receiver_worker_t *worker = userdata;

    worker->recv_value  = -1;
    worker->recv_result = chanRecv(worker->canceled_channel, &worker->recv_value);

    worker->fresh_recv_value  = -1;
    worker->fresh_recv_result = chanRecv(worker->fresh_channel, &worker->fresh_recv_value);
    return (HTHREAD_RETTYPE) 0;
}

// A sender blocked at close time must report failure, and the message it was carrying must
// not survive in the closed channel. The same thread must then be usable on a new channel.
static void testCanceledSenderReportsFailure(void)
{
    wchan_t *canceled = chanOpen(sizeof(int), 1);
    wchan_t *fresh    = chanOpen(sizeof(int), 1);

    int buffered = 11;
    require(chanSend(canceled, &buffered), "buffered send should succeed");

    sender_worker_t worker = {.canceled_channel = canceled, .fresh_channel = fresh, .message = 22};
    wthread_t       thread;
    require(threadCreate(&thread, senderWorkerMain, &worker) == kWThreadErrorNone, "worker thread should start");

    waitUntilParked(canceled, true);
    chanClose(canceled);

    // Draining must yield the message that was really queued, and nothing else: the canceled
    // sender is gone, so its Thr and the stack address it parked with must not be touched.
    int  value  = -1;
    bool closed = false;
    require(chanTryRecv(canceled, &value, &closed), "closed channel should still deliver queued messages");
    require(value == 11, "closed channel delivered the wrong message");

    value  = -1;
    closed = false;
    require(! chanTryRecv(canceled, &value, &closed), "closed channel must not deliver a canceled message");
    require(closed, "drained closed channel should report closed");

    // The cancellation must not leak into the next channel this thread waits on.
    int fresh_message = 42;
    require(chanSend(fresh, &fresh_message), "send on the fresh channel should succeed");

    // Everything the worker reports is read after the join, which is what publishes it.
    require(threadJoin(thread) == 0, "worker thread should join");
    require(! worker.send_result, "a send canceled by close must return false");
    require(worker.fresh_recv_result, "recv on a fresh channel must succeed after an earlier close");
    require(worker.fresh_recv_value == 42, "recv on a fresh channel returned the wrong message");

    chanFree(canceled);
    chanClose(fresh);
    chanFree(fresh);
}

// Same for the receive side: a receiver canceled by close reports closed, and stays usable.
static void testCanceledReceiverStaysUsable(void)
{
    wchan_t *canceled = chanOpen(sizeof(int), 1);
    wchan_t *fresh    = chanOpen(sizeof(int), 1);

    receiver_worker_t worker = {.canceled_channel = canceled, .fresh_channel = fresh};
    wthread_t         thread;
    require(threadCreate(&thread, receiverWorkerMain, &worker) == kWThreadErrorNone, "worker thread should start");

    waitUntilParked(canceled, false);
    chanClose(canceled);

    int fresh_message = 7;
    require(chanSend(fresh, &fresh_message), "send on the fresh channel should succeed");

    // Everything the worker reports is read after the join, which is what publishes it.
    require(threadJoin(thread) == 0, "worker thread should join");
    require(! worker.recv_result, "a recv canceled by close must return false");
    require(worker.fresh_recv_result, "recv on a fresh channel must succeed after an earlier close");
    require(worker.fresh_recv_value == 7, "recv on a fresh channel returned the wrong message");

    chanFree(canceled);
    chanClose(fresh);
    chanFree(fresh);
}

// Ordinary buffered traffic and the closed-and-empty report must keep working.
static void testBufferedRoundTrip(void)
{
    wchan_t *c = chanOpen(sizeof(int), 4);

    for (int i = 0; i < 4; i++)
    {
        require(chanSend(c, &i), "buffered send should succeed");
    }

    int  overflow = 99;
    bool closed   = false;
    require(! chanTrySend(c, &overflow, &closed), "try-send on a full channel should fail");
    require(! closed, "a full channel is not a closed channel");

    for (int i = 0; i < 4; i++)
    {
        int value = -1;
        require(chanRecv(c, &value), "buffered recv should succeed");
        require(value == i, "buffered recv returned messages out of order");
    }

    chanClose(c);

    int value = -1;
    closed    = false;
    require(! chanTryRecv(c, &value, &closed), "try-recv on a closed empty channel should fail");
    require(closed, "try-recv on a closed empty channel should report closed");

    chanFree(c);
}

/* Repeated capacity-one transitions exercise both ring indices after every wrap. */
static void testCapacityOneRepeatedWrap(void)
{
    wchan_t *channel = chanOpen(sizeof(uint32_t), 1);

    for (uint32_t value = 0; value < 4096; ++value)
    {
        bool closed = false;
        require(chanTrySend(channel, &value, &closed), "capacity-one channel rejected an empty-slot send");

        const uint32_t overflow = value ^ UINT32_C(0xA5A5A5A5);
        closed                  = false;
        require(! chanTrySend(channel, (void *) &overflow, &closed), "capacity-one channel did not report full");
        require(! closed, "capacity-one full channel reported closed");

        uint32_t received = UINT32_MAX;
        require(chanTryRecv(channel, &received, &closed), "capacity-one channel lost a queued value");
        require(received == value, "capacity-one channel returned the wrong wrapped value");

        closed = false;
        require(! chanTryRecv(channel, &received, &closed), "capacity-one channel did not become empty");
        require(! closed, "open empty capacity-one channel reported closed");
    }

    chanClose(channel);
    chanFree(channel);
}

/* Capacity three catches wrap arithmetic that happens to work only for powers of two. */
static void testCapacityThreePartialDrainWrap(void)
{
    wchan_t *channel = chanOpen(sizeof(uint32_t), 3);

    for (uint32_t base = 0; base < 4096; base += 3)
    {
        uint32_t value = base;
        require(chanSend(channel, &value), "capacity-three channel rejected first fill");
        value = base + 1;
        require(chanSend(channel, &value), "capacity-three channel rejected second fill");
        value = base + 2;
        require(chanSend(channel, &value), "capacity-three channel rejected third fill");

        for (uint32_t expected = base; expected < base + 2; ++expected)
        {
            uint32_t received = UINT32_MAX;
            require(chanRecv(channel, &received), "capacity-three channel lost a partial-drain value");
            require(received == expected, "capacity-three channel reordered a partial-drain value");
        }

        value = base + 3;
        require(chanSend(channel, &value), "capacity-three channel rejected first refill");
        value = base + 4;
        require(chanSend(channel, &value), "capacity-three channel rejected second refill");

        for (uint32_t expected = base + 2; expected < base + 5; ++expected)
        {
            uint32_t received = UINT32_MAX;
            require(chanRecv(channel, &received), "capacity-three channel lost a wrapped value");
            require(received == expected, "capacity-three channel reordered a wrapped value");
        }
    }

    chanClose(channel);
    chanFree(channel);
}

typedef struct mpsc_producer_s
{
    wchan_t    *channel;
    uint32_t    producer_id;
    uint32_t    tokens;
    atomic_bool start;
    atomic_bool observed_full;
    atomic_uint full_results;
} mpsc_producer_t;

static WTHREAD_ROUTINE(mpscProducerMain) // NOLINT
{
    mpsc_producer_t *producer = userdata;

    while (! atomicLoadExplicit(&producer->start, memory_order_acquire))
    {
        YIELD_THREAD();
    }

    for (uint32_t sequence = 0; sequence < producer->tokens; ++sequence)
    {
        const uint64_t token = ((uint64_t) producer->producer_id << 32U) | sequence;
        for (;;)
        {
            bool closed = false;
            if (chanTrySend(producer->channel, (void *) &token, &closed))
            {
                break;
            }
            require(! closed, "open MPSC channel reported closed while producers were active");
            atomicIncRelaxed(&producer->full_results);
            atomicStoreExplicit(&producer->observed_full, true, memory_order_release);
            YIELD_THREAD();
        }
    }
    return (HTHREAD_RETTYPE) 0;
}

static void testMpscExactnessAndFullTransitions(unsigned int producer_count)
{
    wchan_t         *channel   = chanOpen(sizeof(uint64_t), 3);
    mpsc_producer_t *producers = memoryAllocateZero((size_t) producer_count * sizeof(*producers));
    wthread_t       *threads   = memoryAllocate((size_t) producer_count * sizeof(*threads));
    uint32_t        *expected  = memoryAllocateZero((size_t) producer_count * sizeof(*expected));
    require(producers != NULL && threads != NULL && expected != NULL, "failed to allocate MPSC channel fixture");

    for (unsigned int producer = 0; producer < producer_count; ++producer)
    {
        producers[producer] = (mpsc_producer_t) {
            .channel       = channel,
            .producer_id   = producer,
            .tokens        = kMpscMessagesPerProducer,
            .start         = false,
            .observed_full = false,
            .full_results  = 0,
        };
        require(threadCreate(&threads[producer], mpscProducerMain, &producers[producer]) == kWThreadErrorNone,
                "failed to create an MPSC producer");
    }

    for (unsigned int producer = 0; producer < producer_count; ++producer)
    {
        atomicStoreExplicit(&producers[producer].start, true, memory_order_release);
    }

    /* Let every producer prove it crossed the full boundary before consuming. */
    for (unsigned int producer = 0; producer < producer_count; ++producer)
    {
        while (! atomicLoadExplicit(&producers[producer].observed_full, memory_order_acquire))
        {
            YIELD_THREAD();
        }
    }

    const uint64_t expected_total = (uint64_t) producer_count * kMpscMessagesPerProducer;
    uint64_t       received_total = 0;
    while (received_total < expected_total)
    {
        uint64_t token  = UINT64_MAX;
        bool     closed = false;
        if (! chanTryRecv(channel, &token, &closed))
        {
            require(! closed, "MPSC channel closed before every accepted token drained");
            YIELD_THREAD();
            continue;
        }

        const uint32_t producer = (uint32_t) (token >> 32U);
        const uint32_t sequence = (uint32_t) token;
        require(producer < producer_count, "MPSC channel delivered a token with an invalid producer id");
        require(sequence == expected[producer], "MPSC channel lost, duplicated, or reordered a producer token");
        ++expected[producer];
        ++received_total;
    }

    for (unsigned int producer = 0; producer < producer_count; ++producer)
    {
        require(threadJoin(threads[producer]) == 0, "failed to join an MPSC producer");
        require(expected[producer] == kMpscMessagesPerProducer,
                "MPSC channel did not deliver every token from one producer");
        require(atomicLoadRelaxed(&producers[producer].full_results) != 0,
                "MPSC producer never exercised the Full refusal path");
    }

    chanClose(channel);
    chanFree(channel);
    memoryFree(expected);
    memoryFree(threads);
    memoryFree(producers);
}

typedef struct fast_full_close_probe_s
{
    wchan_t    *channel;
    int         attempted;
    bool        sent;
    bool        closed;
    atomic_bool observed_fast_full;
    atomic_bool release_sender;
} fast_full_close_probe_t;

static void pauseAfterFastFullObservation(wchan_t *channel, void *context)
{
    fast_full_close_probe_t *probe = context;
    require(channel == probe->channel, "fast-full hook received the wrong channel");
    atomicStoreExplicit(&probe->observed_fast_full, true, memory_order_release);
    while (! atomicLoadExplicit(&probe->release_sender, memory_order_acquire))
    {
        YIELD_THREAD();
    }
}

static WTHREAD_ROUTINE(fastFullCloseSenderMain) // NOLINT
{
    fast_full_close_probe_t *probe = userdata;
    probe->closed                  = false;
    probe->sent                    = chanTrySend(probe->channel, &probe->attempted, &probe->closed);
    return (HTHREAD_RETTYPE) 0;
}

/* A close after the documented open/full observation may legally return Full, never consume the token. */
static void testCloseVersusFastFullRejection(void)
{
    wchan_t *channel = chanOpen(sizeof(int), 1);
    int      queued  = 71;
    require(chanSend(channel, &queued), "could not prefill close-race channel");

    fast_full_close_probe_t probe = {
        .channel            = channel,
        .attempted          = 72,
        .observed_fast_full = false,
        .release_sender     = false,
    };
    chanInstallAfterTrySendFastFullHook(pauseAfterFastFullObservation, &probe);

    wthread_t sender;
    require(threadCreate(&sender, fastFullCloseSenderMain, &probe) == kWThreadErrorNone,
            "failed to create close-race sender");
    while (! atomicLoadExplicit(&probe.observed_fast_full, memory_order_acquire))
    {
        YIELD_THREAD();
    }

    chanClose(channel);
    atomicStoreExplicit(&probe.release_sender, true, memory_order_release);
    require(threadJoin(sender) == 0, "failed to join close-race sender");
    chanInstallAfterTrySendFastFullHook(NULL, NULL);

    require(! probe.sent && ! probe.closed,
            "an already observed open/full channel did not report the legal Full result after close");

    int  received = -1;
    bool closed   = false;
    require(chanTryRecv(channel, &received, &closed), "close-race channel lost a pre-close item");
    require(received == queued, "close-race channel returned the wrong pre-close item");
    require(! chanTryRecv(channel, &received, &closed) && closed,
            "close-race channel delivered a post-close fast-full token");
    chanFree(channel);
}

int main(void)
{
    testCanceledSenderReportsFailure();
    testCanceledReceiverStaysUsable();
    testBufferedRoundTrip();
    testCapacityOneRepeatedWrap();
    testCapacityThreePartialDrainWrap();
    testMpscExactnessAndFullTransitions(2);
    testMpscExactnessAndFullTransitions(4);
    testCloseVersusFastFullRejection();

    printf("wchan close semantics tests passed\n");
    return 0;
}
