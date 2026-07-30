// Regression tests for wchan close semantics.
//
// chanClose() used to signal its waiters without removing them from the wait queues, and
// chanSend() ignored the cancellation flag afterwards. A sender blocked at close therefore
// reported success for a message that was never delivered, the closed channel kept handing
// out that canceled message through a Thr that had already returned to its caller, and the
// cancellation flag stayed set on the thread forever, breaking the next channel it used.

#include "wchan.h"
#include "wthread.h"

#include <stdio.h>
#include <stdlib.h>

enum
{
    kParkSettleMs = 150, // time allowed for a worker to reach its blocking call
    kJoinWaitMs   = 150
};

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
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

    wwSleepMS(kParkSettleMs); // let the worker block in chanSend
    chanClose(canceled);
    wwSleepMS(kJoinWaitMs);

    require(! worker.send_result, "a send canceled by close must return false");

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
    require(threadJoin(thread) == 0, "worker thread should join");
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

    wwSleepMS(kParkSettleMs); // let the worker block in chanRecv
    chanClose(canceled);
    wwSleepMS(kJoinWaitMs);

    require(! worker.recv_result, "a recv canceled by close must return false");

    int fresh_message = 7;
    require(chanSend(fresh, &fresh_message), "send on the fresh channel should succeed");
    require(threadJoin(thread) == 0, "worker thread should join");
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

int main(void)
{
    testCanceledSenderReportsFailure();
    testCanceledReceiverStaysUsable();
    testBufferedRoundTrip();

    printf("wchan close semantics tests passed\n");
    return 0;
}
