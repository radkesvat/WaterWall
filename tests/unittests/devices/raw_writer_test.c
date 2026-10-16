/* Native-prefix ownership, timed backpressure, external completion, FIFO,
 * cancellation and generation retirement. Syscall policy remains backend-local.
 * CTest: waterwall.raw_writer_unit */
#include "wwapi.h"

#include "devices/raw/raw_writer.h"
#include "fixtures/worker_registry_fixture.h"
#include "test_assert.h"

#include <pthread.h>

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

typedef struct captured_s
{
    wid_t                        wid;
    uint32_t                     delay;
    WorkerMessageCallback        callback;
    WorkerMessageCleanupCallback cleanup;
    void                        *arg1;
    void                        *arg2;
    void                        *arg3;
} captured_t;

enum
{
    kCapturedMax = 64,
    kOutputMax   = 1024
};
static captured_t        captured[kCapturedMax];
static size_t            captured_count;
static bool              reject_next;
static pthread_mutex_t   capture_mutex = PTHREAD_MUTEX_INITIALIZER;
static atomic_uint       disposals;
static atomic_uint       shutdowns;
static _Atomic(sbuf_t *) borrowed[2];
static pthread_mutex_t   output_mutex = PTHREAD_MUTEX_INITIALIZER;
static atomic_uint       native_entered;
static atomic_bool       native_release;
static atomic_bool       close_started;
static atomic_bool       close_finished;

typedef struct output_s
{
    unsigned                  sequences[2][kOutputMax];
    size_t                    counts[2];
    unsigned                  first[32];
    size_t                    batch_sizes[32];
    size_t                    calls;
    size_t                    prefix;
    raw_writer_batch_status_t status;
    raw_writer_lane_t        *lanes[2];
    bool                      borrow;
    bool                      block;
    unsigned                  stopped;
} output_t;

worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *arg1, void *arg2, void *arg3);
worker_message_submit_result_e __wrap_sendWorkerMessageTimedWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                                        WorkerMessageCleanupCallback cleanup,
                                                                        uint32_t delay, void *arg1, void *arg2,
                                                                        void *arg3);
void                           __real_sbufDestroy(sbuf_t *buffer);
void                           __wrap_sbufDestroy(sbuf_t *buffer);
bool                           __wrap_requestProgramShutdown(int code);

static worker_message_submit_result_e capture(wid_t wid, uint32_t delay, WorkerMessageCallback callback,
                                              WorkerMessageCleanupCallback cleanup, void *arg1, void *arg2, void *arg3)
{
    pthread_mutex_lock(&capture_mutex);
    if (reject_next)
    {
        reject_next = false;
        pthread_mutex_unlock(&capture_mutex);
        cleanup(arg1, arg2, arg3, kWorkerMessageCancelEnqueueFailure);
        return kWorkerMessageSubmitRejectedCleanupRan;
    }
    require(captured_count < kCapturedMax, "too many queued drain tokens");
    captured[captured_count++] = (captured_t) {wid, delay, callback, cleanup, arg1, arg2, arg3};
    pthread_mutex_unlock(&capture_mutex);
    return kWorkerMessageSubmitAccepted;
}

worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *arg1, void *arg2, void *arg3)
{
    return capture(wid, 0, callback, cleanup, arg1, arg2, arg3);
}

worker_message_submit_result_e __wrap_sendWorkerMessageTimedWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                                        WorkerMessageCleanupCallback cleanup,
                                                                        uint32_t delay, void *arg1, void *arg2,
                                                                        void *arg3)
{
    require(delay == 1, "blocked writer must use bounded delayed retry");
    return capture(wid, delay, callback, cleanup, arg1, arg2, arg3);
}

void __wrap_sbufDestroy(sbuf_t *buffer)
{
    for (size_t i = 0; i < ARRAY_SIZE(borrowed); ++i)
        require(atomic_load_explicit(&borrowed[i], memory_order_acquire) != buffer,
                "buffer released before native borrow retired");
    atomicIncRelaxed(&disposals);
    __real_sbufDestroy(buffer);
}

bool __wrap_requestProgramShutdown(int code)
{
    require(code == 1, "wrong fatal exit code");
    atomicIncRelaxed(&shutdowns);
    return true;
}

static captured_t takeToken(size_t index)
{
    pthread_mutex_lock(&capture_mutex);
    require(index < captured_count, "missing drain token");
    captured_t token = captured[index];
    memoryMove(&captured[index], &captured[index + 1], (captured_count - index - 1) * sizeof(captured[0]));
    captured_count--;
    pthread_mutex_unlock(&capture_mutex);
    return token;
}

static void runToken(captured_t token)
{
    testWorkerBindWID(token.wid);
    token.callback(getWorker(token.wid), token.arg1, token.arg2, token.arg3);
}

static void runAll(void)
{
    size_t turns = 0;
    while (captured_count != 0)
    {
        require(++turns <= 32, "drain made no bounded progress");
        runToken(takeToken(0));
    }
    testWorkerBindWID(0);
}

static sbuf_t *packet(unsigned sequence)
{
    sbuf_t *buffer = sbufCreate(64);
    memoryCopy(sbufGetMutablePtr(buffer), &sequence, sizeof(sequence));
    sbufSetLength(buffer, sizeof(sequence));
    return buffer;
}

static unsigned sequence(const sbuf_t *buffer)
{
    unsigned value;
    memoryCopy(&value, sbufGetRawPtr(buffer), sizeof(value));
    return value;
}

static raw_writer_batch_result_t writeBatch(void *context, worker_t *worker, raw_writer_lane_t *lane, sbuf_t **buffers,
                                            size_t count)
{
    output_t *output = context;
    require(currentThreadIsEventWorkerWID(worker->wid), "native write escaped owner");
    require(count > 0 && count <= kRawWriterBatchPackets, "native batch exceeded 512 packets");
    pthread_mutex_lock(&output_mutex);
    require(output->calls < ARRAY_SIZE(output->first), "native observation capacity");
    output->first[output->calls]         = sequence(buffers[0]);
    output->batch_sizes[output->calls++] = count;
    output->lanes[worker->wid]           = lane;
    const size_t consumed                = min(output->prefix, count);
    for (size_t i = 0; i < consumed; ++i)
    {
        require(output->counts[worker->wid] < kOutputMax, "output observation capacity");
        output->sequences[worker->wid][output->counts[worker->wid]++] = sequence(buffers[i]);
        sbufDestroy(buffers[i]);
    }
    if (output->borrow)
    {
        require(consumed < count, "native borrow has no remaining buffer");
        atomic_store_explicit(&borrowed[worker->wid], buffers[consumed], memory_order_release);
    }
    pthread_mutex_unlock(&output_mutex);
    if (output->block)
    {
        atomicIncExplicit(&native_entered, memory_order_release);
        while (! atomicLoadExplicit(&native_release, memory_order_acquire))
            sched_yield();
    }
    return (raw_writer_batch_result_t) {.consumed = consumed, .status = output->status};
}

static void stopWorker(void *context, wid_t wid)
{
    output_t *output = context;
    sbuf_t   *buffer = atomic_exchange_explicit(&borrowed[wid], NULL, memory_order_acq_rel);
    if (buffer != NULL)
        require(sbufGetLength(buffer) == sizeof(unsigned), "native retirement saw freed buffer");
    output->stopped++;
}

static void testBatchAndPartialFifo(void)
{
    raw_writer_t writer;
    output_t     output = {.prefix = SIZE_MAX};
    rawWriterInit(&writer);
    require(rawWriterOpen(&writer, 1024, 1, &output, writeBatch, stopWorker), "open batching writer");
    for (unsigned i = 0; i < 513; ++i)
        require(rawWriterTrySend(&writer, packet(i)) == kRawWriterSendOk, "batch admission");
    require(captured_count == 1 && output.calls == 0, "submission wrote inline or did not coalesce");
    runAll();
    require(output.calls == 2 && output.batch_sizes[0] == 512 && output.batch_sizes[1] == 1, "512-packet drain bound");
    for (unsigned i = 0; i < 513; ++i)
        require(output.sequences[0][i] == i, "batch FIFO");
    rawWriterDestroy(&writer);

    output = (output_t) {.prefix = 1};
    require(rawWriterOpen(&writer, 8, 1, &output, writeBatch, stopWorker), "open partial writer");
    for (unsigned i = 0; i < 3; ++i)
        require(rawWriterTrySend(&writer, packet(i)) == kRawWriterSendOk, "partial admission");
    runToken(takeToken(0));
    require(captured_count == 1 && captured[0].delay == 0, "partial write must yield a continuation");
    require(rawWriterTrySend(&writer, packet(3)) == kRawWriterSendOk, "later packet admission");
    output.prefix = SIZE_MAX;
    runAll();
    require(output.calls == 3 && output.batch_sizes[1] == 2 && output.first[1] == 1 && output.first[2] == 3,
            "partial suffix changed batch or was overtaken");
    rawWriterDestroy(&writer);
}

static void testInterruptedYield(void)
{
    raw_writer_t writer;
    output_t     output = {0};
    rawWriterInit(&writer);
    require(rawWriterOpen(&writer, 8, 1, &output, writeBatch, stopWorker), "open interrupted writer");
    require(rawWriterTrySend(&writer, packet(0)) == kRawWriterSendOk, "interrupted admission");
    runToken(takeToken(0));
    require(output.calls == 1 && captured_count == 1 && captured[0].delay == 0,
            "zero-progress interruption did not yield bounded continuation");
    output.prefix = SIZE_MAX;
    runAll();
    require(output.counts[0] == 1, "interrupted packet was lost");
    rawWriterDestroy(&writer);
}

static void testBlockedBudgetAndRetry(void)
{
    raw_writer_t writer;
    output_t     output = {.prefix = 1, .status = kRawWriterBatchBlocked};
    rawWriterInit(&writer);
    require(rawWriterOpen(&writer, 4, 1, &output, writeBatch, stopWorker), "open blocked writer");
    for (unsigned i = 0; i < 4; ++i)
        require(rawWriterTrySend(&writer, packet(i)) == kRawWriterSendOk, "blocked admission");
    runToken(takeToken(0));
    require(captured_count == 1 && captured[0].delay == 1 && output.counts[0] == 1,
            "blocked write spun or failed to retain suffix");
    testWorkerBindWID(1);
    require(rawWriterTrySend(&writer, packet(4)) == kRawWriterSendOk, "consumed prefix did not release capacity");
    sbuf_t *refused = packet(5);
    require(rawWriterTrySend(&writer, refused) == kRawWriterSendFull, "active suffix escaped shared backlog bound");
    sbufDestroy(refused);
    output.prefix = SIZE_MAX;
    output.status = kRawWriterBatchContinue;
    runAll();
    require(output.counts[0] == 4 && output.counts[1] == 1 && output.first[1] == 1, "timed retry changed suffix order");
    rawWriterDestroy(&writer);
}

static void *notifyForeign(void *arg)
{
    require(! currentThreadIsEventWorker(), "completion fixture has worker identity");
    require(rawWriterNotify(arg), "foreign native completion was refused");
    return NULL;
}

static void *cancelForeign(void *arg)
{
    captured_t *token = arg;
    require(! currentThreadIsEventWorker(), "cancellation fixture has worker identity");
    token->cleanup(token->arg1, token->arg2, token->arg3, kWorkerMessageCancelTeardown);
    return NULL;
}

static void testExternalCompletionAndRetirement(void)
{
    raw_writer_t writer;
    output_t     output = {.status = kRawWriterBatchBlocked, .borrow = true};
    rawWriterInit(&writer);
    require(rawWriterOpen(&writer, 8, 0, &output, writeBatch, stopWorker), "open external writer");
    require(rawWriterTrySend(&writer, packet(0)) == kRawWriterSendOk, "external initial admission");
    runAll();
    require(captured_count == 0 && output.calls == 1, "external wait scheduled timed or spinning retry");
    require(rawWriterTrySend(&writer, packet(1)) == kRawWriterSendOk, "external queued follower");
    require(captured_count == 0, "later submission bypassed pending native borrow");
    atomic_store_explicit(&borrowed[0], NULL, memory_order_release); /* Native completion. */
    output.borrow = false;
    output.prefix = SIZE_MAX;
    output.status = kRawWriterBatchContinue;
    pthread_t completion;
    require(pthread_create(&completion, NULL, notifyForeign, output.lanes[0]) == 0, "completion create");
    require(pthread_join(completion, NULL) == 0, "completion join");
    runAll();
    require(output.counts[0] == 2 && output.sequences[0][0] == 0 && output.sequences[0][1] == 1,
            "external completion violated FIFO");
    rawWriterDestroy(&writer);

    output = (output_t) {.status = kRawWriterBatchBlocked, .borrow = true};
    require(rawWriterOpen(&writer, 8, 0, &output, writeBatch, stopWorker), "open pending-stop writer");
    require(rawWriterTrySend(&writer, packet(2)) == kRawWriterSendOk, "pending-stop admission");
    runAll();
    const unsigned before = atomicLoadRelaxed(&disposals);
    rawWriterCloseRequest(&writer);
    require(! rawWriterNotify(output.lanes[0]), "closed generation accepted completion");
    rawWriterCloseWait(&writer);
    require(output.stopped == 2 && atomicLoadRelaxed(&disposals) == before + 1,
            "native stop did not precede borrowed-buffer disposal");
    rawWriterDestroy(&writer);
}

static void testFailureRetainsOtherNativeBorrows(void)
{
    raw_writer_t writer;
    output_t     output = {.status = kRawWriterBatchBlocked, .borrow = true};
    rawWriterInit(&writer);
    require(rawWriterOpen(&writer, 8, 0, &output, writeBatch, stopWorker), "open multi-worker failure");
    require(rawWriterTrySend(&writer, packet(0)) == kRawWriterSendOk, "native-borrow admission");
    runAll();
    testWorkerBindWID(1);
    output.borrow = false;
    output.status = kRawWriterBatchFailed;
    require(rawWriterTrySend(&writer, packet(1)) == kRawWriterSendOk, "failing-worker admission");
    const unsigned before = atomicLoadRelaxed(&disposals);
    runAll();
    require(atomicLoadRelaxed(&shutdowns) == 1 && atomicLoadRelaxed(&disposals) == before,
            "failure discarded another lane's pending borrow");
    rawWriterDestroy(&writer);
    require(atomicLoadRelaxed(&disposals) == before + 2, "failed generation did not settle after native stop");
}

static void testRefusalCancellationAndStaleTokens(void)
{
    raw_writer_t writer;
    output_t     old = {.prefix = SIZE_MAX}, reopened = {.prefix = SIZE_MAX};
    rawWriterInit(&writer);
    require(rawWriterOpen(&writer, 8, 1, &old, writeBatch, stopWorker), "open refusal writer");
    sbuf_t *buffer = packet(0);
    reject_next    = true;
    require(rawWriterTrySend(&writer, buffer) == kRawWriterSendClosed, "refusal not returned to caller");
    require(rawWriterTrySend(&writer, buffer) == kRawWriterSendOk, "refusal consumed original buffer");
    captured_t stale = takeToken(0);
    rawWriterCloseWait(&writer);
    require(rawWriterOpen(&writer, 8, 1, &reopened, writeBatch, stopWorker), "reopen writer");
    runToken(stale);
    require(old.calls == 0 && reopened.calls == 0, "stale generation invoked native callback");
    require(rawWriterTrySend(&writer, packet(1)) == kRawWriterSendOk, "cancelled-token admission");
    captured_t cancelled = takeToken(0);
    pthread_t  thread;
    require(pthread_create(&thread, NULL, cancelForeign, &cancelled) == 0, "foreign cancellation create");
    require(pthread_join(thread, NULL) == 0, "foreign cancellation join");
    rawWriterDestroy(&writer);

    require(rawWriterOpen(&writer, 8, 1, &reopened, writeBatch, stopWorker), "open late-token writer");
    require(rawWriterTrySend(&writer, packet(2)) == kRawWriterSendOk, "late-token admission");
    stale = takeToken(0);
    rawWriterDestroy(&writer);
    runToken(stale);
    require(reopened.calls == 0, "token outlived device and invoked native callback");

    old = (output_t) {.status = kRawWriterBatchBlocked};
    require(rawWriterOpen(&writer, 8, 1, &old, writeBatch, stopWorker), "open retry-refusal writer");
    require(rawWriterTrySend(&writer, packet(3)) == kRawWriterSendOk, "retry-refusal admission");
    reject_next           = true;
    const unsigned before = atomicLoadRelaxed(&disposals);
    runAll();
    require(atomicLoadRelaxed(&disposals) == before, "refused retry discarded before native retirement");
    rawWriterDestroy(&writer);
    require(atomicLoadRelaxed(&disposals) == before + 1, "refused retry leaked retained packet");
}

static void *runNativeWorker(void *arg)
{
    runToken(*(captured_t *) arg);
    testWorkerUnbindWID();
    return NULL;
}

static void *closeWriter(void *arg)
{
    raw_writer_t *writer = arg;
    rawWriterCloseRequest(writer);
    atomicStoreExplicit(&close_started, true, memory_order_release);
    rawWriterCloseWait(writer);
    atomicStoreExplicit(&close_finished, true, memory_order_release);
    return NULL;
}

static void testConcurrentWritesAndStop(void)
{
    raw_writer_t writer;
    output_t     output = {.prefix = SIZE_MAX, .block = true};
    rawWriterInit(&writer);
    require(rawWriterOpen(&writer, 8, 1, &output, writeBatch, stopWorker), "open parallel writer");
    for (wid_t wid = 0; wid < 2; ++wid)
    {
        testWorkerBindWID(wid);
        require(rawWriterTrySend(&writer, packet(wid)) == kRawWriterSendOk, "parallel admission");
    }
    testWorkerBindWID(0);
    captured_t tokens[2] = {takeToken(0), takeToken(0)};
    pthread_t  workers[2], closer;
    for (size_t i = 0; i < ARRAY_SIZE(workers); ++i)
        require(pthread_create(&workers[i], NULL, runNativeWorker, &tokens[i]) == 0, "parallel worker create");
    /* Both native operations must enter before either returns. */
    while (atomicLoadExplicit(&native_entered, memory_order_acquire) != 2)
        sched_yield();
    require(pthread_create(&closer, NULL, closeWriter, &writer) == 0, "native-stop coordinator create");
    while (! atomicLoadExplicit(&close_started, memory_order_acquire))
        sched_yield();
    require(! atomicLoadExplicit(&close_finished, memory_order_acquire), "close skipped active native operations");
    atomicStoreExplicit(&native_release, true, memory_order_release);
    for (size_t i = 0; i < ARRAY_SIZE(workers); ++i)
        require(pthread_join(workers[i], NULL) == 0, "parallel worker join");
    require(pthread_join(closer, NULL) == 0, "native-stop coordinator join");
    require(output.stopped == 2 && output.counts[0] == 1 && output.counts[1] == 1,
            "parallel writers or native-stop hooks did not settle");
    rawWriterDestroy(&writer);
}

int main(void)
{
    test_worker_registry_t registry = {0};
    GSTATE.workers_count            = 2;
    testWorkerRegistryInstall(&registry);
    testWorkerBindWID(0);
    testBatchAndPartialFifo();
    testBlockedBudgetAndRetry();
    testInterruptedYield();
    testExternalCompletionAndRetirement();
    testFailureRetainsOtherNativeBorrows();
    testRefusalCancellationAndStaleTokens();
    testConcurrentWritesAndStop();
    require(captured_count == 0, "test retained worker messages");
    testWorkerRegistryRestore(&registry);
    testWorkerUnbindWID();
    return 0;
}
