/* Owner-worker batching, backlog admission, cancellation, restart, and admitted
 * native-write quiescence. Syscall behavior belongs to the platform fixtures.
 * CTest: waterwall.tun_writer_unit */
#include "wwapi.h"

#include "devices/tun/tun_writer.h"
#include "fixtures/worker_registry_fixture.h"
#include "test_assert.h"

#include <pthread.h>

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

typedef struct captured_s
{
    wid_t                        wid;
    WorkerMessageCallback        callback;
    WorkerMessageCleanupCallback cleanup;
    void                        *arg1;
    void                        *arg2;
    void                        *arg3;
} captured_t;

enum
{
    kCapturedMax = 256,
    kObservedMax = 1024
};
static captured_t      captured[kCapturedMax];
static size_t          captured_count;
static pthread_mutex_t captured_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool            reject_next;
static atomic_uint     disposals;
static atomic_uint     shutdowns;
static atomic_bool     native_entered;
static atomic_uint     native_entries;
static atomic_bool     native_release;
static atomic_bool     close_started;
static atomic_bool     close_finished;
static atomic_bool     block_native;
static pthread_mutex_t output_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct output_s
{
    unsigned sequences[2][kObservedMax];
    size_t   counts[2];
    size_t   batch_counts[kObservedMax];
    size_t   batch_charges[kObservedMax];
    size_t   batches;
    bool     fail;
} output_t;

worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *arg1, void *arg2, void *arg3);
void                           __wrap_sbufDestroy(sbuf_t *buffer);
bool                           __wrap_requestProgramShutdown(int code);

worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *arg1, void *arg2, void *arg3)
{
    pthread_mutex_lock(&captured_mutex);
    if (reject_next)
    {
        reject_next = false;
        pthread_mutex_unlock(&captured_mutex);
        cleanup(arg1, arg2, arg3, kWorkerMessageCancelEnqueueFailure);
        return kWorkerMessageSubmitRejectedCleanupRan;
    }
    require(captured_count < kCapturedMax, "captured drain-token capacity");
    captured[captured_count++] = (captured_t) {wid, callback, cleanup, arg1, arg2, arg3};
    pthread_mutex_unlock(&captured_mutex);
    return kWorkerMessageSubmitAccepted;
}

void __real_sbufDestroy(sbuf_t *buffer);
void __wrap_sbufDestroy(sbuf_t *buffer)
{
    atomicIncRelaxed(&disposals);
    __real_sbufDestroy(buffer);
}

bool __wrap_requestProgramShutdown(int code)
{
    require(code == 1, "fatal writer exit code");
    atomicIncRelaxed(&shutdowns);
    return true;
}

static captured_t takeToken(size_t index)
{
    pthread_mutex_lock(&captured_mutex);
    require(index < captured_count, "missing queued drain token");
    captured_t token = captured[index];
    memoryMove(&captured[index], &captured[index + 1], (captured_count - index - 1) * sizeof(captured[0]));
    captured_count--;
    pthread_mutex_unlock(&captured_mutex);
    return token;
}

static void runToken(captured_t token)
{
    testWorkerBindWID(token.wid);
    token.callback(getWorker(token.wid), token.arg1, token.arg2, token.arg3);
}

static void runAll(void)
{
    while (captured_count != 0)
        runToken(takeToken(0));
    testWorkerBindWID(0);
}

static sbuf_t *packet(unsigned sequence, uint32_t capacity)
{
    sbuf_t *buffer = sbufCreate(capacity);
    memoryCopy(sbufGetMutablePtr(buffer), &sequence, sizeof(sequence));
    sbufSetLength(buffer, sizeof(sequence));
    return buffer;
}

static bool writeBatch(void *context, worker_t *worker, sbuf_t **buffers, size_t count)
{
    output_t *output = context;
    require(currentThreadOwnsWorker(worker->wid), "native write escaped owner worker");
    require(worker == getWorker(worker->wid), "native callback received wrong worker");
    require(count > 0 && count <= kTunWriterBatchPackets, "native batch packet limit");
    pthread_mutex_lock(&output_mutex);
    size_t charge = 0;
    for (size_t i = 0; i < count; ++i)
    {
        unsigned sequence;
        memoryCopy(&sequence, sbufGetRawPtr(buffers[i]), sizeof(sequence));
        require(output->counts[worker->wid] < kObservedMax, "output observation capacity");
        output->sequences[worker->wid][output->counts[worker->wid]++] = sequence;
        charge += sbufGetAllocationCharge(buffers[i]);
        sbufDestroy(buffers[i]);
    }
    require(count == 1 || charge <= kTunWriterBatchCharge, "native batch charge limit");
    output->batch_counts[output->batches]    = count;
    output->batch_charges[output->batches++] = charge;
    pthread_mutex_unlock(&output_mutex);
    if (atomicLoadRelaxed(&block_native))
    {
        atomicIncExplicit(&native_entries, memory_order_release);
        atomicStoreExplicit(&native_entered, true, memory_order_release);
        while (! atomicLoadExplicit(&native_release, memory_order_acquire))
            sched_yield();
    }
    return ! output->fail;
}

static void testBatchingAndOrdering(void)
{
    tun_writer_t writer;
    output_t     output = {0};
    tunWriterInit(&writer);
    require(tunWriterOpen(&writer, 1024, SIZE_MAX, &output, writeBatch), "open batching writer");
    for (unsigned i = 0; i < 130; ++i)
        require(tunWriterTrySend(&writer, packet(i, 64)) == kTunWriterSendOk, "enqueue batch member");
    require(captured_count == 1 && output.batches == 0, "payload did not coalesce deferred writes");
    runAll();
    require(output.batches == 3 && output.batch_counts[0] == 64 && output.batch_counts[1] == 64 &&
                output.batch_counts[2] == 2,
            "bounded drain did not continue to completion");
    for (unsigned i = 0; i < 130; ++i)
        require(output.sequences[0][i] == i, "worker FIFO changed packet order");
    tunWriterDestroy(&writer);

    output = (output_t) {0};
    require(tunWriterOpen(&writer, 16, SIZE_MAX, &output, writeBatch), "open charged writer");
    for (unsigned i = 0; i < 5; ++i)
        require(tunWriterTrySend(&writer, packet(i, 65536)) == kTunWriterSendOk, "enqueue charged buffer");
    require(tunWriterTrySend(&writer, packet(5, 300000)) == kTunWriterSendOk, "enqueue oversized allocation");
    require(tunWriterTrySend(&writer, packet(6, 64)) == kTunWriterSendOk, "enqueue trailing buffer");
    runAll();
    require(output.batches == 4 && output.batch_counts[0] == 3 && output.batch_counts[1] == 2 &&
                output.batch_counts[2] == 1 && output.batch_counts[3] == 1,
            "charge budget or oversized singleton made no progress");
    tunWriterDestroy(&writer);
}

static void testAdmissionAndRefusal(void)
{
    tun_writer_t writer;
    output_t     output = {0};
    tunWriterInit(&writer);
    sbuf_t *refused = packet(9, 64);
    require(tunWriterTrySend(&writer, refused) == kTunWriterSendDown, "closed writer accepted output");
    const size_t charge = sbufGetAllocationCharge(refused);
    require(tunWriterOpen(&writer, 2, SIZE_MAX, &output, writeBatch), "open packet-limited writer");
    require(tunWriterTrySend(&writer, packet(0, 64)) == kTunWriterSendOk, "worker zero admission");
    testWorkerBindWID(1);
    require(tunWriterTrySend(&writer, packet(1, 64)) == kTunWriterSendOk, "worker one admission");
    require(tunWriterTrySend(&writer, refused) == kTunWriterSendFull, "global packet cap multiplied by workers");
    require(captured_count == 2, "each worker needs one independent drain");
    runAll();
    require(output.counts[0] == 1 && output.counts[1] == 1, "worker-local drain output");
    tunWriterDestroy(&writer);

    require(tunWriterOpen(&writer, 4, charge, &output, writeBatch), "open charge-limited writer");
    require(tunWriterTrySend(&writer, packet(2, 64)) == kTunWriterSendOk, "first charge reservation");
    require(tunWriterTrySend(&writer, refused) == kTunWriterSendFull, "charge cap ignored");
    runAll();
    reject_next = true;
    require(tunWriterTrySend(&writer, refused) == kTunWriterSendClosed, "synchronous queue refusal not reported");
    require(tunWriterTrySend(&writer, refused) == kTunWriterSendOk, "queue refusal lost buffer or budget");
    runAll();
    tunWriterDestroy(&writer);
}

static void *cancelForeign(void *arg)
{
    captured_t *token = arg;
    require(! currentThreadIsWorker(), "cancellation fixture has worker identity");
    token->cleanup(token->arg1, token->arg2, token->arg3, kWorkerMessageCancelTeardown);
    return NULL;
}

static void testCancelledAndStaleTokens(void)
{
    tun_writer_t writer;
    output_t     old_output = {0}, new_output = {0};
    tunWriterInit(&writer);
    require(tunWriterOpen(&writer, 8, SIZE_MAX, &old_output, writeBatch), "open old generation");
    require(tunWriterTrySend(&writer, packet(0, 64)) == kTunWriterSendOk, "old generation enqueue");
    captured_t     old    = takeToken(0);
    const unsigned before = atomicLoadRelaxed(&disposals);
    tunWriterCloseRequest(&writer);
    tunWriterCloseWait(&writer);
    require(atomicLoadRelaxed(&disposals) == before + 1, "close did not discard queued ownership");
    require(tunWriterOpen(&writer, 8, SIZE_MAX, &new_output, writeBatch), "reopen generation");
    runToken(old);
    require(old_output.batches == 0 && new_output.batches == 0, "stale token wrote native device");
    require(tunWriterTrySend(&writer, packet(1, 64)) == kTunWriterSendOk, "new generation enqueue");
    captured_t cancelled = takeToken(0);
    pthread_t  foreign;
    require(pthread_create(&foreign, NULL, cancelForeign, &cancelled) == 0, "foreign cancellation create");
    require(pthread_join(foreign, NULL) == 0, "foreign cancellation join");
    sbuf_t *refused = packet(2, 64);
    require(tunWriterTrySend(&writer, refused) == kTunWriterSendClosed, "cancelled owner accepted stranded work");
    sbufDestroy(refused);
    tunWriterDestroy(&writer);

    require(tunWriterOpen(&writer, 8, SIZE_MAX, &new_output, writeBatch), "open token-after-destroy generation");
    require(tunWriterTrySend(&writer, packet(3, 64)) == kTunWriterSendOk, "late token enqueue");
    old = takeToken(0);
    tunWriterDestroy(&writer);
    runToken(old);
    require(new_output.batches == 0, "token outliving writer accessed device");
}

static void *runForeignWorker(void *arg)
{
    runToken(*(captured_t *) arg);
    testWorkerUnbindWID();
    return NULL;
}

static void *closeWriter(void *arg)
{
    tun_writer_t *writer = arg;
    tunWriterCloseRequest(writer);
    atomicStoreExplicit(&close_started, true, memory_order_release);
    tunWriterCloseWait(writer);
    atomicStoreExplicit(&close_finished, true, memory_order_release);
    return NULL;
}

static void testNativeWriteQuiescence(void)
{
    tun_writer_t writer;
    output_t     output = {0};
    tunWriterInit(&writer);
    require(tunWriterOpen(&writer, 8, SIZE_MAX, &output, writeBatch), "open concurrent writer");
    testWorkerBindWID(1);
    require(tunWriterTrySend(&writer, packet(0, 64)) == kTunWriterSendOk, "enqueue concurrent write");
    testWorkerBindWID(0);
    captured_t token = takeToken(0);
    atomicStoreRelaxed(&block_native, true);
    pthread_t worker, closer;
    require(pthread_create(&worker, NULL, runForeignWorker, &token) == 0, "native worker create");
    while (! atomicLoadExplicit(&native_entered, memory_order_acquire))
        sched_yield();
    require(pthread_create(&closer, NULL, closeWriter, &writer) == 0, "close owner create");
    while (! atomicLoadExplicit(&close_started, memory_order_acquire))
        sched_yield();
    require(! atomicLoadExplicit(&close_finished, memory_order_acquire), "close reclaimed an active native callback");
    sbuf_t *refused = packet(1, 64);
    require(tunWriterTrySend(&writer, refused) == kTunWriterSendDown, "stop did not close admission");
    sbufDestroy(refused);
    atomicStoreExplicit(&native_release, true, memory_order_release);
    require(pthread_join(worker, NULL) == 0 && pthread_join(closer, NULL) == 0, "concurrent writer joins");
    require(atomicLoadRelaxed(&close_finished), "close failed to complete after callback");
    atomicStoreRelaxed(&block_native, false);
    tunWriterDestroy(&writer);
}

static void testConcurrentNativeWrites(void)
{
    tun_writer_t writer;
    output_t     output = {0};
    tunWriterInit(&writer);
    require(tunWriterOpen(&writer, 8, SIZE_MAX, &output, writeBatch), "open parallel writer");
    for (wid_t wid = 0; wid < 2; ++wid)
    {
        testWorkerBindWID(wid);
        require(tunWriterTrySend(&writer, packet(wid, 64)) == kTunWriterSendOk, "enqueue parallel native writes");
    }
    testWorkerBindWID(0);
    captured_t tokens[2] = {takeToken(0), takeToken(0)};
    atomicStoreRelaxed(&native_entries, 0);
    atomicStoreRelaxed(&native_release, false);
    atomicStoreRelaxed(&block_native, true);
    pthread_t threads[2];
    for (size_t i = 0; i < 2; ++i)
        require(pthread_create(&threads[i], NULL, runForeignWorker, &tokens[i]) == 0, "parallel worker create");
    /* Both callbacks must enter before either can finish. A shared write mutex
     * would prevent the second worker from reaching this barrier. */
    while (atomicLoadExplicit(&native_entries, memory_order_acquire) != 2)
        sched_yield();
    atomicStoreExplicit(&native_release, true, memory_order_release);
    for (size_t i = 0; i < 2; ++i)
        require(pthread_join(threads[i], NULL) == 0, "parallel worker join");
    atomicStoreRelaxed(&block_native, false);
    require(output.counts[0] == 1 && output.counts[1] == 1, "parallel workers lost native output");
    tunWriterDestroy(&writer);
}

static void testFailureAndContinuationCancellation(void)
{
    tun_writer_t writer;
    output_t     output = {.fail = true};
    tunWriterInit(&writer);
    require(tunWriterOpen(&writer, 256, SIZE_MAX, &output, writeBatch), "open failure writer");
    for (unsigned i = 0; i < 65; ++i)
        require(tunWriterTrySend(&writer, packet(i, 64)) == kTunWriterSendOk, "failure backlog enqueue");
    runAll();
    require(atomicLoadRelaxed(&shutdowns) == 1 && output.counts[0] == 64,
            "fatal write did not stop/drain exactly once");
    tunWriterDestroy(&writer);

    output = (output_t) {0};
    require(tunWriterOpen(&writer, 256, SIZE_MAX, &output, writeBatch), "open continuation writer");
    for (unsigned i = 0; i < 65; ++i)
        require(tunWriterTrySend(&writer, packet(i, 64)) == kTunWriterSendOk, "continuation backlog enqueue");
    reject_next           = true;
    const unsigned before = atomicLoadRelaxed(&disposals);
    runAll();
    require(output.counts[0] == 64 && atomicLoadRelaxed(&disposals) == before + 65,
            "refused continuation did not settle retained suffix");
    tunWriterDestroy(&writer);
}

int main(void)
{
    test_worker_registry_t registry = {0};
    GSTATE.workers_count            = 2;
    testWorkerRegistryInstall(&registry);
    testWorkerBindWID(0);
    testBatchingAndOrdering();
    testAdmissionAndRefusal();
    testCancelledAndStaleTokens();
    testNativeWriteQuiescence();
    testConcurrentNativeWrites();
    testFailureAndContinuationCancellation();
    require(captured_count == 0, "test left owned drain tokens");
    testWorkerRegistryRestore(&registry);
    testWorkerUnbindWID();
    return 0;
}
