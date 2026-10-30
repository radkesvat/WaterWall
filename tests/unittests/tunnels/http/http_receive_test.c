/*
 * Covers: HttpCommon receive serialization, nested budgets and stream retention.
 * Setup: Real standalone pools and a registered worker for pending-queue cleanup.
 * Checks: 16 KiB FIFO slices, byte/charge/entry boundaries, popped reservations,
 *         empty recycling, destruction and small-suffix/entry-count compaction.
 * Limits: HTTP parser and callback-lifetime behavior belong to the node fixtures.
 * CTest: waterwall.http_receive_unit.
 */
#include "HttpCommon/receive.h"
#include "fixtures/worker_registry_fixture.h"
#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static size_t recycled;

void __real_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buffer);
void __wrap_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buffer);
void __wrap_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buffer)
{
    ++recycled;
    __real_bufferpoolReuseBuffer(pool, buffer);
}

static uint8_t pattern(size_t offset)
{
    return (uint8_t) ((offset * 131U + 29U) % 251U);
}

static sbuf_t *makeBuffer(uint32_t capacity, uint32_t length, size_t offset)
{
    sbuf_t *buffer = sbufCreateWithPadding(capacity, 0);
    sbufSetLength(buffer, length);
    for (uint32_t i = 0; i < length; ++i)
        sbufGetMutablePtr(buffer)[i] = pattern(offset + i);
    return buffer;
}

static void checkUsage(http_receive_t *receive, size_t bytes, size_t charge, size_t entries)
{
    buffer_budget_cost_t used = bufferbudgetGetUsage(&receive->budget);
    require(used.bytes == bytes && used.charge == charge && used.entries == entries,
            "receive budget usage changed unexpectedly");
}

static void checkBody(sbuf_t *buffer, size_t offset)
{
    require(buffer != NULL && sbufGetLength(buffer) > 0 && sbufGetLength(buffer) <= kHttpReceiveSliceBytes,
            "receive helper returned an empty or oversized slice");
    const uint8_t *bytes = sbufGetRawPtr(buffer);
    for (uint32_t i = 0; i < sbufGetLength(buffer); ++i)
        require(bytes[i] == pattern(offset + i), "receive helper changed bytes or FIFO ordering");
}

static void caseFifoAndEmpty(buffer_pool_t *pool)
{
    testCaseSet("HTTP receive slices preserve outer-before-nested FIFO");
    http_receive_t receive;
    httpReceiveInit(&receive);
    size_t previous_recycled = recycled;
    require(httpReceiveAdmit(&receive, pool, makeBuffer(4U << 20, 0, 0)) == kHttpReceiveEmpty,
            "empty outer input entered the drain");
    require(recycled == previous_recycled + 1 && ! receive.draining && receive.active == NULL,
            "empty outer input was not recycled immediately");

    const uint32_t outer  = 3 * kHttpReceiveSliceBytes + 3;
    const uint32_t nested = kHttpReceiveSliceBytes + 5;
    require(httpReceiveAdmit(&receive, pool, makeBuffer(outer, outer, 0)) == kHttpReceiveDrain,
            "first delivery did not start the drain");
    checkUsage(&receive, 0, 0, 0);
    sbuf_t *slice = httpReceiveNext(&receive, pool);
    checkBody(slice, 0);
    require(sbufGetLength(slice) == kHttpReceiveSliceBytes, "outer delivery was not sliced at 16 KiB");
    size_t received = sbufGetLength(slice);
    bufferpoolReuseBuffer(pool, slice);
    require(receive.active != NULL && sbufGetLength(receive.active) == outer - received,
            "outer consumption was not published before output");

    require(httpReceiveAdmit(&receive, pool, makeBuffer(nested, nested, outer)) == kHttpReceiveQueued,
            "nested input did not queue");
    require(httpReceiveAdmit(&receive, pool, makeBuffer(7, 7, outer + nested)) == kHttpReceiveQueued,
            "second nested input did not queue");
    previous_recycled = recycled;
    require(httpReceiveAdmit(&receive, pool, makeBuffer(4U << 20, 0, 0)) == kHttpReceiveEmpty,
            "empty nested input used a queue slot");
    require(recycled == previous_recycled + 1 && bufferqueueGetBufCount(&receive.pending) == 2,
            "empty nested input was retained");

    while ((slice = httpReceiveNext(&receive, pool)) != NULL)
    {
        checkBody(slice, received);
        received += sbufGetLength(slice);
        bufferpoolReuseBuffer(pool, slice);
    }
    require(received == outer + nested + 7 && ! receive.draining && receive.active == NULL,
            "receive drain did not end after all bytes");
    checkUsage(&receive, 0, 0, 0);
    httpReceiveDestroy(&receive, pool);
}

static void caseByteLimitAndPoppedReservation(buffer_pool_t *pool)
{
    testCaseSet("HTTP nested active buffers retain their complete reservation");
    http_receive_t receive;
    httpReceiveInit(&receive);
    require(httpReceiveAdmit(&receive, pool, makeBuffer(1, 1, 0)) == kHttpReceiveDrain, "outer input did not start");
    sbuf_t      *nested = makeBuffer(kHttpReceiveNestedBytes, kHttpReceiveNestedBytes, 1);
    const size_t charge = sbufGetQueueCharge(nested);
    require(httpReceiveAdmit(&receive, pool, nested) == kHttpReceiveQueued, "exact nested byte allowance was rejected");
    checkUsage(&receive, kHttpReceiveNestedBytes, charge, 1);
    sbuf_t *rejected = makeBuffer(1, 1, 0);
    require(httpReceiveAdmit(&receive, pool, rejected) == kHttpReceiveRejected,
            "nested byte allowance plus one was accepted");
    require(sbufGetLength(rejected) == 1 && ((const uint8_t *) sbufGetRawPtr(rejected))[0] == pattern(0),
            "rejection consumed caller-owned input");

    sbuf_t *slice = httpReceiveNext(&receive, pool);
    bufferpoolReuseBuffer(pool, slice);
    slice = httpReceiveNext(&receive, pool);
    checkBody(slice, 1);
    size_t received = sbufGetLength(slice);
    bufferpoolReuseBuffer(pool, slice);
    require(bufferqueueGetBufCount(&receive.pending) == 0 && receive.active != NULL,
            "nested input was not moved into the active position");
    checkUsage(&receive, kHttpReceiveNestedBytes, charge, 1);
    require(httpReceiveAdmit(&receive, pool, rejected) == kHttpReceiveRejected,
            "popping a nested buffer bypassed its budget");
    bufferpoolReuseBuffer(pool, rejected);
    while ((slice = httpReceiveNext(&receive, pool)) != NULL)
    {
        checkBody(slice, 1 + received);
        received += sbufGetLength(slice);
        if (receive.active != NULL)
            checkUsage(&receive, kHttpReceiveNestedBytes, charge, 1);
        else
            checkUsage(&receive, 0, 0, 0);
        bufferpoolReuseBuffer(pool, slice);
    }
    require(received == kHttpReceiveNestedBytes, "nested active drain lost bytes");
    httpReceiveDestroy(&receive, pool);
}

static void caseChargeLimit(buffer_pool_t *pool)
{
    testCaseSet("HTTP nested allocation charge is independent of payload length");
    http_receive_t receive;
    httpReceiveInit(&receive);
    require(httpReceiveAdmit(&receive, pool, makeBuffer(1, 1, 0)) == kHttpReceiveDrain, "outer input did not start");
    const uint32_t overhead        = sizeof(sbuf_t) + kSbufAllocationAlignment;
    const uint32_t second_capacity = kCpuLineCacheSize;
    const uint32_t first_capacity  = kHttpReceiveNestedCharge - 2 * overhead - second_capacity;
    sbuf_t        *first           = makeBuffer(first_capacity, 1, 1);
    sbuf_t        *second          = makeBuffer(second_capacity, 1, 2);
    require(sbufGetQueueCharge(first) + sbufGetQueueCharge(second) == kHttpReceiveNestedCharge,
            "charge-boundary fixture geometry changed");
    require(httpReceiveAdmit(&receive, pool, first) == kHttpReceiveQueued &&
                httpReceiveAdmit(&receive, pool, second) == kHttpReceiveQueued,
            "exact nested charge allowance was rejected");
    checkUsage(&receive, 2, kHttpReceiveNestedCharge, 2);
    sbuf_t *extra = makeBuffer(1, 1, 3);
    require(httpReceiveAdmit(&receive, pool, extra) == kHttpReceiveRejected, "nested charge overflow was accepted");
    bufferpoolReuseBuffer(pool, extra);
    httpReceiveDestroy(&receive, pool);
    checkUsage(&receive, 0, 0, 0);
    require(receive.active == NULL && ! receive.draining && bufferqueueGetBufCount(&receive.pending) == 0,
            "destroy retained active or queued input");
}

static void caseEntryLimit(buffer_pool_t *pool)
{
    testCaseSet("HTTP nested queue entry limit is exact");
    http_receive_t receive;
    httpReceiveInit(&receive);
    require(httpReceiveAdmit(&receive, pool, makeBuffer(1, 1, 0)) == kHttpReceiveDrain, "outer input did not start");
    for (size_t i = 0; i < kHttpReceiveNestedEntries; ++i)
        require(httpReceiveAdmit(&receive, pool, makeBuffer(1, 1, i)) == kHttpReceiveQueued,
                "entry allowance was rejected before the boundary");
    require(bufferbudgetGetUsage(&receive.budget).entries == kHttpReceiveNestedEntries,
            "nested entry accounting missed an input");
    sbuf_t *extra = makeBuffer(1, 1, 0);
    require(httpReceiveAdmit(&receive, pool, extra) == kHttpReceiveRejected, "entry allowance plus one was accepted");
    bufferpoolReuseBuffer(pool, extra);
    httpReceiveDestroy(&receive, pool);
    checkUsage(&receive, 0, 0, 0);
}

static void caseSettle(buffer_pool_t *pool)
{
    testCaseSet("HTTP stream settlement compacts retained storage without changing bytes");
    buffer_stream_t stream = bufferstreamCreate(pool, 0);
    bufferstreamPush(&stream, makeBuffer(4U << 20, 3, 0));
    require(bufferstreamGetCharge(&stream) > kHttpReceiveStreamCharge, "oversized allocation fixture is too small");
    require(httpReceiveSettle(&stream, kHttpReceiveStreamBytes), "small incomplete suffix was rejected");
    require(bufferstreamGetBufLen(&stream) == 3 && bufferstreamGetCharge(&stream) <= kHttpReceiveStreamCharge,
            "small suffix retained an oversized allocation");
    sbuf_t *body = bufferstreamReadExact(&stream, 3);
    checkBody(body, 0);
    bufferpoolReuseBuffer(pool, body);

    for (size_t i = 0; i <= kHttpReceiveNestedEntries; ++i)
    {
        sbuf_t        *one  = makeBuffer(1, 0, 0);
        const uint32_t skip = sbufGetMaximumWriteableSize(one) - 1;
        sbufSetLength(one, skip);
        sbufShiftRight(one, skip);
        sbufSetLength(one, 1);
        sbufGetMutablePtr(one)[0] = pattern(i);
        bufferstreamPush(&stream, one);
    }
    require(bufferstreamGetEntryCount(&stream) == kHttpReceiveNestedEntries + 1,
            "separate-entry fixture unexpectedly coalesced");
    require(httpReceiveSettle(&stream, kHttpReceiveStreamBytes) && bufferstreamGetEntryCount(&stream) == 1,
            "too many small entries were not compacted");
    body = bufferstreamFullRead(&stream);
    checkBody(body, 0);
    require(sbufGetLength(body) == kHttpReceiveNestedEntries + 1, "entry compaction lost bytes");
    bufferpoolReuseBuffer(pool, body);

    bufferstreamPush(&stream, makeBuffer(kHttpReceiveStreamBytes, kHttpReceiveStreamBytes, 0));
    require(httpReceiveSettle(&stream, kHttpReceiveStreamBytes), "exact stream byte allowance was rejected");
    bufferstreamPush(&stream, makeBuffer(1, 1, 0));
    size_t previous_charge = bufferstreamGetCharge(&stream);
    require(! httpReceiveSettle(&stream, kHttpReceiveStreamBytes), "stream byte allowance plus one was accepted");
    require(bufferstreamGetBufLen(&stream) == kHttpReceiveStreamBytes + 1 &&
                bufferstreamGetCharge(&stream) == previous_charge,
            "failed settlement changed retained input");
    require(httpReceiveSettle(&stream, kHttpReceiveStreamBytes + 1), "caller-specific byte allowance was ignored");
    bufferstreamEmpty(&stream);

    bufferstreamPush(&stream, makeBuffer(4U << 20, 0, 0));
    size_t previous_recycled = recycled;
    require(httpReceiveSettle(&stream, 0) && bufferstreamGetEntryCount(&stream) == 0 &&
                bufferstreamGetCharge(&stream) == 0 && recycled == previous_recycled + 1,
            "logical-empty stream retained an allocation");
    bufferstreamDestroy(&stream);
}

int main(void)
{
    master_pool_t *large  = masterpoolCreateWithCapacity(8);
    master_pool_t *medium = masterpoolCreateWithCapacity(8);
    master_pool_t *small  = masterpoolCreateWithCapacity(8);
    buffer_pool_t *pool   = bufferpoolCreate(large, medium, small, 4, 16384, 65536, 1024, 16384, 16384);
    require(pool != NULL, "failed to create receive-test buffer pool");
    buffer_pool_t *pools[]          = {pool};
    GSTATE.workers_count            = 1;
    GSTATE.shortcut_buffer_pools    = pools;
    test_worker_registry_t registry = {0};
    testWorkerRegistryInstall(&registry);
    registry.slots[0].buffer_pool = pool;
    testWorkerBindWID(0);
    caseFifoAndEmpty(pool);
    caseByteLimitAndPoppedReservation(pool);
    caseChargeLimit(pool);
    caseEntryLimit(pool);
    caseSettle(pool);
    testWorkerUnbindWID();
    testWorkerRegistryRestore(&registry);
    GSTATE.shortcut_buffer_pools = NULL;
    bufferpoolDestroy(pool);
    masterpoolMakeEmpty(large);
    masterpoolMakeEmpty(medium);
    masterpoolMakeEmpty(small);
    masterpoolDestroy(large);
    masterpoolDestroy(medium);
    masterpoolDestroy(small);
    puts("http_receive_test: all checks passed");
    return 0;
}
