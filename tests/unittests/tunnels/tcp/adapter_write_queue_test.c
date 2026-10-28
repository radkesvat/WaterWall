/*
 * Covers: shared TCP adapter FIFO, active write accounting and notification latches.
 * Setup: worker pool fixture without lines or sockets; the scenario acts as WIO's
 * independent buffer owner and publishes explicit partial/completed byte counts.
 * Cases: direct/queued ownership, original charge through partial progress, exact
 * charge boundaries, empty inputs, deferred Resume, failed writes and terminal pops.
 * Checks: FIFO bytes/representation, exclusive buffer recycling, charge/entry
 * settlement and exactly one notification per actual Pause/Resume cycle.
 * Limits: socket callbacks, Est dispatch and close reentry belong to the adapter suites.
 * CTest: waterwall.adapter_write_queue_unit
 */
#include "TcpAdapterCommon/adapter_write_queue.h"

#include "fixtures/failure/tunnel_line_failure_harness.h"
#include "splice_buffer.h"

#include <unistd.h>

static twf_worker_env_t env;

static sbuf_t *ordinary(uint32_t capacity, const char *data, uint32_t length)
{
    sbuf_t *buf = twfTrackAcquired(sbufCreate(capacity));
    if (length != 0)
        sbufWrite(buf, data, length);
    sbufSetLength(buf, length);
    return buf;
}

static void requireUsage(const adapter_write_queue_t *q, size_t bytes, size_t charge, size_t entries)
{
    const buffer_budget_cost_t usage = awqGetUsage(q);
    twfRequire(usage.bytes == bytes && usage.charge == charge && usage.entries == entries,
               "retained byte/charge/entry accounting differs from ownership");
}

static void completeOwned(adapter_write_queue_t *q, sbuf_t *buf, const char *expected, uint32_t bytes)
{
    char actual[8];
    twfRequire(buf != NULL && bytes <= sizeof(actual) && sbufGetLength(buf) == bytes,
               "drain returned the wrong payload length");
    sbufReadRangeToMemory(buf, actual, bytes);
    twfRequire(memoryEqual(actual, expected, bytes), "drain changed FIFO bytes");
    /* WIO may recycle before the node observes completion; accounting holds no alias. */
    bufferpoolReuseBuffer(env.pool, buf);
    twfRequire(awqAfterWrite(q, (int) bytes, bytes, 0) == kAwqWriteComplete,
               "completed socket write did not settle its reservation");
}

static void testDirectOwnership(void)
{
    twfSetCase("direct writes reserve before transfer and discard admitted empty input");
    adapter_write_queue_t q;
    awqInit(&q, false);
    twfRequire(! awqIsBlocked(&q) && ! awqTakeResume(&q), "new writable queue emitted Resume");
    sbuf_t        *buf      = ordinary(32, "A", 1);
    sbuf_t        *original = buf;
    const size_t   charge   = sbufGetQueueCharge(buf);
    const uint32_t before   = twfRecycleCount();
    twfRequire(awqAdmit(&q, env.pool, &buf) == kAwqWriteNow && buf == original,
               "direct admission consumed or replaced caller ownership");
    requireUsage(&q, 1, charge, 1);
    completeOwned(&q, buf, "A", 1);
    requireUsage(&q, 0, 0, 0);
    twfRequire(twfRecycleCount() == before + 1 && ! awqTakeResume(&q),
               "direct completion recycled twice or emitted an unpaired Resume");

    buf = ordinary(32, NULL, 0);
    twfRequire(awqAdmit(&q, env.pool, &buf) == kAwqConsumed && buf == NULL,
               "direct empty input escaped to a socket write");
    requireUsage(&q, 0, 0, 0);
    awqReleaseCompleted(&q);
    awqDestroy(&q);
}

static void testShortWriteAndResume(void)
{
    twfSetCase("short direct writes pause below threshold and retain original charge until completion");
    adapter_write_queue_t q;
    awqInit(&q, false);
    sbuf_t      *active = ordinary(64, "AB", 2);
    const size_t charge = sbufGetQueueCharge(active);
    twfRequire(charge < kAwqPauseThreshold && awqAdmit(&q, env.pool, &active) == kAwqWriteNow,
               "small active fixture did not take the direct path");
    twfRequire(awqAfterWrite(&q, 1, 2, 1) == kAwqWriteBlocked && awqIsBlocked(&q),
               "one-byte retained write did not block subsequent direct writes");
    requireUsage(&q, 1, charge, 1);
    twfRequire(awqTakePause(&q) && ! awqTakePause(&q) && ! awqTakeResume(&q),
               "short write repeated Pause or resumed while blocked");

    sbuf_t      *tail        = ordinary(32, "C", 1);
    const size_t tail_charge = sbufGetQueueCharge(tail);
    twfRequire(awqAdmit(&q, env.pool, &tail) == kAwqQueued && tail == NULL,
               "paused admission lost ownership or repeated Pause");
    requireUsage(&q, 2, charge + tail_charge, 2);
    bufferpoolReuseBuffer(env.pool, active);
    awqRefreshPending(&q, 0);
    requireUsage(&q, 1, charge + tail_charge, 2);
    awqReleaseCompleted(&q);
    requireUsage(&q, 1, tail_charge, 1);
    tail = awqNextToWrite(&q, env.pool);
    requireUsage(&q, 1, tail_charge, 1);
    completeOwned(&q, tail, "C", 1);
    twfRequire(awqNextToWrite(&q, env.pool) == NULL && ! awqIsBlocked(&q),
               "exhausted drain did not reopen direct writes");
    twfRequire(awqTakeResume(&q) && ! awqTakeResume(&q), "drain lost or repeated its Resume");
    requireUsage(&q, 0, 0, 0);
    awqDestroy(&q);
}

static void testConnectingThresholds(void)
{
    twfSetCase("connecting queue threshold counts allocation charge and preserves empty entries");
    adapter_write_queue_t q;
    awqInit(&q, true);
    const uint32_t overhead = (uint32_t) (sizeof(sbuf_t) + kSbufAllocationAlignment);
    sbuf_t        *buf      = ordinary(kAwqPauseThreshold - overhead - kCpuLineCacheSize, "A", 1);
    const size_t   charge   = sbufGetQueueCharge(buf);
    twfRequire(charge == kAwqPauseThreshold - kCpuLineCacheSize && awqAdmit(&q, env.pool, &buf) == kAwqQueued &&
                   buf == NULL,
               "below-threshold connecting queue notified Pause");
    buf = awqNextToWrite(&q, env.pool);
    twfRequire(awqAfterWrite(&q, 0, 1, 1) == kAwqWriteBlocked && ! q.pause_sent,
               "resumed connecting FIFO invented a Pause latch");
    bufferpoolReuseBuffer(env.pool, buf);
    awqRefreshPending(&q, 0);
    awqReleaseCompleted(&q);
    twfRequire(awqNextToWrite(&q, env.pool) == NULL && ! awqTakeResume(&q), "unpaused connecting FIFO emitted Resume");
    awqDestroy(&q);

    awqInit(&q, true);
    buf = ordinary(kAwqPauseThreshold - overhead, NULL, 0);
    twfRequire(sbufGetQueueCharge(buf) == kAwqPauseThreshold && awqAdmit(&q, env.pool, &buf) == kAwqQueuedPause &&
                   buf == NULL,
               "exact charge threshold missed Pause or discarded empty ownership");
    requireUsage(&q, 0, kAwqPauseThreshold, 1);
    twfRequire(awqGetQueuedBytes(&q) == 0 && q.pause_sent, "empty entry acquired bytes or failed to publish Pause");
    twfRequire(awqNextToWrite(&q, env.pool) == NULL && awqTakeResume(&q) && ! awqTakeResume(&q),
               "empty-only drain failed to settle its notification");
    requireUsage(&q, 0, 0, 0);
    awqDestroy(&q);
}

static void testResumeAfterReentry(void)
{
    twfSetCase("drain preserves Pause latch across Est-like reentry and renewed socket pressure");
    adapter_write_queue_t q;
    awqInit(&q, true);
    sbuf_t *buf = ordinary(kAwqPauseThreshold, "A", 1);
    twfRequire(awqAdmit(&q, env.pool, &buf) == kAwqQueuedPause, "connecting fixture did not pause");
    completeOwned(&q, awqNextToWrite(&q, env.pool), "A", 1);
    twfRequire(awqNextToWrite(&q, env.pool) == NULL && ! awqIsBlocked(&q) && q.pause_sent,
               "drain consumed the latch before caller revalidation");

    buf = ordinary(32, "BC", 2);
    twfRequire(awqAdmit(&q, env.pool, &buf) == kAwqWriteNow && awqAfterWrite(&q, 1, 2, 1) == kAwqWriteBlocked &&
                   ! awqTakePause(&q) && ! awqTakeResume(&q),
               "renewed pressure repeated Pause or allowed stale Resume");
    bufferpoolReuseBuffer(env.pool, buf);
    awqRefreshPending(&q, 0);
    awqReleaseCompleted(&q);
    twfRequire(awqNextToWrite(&q, env.pool) == NULL && awqTakeResume(&q) && ! awqTakeResume(&q),
               "second drain failed to resume exactly once");
    awqDestroy(&q);
}

static void testHardLimitAndRefusal(void)
{
    twfSetCase("active allocation and queued capacity share one exact hard limit");
    adapter_write_queue_t q;
    awqInit(&q, false);
    sbuf_t      *active        = ordinary(64, "AB", 2);
    const size_t active_charge = sbufGetQueueCharge(active);
    twfRequire(awqAdmit(&q, env.pool, &active) == kAwqWriteNow && awqAfterWrite(&q, 1, 2, 1) == kAwqWriteBlocked &&
                   awqTakePause(&q),
               "hard-limit fixture did not reserve its partial write");
    const uint32_t tail_capacity =
        (uint32_t) (kAwqMaxRetained - active_charge - sizeof(sbuf_t) - kSbufAllocationAlignment);
    sbuf_t *buf = ordinary(tail_capacity, "C", 1);
    twfRequire(awqAdmit(&q, env.pool, &buf) == kAwqQueued && buf == NULL, "exact combined charge limit was refused");
    requireUsage(&q, 2, kAwqMaxRetained, 2);
    buf                     = ordinary(0, NULL, 0);
    const uint32_t recycled = twfRecycleCount();
    twfRequire(awqAdmit(&q, env.pool, &buf) == kAwqOverflow && buf == NULL && twfRecycleCount() == recycled + 1,
               "over-limit empty input was retained or recycled incorrectly");
    requireUsage(&q, 2, kAwqMaxRetained, 2);
    awqRefreshPending(&q, 0);
    requireUsage(&q, 1, kAwqMaxRetained, 2);
    awqDestroy(&q);
    requireUsage(&q, 0, 0, 0);
    /* Destroy settled accounting without recycling the separate WIO owner. */
    twfRequire(twfLedgerContains(g_twf_buffers.live, g_twf_buffers.live_count, active),
               "queue destruction reclaimed WIO-owned input");
    bufferpoolReuseBuffer(env.pool, active);

    twfSetCase("direct empty input still undergoes capacity admission before discard");
    awqInit(&q, false);
    buf = ordinary(kAwqMaxRetained, NULL, 0);
    twfRequire(awqAdmit(&q, env.pool, &buf) == kAwqOverflow && buf == NULL,
               "oversized direct empty input bypassed budget admission");
    requireUsage(&q, 0, 0, 0);
    awqDestroy(&q);
}

static void testFailedWriteAndTerminalPop(void)
{
    twfSetCase("failed write retains terminal accounting without issuing Resume");
    adapter_write_queue_t q;
    awqInit(&q, false);
    sbuf_t      *buf    = ordinary(32, "A", 1);
    const size_t charge = sbufGetQueueCharge(buf);
    twfRequire(awqAdmit(&q, env.pool, &buf) == kAwqWriteNow, "failed-write fixture admission failed");
    bufferpoolReuseBuffer(env.pool, buf);
    twfRequire(awqAfterWrite(&q, -1, 1, 0) == kAwqWriteFailed && ! awqTakeResume(&q),
               "failed socket write was classified as a successful drain");
    requireUsage(&q, 0, charge, 1);
    buf = ordinary(32, "B", 1);
    twfRequire(awqIsBlocked(&q) && awqAdmit(&q, env.pool, &buf) == kAwqQueued && buf == NULL,
               "payload before asynchronous close reused the occupied active reservation");
    requireUsage(&q, 1, charge * 2, 2);
    awqDestroy(&q);
    requireUsage(&q, 0, 0, 0);

    twfSetCase("terminal flush releases queued costs without active reservation or Resume");
    awqInit(&q, false);
    sbuf_t *active = ordinary(32, "AB", 2);
    twfRequire(awqAdmit(&q, env.pool, &active) == kAwqWriteNow && awqAfterWrite(&q, 1, 2, 1) == kAwqWriteBlocked &&
                   awqTakePause(&q),
               "terminal flush fixture did not pause");
    buf = ordinary(0, NULL, 0);
    twfRequire(awqAdmit(&q, env.pool, &buf) == kAwqQueued, "terminal empty entry was not admitted");
    buf = ordinary(32, "C", 1);
    twfRequire(awqAdmit(&q, env.pool, &buf) == kAwqQueued, "terminal payload was not admitted");
    buf = awqPopForFinish(&q, env.pool);
    twfRequire(buf != NULL && sbufGetLength(buf) == 1 && memoryEqual(sbufGetRawPtr(buf), "C", 1),
               "terminal pop lost the nonempty FIFO entry");
    requireUsage(&q, 1, charge, 1);
    bufferpoolReuseBuffer(env.pool, buf);
    twfRequire(awqPopForFinish(&q, env.pool) == NULL && awqIsBlocked(&q) && ! awqTakeResume(&q),
               "terminal drain reopened application callbacks");
    awqDestroy(&q);
    bufferpoolReuseBuffer(env.pool, active);
    requireUsage(&q, 0, 0, 0);
}

#if WW_HAVE_SPLICE
static void testMixedRepresentations(void)
{
    twfSetCase("ordinary and private-pipe buffers retain representation and FIFO order");
    adapter_write_queue_t q;
    awqInit(&q, true);
    sbuf_t *buf = ordinary(32, "A", 1);
    twfRequire(awqAdmit(&q, env.pool, &buf) == kAwqQueued, "ordinary prefix was not queued");
    buf = bufferpoolGetSpliceBuffer(env.pool);
    twfRequire(buf != NULL && write(sbufSpliceMetadata(buf).pipefd[1], "BC", 2) == 2,
               "failed to fill private splice pipe");
    buf->capacity = buf->l_pad + 2;
    sbufSetLength(buf, 2);
    sbuf_t *splice = buf;
    twfRequire(awqAdmit(&q, env.pool, &buf) == kAwqQueued && buf == NULL, "splice ownership was not admitted");
    buf = ordinary(32, "D", 1);
    twfRequire(awqAdmit(&q, env.pool, &buf) == kAwqQueued, "ordinary suffix was not queued");
    completeOwned(&q, awqNextToWrite(&q, env.pool), "A", 1);
    buf = awqNextToWrite(&q, env.pool);
    twfRequire(buf == splice && sbufIsSplice(buf), "FIFO materialized or replaced private pipe ownership");
    completeOwned(&q, buf, "BC", 2);
    completeOwned(&q, awqNextToWrite(&q, env.pool), "D", 1);
    twfRequire(awqNextToWrite(&q, env.pool) == NULL && ! awqTakeResume(&q), "unpaused mixed FIFO emitted Resume");
    requireUsage(&q, 0, 0, 0);
    awqDestroy(&q);
}
#endif

int main(void)
{
    twfWorkerEnvSetup(&env, 4096, 0);
    testDirectOwnership();
    testShortWriteAndResume();
    testConnectingThresholds();
    testResumeAfterReentry();
    testHardLimitAndRefusal();
    testFailedWriteAndTerminalPop();
#if WW_HAVE_SPLICE
    testMixedRepresentations();
#endif
    twfWorkerEnvTeardown(&env);
    puts("adapter_write_queue_test: all cases passed");
    return 0;
}
