/*
 * SpeedLimit drain-timer failure injection.
 *
 * A drain timer that cannot be created means the queued bytes of that one line can never leave. That is a
 * per-line resource failure: SpeedLimit must recycle everything the line owned, close the line upstream first and
 * downstream second, and leave the process and every other line untouched.
 *
 * All four scheduling points are covered:
 *   1. the first upstream schedule, with every byte still in the queue;
 *   2. the first downstream schedule, same ownership state;
 *   3. a reschedule after a partial slice, with a detached send buffer in flight;
 *   4. the final local-resume tick, with the whole front buffer detached.
 */
#include "SpeedLimit/structure.h"

#include "tunnel_line_failure_harness.h"

// ---------------------------------------------------------------------------
// wtimerAdd injection
// ---------------------------------------------------------------------------

static uint32_t  g_timer_calls        = 0;
static uint32_t  g_timer_fail_at_call = 0; // 1-based; 0 disables injection
static wtimer_t *g_last_timer         = NULL;

wtimer_t *__real_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t timeout_ms, uint32_t repeat);
wtimer_t *__wrap_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t timeout_ms, uint32_t repeat);

wtimer_t *__wrap_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t timeout_ms, uint32_t repeat)
{
    ++g_timer_calls;
    if (g_timer_fail_at_call == g_timer_calls)
    {
        return NULL;
    }

    g_last_timer = __real_wtimerAdd(loop, cb, timeout_ms, repeat);
    return g_last_timer;
}

static void timerInjectionReset(uint32_t fail_at_call)
{
    g_timer_calls        = 0;
    g_timer_fail_at_call = fail_at_call;
    g_last_timer         = NULL;
}

// A drain callback clears its own line-state pointer before running, so the timer object itself outlives the
// line state and this test owns it from that point on.
static void releaseOrphanedTimer(void)
{
    if (g_last_timer != NULL)
    {
        weventSetUserData(g_last_timer, NULL);
        wtimerDelete(g_last_timer);
        g_last_timer = NULL;
    }
}

// ---------------------------------------------------------------------------
// fixture
// ---------------------------------------------------------------------------

enum
{
    kTestBytesPerSecond   = 16,
    kTestLargeBufferSize  = 8192,
    kTestPayloadLength    = 64,
    kTestSmallPayloadSize = 8
};

typedef struct speedlimit_fixture_s
{
    twf_worker_env_t env;
    twf_trace_t      trace;
    tunnel_t        *prev;
    tunnel_t        *speedlimit;
    tunnel_t        *next;
} speedlimit_fixture_t;

static tunnel_t *createSpeedLimitTunnel(void)
{
    tunnel_t *t =
        tunnelCreate(NULL, sizeof(speedlimit_tstate_t) + sizeof(speedlimit_bucket_t), sizeof(speedlimit_lstate_t));
    twfRequire(t != NULL, "failed to create the SpeedLimit tunnel");

    speedlimit_tstate_t *ts = tunnelGetState(t);

    ts->bytes_per_sec         = kTestBytesPerSecond;
    ts->recharge_interval_ms  = kSpeedLimitDefaultTickMs;
    ts->bucket_capacity_units = ts->bytes_per_sec * (uint64_t) kSpeedLimitUnitsPerByte;
    ts->refill_units_per_step = ts->bytes_per_sec * (uint64_t) ts->recharge_interval_ms;
    ts->limit_mode            = kSpeedLimitLimitModePerLine;
    ts->work_mode             = kSpeedLimitWorkModePause;

    atomicStoreRelaxed(&ts->global_bucket.tokens_units, ts->bucket_capacity_units);
    atomicStoreRelaxed(&ts->global_bucket.last_refill_ms, 0);
    ts->worker_buckets[0].tokens_units   = ts->bucket_capacity_units;
    ts->worker_buckets[0].last_refill_ms = 0;

    t->fnInitU    = &speedlimitTunnelUpStreamInit;
    t->fnEstU     = &speedlimitTunnelUpStreamEst;
    t->fnFinU     = &speedlimitTunnelUpStreamFinish;
    t->fnPayloadU = &speedlimitTunnelUpStreamPayload;
    t->fnPauseU   = &speedlimitTunnelUpStreamPause;
    t->fnResumeU  = &speedlimitTunnelUpStreamResume;

    t->fnInitD    = &speedlimitTunnelDownStreamInit;
    t->fnEstD     = &speedlimitTunnelDownStreamEst;
    t->fnFinD     = &speedlimitTunnelDownStreamFinish;
    t->fnPayloadD = &speedlimitTunnelDownStreamPayload;
    t->fnPauseD   = &speedlimitTunnelDownStreamPause;
    t->fnResumeD  = &speedlimitTunnelDownStreamResume;

    return t;
}

static void fixtureSetup(speedlimit_fixture_t *fixture)
{
    memoryZero(&fixture->trace, sizeof(fixture->trace));
    twfWorkerEnvSetup(&fixture->env, kTestLargeBufferSize, 0);

    fixture->prev       = twfCreatePrevTunnel(&fixture->trace);
    fixture->speedlimit = createSpeedLimitTunnel();
    fixture->next       = twfCreateNextTunnel(&fixture->trace);

    tunnelBind(fixture->prev, fixture->speedlimit);
    tunnelBind(fixture->speedlimit, fixture->next);
}

static sbuf_t *makePayload(speedlimit_fixture_t *fixture, uint32_t length)
{
    sbuf_t *buf = bufferpoolGetLargeBuffer(fixture->env.pool);
    twfRequire(buf != NULL, "failed to allocate a test payload");
    sbufSetLength(buf, length);
    memorySet(sbufGetMutablePtr(buf), 0x5A, length);
    return buf;
}

/**
 * Empty the line's token bucket so the very next grant request is refused. The event loop never runs in this
 * test, so its cached "now" does not advance and the bucket cannot silently refill.
 */
static void drainLineTokens(speedlimit_fixture_t *fixture, line_t *l)
{
    discard speedlimitPeekAvailableUnits(fixture->speedlimit, l);

    speedlimit_lstate_t *ls        = lineGetState(l, fixture->speedlimit);
    ls->line_bucket.tokens_units   = 0;
    ls->line_bucket.last_refill_ms = wloopNowMS(fixture->env.loop);
}

static void grantLineTokens(speedlimit_fixture_t *fixture, line_t *l, uint32_t bytes)
{
    speedlimit_lstate_t *ls      = lineGetState(l, fixture->speedlimit);
    ls->line_bucket.tokens_units = (uint64_t) bytes * (uint64_t) kSpeedLimitUnitsPerByte;
}

/**
 * A second line must keep working after the first one was closed by the injected failure.
 */
static void requireSiblingLineStillWorks(speedlimit_fixture_t *fixture)
{
    timerInjectionReset(0);

    line_t *sibling = twfLineCreate(fixture->speedlimit->lstate_size);

    const uint32_t before_next_payload = fixture->trace.next_payload;
    const uint32_t before_next_init    = fixture->trace.next_init;
    const uint32_t before_prev_finish  = fixture->trace.prev_finish;

    speedlimitTunnelUpStreamInit(fixture->speedlimit, sibling);
    twfRequireEqualU32(
        fixture->trace.next_init - before_next_init, 1, "the sibling line did not reach the next tunnel");

    // Small enough to pass on the very first grant, so it never needs a drain timer.
    speedlimitTunnelUpStreamPayload(fixture->speedlimit, sibling, makePayload(fixture, 4));
    twfRequireEqualU32(fixture->trace.next_payload - before_next_payload,
                       1,
                       "the sibling line could not forward traffic after the failed line closed");
    twfRequireEqualU32(fixture->trace.prev_finish - before_prev_finish,
                       0,
                       "the sibling line was closed even though its timers were fine");

    speedlimitTunnelUpStreamFinish(fixture->speedlimit, sibling);
    twfRequireLineStateZeroed(sibling, fixture->speedlimit, "the sibling line state was not zeroed");
    twfLineDestroy(sibling);
}

static void fixtureTeardown(speedlimit_fixture_t *fixture)
{
    releaseOrphanedTimer();
    twfRequireNoLeakedBuffers();
    memoryFree(fixture->prev);
    memoryFree(fixture->speedlimit);
    memoryFree(fixture->next);
}

// ---------------------------------------------------------------------------
// cases
// ---------------------------------------------------------------------------

static void caseFirstUpstreamScheduleFails(void)
{
    twfSetCase("first upstream schedule fails");

    speedlimit_fixture_t fixture;
    fixtureSetup(&fixture);

    line_t        *l              = twfLineCreate(fixture.speedlimit->lstate_size);
    const uint32_t refc_at_start  = twfLineRefCount(l);
    const uint32_t recycled_start = twfRecycleCount();

    timerInjectionReset(0);
    speedlimitTunnelUpStreamInit(fixture.speedlimit, l);
    drainLineTokens(&fixture, l);

    // The very first schedule of this line is the one that fails.
    timerInjectionReset(1);
    speedlimitTunnelUpStreamPayload(fixture.speedlimit, l, makePayload(&fixture, kTestPayloadLength));

    twfRequireEqualText(fixture.trace.seq, "IFf", "the failing line did not close upstream first, downstream second");
    twfRequireEqualU32(fixture.trace.next_payload, 0, "a payload escaped after the close decision");
    twfRequireEqualU32(twfRecycleCount() - recycled_start, 1, "the queued payload was not recycled exactly once");
    twfRequireLineStateZeroed(l, fixture.speedlimit, "the failing line state was not zeroed");
    twfRequireEqualU32(twfLineRefCount(l), refc_at_start, "the line reference count did not return to its start");

    requireSiblingLineStillWorks(&fixture);

    twfLineDestroy(l);
    fixtureTeardown(&fixture);
}

static void caseFirstDownstreamScheduleFails(void)
{
    twfSetCase("first downstream schedule fails");

    speedlimit_fixture_t fixture;
    fixtureSetup(&fixture);

    line_t        *l              = twfLineCreate(fixture.speedlimit->lstate_size);
    const uint32_t refc_at_start  = twfLineRefCount(l);
    const uint32_t recycled_start = twfRecycleCount();

    timerInjectionReset(0);
    speedlimitTunnelUpStreamInit(fixture.speedlimit, l);
    drainLineTokens(&fixture, l);

    timerInjectionReset(1);
    speedlimitTunnelDownStreamPayload(fixture.speedlimit, l, makePayload(&fixture, kTestPayloadLength));

    twfRequireEqualText(fixture.trace.seq, "IFf", "the failing line did not close upstream first, downstream second");
    twfRequireEqualU32(fixture.trace.prev_payload, 0, "a payload escaped after the close decision");
    twfRequireEqualU32(twfRecycleCount() - recycled_start, 1, "the queued payload was not recycled exactly once");
    twfRequireLineStateZeroed(l, fixture.speedlimit, "the failing line state was not zeroed");
    twfRequireEqualU32(twfLineRefCount(l), refc_at_start, "the line reference count did not return to its start");

    requireSiblingLineStillWorks(&fixture);

    twfLineDestroy(l);
    fixtureTeardown(&fixture);
}

static void caseRescheduleAfterPartialSliceFails(void)
{
    twfSetCase("reschedule after a partial slice fails");

    speedlimit_fixture_t fixture;
    fixtureSetup(&fixture);

    line_t        *l              = twfLineCreate(fixture.speedlimit->lstate_size);
    const uint32_t refc_at_start  = twfLineRefCount(l);
    const uint32_t recycled_start = twfRecycleCount();

    timerInjectionReset(0);
    speedlimitTunnelUpStreamInit(fixture.speedlimit, l);
    drainLineTokens(&fixture, l);

    // The first schedule succeeds, so the payload is queued and the previous side is paused.
    timerInjectionReset(0);
    speedlimitTunnelUpStreamPayload(fixture.speedlimit, l, makePayload(&fixture, kTestPayloadLength));
    twfRequireEqualText(fixture.trace.seq, "Iu", "the queued payload did not pause the previous side");

    speedlimit_lstate_t *ls = lineGetState(l, fixture.speedlimit);
    twfRequire(ls->up_timer != NULL, "the first upstream drain timer was not armed");

    wtimer_t *armed_timer = ls->up_timer;

    // Enough tokens for a slice but not for the whole queued buffer, so the drain detaches a send buffer and then
    // has to arm a follow-up timer, which is the call that fails.
    grantLineTokens(&fixture, l, kTestPayloadLength / 4U);
    timerInjectionReset(1);
    speedlimitUpstreamDrainTimerCallback(armed_timer);

    twfRequireEqualText(fixture.trace.seq, "IuFf", "the failing line did not close upstream first, downstream second");
    twfRequireEqualU32(fixture.trace.next_payload, 0, "the detached slice was forwarded after the close decision");
    // one detached slice plus the remainder still sitting in the queue
    twfRequireEqualU32(twfRecycleCount() - recycled_start,
                       2,
                       "the detached slice and the queued remainder were not each recycled once");
    twfRequireLineStateZeroed(l, fixture.speedlimit, "the failing line state was not zeroed");
    twfRequireEqualU32(twfLineRefCount(l), refc_at_start, "the line reference count did not return to its start");

    // The callback detached the timer from the line state before the failure, so the test owns it now.
    g_last_timer = armed_timer;

    requireSiblingLineStillWorks(&fixture);

    twfLineDestroy(l);
    fixtureTeardown(&fixture);
}

static void caseFinalResumeTickFails(void)
{
    twfSetCase("final local-resume tick fails");

    speedlimit_fixture_t fixture;
    fixtureSetup(&fixture);

    line_t        *l              = twfLineCreate(fixture.speedlimit->lstate_size);
    const uint32_t refc_at_start  = twfLineRefCount(l);
    const uint32_t recycled_start = twfRecycleCount();

    timerInjectionReset(0);
    speedlimitTunnelUpStreamInit(fixture.speedlimit, l);
    drainLineTokens(&fixture, l);

    timerInjectionReset(0);
    speedlimitTunnelUpStreamPayload(fixture.speedlimit, l, makePayload(&fixture, kTestSmallPayloadSize));
    twfRequireEqualText(fixture.trace.seq, "Iu", "the queued payload did not pause the previous side");

    speedlimit_lstate_t *ls          = lineGetState(l, fixture.speedlimit);
    wtimer_t            *armed_timer = ls->up_timer;
    twfRequire(armed_timer != NULL, "the first upstream drain timer was not armed");

    // Exactly enough tokens to drain the queue completely, so the only remaining work is the local-resume tick.
    grantLineTokens(&fixture, l, kTestSmallPayloadSize);
    timerInjectionReset(1);
    speedlimitUpstreamDrainTimerCallback(armed_timer);

    twfRequireEqualText(fixture.trace.seq, "IuFf", "the failing line did not close upstream first, downstream second");
    twfRequireEqualU32(fixture.trace.next_payload, 0, "the detached buffer was forwarded after the close decision");
    twfRequireEqualU32(
        twfRecycleCount() - recycled_start, 1, "the detached front buffer was not recycled exactly once");
    twfRequireLineStateZeroed(l, fixture.speedlimit, "the failing line state was not zeroed");
    twfRequireEqualU32(twfLineRefCount(l), refc_at_start, "the line reference count did not return to its start");

    g_last_timer = armed_timer;

    requireSiblingLineStillWorks(&fixture);

    twfLineDestroy(l);
    fixtureTeardown(&fixture);
}

int main(void)
{
    caseFirstUpstreamScheduleFails();
    caseFirstDownstreamScheduleFails();
    caseRescheduleAfterPartialSliceFails();
    caseFinalResumeTickFails();

    printf("speedlimit_line_failure_test: all cases passed\n");
    return 0;
}
