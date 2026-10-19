/*
 * SpeedLimit byte/order, private-pipe splitting, consumer Pause, combined source
 * holds, reentrant close/input and finite byte/charge/entry admission.
 * Uses real worker-local pools and timers; callbacks are driven with a fixed
 * cached clock. No throughput claims. Both build variants compile the actual
 * tunnel and representation helpers, including WW_HAVE_SPLICE=0 fallback.
 * CTest: waterwall.speedlimit_splice_unit; waterwall.speedlimit_no_splice_unit
 */
#include "SpeedLimit/interface.h"
#include "SpeedLimit/structure.h"
#include "fixtures/failure/tunnel_line_failure_harness.h"
#include "fixtures/protocols/splice_source.h"

#include <unistd.h>

enum
{
    kPadding         = 256,
    kExpectedBytes   = 16U * 1024U * 1024U,
    kExpectedCharge  = 32U * 1024U * 1024U,
    kExpectedEntries = 1024
};

static twf_worker_env_t env;
static twf_line_pool_t  lines;
static node_t           metadata;
static tunnel_t        *node, *prev, *next;
static line_t          *line;
static uint8_t          received[65536];
static size_t           received_length, materialized;
static unsigned         payloads, pauses, resumes, finishes;
static bool upstream, measuring, expect_splice, expect_ordinary, pause_output, close_output, close_resume, inject_input;
static sbuf_t *expected_identity;
static bool    independent_sources;

#if WW_HAVE_SPLICE
ssize_t __real_read(int fd, void *destination, size_t bytes);
ssize_t __wrap_read(int fd, void *destination, size_t bytes);
ssize_t __wrap_read(int fd, void *destination, size_t bytes)
{
    ssize_t result = __real_read(fd, destination, bytes);
    if (measuring && result > 0)
        materialized += (size_t) result;
    return result;
}
#endif

static speedlimit_lstate_t *state(void)
{
    return lineGetState(line, node);
}

static buffer_queue_t *queue(void)
{
    return upstream ? &state()->up.queue : &state()->down.queue;
}

static wtimer_t *timer(void)
{
    return upstream ? state()->up.timer : state()->down.timer;
}

static sbuf_t *ordinary(const void *data, uint32_t length)
{
    sbuf_t *buf = bufferpoolGetBestFit(env.pool, length, kPadding);
    sbufSetLength(buf, length);
    memoryCopy(sbufGetMutablePtr(buf), data, length);
    return buf;
}

#if WW_HAVE_SPLICE
static sbuf_t *pipeBytes(const void *data, uint32_t length, uint32_t prefix)
{
    sbuf_t *buf = independent_sources ? twfTrackAcquired(testSpliceSourceBuffer(kPadding, length - prefix))
                                      : bufferpoolGetSpliceBuffer(env.pool);
    twfRequire(buf != NULL && prefix <= length && prefix <= kPadding, "allocate private pipe input");
    uint32_t body = length - prefix;
    twfRequire(write(sbufSpliceMetadata(buf).pipefd[1], (const uint8_t *) data + prefix, body) == (ssize_t) body,
               "populate private pipe input");
    buf->capacity = buf->l_pad + body;
    sbufSetLength(buf, body);
    sbufShiftLeft(buf, prefix);
    memoryCopy(sbufGetMutablePtr(buf), data, prefix);
    return buf;
}
#endif

static sbuf_t *input(const void *data, uint32_t length, bool splice, uint32_t prefix)
{
#if WW_HAVE_SPLICE
    if (splice)
        return pipeBytes(data, length, prefix);
#else
    discard splice;
    discard prefix;
#endif
    return ordinary(data, length);
}

static void submit(sbuf_t *buf)
{
    if (upstream)
        node->fnPayloadU(node, line, buf);
    else
        node->fnPayloadD(node, line, buf);
}

static void pauseConsumer(void)
{
    if (upstream)
        node->fnPauseD(node, line);
    else
        node->fnPauseU(node, line);
}

static void resumeConsumer(void)
{
    if (upstream)
        node->fnResumeD(node, line);
    else
        node->fnResumeU(node, line);
}

static void finish(tunnel_t *t, line_t *l)
{
    ++finishes;
    if (t == prev)
        lineDestroy(l);
}

static void init(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
}

static void closeFrom(tunnel_t *t, line_t *l)
{
    if (t == prev)
    {
        node->fnFinU(node, l);
        lineDestroy(l);
    }
    else
        node->fnFinD(node, l);
}

static void pauseSource(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    ++pauses;
}

static void resumeSource(tunnel_t *t, line_t *l)
{
    ++resumes;
    if (close_resume)
        closeFrom(t, l);
}

static void receive(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    twfRequire(t == (upstream ? next : prev), "limiter changed callback direction");
    twfRequire(! expected_identity || buf == expected_identity, "whole-buffer forwarding replaced input");
    if (expect_splice)
        twfRequire(sbufIsSplice(buf), "feasible split materialized the pipe body");
    if (expect_ordinary)
        twfRequire(! sbufIsSplice(buf), "pipe creation failure did not use ordinary fallback");
    twfRequire(sbufGetLeftCapacity(buf) >= 128, "split lost onward padding");
    uint32_t length = sbufGetLength(buf);
    twfRequire(length <= sizeof(received) - received_length, "capture overflow");
    bool saved = measuring;
    measuring  = false;
    sbufReadRangeToMemory(buf, received + received_length, length);
    measuring = saved;
    received_length += length;
    ++payloads;
    lineReuseBuffer(l, buf);
    if (inject_input)
    {
        inject_input = false;
        submit(input("B", 1, WW_HAVE_SPLICE, 0));
    }
    if (pause_output)
        pauseConsumer();
    if (close_output)
        closeFrom(t, l);
}

static void setup(bool up, const char *work_mode, const char *limit_mode)
{
    upstream        = up;
    received_length = materialized = 0;
    payloads = pauses = resumes = finishes = 0;
    measuring = expect_splice = expect_ordinary = pause_output = close_output = close_resume = inject_input = false;
    expected_identity                                                                                       = NULL;
    twfWorkerEnvSetup(&env, 8192, kPadding);
    metadata = nodeSpeedLimitGet();
    char settings[192];
    snprintf(settings,
             sizeof(settings),
             "{\"bytes-per-sec\":16777216,\"limit-mode\":\"%s\",\"work-mode\":\"%s\"}",
             limit_mode,
             work_mode);
    metadata.node_settings_json = cJSON_Parse(settings);
    node                        = speedlimitTunnelCreate(&metadata);
    prev                        = tunnelCreate(NULL, 0, 0);
    next                        = tunnelCreate(NULL, 0, 0);
    twfRequire(node && prev && next, "construct limiter fixture");
    prev->fnPayloadD = next->fnPayloadU = receive;
    next->fnInitU                       = init;
    prev->fnFinD = next->fnFinU = finish;
    prev->fnPauseD = next->fnPauseU = pauseSource;
    prev->fnResumeD = next->fnResumeU = resumeSource;
    tunnelBind(prev, node);
    tunnelBind(node, next);
    twfLinePoolSetup(&lines, node->lstate_size, 4);
    line = twfLinePoolCreateLine(&lines);
    lineRef(line);
    node->fnInitU(node, line);
}

static void tokens(uint32_t bytes)
{
    speedlimit_tstate_t *ts    = tunnelGetState(node);
    uint64_t             units = (uint64_t) bytes * kSpeedLimitUnitsPerByte;
    uint64_t             now   = wloopNowMS(env.loop);
    state()->line_bucket  = (speedlimit_bucket_t) {.tokens_units = units, .last_refill_ms = now, .has_clock = true};
    ts->worker_buckets[0] = (speedlimit_bucket_t) {.tokens_units   = units,
                                                   .last_refill_ms = now,
                                                   .has_clock      = true,
                                                   .active_lines   = ts->worker_buckets[0].active_lines};
    atomicStoreU64Relaxed(&ts->global_bucket.tokens_units, units);
    atomicStoreU64Relaxed(&ts->global_bucket.last_refill_ms, now);
}

static void tick(void)
{
    wtimer_t *pending = timer();
    twfRequire(pending != NULL, "missing drain timer");
    if (upstream)
        speedlimitUpstreamDrainTimerCallback(pending);
    else
        speedlimitDownstreamDrainTimerCallback(pending);
    /* Direct invocation leaves event-loop dispatch/reclamation to the fixture. */
    weventSetUserData(pending, NULL);
    wtimerDelete(pending);
}

static void teardown(void)
{
    if (lineIsAlive(line))
    {
        node->fnFinU(node, line);
        lineDestroy(line);
    }
    twfRequireLineStateZeroed(line, node, "limiter retained queues/timers after Finish");
    twfRequire(twfLineRefCount(line) == 1, "limiter leaked a line reference");
    lineUnref(line);
    twfLinePoolTeardown(&lines);
    tunnelDestroy(node);
    tunnelDestroy(prev);
    tunnelDestroy(next);
    cJSON_Delete(metadata.node_settings_json);
    memoryFree(metadata.type);
    twfWorkerEnvTeardown(&env);
}

static void testPausedTimer(bool up)
{
    setup(up, "pause", "per-line");
    tokens(0);
    submit(ordinary("ABCDEFGH", 8));
    pauseConsumer();
    tokens(8);
    tick();
    twfRequire(payloads == 0 && bufferqueueGetBufLen(queue()) == 8, "paused timer sent queued bytes to its consumer");
    twfRequire(timer() == NULL && resumes == 0, "paused backlog kept polling or released source");
    tokens(0);
    close_resume = true;
    resumeConsumer();
    close_resume = false;
    twfRequire(lineIsAlive(line), "external Resume reached a source still held by its local backlog");
    twfRequire(resumes == 0 && pauses == 1, "external Resume transiently released a locally held source");
    tokens(8);
    tick();
    twfRequire(received_length == 8 && memoryCompare(received, "ABCDEFGH", 8) == 0, "Resume lost queued bytes");
    pauseConsumer();
    tick();
    twfRequire(resumes == 0, "empty-queue tick ignored renewed external Pause");
    resumeConsumer();
    twfRequire(resumes == 1, "source did not resume when both holds cleared");
    resumeConsumer();
    twfRequire(resumes == 1, "duplicate Resume emitted another source notification");
    teardown();
}

static void testSplit(bool up, bool splice, uint32_t prefix, const char *mode)
{
    setup(up, "pause", mode);
    tokens(0);
    submit(input("ABCDEFGH", 8, splice, prefix));
    inject_input = pause_output = true;
    expect_splice               = splice;
    measuring                   = true;
    tokens(2);
    tick();
    twfRequire(received_length == 2 && bufferqueueGetBufLen(queue()) == 7, "split/reentry lost FIFO remainder");
    twfRequire(materialized == 0, "feasible split read pipe bytes into userspace");
    tokens(32);
    tick();
    twfRequire(received_length == 2, "timer sent remainder after reentrant Pause");
    pause_output = false;
    resumeConsumer();
    tick();
    tick();
    twfRequire(received_length == 9 && memoryCompare(received, "ABCDEFGHB", 9) == 0,
               "nested input overtook the older private-pipe remainder");
    twfRequire(materialized == 0, "opaque remainder was materialized");
    tick();
    twfRequire(resumes == 1, "split backlog failed to release its source");
    teardown();
}

static void testFallback(bool up)
{
#if WW_HAVE_SPLICE
    setup(up, "pause", "per-line");
    tokens(0);
    uint8_t bytes[4096];
    for (unsigned i = 0; i < sizeof(bytes); ++i)
        bytes[i] = (uint8_t) i;
    submit(pipeBytes(bytes, sizeof(bytes), 7));
    test_splice_inventory_hold_t held = testSpliceInventoryHoldAvailable(getCurrentEventWorkerBufferPool());
    expect_ordinary = measuring = true;
    tokens(2048);
    tick();
    twfRequire(materialized == 2048 - 7, "ordinary fallback did not consume the exact granted pipe range");
    testSpliceInventoryReleaseHeld(&held);
    expect_ordinary = false;
    tokens(2048);
    tick();
    twfRequire(received_length == sizeof(bytes) && memoryCompare(received, bytes, sizeof(bytes)) == 0,
               "fallback input bytes changed");
    teardown();
#else
    discard up;
#endif
}

static void testBudgetedSpliceFallback(bool up)
{
#if WW_HAVE_SPLICE
    for (unsigned dimension = 0; dimension < 2; ++dimension)
    {
        setup(up, "pause", "per-line");
        tokens(0);
        uint8_t bytes[4096];
        for (unsigned i = 0; i < sizeof(bytes); ++i)
            bytes[i] = (uint8_t) i;
        sbuf_t           *source = pipeBytes(bytes, sizeof(bytes), 7);
        buffer_pool_fit_t fit;
        twfRequire(bufferpoolQueryBestFit(env.pool, 2048, bufferpoolGetLargeBufferPadding(env.pool), &fit),
                   "query partial-output fallback geometry");
        buffer_budget_t     *budget = up ? &state()->up_budget : &state()->down_budget;
        buffer_budget_cost_t limits = bufferbudgetGetLimits(budget);
        if (dimension == 0)
            limits.charge = sbufGetQueueCharge(source) + fit.allocation_charge;
        else
            limits.entries = 2;
        // The source plus one ordinary candidate fits exactly. A simultaneous
        // splice wrapper and ordinary fallback cannot enter the retained turn.
        bufferbudgetInit(budget, limits);
        submit(source);
        expect_ordinary = measuring = true;
        tokens(2048);
        tick();
        twfRequire(lineIsAlive(line) && received_length == 2048 && payloads == 1,
                   "refused temporary wrapper budget prevented ordinary partial progress");
        twfRequire(materialized == 2048 - 7, "budget fallback did not consume the exact granted pipe range");
        const buffer_budget_cost_t usage = bufferbudgetGetUsage(budget);
        twfRequire(usage.bytes == 2048 && usage.entries == 1 &&
                       usage.charge == sbufGetQueueCharge(bufferqueueFront(queue())),
                   "budget fallback retained temporary output/wrapper costs after handoff");
        expect_ordinary = false;
        tokens(2048);
        tick();
        twfRequire(received_length == sizeof(bytes) && memoryCompare(received, bytes, sizeof(bytes)) == 0,
                   "budget fallback damaged the accepted FIFO remainder");
        twfRequire(bufferbudgetGetUsage(budget).bytes == 0 && bufferbudgetGetUsage(budget).charge == 0 &&
                       bufferbudgetGetUsage(budget).entries == 0,
                   "budget fallback did not settle all retained costs");
        teardown();
    }
#else
    discard up;
#endif
}

static void testForwardAndDrop(bool up, bool splice)
{
    setup(up, "drop", "per-line");
    sbuf_t *buf       = input("whole", 5, splice, 1);
    expected_identity = buf;
    tokens(5);
    submit(buf);
    twfRequire(payloads == 1 && received_length == 5, "drop mode failed whole-buffer grant");
    expected_identity = NULL;
    submit(input("discard", 7, splice, 0));
    twfRequire(payloads == 1 && timer() == NULL && pauses == 0, "drop mode queued or emitted ungranted data");
    teardown();
    setup(up, "pause", "per-line");
    buf               = input("whole", 5, splice, 1);
    expected_identity = buf;
    tokens(5);
    submit(buf);
    twfRequire(payloads == 1 && timer() == NULL, "direct forwarding needlessly queued input");
    teardown();
}

static void testClose(bool up, bool from_resume)
{
    setup(up, "pause", "per-line");
    if (from_resume)
    {
        pauseConsumer();
        close_resume = true;
        resumeConsumer();
    }
    else
    {
        tokens(0);
        submit(input("closing", 7, WW_HAVE_SPLICE, 1));
        tokens(2);
        close_output = true;
        tick();
    }
    twfRequire(! lineIsAlive(line), "reentrant close left borrowed connection alive");
    teardown();
}

static void testLimits(bool up, unsigned dimension)
{
    setup(up, "pause", "per-line");
    independent_sources = dimension == 2;
    pauseConsumer();
    tokens(0);
    if (dimension == 0)
    {
        sbuf_t *buf = bufferpoolGetBestFit(env.pool, kExpectedBytes, kPadding);
        sbufSetLength(buf, kExpectedBytes);
        submit(buf);
        twfRequire(lineIsAlive(line) && bufferqueueGetBufLen(queue()) == kExpectedBytes,
                   "refused exact payload-byte limit");
    }
    else if (dimension == 1)
    {
        const uint32_t capacity = kExpectedCharge - sizeof(sbuf_t) - kSbufAllocationAlignment - kPadding;
        sbuf_t        *buf      = bufferpoolGetBestFit(env.pool, capacity, kPadding);
        sbufSetLength(buf, 1);
        twfRequire(sbufGetQueueCharge(buf) == kExpectedCharge, "construct exact capacity charge");
        submit(buf);
        twfRequire(lineIsAlive(line) && bufferqueueGetCharge(queue()) == kExpectedCharge,
                   "refused exact retained-capacity limit");
    }
    else
    {
        for (unsigned i = 0; i < kExpectedEntries; ++i)
            submit(input("", 0, WW_HAVE_SPLICE, 0));
        twfRequire(lineIsAlive(line) && bufferqueueGetBufCount(queue()) == kExpectedEntries,
                   "refused exact entry limit, including empty private pipes");
    }
    submit(input("X", 1, WW_HAVE_SPLICE, 0));
    twfRequire(! lineIsAlive(line) && finishes == 2 && payloads == 0, "overflow did not close and discard owned data");
    independent_sources = false;
    teardown();
}

static void testEmpty(void)
{
    setup(true, "pause", "per-line");
    tokens(0);
    submit(ordinary("A", 1));
    submit(input("", 0, WW_HAVE_SPLICE, 0));
    tokens(1);
    tick();
    tick();
    tick();
    twfRequire(received_length == 1 && resumes == 1, "empty queued payload stalled source Resume");
    teardown();
}

static void testResetRefusal(bool up, bool from_resume)
{
    setup(up, "pause", "per-line");
    tokens(0);
    submit(ordinary("A", 1));
    twfRequire(timer() != NULL, "initial drain timer was not armed");
    if (from_resume)
        pauseConsumer();

    discard wloopRequestQuiesce(env.loop);
    twfRequire(! wloopNormalDispatchAllowed(env.loop), "failed to close drain timer admission");
    if (from_resume)
        resumeConsumer();
    else
        submit(ordinary("B", 1));

    twfRequire(! lineIsAlive(line) && finishes == 2 && payloads == 0 && resumes == 0,
               "refused timer reset retained the line instead of closing without output");
    twfRequireLineStateZeroed(line, node, "refused timer reset retained queues or timers");
    teardown();
}

static void testRetryRounding(void)
{
    setup(true, "pause", "per-line");
    speedlimit_tstate_t *ts   = tunnelGetState(node);
    ts->bytes_per_sec         = 1;
    ts->bucket_capacity_units = kSpeedLimitUnitsPerByte;
    ts->recharge_interval_ms  = 997;
    ts->refill_units_per_step = 997;
    tokens(0);
    twfRequire(speedlimitGetRetryDelayMs(node, line) == 1994, "retry lost a partial recharge step");
    ts->recharge_interval_ms  = INT_MAX;
    ts->refill_units_per_step = INT_MAX;
    twfRequire(speedlimitGetRetryDelayMs(node, line) == INT_MAX, "maximum recharge interval did not remain valid");
    teardown();
}

static void testRateSettings(void)
{
    twfWorkerEnvSetup(&env, 8192, kPadding);
    const char  *keys[]        = {"bytes-per-sec", "kilo-bytes-per-sec", "mega-bytes-per-sec"};
    const double multipliers[] = {1.0, 1024.0, 1024.0 * 1024.0};
    const double invalid[]     = {0.0, -1.0, 0.49, 0x1p64, INFINITY, NAN};
    for (size_t key = 0; key < sizeof(keys) / sizeof(keys[0]); ++key)
    {
        for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
        {
            cJSON *settings = cJSON_Parse("{\"limit-mode\":\"per-line\",\"work-mode\":\"pause\"}");
            cJSON_AddNumberToObject(settings, keys[key], invalid[i] / multipliers[key]);
            node_t    config  = {.node_settings_json = settings};
            tunnel_t *limiter = speedlimitTunnelCreate(&config);
            twfRequire(limiter == NULL, "invalid or unrepresentable rate was accepted");
            cJSON_Delete(settings);
        }
    }
    const double   valid[]   = {0.5, 1.49, 1.5};
    const uint64_t rounded[] = {1, 1, 2};
    for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); ++i)
    {
        cJSON *settings = cJSON_Parse("{\"limit-mode\":\"per-line\",\"work-mode\":\"pause\"}");
        cJSON_AddNumberToObject(settings, "bytes-per-sec", valid[i]);
        node_t    config  = {.node_settings_json = settings};
        tunnel_t *limiter = speedlimitTunnelCreate(&config);
        twfRequire(limiter != NULL && ((speedlimit_tstate_t *) tunnelGetState(limiter))->bytes_per_sec == rounded[i],
                   "valid fractional rate changed its nearest-byte rounding");
        tunnelDestroy(limiter);
        cJSON_Delete(settings);
    }
    twfWorkerEnvTeardown(&env);
}

static void testSharedRateArithmetic(void)
{
    rate_bucket_t bucket;
    ratebucketInit(&bucket, 0);
    ratebucketRefill(&bucket, 1, 100, 1, 0);
    twfRequire(bucket.has_clock && bucket.last_refill_ms == 0, "time zero was mistaken for an absent clock");
    ratebucketRefill(&bucket, 1, 100, 1, 999);
    twfRequire(bucket.credit == 0 && bucket.remainder == 999, "one-byte rate lost fractional refill");
    twfRequire(ratebucketRetryMs(&bucket, 1, 1, 999, 1) == 1, "one-byte retry rounded down");
    ratebucketRefill(&bucket, 1, 100, 1, 1000);
    twfRequire(ratebucketGrant(&bucket, 1, false) == 1, "one-byte rate failed to progress");
    ratebucketRefill(&bucket, 1, 100, 1, 500);
    twfRequire(bucket.last_refill_ms == 1000 && bucket.credit == 0, "older clock rewound or refilled bucket");
    ratebucketRefill(&bucket, 1, 100, 1, UINT64_MAX);
    twfRequire(bucket.credit == 100 && bucket.remainder == 0, "long idle refill did not cap safely");

    ratebucketInit(&bucket, 0);
    ratebucketRefill(&bucket, UINT64_MAX, UINT64_MAX, 1, 0);
    twfRequire(ratebucketRetryMs(&bucket, UINT64_MAX, 1, 0, UINT64_MAX) == 1000, "maximum-rate retry overflowed");
    ratebucketRefill(&bucket, UINT64_MAX, UINT64_MAX, 1, 1);
    twfRequire(bucket.credit == UINT64_MAX / 1000 && bucket.remainder == UINT64_MAX % 1000,
               "maximum-rate fractional refill overflowed");
    ratebucketRefill(&bucket, UINT64_MAX, UINT64_MAX, 1, 999);
    const uint64_t remaining = UINT64_MAX / 1000 + (UINT64_MAX % 1000 != 0);
    twfRequire(bucket.credit == UINT64_MAX - remaining, "maximum-rate refill lost precision across samples");
    ratebucketRefill(&bucket, UINT64_MAX, UINT64_MAX, 1, 1000);
    twfRequire(bucket.credit == UINT64_MAX && bucket.remainder == 0, "maximum-rate full second did not saturate");

    ratebucketInit(&bucket, 0);
    ratebucketRefill(&bucket, 1, 100, 997, 0);
    twfRequire(ratebucketRetryMs(&bucket, 1, 997, 0, 1) == 1994, "recharge-step retry lost a fractional step");
    ratebucketRefill(&bucket, 1, 100, 997, 1994);
    twfRequire(bucket.credit == 1 && bucket.remainder == 994, "recharge-step refill changed precision");
    twfRequire(ratebucketRetryMs(&bucket, 1, 1, 1994, UINT64_MAX) == UINT64_MAX,
               "unrepresentable wait did not saturate");
}

static void testQuiesce(bool up)
{
    setup(up, "pause", "per-line");
    tokens(0);
    submit(ordinary("retained", 8));
    speedlimit_tstate_t *settings = tunnelGetState(node);
    twfRequire(settings->worker_buckets[0].active_lines == state(), "active line absent from owner inventory");
    speedlimitTunnelWorkerQuiesce(node, 0, NULL);
    twfRequire(timer() == NULL && bufferqueueGetBufLen(queue()) == 8,
               "quiescence did not detach timer while preserving owner-drain buffers");
    teardown();
}

int main(void)
{
    testSharedRateArithmetic();
    testRateSettings();
    testRetryRounding();
    for (unsigned up = 0; up < 2; ++up)
    {
        testQuiesce(up);
        testResetRefusal(up, false);
        testResetRefusal(up, true);
        testPausedTimer(up);
        testClose(up, true);
        testClose(up, false);
        for (unsigned dimension = 0; dimension < 3; ++dimension)
            testLimits(up, dimension);
        const char *modes[] = {"per-line", "per-worker", "all-lines"};
        for (unsigned mode = 0; mode < 3; ++mode)
        {
            testSplit(up, false, 0, modes[mode]);
#if WW_HAVE_SPLICE
            testSplit(up, true, 0, modes[mode]);
            testSplit(up, true, 4, modes[mode]);
#endif
        }
        testForwardAndDrop(up, false);
#if WW_HAVE_SPLICE
        testForwardAndDrop(up, true);
#endif
        testFallback(up);
        testBudgetedSpliceFallback(up);
    }
    testEmpty();
    metadata = nodeSpeedLimitGet();
    twfRequire(metadata.flags & kNodeFlagSupportsSplice, "SpeedLimit lacks splice capability");
    memoryFree(metadata.type);
    puts("SpeedLimit splice, flow control and bounded retention passed");
    return 0;
}
