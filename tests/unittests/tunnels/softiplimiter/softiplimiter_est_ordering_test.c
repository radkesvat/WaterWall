/*
 * Covers: softiplimiter est ordering; the explicit inputs, callbacks and expected results below define
 * this suite.
 * Setup: The included implementation/API and the deterministic inputs shown below; no integration
 * topology is implied.
 * Cases: testInitialOrder, testReentryLimit, testStartupPressure
 * Checks: Assertion labels include: SoftIpLimiter table initialization; SoftIpLimiter lost or duplicated
 * synchronous Est; SoftIpLimiter sent initial data after Est close; SoftIpLimiter nested Est input
 * overtook original identity replay
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.softiplimiter_est_ordering_unit
 */
#include "SoftIpLimiter/structure.h"
#include "fixtures/protocols/protocol_est_ordering_fixture.h"

sbuf_t *__real_sbufAppendMerge(buffer_pool_t *pool, sbuf_t *restrict first, sbuf_t *restrict second);
sbuf_t *__wrap_sbufAppendMerge(buffer_pool_t *pool, sbuf_t *restrict first, sbuf_t *restrict second);

sbuf_t *__wrap_sbufAppendMerge(buffer_pool_t *pool, sbuf_t *restrict first, sbuf_t *restrict second)
{
    sbuf_t *merged = __real_sbufAppendMerge(pool, first, second);
    /* BufferPool's internal recycle bypasses the external reuse wrapper. */
    twfLedgerForget(g_twf_buffers.live, &g_twf_buffers.live_count, second);
    if (! twfLedgerContains(g_twf_buffers.recycled, g_twf_buffers.recycled_count, second))
        twfLedgerRemember(g_twf_buffers.recycled, &g_twf_buffers.recycled_count, second, "too many merged buffers");
    if (merged != first)
    {
        twfLedgerForget(g_twf_buffers.live, &g_twf_buffers.live_count, first);
        if (! twfLedgerContains(g_twf_buffers.live, g_twf_buffers.live_count, merged))
            twfTrackAcquired(merged);
    }
    return merged;
}

static void initEst(est_fixture_t *f, line_t *l)
{
    softiplimiterTunnelDownStreamEst(f->node, l);
    if (lineIsAlive(l))
        softiplimiterTunnelDownStreamEst(f->node, l);
}

static void nestedInput(est_fixture_t *f, line_t *l)
{
    softiplimiterTunnelUpStreamPayload(f->node, l, estBytes(l, "B", 1));
    softiplimiterTunnelDownStreamPause(f->node, l);
}

static void nestedAfterFirst(est_fixture_t *f, line_t *l)
{
    f->on_up = NULL;
    softiplimiterTunnelUpStreamPayload(f->node, l, estBytes(l, "C", 1));
}

static void closeFromEst(est_fixture_t *f, line_t *l)
{
    softiplimiterTunnelUpStreamFinish(f->node, l);
    lineDestroy(l);
}

static void testInitialOrder(bool passthrough, bool close)
{
    est_fixture_t f;
    estFixtureSetup(&f, sizeof(softiplimiter_tstate_t), sizeof(softiplimiter_lstate_t));
    softiplimiter_tstate_t *ts = tunnelGetState(f.node);
    twfRequire(softiplimiterTunnelstateInitialize(ts), "SoftIpLimiter table initialization");
    ts->identifier_mode               = kSoftIpLimiterIdentifierVless;
    ts->identification_failure_action = kSoftIpLimiterIdentificationFailurePassthrough;
    ts->simultaneous_user_limit       = 1;
    ts->tolerance_ms                  = 60000;
    addresscontextSetIpAddress(lineGetSourceAddressContext(f.line), "192.0.2.1");
    f.on_init = initEst;
    f.on_est  = close ? closeFromEst : nestedInput;
    f.on_up   = nestedAfterFirst;
    softiplimiterTunnelUpStreamInit(f.node, f.line);
    uint8_t input[18] = {0};
    memorySet(input + 1, 0x42, 16);
    input[0]  = passthrough ? 1 : 0;
    input[17] = 'A';
    softiplimiterTunnelUpStreamPayload(f.node, f.line, estBytes(f.line, input, sizeof(input)));
    twfRequire(f.init_count == 1 && f.est_count == 1, "SoftIpLimiter lost or duplicated synchronous Est");
    if (close)
        twfRequire(f.up_len == 0 && f.up_finish_count == 1, "SoftIpLimiter sent initial data after Est close");
    else
    {
        twfRequire(f.up_len == sizeof(input) + 2 && memoryCompare(f.up, input, sizeof(input)) == 0 &&
                       memoryCompare(f.up + sizeof(input), "BC", 2) == 0,
                   "SoftIpLimiter nested Est input overtook original identity replay");
        softiplimiterTunnelUpStreamFinish(f.node, f.line);
        lineDestroy(f.line);
    }
    twfRequireLineStateZeroed(f.line, f.node, "SoftIpLimiter retained state after Finish");
    softiplimiterTunnelstateDestroy(ts);
    estFixtureDestroy(&f);
}

static void overflowReentryBytes(est_fixture_t *f, line_t *l)
{
    sbuf_t *large = bufferpoolGetBestFit(lineGetBufferPool(l), kSoftIpLimiterMaxReentryBytes, 16);
    sbufSetLength(large, kSoftIpLimiterMaxReentryBytes);
    softiplimiterTunnelUpStreamPayload(f->node, l, large);
    softiplimiter_lstate_t *ls = lineGetState(l, f->node);
    twfRequire(bufferqueueGetBufLen(&ls->initial_reentry) == kSoftIpLimiterMaxReentryBytes,
               "SoftIpLimiter rejected exact transient reentry byte limit");
    softiplimiterTunnelUpStreamPayload(f->node, l, estBytes(l, "X", 1));
}

static void overflowReentryEntries(est_fixture_t *f, line_t *l)
{
    for (unsigned i = 0; i < kSoftIpLimiterMaxReentryBuffers; ++i)
        softiplimiterTunnelUpStreamPayload(f->node, l, estBytes(l, "", 0));
    softiplimiter_lstate_t *ls = lineGetState(l, f->node);
    twfRequire(bufferqueueGetBufCount(&ls->initial_reentry) == kSoftIpLimiterMaxReentryBuffers,
               "SoftIpLimiter rejected exact transient reentry entry limit");
    softiplimiterTunnelUpStreamPayload(f->node, l, estBytes(l, "", 0));
}

static void testReentryLimit(est_inject_fn inject)
{
    est_fixture_t f;
    estFixtureSetup(&f, sizeof(softiplimiter_tstate_t), sizeof(softiplimiter_lstate_t));
    softiplimiter_tstate_t *ts = tunnelGetState(f.node);
    twfRequire(softiplimiterTunnelstateInitialize(ts), "SoftIpLimiter table initialization");
    ts->identifier_mode               = kSoftIpLimiterIdentifierVless;
    ts->identification_failure_action = kSoftIpLimiterIdentificationFailurePassthrough;
    f.on_init                         = initEst;
    f.on_est                          = inject;
    softiplimiterTunnelUpStreamInit(f.node, f.line);
    const uint8_t input[] = {1, 'A'};
    softiplimiterTunnelUpStreamPayload(f.node, f.line, estBytes(f.line, input, sizeof(input)));
    softiplimiterTunnelstateDestroy(ts);
    twfRequire(! lineIsAlive(f.line) && f.up_finish_count == 1 && f.down_finish_count == 1 && f.up_len == 0,
               "SoftIpLimiter reentry overflow did not close both directions and discard initial bytes");
    twfRequireLineStateZeroed(f.line, f.node, "SoftIpLimiter reentry overflow retained state");
    estFixtureDestroy(&f);
}

typedef enum startup_pressure_action_e
{
    kPressureRetained,
    kPressureCanceledBeforeInit,
    kPressureRenewedBeforeInit,
    kPressureResumeInInit,
    kPressurePauseInInit,
    kPressurePauseResumeInInit,
    kPressureResumePauseInInit,
    kPressureNestedPayload,
    kPressureCloseInPause,
    kPressureFinishInPause,
    kPressureCloseInInit,
    kPressureFinishInInit
} startup_pressure_action_t;

static startup_pressure_action_t pressure_action;
static char                      pressure_trace[32];
static size_t                    pressure_trace_length;

static void pressureTrace(char event)
{
    twfRequire(pressure_trace_length + 1 < sizeof(pressure_trace), "SoftIpLimiter pressure trace overflow");
    pressure_trace[pressure_trace_length++] = event;
    pressure_trace[pressure_trace_length]   = '\0';
}

static void pressureInit(est_fixture_t *f, line_t *l)
{
    pressureTrace('I');
    switch (pressure_action)
    {
    case kPressureResumeInInit:
        softiplimiterTunnelUpStreamResume(f->node, l);
        break;
    case kPressurePauseInInit:
        softiplimiterTunnelUpStreamPause(f->node, l);
        break;
    case kPressurePauseResumeInInit:
        softiplimiterTunnelUpStreamPause(f->node, l);
        softiplimiterTunnelUpStreamResume(f->node, l);
        break;
    case kPressureResumePauseInInit:
        softiplimiterTunnelUpStreamResume(f->node, l);
        softiplimiterTunnelUpStreamPause(f->node, l);
        break;
    case kPressureCloseInInit:
        softiplimiterTunnelDownStreamFinish(f->node, l);
        break;
    case kPressureFinishInInit:
        softiplimiterTunnelUpStreamFinish(f->node, l);
        break;
    default:
        break;
    }
}

static void pressurePause(tunnel_t *t, line_t *l)
{
    est_fixture_t *f = estContext(t);
    pressureTrace('U');
    if (pressure_action == kPressureNestedPayload || pressure_action == kPressureCloseInPause ||
        pressure_action == kPressureFinishInPause)
    {
        twfRequire(((softiplimiter_lstate_t *) lineGetState(l, f->node))->initial_forwarding,
                   "SoftIpLimiter released startup FIFO guard before pending Pause");
        softiplimiterTunnelUpStreamPayload(f->node, l, estBytes(l, "B", 1));
    }
    if (pressure_action == kPressureCloseInPause)
        softiplimiterTunnelDownStreamFinish(f->node, l);
    else if (pressure_action == kPressureFinishInPause)
        softiplimiterTunnelUpStreamFinish(f->node, l);
}

static void pressureResume(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    pressureTrace('R');
}

static void pressurePayload(est_fixture_t *f, line_t *l)
{
    pressureTrace('P');
    if (pressure_action == kPressureNestedPayload && pressure_trace_length == 3)
        softiplimiterTunnelUpStreamPayload(f->node, l, estBytes(l, "C", 1));
}

static void testStartupPressure(bool passthrough, startup_pressure_action_t action, const char *expected)
{
    est_fixture_t f;
    estFixtureSetup(&f, sizeof(softiplimiter_tstate_t), sizeof(softiplimiter_lstate_t));
    softiplimiter_tstate_t *ts = tunnelGetState(f.node);
    twfRequire(softiplimiterTunnelstateInitialize(ts), "SoftIpLimiter pressure table initialization");
    ts->identifier_mode               = kSoftIpLimiterIdentifierTrojan;
    ts->identification_failure_action = kSoftIpLimiterIdentificationFailurePassthrough;
    ts->simultaneous_user_limit       = 1;
    ts->tolerance_ms                  = 60000;
    addresscontextSetIpAddress(lineGetSourceAddressContext(f.line), "192.0.2.1");
    f.next->fnPauseU      = pressurePause;
    f.next->fnResumeU     = pressureResume;
    f.on_init             = pressureInit;
    f.on_up               = pressurePayload;
    pressure_action       = action;
    pressure_trace_length = 0;
    pressure_trace[0]     = '\0';
    softiplimiterTunnelUpStreamInit(f.node, f.line);

    char input[] = "0123456789abcdef0123456789abcdef0123456789abcdef01234567\r\nA";
    if (passthrough)
        input[8] = 'x';
    softiplimiterTunnelUpStreamPayload(f.node, f.line, estBytes(f.line, input, 8));
    softiplimiterTunnelUpStreamPause(f.node, f.line);
    softiplimiterTunnelUpStreamPause(f.node, f.line);
    if (action == kPressureCanceledBeforeInit || action == kPressureRenewedBeforeInit)
        softiplimiterTunnelUpStreamResume(f.node, f.line);
    if (action == kPressureRenewedBeforeInit)
        softiplimiterTunnelUpStreamPause(f.node, f.line);
    twfRequire(f.init_count == 0 && pressure_trace_length == 0 && f.up_len == 0,
               "SoftIpLimiter notified an uninitialized next branch");
    softiplimiterTunnelUpStreamPayload(f.node, f.line, estBytes(f.line, input + 8, sizeof(input) - 9));
    twfRequire(f.init_count == 1 && stringCompare(pressure_trace, expected) == 0,
               "SoftIpLimiter lost, duplicated or reordered startup pressure");

    const bool closed   = action == kPressureCloseInPause || action == kPressureCloseInInit;
    const bool finished = action == kPressureFinishInPause || action == kPressureFinishInInit;
    if (closed || finished)
    {
        twfRequire(f.up_len == 0 && lineIsAlive(f.line) == ! closed,
                   "SoftIpLimiter forwarded initial bytes after startup Finish");
        twfRequire(f.up_finish_count == (unsigned) finished && f.down_finish_count == (unsigned) closed,
                   "SoftIpLimiter reflected startup Finish toward its sender");
        if (finished)
            lineDestroy(f.line); /* The initiating mock owner closes after its Finish returns. */
    }
    else
    {
        const bool nested = action == kPressureNestedPayload;
        twfRequire(f.up_len == sizeof(input) - 1 + (nested ? 2 : 0) &&
                       memoryCompare(f.up, input, sizeof(input) - 1) == 0 &&
                       (! nested || memoryCompare(f.up + sizeof(input) - 1, "BC", 2) == 0),
                   "SoftIpLimiter pending Pause changed startup FIFO ordering");
        softiplimiter_lstate_t *ls = lineGetState(f.line, f.node);
        twfRequire(ls->phase == (passthrough ? kSoftIpLimiterPhasePassthrough : kSoftIpLimiterPhaseEstablished) &&
                       ! ls->initial_forwarding && ! ls->pending_next_pause,
                   "SoftIpLimiter retained startup state after pressure replay");
        pressure_action       = kPressureRetained;
        pressure_trace_length = 0;
        softiplimiterTunnelUpStreamPause(f.node, f.line);
        softiplimiterTunnelUpStreamPause(f.node, f.line);
        softiplimiterTunnelUpStreamResume(f.node, f.line);
        softiplimiterTunnelUpStreamResume(f.node, f.line);
        twfRequire(stringCompare(pressure_trace, "UURR") == 0,
                   "SoftIpLimiter suppressed established repeated pressure notifications");
        softiplimiterTunnelUpStreamFinish(f.node, f.line);
        lineDestroy(f.line);
    }
    twfRequireLineStateZeroed(f.line, f.node, "SoftIpLimiter retained state after pressure Finish");
    softiplimiterTunnelstateDestroy(ts);
    estFixtureDestroy(&f);
}

int main(void)
{
    testReentryLimit(overflowReentryBytes);
    testReentryLimit(overflowReentryEntries);
    testInitialOrder(false, false);
    testInitialOrder(true, false);
    testInitialOrder(false, true);
    testInitialOrder(true, true);
    for (unsigned passthrough = 0; passthrough < 2; ++passthrough)
    {
        testStartupPressure(passthrough, kPressureRetained, "IUP");
        testStartupPressure(passthrough, kPressureCanceledBeforeInit, "IP");
        testStartupPressure(passthrough, kPressureRenewedBeforeInit, "IUP");
        testStartupPressure(passthrough, kPressureResumeInInit, "IRP");
        testStartupPressure(passthrough, kPressurePauseInInit, "IUP");
        testStartupPressure(passthrough, kPressurePauseResumeInInit, "IURP");
        testStartupPressure(passthrough, kPressureResumePauseInInit, "IRUP");
        testStartupPressure(passthrough, kPressureNestedPayload, "IUPPP");
        testStartupPressure(passthrough, kPressureCloseInPause, "IU");
        testStartupPressure(passthrough, kPressureFinishInPause, "IU");
        testStartupPressure(passthrough, kPressureCloseInInit, "I");
        testStartupPressure(passthrough, kPressureFinishInInit, "I");
    }
    return 0;
}
