#include "SoftIpLimiter/structure.h"
#include "protocol_est_ordering_fixture.h"

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

int main(void)
{
    testReentryLimit(overflowReentryBytes);
    testReentryLimit(overflowReentryEntries);
    testInitialOrder(false, false);
    testInitialOrder(true, false);
    testInitialOrder(false, true);
    testInitialOrder(true, true);
    return 0;
}
