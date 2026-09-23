#include "HeaderServer/structure.h"
#include "protocol_est_ordering_fixture.h"

static void initEst(est_fixture_t *f, line_t *l)
{
    headerserverTunnelDownStreamEst(f->node, l);
    if (lineIsAlive(l))
        headerserverTunnelDownStreamEst(f->node, l);
}

static void nestedInput(est_fixture_t *f, line_t *l)
{
    headerserverTunnelUpStreamPayload(f->node, l, estBytes(l, "B", 1));
    headerserverTunnelDownStreamPause(f->node, l);
}

static void nestedAfterFirst(est_fixture_t *f, line_t *l)
{
    f->on_up = NULL;
    headerserverTunnelUpStreamPayload(f->node, l, estBytes(l, "C", 1));
}

static void closeFromEst(est_fixture_t *f, line_t *l)
{
    headerserverTunnelUpStreamFinish(f->node, l);
    lineDestroy(l);
}

static void testInitialOrder(bool close)
{
    est_fixture_t f;
    estFixtureSetup(&f, sizeof(headerserver_tstate_t), sizeof(headerserver_lstate_t));
    ((headerserver_tstate_t *) tunnelGetState(f.node))->override_mode = kHeaderServerOverrideModeHeaderPort;
    f.on_init                                                         = initEst;
    f.on_est                                                          = close ? closeFromEst : nestedInput;
    f.on_up                                                           = nestedAfterFirst;
    headerserverTunnelUpStreamInit(f.node, f.line);
    const uint8_t input[] = {0x01, 0xbb, 'A'};
    headerserverTunnelUpStreamPayload(f.node, f.line, estBytes(f.line, input, sizeof(input)));
    twfRequire(f.init_count == 1 && f.est_count == 1, "HeaderServer lost or duplicated synchronous Est");
    if (close)
        twfRequire(f.up_len == 0 && f.up_finish_count == 1, "HeaderServer sent initial data after Est close");
    else
    {
        twfRequire(f.up_len == 3 && memoryCompare(f.up, "ABC", 3) == 0,
                   "HeaderServer nested Est input overtook original payload");
        headerserverTunnelUpStreamFinish(f.node, f.line);
        lineDestroy(f.line);
    }
    twfRequireLineStateZeroed(f.line, f.node, "HeaderServer retained state after Finish");
    estFixtureDestroy(&f);
}

static void overflowReentryBytes(est_fixture_t *f, line_t *l)
{
    sbuf_t *large = bufferpoolGetBestFit(lineGetBufferPool(l), kHeaderServerMaxReentryBytes, 16);
    sbufSetLength(large, kHeaderServerMaxReentryBytes);
    headerserverTunnelUpStreamPayload(f->node, l, large);
    headerserver_lstate_t *ls = lineGetState(l, f->node);
    twfRequire(bufferqueueGetBufLen(&ls->initial_reentry) == kHeaderServerMaxReentryBytes,
               "HeaderServer rejected exact transient reentry byte limit");
    headerserverTunnelUpStreamPayload(f->node, l, estBytes(l, "X", 1));
}

static void overflowReentryEntries(est_fixture_t *f, line_t *l)
{
    for (unsigned i = 0; i < kHeaderServerMaxReentryBuffers; ++i)
        headerserverTunnelUpStreamPayload(f->node, l, estBytes(l, "", 0));
    headerserver_lstate_t *ls = lineGetState(l, f->node);
    twfRequire(bufferqueueGetBufCount(&ls->initial_reentry) == kHeaderServerMaxReentryBuffers,
               "HeaderServer rejected exact transient reentry entry limit");
    headerserverTunnelUpStreamPayload(f->node, l, estBytes(l, "", 0));
}

static void testReentryLimit(est_inject_fn inject)
{
    est_fixture_t f;
    estFixtureSetup(&f, sizeof(headerserver_tstate_t), sizeof(headerserver_lstate_t));
    ((headerserver_tstate_t *) tunnelGetState(f.node))->override_mode = kHeaderServerOverrideModeHeaderPort;
    f.on_init                                                         = initEst;
    f.on_est                                                          = inject;
    headerserverTunnelUpStreamInit(f.node, f.line);
    const uint8_t input[] = {0x01, 0xbb, 'A'};
    headerserverTunnelUpStreamPayload(f.node, f.line, estBytes(f.line, input, sizeof(input)));
    twfRequire(! lineIsAlive(f.line) && f.up_finish_count == 1 && f.down_finish_count == 1 && f.up_len == 0,
               "HeaderServer reentry overflow did not close both directions and discard initial bytes");
    twfRequireLineStateZeroed(f.line, f.node, "HeaderServer reentry overflow retained state");
    estFixtureDestroy(&f);
}

int main(void)
{
    testReentryLimit(overflowReentryBytes);
    testReentryLimit(overflowReentryEntries);
    testInitialOrder(false);
    testInitialOrder(true);
    return 0;
}
