#include "VlessServer/structure.h"

#include "fallback_finish_lifetime_fixture.h"

enum
{
    kTestLargeBufferSize = 64 * 1024,
    kTestLinePoolItems   = 4
};

typedef struct vlessserver_fallback_fixture_s
{
    twf_worker_env_t          env;
    twf_line_pool_t           lines;
    twf_trace_t               trace;
    fallback_finish_fixture_t fallback;
    tunnel_t                 *prev;
    tunnel_t                 *node;
    line_t                   *line;
} vlessserver_fallback_fixture_t;

static void requireVlessStateZero(fallback_finish_fixture_t *fallback, line_t *line)
{
    twfRequireLineStateZeroed(line, fallback->node, "VlessServer state survived fallback Finish");
}

static void injectVlessNonterminal(fallback_finish_fixture_t *fallback, line_t *line)
{
    tunnel_t *node = fallback->node;

    vlessserverTunnelDownStreamPayload(node, line, fallbackFinishMakePayload(lineGetBufferPool(line), "reply"));
    vlessserverTunnelDownStreamInit(node, line);
    vlessserverTunnelDownStreamEst(node, line);
    vlessserverTunnelDownStreamPause(node, line);
    vlessserverTunnelDownStreamResume(node, line);
}

static void injectVlessBranchFinish(fallback_finish_fixture_t *fallback, line_t *line)
{
    vlessserverTunnelDownStreamFinish(fallback->node, line);
}

static void injectVlessPause(fallback_finish_fixture_t *fallback, line_t *line)
{
    vlessserverTunnelDownStreamPause(fallback->node, line);
}

static void fixtureSetup(vlessserver_fallback_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    twfWorkerEnvSetup(&fixture->env, kTestLargeBufferSize, 0);

    fixture->prev = twfCreatePrevTunnel(&fixture->trace);
    fixture->node = tunnelCreate(NULL, sizeof(vlessserver_tstate_t), sizeof(vlessserver_lstate_t));
    twfRequire(fixture->node != NULL, "failed to create the VlessServer tunnel");
    tunnelBind(fixture->prev, fixture->node);

    fixture->fallback.node                    = fixture->node;
    fixture->fallback.require_node_state_zero = requireVlessStateZero;
    fallbackFinishCreateBranch(&fixture->fallback);

    vlessserver_tstate_t *ts                 = tunnelGetState(fixture->node);
    ts->fallback_tunnel                      = fixture->fallback.fallback;
    ts->fallback_intentional_delay_ms        = 7;
    ts->fallback_intentional_delay_jitter_ms = 0;

    twfLinePoolSetup(&fixture->lines, fixture->node->lstate_size, kTestLinePoolItems);
    fixture->line = twfLinePoolCreateLine(&fixture->lines);

    vlessserver_lstate_t *ls = lineGetState(fixture->line, fixture->node);
    vlessserverLinestateInitialize(ls, fixture->node, fixture->line, kVlessServerLineKindClient);
    ls->phase = kVlessServerPhaseFallback;
    tunnelUpStreamInit(fixture->fallback.fallback, fixture->line);
    fallbackFinishResetScheduledTask();
}

static void fixtureDestroyClosedLine(vlessserver_fallback_fixture_t *fixture)
{
    twfRequire(! g_fallback_finish_task.pending, "fixture teardown retained a delayed task");
    twfRequireNoLeakedBuffers();
    twfLinePoolTeardown(&fixture->lines);
    tunnelDestroy(fixture->fallback.fallback);
    tunnelDestroy(fixture->node);
    tunnelDestroy(fixture->prev);
    twfWorkerEnvTeardown(&fixture->env);
}

static void closeFromPreviousOwner(vlessserver_fallback_fixture_t *fixture)
{
    lineRef(fixture->line);
    vlessserverTunnelUpStreamFinish(fixture->node, fixture->line);
    lineDestroy(fixture->line);
}

static void releaseOwnerReference(vlessserver_fallback_fixture_t *fixture)
{
    twfRequireEqualU32(twfLineRefCount(fixture->line), 1, "VlessServer close retained an unexpected line reference");
    lineUnref(fixture->line);
    fixture->line = NULL;
}

static void caseNoPendingPayload(void)
{
    twfSetCase("VlessServer fallback Finish without pending payload");

    vlessserver_fallback_fixture_t fixture;
    fixtureSetup(&fixture);

    closeFromPreviousOwner(&fixture);
    twfRequireEqualU32(fixture.fallback.finish_calls, 1, "fallback did not receive one Finish");
    twfRequireEqualU32(fixture.fallback.payload_calls, 0, "empty fallback close delivered payload");
    twfRequireEqualText(fixture.trace.seq, "", "upstream Finish reflected toward its sender");
    twfRequireLineStateZeroed(fixture.line, fixture.node, "VlessServer state was not destroyed before fallback Finish");

    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void casePendingFifoFlushAndDeadTask(void)
{
    twfSetCase("VlessServer pending fallback FIFO flushes before owner destruction");

    vlessserver_fallback_fixture_t fixture;
    fixtureSetup(&fixture);
    vlessserver_lstate_t *ls = lineGetState(fixture.line, fixture.node);

    twfRequire(vlessserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "one")),
               "first fallback payload was rejected");
    twfRequire(vlessserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "-two")),
               "second fallback payload was rejected");
    twfRequire(vlessserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "-three")),
               "third fallback payload was rejected");
    twfRequire(g_fallback_finish_task.pending, "fallback delay did not retain one task");

    closeFromPreviousOwner(&fixture);
    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "pending fallback payload was not coalesced");
    twfRequireEqualText(
        (const char *) fixture.fallback.received, "one-two-three", "fallback FIFO order changed during close");
    twfRequireEqualU32(fixture.fallback.finish_calls, 1, "fallback Finish was not settled exactly once");
    twfRequireEqualText(fixture.trace.seq, "", "fallback close reflected an event toward its sender");

    fallbackFinishDriveDelayedTask();
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void caseReentrantNonterminalCallbacksAreAbsorbed(void)
{
    twfSetCase("VlessServer re-entrant nonterminal fallback callbacks are absorbed");

    vlessserver_fallback_fixture_t fixture;
    fixtureSetup(&fixture);
    fixture.fallback.inject_during_payload = injectVlessNonterminal;
    vlessserver_lstate_t *ls               = lineGetState(fixture.line, fixture.node);

    twfRequire(vlessserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "final")),
               "fallback payload was rejected");
    const uint32_t recycled_before_close = twfRecycleCount();
    closeFromPreviousOwner(&fixture);

    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "final fallback payload was not delivered");
    twfRequireEqualU32(fixture.fallback.finish_calls, 1, "fallback did not receive its final Finish");
    twfRequireEqualU32(twfRecycleCount(),
                       recycled_before_close + 2,
                       "the final and re-entrant fallback Payload buffers were not recycled");
    twfRequireEqualText(fixture.trace.seq, "", "re-entrant fallback callback reached the finished previous side");
    twfRequireLineStateZeroed(fixture.line, fixture.node, "VlessServer state survived the final fallback Finish");

    fallbackFinishDriveDelayedTask();
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void caseReentrantBranchFinishIsAbsorbed(void)
{
    twfSetCase("VlessServer fallback Finish during final payload is absorbed");

    vlessserver_fallback_fixture_t fixture;
    fixtureSetup(&fixture);
    fixture.fallback.inject_during_payload = injectVlessBranchFinish;
    vlessserver_lstate_t *ls               = lineGetState(fixture.line, fixture.node);

    twfRequire(vlessserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "final")),
               "fallback payload was rejected");
    closeFromPreviousOwner(&fixture);

    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "final fallback payload was not delivered");
    twfRequireEqualU32(fixture.fallback.finish_calls, 0, "fallback received a reflected second Finish");
    twfRequireEqualText(fixture.trace.seq, "", "re-entrant fallback Finish reached the finished previous side");
    twfRequireLineStateZeroed(fixture.line, fixture.node, "VlessServer state survived branch Finish absorption");

    fallbackFinishDriveDelayedTask();
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void caseOrdinaryDelayedBatchHonorsPause(void)
{
    twfSetCase("VlessServer delayed fallback batch coalesces and honors Pause Resume");

    vlessserver_fallback_fixture_t fixture;
    fixtureSetup(&fixture);
    fixture.fallback.inject_during_payload = injectVlessPause;
    vlessserver_lstate_t *ls               = lineGetState(fixture.line, fixture.node);

    twfRequire(vlessserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "one")),
               "first delayed fallback payload was rejected");
    twfRequire(vlessserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "-two")),
               "second delayed fallback payload was rejected");
    twfRequire(vlessserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "-three")),
               "third delayed fallback payload was rejected");
    twfRequire(g_fallback_finish_task.pending, "delayed fallback batch did not schedule one task");

    fallbackFinishDriveDelayedTask();
    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "delayed batch emitted more than one Payload callback");
    twfRequireEqualText(
        (const char *) fixture.fallback.received, "one-two-three", "delayed fallback batch lost FIFO ordering");
    twfRequireEqualText(fixture.trace.seq, "u", "live fallback Pause was not forwarded exactly once");
    twfRequire(! g_fallback_finish_task.pending, "paused fallback scheduled another payload from the original batch");

    twfRequire(vlessserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "held")),
               "paused fallback payload was rejected instead of retained");
    twfRequire(! g_fallback_finish_task.pending, "paused fallback scheduled retained bytes");
    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "paused fallback delivered retained bytes early");

    vlessserverTunnelDownStreamResume(fixture.node, fixture.line);
    twfRequireEqualText(fixture.trace.seq, "ur", "fallback Resume was not forwarded exactly once");
    twfRequire(g_fallback_finish_task.pending, "fallback Resume did not schedule retained bytes");
    fallbackFinishDriveDelayedTask();
    twfRequireEqualU32(
        fixture.fallback.payload_calls, 2, "retained fallback bytes were not delivered once after Resume");
    twfRequireEqualText(
        (const char *) fixture.fallback.received, "one-two-threeheld", "retained fallback bytes changed ordering");

    closeFromPreviousOwner(&fixture);
    twfRequireEqualU32(fixture.fallback.finish_calls, 1, "fallback was not finished after delayed batch test");
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void caseZeroDelayIsInlineAndRetainedBytesDoNotOvertake(void)
{
    twfSetCase("VlessServer zero-delay fallback is inline without FIFO overtaking");

    vlessserver_fallback_fixture_t fixture;
    fixtureSetup(&fixture);
    ((vlessserver_tstate_t *) tunnelGetState(fixture.node))->fallback_intentional_delay_ms = 0;
    fixture.fallback.inject_during_payload                                                 = injectVlessPause;
    vlessserver_lstate_t *ls = lineGetState(fixture.line, fixture.node);

    twfRequire(vlessserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "inline")),
               "zero-delay fallback payload was rejected");
    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "zero-delay fallback Payload was not delivered inline");
    twfRequire(! g_fallback_finish_task.pending, "zero-delay inline fallback admitted a delayed task");
    twfRequireEqualText(fixture.trace.seq, "u", "inline fallback Pause was not forwarded");
    twfRequire(lineIsAlive(fixture.line), "inline fallback Pause unexpectedly closed the line");
    twfRequire(((vlessserver_lstate_t *) lineGetState(fixture.line, fixture.node))->fallback_payload_paused,
               "inline fallback Pause was not published before returning");

    twfRequire(vlessserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "-held")),
               "paused zero-delay fallback payload was rejected instead of retained");
    twfRequire(! g_fallback_finish_task.pending, "paused zero-delay fallback scheduled payload");
    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "paused zero-delay fallback delivered retained bytes early");

    vlessserverTunnelDownStreamResume(fixture.node, fixture.line);
    twfRequireEqualText(fixture.trace.seq, "ur", "zero-delay fallback Resume was not forwarded");
    twfRequire(g_fallback_finish_task.pending, "zero-delay Resume did not schedule retained bytes");
    twfRequireEqualU32(g_fallback_finish_task.delay_ms, 0, "zero-delay retained drain did not use zero delay");

    twfRequire(vlessserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "-later")),
               "new zero-delay fallback payload was rejected");
    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "new zero-delay payload overtook retained bytes");
    twfRequire(g_fallback_finish_task.pending, "retained zero-delay drain was lost before task drive");
    fallbackFinishDriveDelayedTask();
    twfRequireEqualU32(fixture.fallback.payload_calls, 2, "retained zero-delay FIFO was not delivered once");
    twfRequireEqualText(
        (const char *) fixture.fallback.received, "inline-held-later", "zero-delay retained FIFO order changed");

    closeFromPreviousOwner(&fixture);
    twfRequireEqualU32(fixture.fallback.finish_calls, 1, "fallback was not finished after zero-delay test");
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void caseAlreadyPausedCloseDiscardsLocalBatch(void)
{
    twfSetCase("VlessServer close does not bypass an already-paused fallback");

    vlessserver_fallback_fixture_t fixture;
    fixtureSetup(&fixture);
    vlessserver_lstate_t *ls = lineGetState(fixture.line, fixture.node);

    vlessserverTunnelDownStreamPause(fixture.node, fixture.line);
    twfRequire(vlessserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "discard")),
               "paused fallback payload was not retained locally");
    closeFromPreviousOwner(&fixture);

    twfRequireEqualU32(fixture.fallback.payload_calls, 0, "close bypassed fallback Pause with a new payload");
    twfRequireEqualU32(fixture.fallback.finish_calls, 1, "paused fallback was not finished exactly once");
    twfRequire(! g_fallback_finish_task.pending, "paused close retained a delayed task reference");
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

int main(void)
{
    caseNoPendingPayload();
    casePendingFifoFlushAndDeadTask();
    caseReentrantNonterminalCallbacksAreAbsorbed();
    caseReentrantBranchFinishIsAbsorbed();
    caseOrdinaryDelayedBatchHonorsPause();
    caseZeroDelayIsInlineAndRetainedBytesDoNotOvertake();
    caseAlreadyPausedCloseDiscardsLocalBatch();

    printf("vlessserver_fallback_finish_lifetime_test: all cases passed\n");
    return 0;
}
