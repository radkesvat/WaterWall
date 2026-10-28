/*
 * Covers: trojanserver fallback finish lifetime; the explicit inputs, callbacks and expected results
 * below define this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: caseNoPendingPayload, casePendingFifoFlushAndDeadTask,
 * caseReentrantNonterminalCallbacksAreAbsorbed, caseReentrantBranchFinishIsAbsorbed,
 * caseOrdinaryDelayedBatchIgnoresAdvisoryPause, caseZeroDelayIsInlineAndRetainedBytesDoNotOvertake,
 * caseAlreadyPausedCloseFlushesLocalBatch, caseMixedSpliceFinalBatch; the driver lists the remaining
 * cases
 * Checks: Assertion labels include: TrojanServer state survived fallback Finish; TrojanServer close
 * retained an unexpected line reference; fallback did not receive one Finish; empty fallback close
 * delivered payload
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.trojanserver_fallback_finish_lifetime_unit
 */
#include "TrojanServer/internal.h"

#include "fixtures/protocols/fallback_finish_lifetime_fixture.h"

enum
{
    kTestLargeBufferSize = 64 * 1024,
    kTestLinePoolItems   = 4
};

typedef struct trojanserver_fallback_fixture_s
{
    twf_worker_env_t          env;
    twf_line_pool_t           lines;
    twf_trace_t               trace;
    fallback_finish_fixture_t fallback;
    tunnel_t                 *prev;
    tunnel_t                 *node;
    line_t                   *line;
} trojanserver_fallback_fixture_t;

static void requireTrojanStateZero(fallback_finish_fixture_t *fallback, line_t *line)
{
    twfRequireLineStateZeroed(line, fallback->node, "TrojanServer state survived fallback Finish");
}

static void injectTrojanNonterminal(fallback_finish_fixture_t *fallback, line_t *line)
{
    tunnel_t *node = fallback->node;

    trojanserverTunnelDownStreamPayload(node, line, fallbackFinishMakePayload(lineGetBufferPool(line), "reply"));
    trojanserverTunnelDownStreamEst(node, line);
    trojanserverTunnelDownStreamPause(node, line);
    trojanserverTunnelDownStreamResume(node, line);
    trojanserverTunnelUpStreamInit(node, line);
    trojanserverTunnelUpStreamPause(node, line);
    trojanserverTunnelUpStreamResume(node, line);
}

static void injectTrojanBranchFinish(fallback_finish_fixture_t *fallback, line_t *line)
{
    trojanserverTunnelDownStreamFinish(fallback->node, line);
}

static void injectTrojanPause(fallback_finish_fixture_t *fallback, line_t *line)
{
    trojanserverTunnelDownStreamPause(fallback->node, line);
}

static void fixtureSetupUnselected(trojanserver_fallback_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    twfWorkerEnvSetup(&fixture->env, kTestLargeBufferSize, 0);

    fixture->prev = twfCreatePrevTunnel(&fixture->trace);
    fixture->node = tunnelCreate(NULL, sizeof(trojanserver_tstate_t), sizeof(trojanserver_lstate_t));
    twfRequire(fixture->node != NULL, "failed to create the TrojanServer tunnel");
    tunnelBind(fixture->prev, fixture->node);
    fixture->node->fnPauseU = trojanserverTunnelUpStreamPause;

    fixture->fallback.node                    = fixture->node;
    fixture->fallback.require_node_state_zero = requireTrojanStateZero;
    fallbackFinishCreateBranch(&fixture->fallback);

    trojanserver_tstate_t *ts                  = tunnelGetState(fixture->node);
    ts->fallback_tunnel                        = fixture->fallback.fallback;
    ts->fallback_replay_config.delay_ms        = 7;
    ts->fallback_replay_config.jitter_ms       = 0;
    ts->fallback_replay_config.max_batch_bytes = kTrojanServerMaxPendingBytes;
    ts->fallback_replay_config.zero_delay_mode = kFallbackReplayCallerDriven;

    twfLinePoolSetup(&fixture->lines, fixture->node->lstate_size, kTestLinePoolItems);
    fixture->line = twfLinePoolCreateLine(&fixture->lines);

    trojanserver_lstate_t *ls = lineGetState(fixture->line, fixture->node);
    trojanserverLinestateInitialize(ls, fixture->node, fixture->line, kTrojanServerLineKindClient);
    fallbackFinishResetScheduledTask();
}

static void fixtureSetup(trojanserver_fallback_fixture_t *fixture)
{
    fixtureSetupUnselected(fixture);
    trojanserverStartFallback(fixture->node, fixture->line, lineGetState(fixture->line, fixture->node));
}

static void fixtureDestroyClosedLine(trojanserver_fallback_fixture_t *fixture)
{
    twfRequire(! g_fallback_finish_task.pending, "fixture teardown retained a delayed task");
    twfRequireNoLeakedBuffers();
    twfLinePoolTeardown(&fixture->lines);
    tunnelDestroy(fixture->fallback.fallback);
    tunnelDestroy(fixture->node);
    tunnelDestroy(fixture->prev);
    twfWorkerEnvTeardown(&fixture->env);
}

static void closeFromPreviousOwner(trojanserver_fallback_fixture_t *fixture)
{
    lineRef(fixture->line);
    trojanserverTunnelUpStreamFinish(fixture->node, fixture->line);
    lineDestroy(fixture->line);
}

static void releaseOwnerReference(trojanserver_fallback_fixture_t *fixture)
{
    twfRequireEqualU32(twfLineRefCount(fixture->line), 1, "TrojanServer close retained an unexpected line reference");
    lineUnref(fixture->line);
    fixture->line = NULL;
}

static void caseNoPendingPayload(void)
{
    twfSetCase("TrojanServer fallback Finish without pending payload");

    trojanserver_fallback_fixture_t fixture;
    fixtureSetup(&fixture);

    closeFromPreviousOwner(&fixture);
    twfRequireEqualU32(fixture.fallback.finish_calls, 1, "fallback did not receive one Finish");
    twfRequireEqualU32(fixture.fallback.payload_calls, 0, "empty fallback close delivered payload");
    twfRequireEqualText(fixture.trace.seq, "", "upstream Finish reflected toward its sender");
    twfRequireLineStateZeroed(
        fixture.line, fixture.node, "TrojanServer state was not destroyed before fallback Finish");

    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void casePendingFifoFlushAndDeadTask(void)
{
    twfSetCase("TrojanServer pending fallback FIFO flushes before owner destruction");

    trojanserver_fallback_fixture_t fixture;
    fixtureSetup(&fixture);
    trojanserver_lstate_t *ls = lineGetState(fixture.line, fixture.node);

    twfRequire(trojanserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "one")),
               "first fallback payload was rejected");
    twfRequire(trojanserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "-two")),
               "second fallback payload was rejected");
    twfRequire(trojanserverSendFallbackPayload(
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
    twfSetCase("TrojanServer re-entrant nonterminal fallback callbacks are absorbed");

    trojanserver_fallback_fixture_t fixture;
    fixtureSetup(&fixture);
    fixture.fallback.inject_during_payload = injectTrojanNonterminal;
    trojanserver_lstate_t *ls              = lineGetState(fixture.line, fixture.node);

    twfRequire(trojanserverSendFallbackPayload(
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
    twfRequireLineStateZeroed(fixture.line, fixture.node, "TrojanServer state survived the final fallback Finish");

    fallbackFinishDriveDelayedTask();
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void caseReentrantBranchFinishIsAbsorbed(void)
{
    twfSetCase("TrojanServer fallback Finish during final payload is absorbed");

    trojanserver_fallback_fixture_t fixture;
    fixtureSetup(&fixture);
    fixture.fallback.inject_during_payload = injectTrojanBranchFinish;
    trojanserver_lstate_t *ls              = lineGetState(fixture.line, fixture.node);

    twfRequire(trojanserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "final")),
               "fallback payload was rejected");
    closeFromPreviousOwner(&fixture);

    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "final fallback payload was not delivered");
    twfRequireEqualU32(fixture.fallback.finish_calls, 0, "fallback received a reflected second Finish");
    twfRequireEqualText(fixture.trace.seq, "", "re-entrant fallback Finish reached the finished previous side");
    twfRequireLineStateZeroed(fixture.line, fixture.node, "TrojanServer state survived branch Finish absorption");

    fallbackFinishDriveDelayedTask();
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void caseOrdinaryDelayedBatchIgnoresAdvisoryPause(void)
{
    twfSetCase("TrojanServer delayed fallback batch stays ordered through repeated advisory Pause Resume");

    trojanserver_fallback_fixture_t fixture;
    fixtureSetup(&fixture);
    fixture.fallback.inject_during_payload = injectTrojanPause;
    trojanserver_lstate_t *ls              = lineGetState(fixture.line, fixture.node);

    twfRequire(trojanserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "one")),
               "first delayed fallback payload was rejected");
    twfRequire(trojanserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "-two")),
               "second delayed fallback payload was rejected");
    twfRequire(trojanserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "-three")),
               "third delayed fallback payload was rejected");
    twfRequire(g_fallback_finish_task.pending, "delayed fallback batch did not schedule one task");

    trojanserverTunnelDownStreamPause(fixture.node, fixture.line);
    fallbackFinishDriveDelayedTask();
    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "Pause stopped or split the due delayed batch");
    twfRequireEqualText(
        (const char *) fixture.fallback.received, "one-two-three", "delayed fallback batch lost FIFO ordering");
    twfRequireEqualText(fixture.trace.seq, "uu", "repeated live fallback Pause was suppressed");
    twfRequire(! g_fallback_finish_task.pending, "drained fallback batch scheduled an empty task");

    twfRequire(trojanserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "held")),
               "paused fallback payload was rejected instead of retained");
    twfRequire(g_fallback_finish_task.pending, "Pause stopped scheduling of retained fallback bytes");
    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "fallback intentional delay was skipped");
    fallbackFinishDriveDelayedTask();
    twfRequireEqualU32(fixture.fallback.payload_calls, 2, "due fallback bytes waited for Resume");
    trojanserverTunnelDownStreamResume(fixture.node, fixture.line);
    trojanserverTunnelDownStreamResume(fixture.node, fixture.line);
    twfRequireEqualText(fixture.trace.seq, "uuurr", "repeated fallback Pause/Resume was suppressed");
    twfRequireEqualText(
        (const char *) fixture.fallback.received, "one-two-threeheld", "retained fallback bytes changed ordering");

    closeFromPreviousOwner(&fixture);
    twfRequireEqualU32(fixture.fallback.finish_calls, 1, "fallback was not finished after delayed batch test");
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void caseZeroDelayIsInlineAndRetainedBytesDoNotOvertake(void)
{
    twfSetCase("TrojanServer zero-delay fallback is inline without FIFO overtaking");

    trojanserver_fallback_fixture_t fixture;
    fixtureSetup(&fixture);
    ((trojanserver_tstate_t *) tunnelGetState(fixture.node))->fallback_replay_config.delay_ms = 0;
    fixture.fallback.inject_during_payload                                                    = injectTrojanPause;
    trojanserver_lstate_t *ls = lineGetState(fixture.line, fixture.node);

    twfRequire(trojanserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "inline")),
               "zero-delay fallback payload was rejected");
    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "zero-delay fallback Payload was not delivered inline");
    twfRequire(! g_fallback_finish_task.pending, "zero-delay inline fallback admitted a delayed task");
    twfRequireEqualText(fixture.trace.seq, "u", "inline fallback Pause was not forwarded");
    twfRequire(lineIsAlive(fixture.line), "inline fallback Pause unexpectedly closed the line");

    twfRequire(trojanserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "-held")),
               "admitted zero-delay fallback payload was rejected");
    twfRequire(! g_fallback_finish_task.pending, "paused zero-delay fallback scheduled payload");
    twfRequireEqualU32(fixture.fallback.payload_calls, 2, "paused zero-delay fallback stranded admitted bytes");

    trojanserverTunnelDownStreamResume(fixture.node, fixture.line);
    twfRequireEqualText(fixture.trace.seq, "uur", "zero-delay fallback repeated Pause/Resume was not forwarded");
    twfRequire(! g_fallback_finish_task.pending, "zero-delay Resume created an unnecessary drain");

    twfRequire(trojanserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "-later")),
               "new zero-delay fallback payload was rejected");
    twfRequireEqualU32(fixture.fallback.payload_calls, 3, "new zero-delay payload was not delivered inline");
    twfRequire(! g_fallback_finish_task.pending, "zero-delay callback left an independent drain");
    twfRequireEqualText(
        (const char *) fixture.fallback.received, "inline-held-later", "zero-delay retained FIFO order changed");

    closeFromPreviousOwner(&fixture);
    twfRequireEqualU32(fixture.fallback.finish_calls, 1, "fallback was not finished after zero-delay test");
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void injectTrojanNestedInput(fallback_finish_fixture_t *fallback, line_t *line)
{
    if (fallback->payload_calls == 1)
    {
        trojanserverTunnelUpStreamPayload(
            fallback->node, line, fallbackFinishMakePayload(lineGetBufferPool(line), "-two"));
        trojanserverTunnelUpStreamPayload(
            fallback->node, line, fallbackFinishMakePayload(lineGetBufferPool(line), "-three"));
        twfRequireEqualU32(fallback->payload_calls, 1, "nested input recursively entered the active Payload");
    }
    else if (fallback->payload_calls == 2)
    {
        twfRequireEqualText((const char *) fallback->received, "one-two", "pump merged distinct nested entries");
        trojanserverTunnelUpStreamPayload(
            fallback->node, line, fallbackFinishMakePayload(lineGetBufferPool(line), "-four"));
        twfRequireEqualU32(fallback->payload_calls, 2, "second nested input recursively entered the pump");
    }
    else if (fallback->payload_calls == 3)
    {
        twfRequireEqualText((const char *) fallback->received, "one-two-three", "later input overtook older input");
    }
}

static void caseNestedZeroDelayInputDrainsSynchronously(void)
{
    twfSetCase("TrojanServer zero-delay nested input drains FIFO one entry at a time before return");
    trojanserver_fallback_fixture_t fixture;
    fixtureSetup(&fixture);
    ((trojanserver_tstate_t *) tunnelGetState(fixture.node))->fallback_replay_config.delay_ms = 0;
    fixture.fallback.inject_during_payload                                                    = injectTrojanNestedInput;

    trojanserverTunnelUpStreamPayload(fixture.node, fixture.line, fallbackFinishMakePayload(fixture.env.pool, "one"));
    twfRequireEqualU32(fixture.fallback.payload_calls, 4, "nested zero-delay input escaped the synchronous pump");
    twfRequireEqualText((const char *) fixture.fallback.received, "one-two-three-four", "nested FIFO changed");
    twfRequire(! g_fallback_finish_task.pending, "nested zero-delay input scheduled an asynchronous drain");
    closeFromPreviousOwner(&fixture);
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void injectTrojanInitInput(fallback_finish_fixture_t *fallback, line_t *line)
{
    trojanserverTunnelUpStreamPayload(
        fallback->node, line, fallbackFinishMakePayload(lineGetBufferPool(line), "-init"));
}

static void injectTrojanPauseInput(fallback_finish_fixture_t *fallback, line_t *line)
{
    trojanserverTunnelUpStreamPayload(
        fallback->node, line, fallbackFinishMakePayload(lineGetBufferPool(line), "-pause"));
}

static void caseInitialZeroDelayBatchIncludesStartupInput(void)
{
    twfSetCase("TrojanServer initial zero-delay transcript includes Init and Pause input in one batch");
    trojanserver_fallback_fixture_t fixture;
    fixtureSetupUnselected(&fixture);
    ((trojanserver_tstate_t *) tunnelGetState(fixture.node))->fallback_replay_config.delay_ms = 0;
    fixture.fallback.inject_during_init                                                       = injectTrojanInitInput;
    fixture.fallback.inject_during_pause                                                      = injectTrojanPauseInput;
    trojanserverTunnelUpStreamPause(fixture.node, fixture.line);
    trojanserverTunnelUpStreamPayload(fixture.node, fixture.line, fallbackFinishMakePayload(fixture.env.pool, "probe"));
    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "startup input split the initial merged replay");
    twfRequireEqualText((const char *) fixture.fallback.received, "probe-init-pause", "startup input overtook replay");
    twfRequire(! g_fallback_finish_task.pending, "zero-delay startup scheduled a task");
    closeFromPreviousOwner(&fixture);
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void injectTrojanSourceFinish(fallback_finish_fixture_t *fallback, line_t *line)
{
    trojanserverTunnelUpStreamFinish(fallback->node, line);
}

static void caseSourceCloseDuringStartup(void)
{
    for (unsigned during_pause = 0; during_pause < 2; ++during_pause)
    {
        twfSetCase(during_pause ? "TrojanServer source close during Pause flushes completed Init transcript"
                                : "TrojanServer source close during Init discards unfinished transcript");
        trojanserver_fallback_fixture_t fixture;
        fixtureSetupUnselected(&fixture);
        if (during_pause)
        {
            trojanserverTunnelUpStreamPause(fixture.node, fixture.line);
            fixture.fallback.inject_during_pause = injectTrojanSourceFinish;
        }
        else
            fixture.fallback.inject_during_init = injectTrojanSourceFinish;

        /* Leave the borrowed allocation alive until the initiating dispatch
         * returns: a surviving line must not let the pump revive wiped state. */
        trojanserverTunnelUpStreamPayload(
            fixture.node, fixture.line, fallbackFinishMakePayload(fixture.env.pool, "probe"));
        twfRequire(lineIsAlive(fixture.line), "borrower destroyed the source-owned line");
        twfRequireEqualU32(fixture.fallback.init_calls, 1, "fallback Init count changed");
        twfRequireEqualU32(fixture.fallback.payload_calls, during_pause, "startup close used the wrong Init barrier");
        if (during_pause)
            twfRequireEqualText((const char *) fixture.fallback.received, "probe", "Pause close lost transcript");
        twfRequireEqualU32(fixture.fallback.finish_calls, 1, "startup close did not finish exactly once");
        twfRequireLineStateZeroed(fixture.line, fixture.node, "outer pump revived closed fallback state");
        twfRequire(! g_fallback_finish_task.pending, "closed startup admitted a delayed task");
        twfRequireEqualText(fixture.trace.seq, "", "source startup close reflected a callback");
        lineRef(fixture.line);
        lineDestroy(fixture.line);
        releaseOwnerReference(&fixture);
        fixtureDestroyClosedLine(&fixture);
    }
}

static void caseSourceCloseDuringPayloadLeavesStateRetired(void)
{
    for (unsigned delayed = 0; delayed < 2; ++delayed)
    {
        twfSetCase("TrojanServer fallback dispatch stops after nested source close while borrowed line survives");
        trojanserver_fallback_fixture_t fixture;
        fixtureSetup(&fixture);
        ((trojanserver_tstate_t *) tunnelGetState(fixture.node))->fallback_replay_config.delay_ms = delayed ? 7 : 0;
        fixture.fallback.inject_during_payload = injectTrojanSourceFinish;
        trojanserverTunnelUpStreamPayload(
            fixture.node, fixture.line, fallbackFinishMakePayload(fixture.env.pool, "final"));
        if (delayed)
            fallbackFinishDriveDelayedTask();
        twfRequire(lineIsAlive(fixture.line), "borrower destroyed the source-owned line during Payload");
        twfRequireEqualU32(fixture.fallback.payload_calls, 1, "nested close replayed a transferred buffer");
        twfRequireEqualU32(fixture.fallback.finish_calls, 1, "nested close did not settle branch Finish");
        twfRequireLineStateZeroed(fixture.line, fixture.node, "dispatch resumed a destroyed fallback state");
        twfRequire(! g_fallback_finish_task.pending, "closed dispatch left a pending task");
        lineRef(fixture.line);
        lineDestroy(fixture.line);
        releaseOwnerReference(&fixture);
        fixtureDestroyClosedLine(&fixture);
    }
}

static void caseAlreadyPausedCloseFlushesLocalBatch(void)
{
    twfSetCase("TrojanServer close flushes fallback bytes despite advisory Pause");

    trojanserver_fallback_fixture_t fixture;
    fixtureSetup(&fixture);
    trojanserver_lstate_t *ls = lineGetState(fixture.line, fixture.node);

    trojanserverTunnelDownStreamPause(fixture.node, fixture.line);
    twfRequire(trojanserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "discard")),
               "paused fallback payload was not retained locally");
    closeFromPreviousOwner(&fixture);

    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "Pause discarded the final fallback batch");
    twfRequireEqualText((const char *) fixture.fallback.received, "discard", "final fallback bytes changed");
    twfRequireEqualU32(fixture.fallback.finish_calls, 1, "paused fallback was not finished exactly once");
    fallbackFinishDriveDelayedTask();
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

#if WW_HAVE_SPLICE
#include <unistd.h>

static void captureSpliceFallback(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    if (sbufIsSplice(buf))
    {
        buffer_pool_t *pool     = lineGetBufferPool(line);
        sbuf_t        *ordinary = bufferpoolGetBestFit(pool, sbufGetLength(buf), bufferpoolGetLargeBufferPadding(pool));
        buf                     = sbufSpliceMaterializeToBuffer(buf, ordinary, pool);
    }
    fallbackFinishFallbackPayload(t, line, buf);
}

static void caseMixedSpliceFinalBatch(void)
{
    for (unsigned paused = 0; paused < 2; ++paused)
    {
        twfSetCase("TrojanServer mixed private-pipe fallback batch settles during source shutdown");
        trojanserver_fallback_fixture_t fixture;
        fixtureSetup(&fixture);
        fixture.fallback.fallback->fnPayloadU  = captureSpliceFallback;
        fixture.fallback.inject_during_payload = injectTrojanNonterminal;
        trojanserver_lstate_t *ls              = lineGetState(fixture.line, fixture.node);
        sbuf_t                *pipe            = bufferpoolGetSpliceBuffer(fixture.env.pool);
        twfRequire(pipe != NULL, "private pipe checkout failed");
        const uint8_t  prefix[] = "private-pipe-prefix";
        const uint32_t count    = sizeof(prefix) - 1;
        twfRequire(write(sbufSpliceMetadata(pipe).pipefd[1], prefix, count) == count, "small pipe write failed");
        pipe->capacity = pipe->l_pad + count;
        sbufSetLength(pipe, count);
        twfRequire(trojanserverSendFallbackPayload(fixture.node, fixture.line, ls, pipe), "pipe fallback rejected");
        const uint32_t large_size = kTestLargeBufferSize + 17;
        sbuf_t        *large      = bufferpoolGetBestFit(fixture.env.pool, large_size, 0);
        memset(sbufGetMutablePtr(large), 'B', large_size);
        sbufSetLength(large, large_size);
        twfRequire(trojanserverSendFallbackPayload(fixture.node, fixture.line, ls, large), "large fallback rejected");
        if (paused)
            trojanserverTunnelDownStreamPause(fixture.node, fixture.line);
        closeFromPreviousOwner(&fixture);
        twfRequire(fixture.fallback.payload_calls == 1, "source Finish lost or split the final batch");
        twfRequire(fixture.fallback.finish_calls == 1, "mixed fallback Finish not settled once");
        twfRequire(fixture.fallback.received_total_len == count + large_size, "mixed final batch truncated");
        twfRequire(memcmp(fixture.fallback.received_prefix, prefix, count) == 0, "private prefix changed");
        for (unsigned i = 0; i < kFallbackFinishCaptureSpan; ++i)
            twfRequire(fixture.fallback.received_suffix[i] == 'B', "large fallback suffix changed");
        twfRequireEqualText(fixture.trace.seq, paused ? "u" : "", "final batch reflected a callback");
        fallbackFinishDriveDelayedTask();
        releaseOwnerReference(&fixture);
        fixtureDestroyClosedLine(&fixture);
    }
}
#endif

static void driveTrojanTaskDuringFinalReplay(fallback_finish_fixture_t *fallback, line_t *line)
{
    discard fallback;
    discard line;
    fallbackFinishDriveDelayedTask();
}

static void casePendingTaskDuringFinalReplayIsHarmless(void)
{
    twfSetCase("TrojanServer old timer reentry during final replay does not restart the fallback pump");
    trojanserver_fallback_fixture_t fixture;
    fixtureSetup(&fixture);
    fixture.fallback.inject_during_payload = driveTrojanTaskDuringFinalReplay;
    trojanserverTunnelUpStreamPayload(fixture.node, fixture.line, fallbackFinishMakePayload(fixture.env.pool, "final"));
    twfRequire(g_fallback_finish_task.pending, "final replay did not begin with a pending timer");
    closeFromPreviousOwner(&fixture);
    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "old timer duplicated final replay");
    twfRequireEqualU32(fixture.fallback.finish_calls, 1, "old timer disrupted final Finish");
    twfRequireEqualText(fixture.trace.seq, "", "old timer reflected a callback toward source");
    twfRequire(! g_fallback_finish_task.pending, "final replay timer reentry rescheduled work");
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void caseCanceledTaskLeavesCleanupWithOwner(void)
{
    twfSetCase("TrojanServer quiesced fallback task leaves its represented FIFO for owner cleanup");
    trojanserver_fallback_fixture_t fixture;
    fixtureSetup(&fixture);
    trojanserver_lstate_t *ls = lineGetState(fixture.line, fixture.node);
    twfRequire(trojanserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "pending")),
               "fallback enqueue failed");
    twfRequire(g_fallback_finish_task.pending, "no task to cancel");
    // The production submission uses no cancellation callback. Quiescence
    // releases its physical reference without running owner-affine state work.
    line_t *task_line = g_fallback_finish_task.line;
    memoryZero(&g_fallback_finish_task, sizeof(g_fallback_finish_task));
    lineUnref(task_line);
    closeFromPreviousOwner(&fixture);
    twfRequire(fixture.fallback.payload_calls == 1 && fixture.fallback.finish_calls == 1,
               "canceled task lost the owner-controlled final batch");
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

int main(void)
{
    caseNoPendingPayload();
    casePendingFifoFlushAndDeadTask();
    caseReentrantNonterminalCallbacksAreAbsorbed();
    caseReentrantBranchFinishIsAbsorbed();
    caseOrdinaryDelayedBatchIgnoresAdvisoryPause();
    caseZeroDelayIsInlineAndRetainedBytesDoNotOvertake();
    caseNestedZeroDelayInputDrainsSynchronously();
    caseSourceCloseDuringStartup();
    caseInitialZeroDelayBatchIncludesStartupInput();
    caseSourceCloseDuringPayloadLeavesStateRetired();
    caseAlreadyPausedCloseFlushesLocalBatch();
    caseCanceledTaskLeavesCleanupWithOwner();
    casePendingTaskDuringFinalReplayIsHarmless();
#if WW_HAVE_SPLICE
    caseMixedSpliceFinalBatch();
#endif

    printf("trojanserver_fallback_finish_lifetime_test: all cases passed\n");
    return 0;
}
