#pragma once

/* Shared VLESS/VMess node regressions. Each runner supplies protocol aliases;
 * these cases invoke actual node callbacks and StartFallback integration.
 * Both nodes borrow the normal line created and retired by this fixture.
 * Covers initial and delayed FIFO replay, reentry, Finish direction, task refusal,
 * and state retirement. CTest entries are declared by the two including suites. */

#include "fixtures/protocols/fallback_finish_lifetime_fixture.h"

enum
{
    kTestLargeBufferSize = 64 * 1024,
    kTestLinePoolItems   = 4
};

typedef struct fallback_server_fixture_s
{
    twf_worker_env_t          env;
    twf_line_pool_t           lines;
    twf_trace_t               trace;
    fallback_finish_fixture_t fallback;
    tunnel_t                 *prev;
    tunnel_t                 *node;
    line_t                   *line;
} fallback_server_fixture_t;

static void requireServerStateZero(fallback_finish_fixture_t *fallback, line_t *line)
{
    twfRequireLineStateZeroed(line, fallback->node, "fallback server state survived fallback Finish");
}

static void injectServerNonterminal(fallback_finish_fixture_t *fallback, line_t *line)
{
    tunnel_t *node = fallback->node;

    fallbackServerTunnelDownStreamPayload(node, line, fallbackFinishMakePayload(lineGetBufferPool(line), "reply"));
    fallbackServerTunnelDownStreamEst(node, line);
    fallbackServerTunnelDownStreamPause(node, line);
    fallbackServerTunnelDownStreamResume(node, line);
}

static void injectServerBranchFinish(fallback_finish_fixture_t *fallback, line_t *line)
{
    fallbackServerTunnelDownStreamFinish(fallback->node, line);
}

static void injectServerPause(fallback_finish_fixture_t *fallback, line_t *line)
{
    fallbackServerTunnelDownStreamPause(fallback->node, line);
}

/* The fixture creates this owned normal line; both protocol nodes borrow it. */
static void fallbackServerOwnerFinish(tunnel_t *t, line_t *line)
{
    twfPrevFinish(t, line);
    lineDestroy(line);
}

static void fixtureSetupUnselected(fallback_server_fixture_t *fixture, uint32_t delay_ms)
{
    memoryZero(fixture, sizeof(*fixture));
    twfWorkerEnvSetup(&fixture->env, kTestLargeBufferSize, 0);

    fixture->prev         = twfCreatePrevTunnel(&fixture->trace);
    fixture->prev->fnFinD = fallbackServerOwnerFinish;
    fixture->node         = tunnelCreate(NULL, sizeof(fallback_server_tstate_t), sizeof(fallback_server_lstate_t));
    twfRequire(fixture->node != NULL, "failed to create the fallback server tunnel");
    tunnelBind(fixture->prev, fixture->node);

    fixture->fallback.node                    = fixture->node;
    fixture->fallback.require_node_state_zero = requireServerStateZero;
    fallbackFinishCreateBranch(&fixture->fallback);

    fallback_server_tstate_t *ts = tunnelGetState(fixture->node);
    ts->fallback_tunnel          = fixture->fallback.fallback;
    ts->fallback_replay_config   = (fallback_replay_config_t) {
          .delay_ms = delay_ms, .jitter_ms = 0, .max_batch_bytes = kFallbackServerMaxPendingBytes};

    twfLinePoolSetup(&fixture->lines, fixture->node->lstate_size, kTestLinePoolItems);
    fixture->line = twfLinePoolCreateLine(&fixture->lines);

    fallback_server_lstate_t *ls = lineGetState(fixture->line, fixture->node);
    fallbackServerLinestateInitialize(ls, fixture->node, fixture->line, kFallbackServerLineKindClient);
    fallbackFinishResetScheduledTask();
}

static void fixtureSetupWithDelay(fallback_server_fixture_t *fixture, uint32_t delay_ms)
{
    fixtureSetupUnselected(fixture, delay_ms);
    twfRequire(fallbackServerStartFallback(fixture->node, fixture->line), "fallback branch did not initialize");
}

static void fixtureSetup(fallback_server_fixture_t *fixture)
{
    fixtureSetupWithDelay(fixture, 7);
}

static void fixtureDestroyClosedLine(fallback_server_fixture_t *fixture)
{
    twfRequire(! g_fallback_finish_task.pending, "fixture teardown retained a delayed task");
    twfRequireNoLeakedBuffers();
    twfLinePoolTeardown(&fixture->lines);
    tunnelDestroy(fixture->fallback.fallback);
    tunnelDestroy(fixture->node);
    tunnelDestroy(fixture->prev);
    twfWorkerEnvTeardown(&fixture->env);
}

static void closeFromPreviousOwner(fallback_server_fixture_t *fixture)
{
    lineRef(fixture->line);
    fallbackServerTunnelUpStreamFinish(fixture->node, fixture->line);
    lineDestroy(fixture->line);
}

static void releaseOwnerReference(fallback_server_fixture_t *fixture)
{
    twfRequireEqualU32(
        twfLineRefCount(fixture->line), 1, "fallback server close retained an unexpected line reference");
    lineUnref(fixture->line);
    fixture->line = NULL;
}

static void caseNoPendingPayload(void)
{
    twfSetCase("fallback server fallback Finish without pending payload");

    fallback_server_fixture_t fixture;
    fixtureSetup(&fixture);

    closeFromPreviousOwner(&fixture);
    twfRequireEqualU32(fixture.fallback.finish_calls, 1, "fallback did not receive one Finish");
    twfRequireEqualU32(fixture.fallback.payload_calls, 0, "empty fallback close delivered payload");
    twfRequireEqualText(fixture.trace.seq, "", "upstream Finish reflected toward its sender");
    twfRequireLineStateZeroed(
        fixture.line, fixture.node, "fallback server state was not destroyed before fallback Finish");

    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void casePendingFifoFlushAndDeadTask(void)
{
    twfSetCase("fallback server pending fallback FIFO flushes before owner destruction");

    fallback_server_fixture_t fixture;
    fixtureSetup(&fixture);
    fallback_server_lstate_t *ls = lineGetState(fixture.line, fixture.node);

    twfRequire(fallbackServerSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "one")),
               "first fallback payload was rejected");
    twfRequire(fallbackServerSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "-two")),
               "second fallback payload was rejected");
    twfRequire(fallbackServerSendFallbackPayload(
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
    twfSetCase("fallback server re-entrant nonterminal fallback callbacks are absorbed");

    fallback_server_fixture_t fixture;
    fixtureSetup(&fixture);
    fixture.fallback.inject_during_payload = injectServerNonterminal;
    fallback_server_lstate_t *ls           = lineGetState(fixture.line, fixture.node);

    twfRequire(fallbackServerSendFallbackPayload(
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
    twfRequireLineStateZeroed(fixture.line, fixture.node, "fallback server state survived the final fallback Finish");

    fallbackFinishDriveDelayedTask();
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void caseReentrantBranchFinishIsAbsorbed(void)
{
    twfSetCase("fallback server fallback Finish during final payload is absorbed");

    fallback_server_fixture_t fixture;
    fixtureSetup(&fixture);
    fixture.fallback.inject_during_payload = injectServerBranchFinish;
    fallback_server_lstate_t *ls           = lineGetState(fixture.line, fixture.node);

    twfRequire(fallbackServerSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "final")),
               "fallback payload was rejected");
    closeFromPreviousOwner(&fixture);

    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "final fallback payload was not delivered");
    twfRequireEqualU32(fixture.fallback.finish_calls, 0, "fallback received a reflected second Finish");
    twfRequireEqualText(fixture.trace.seq, "", "re-entrant fallback Finish reached the finished previous side");
    twfRequireLineStateZeroed(fixture.line, fixture.node, "fallback server state survived branch Finish absorption");

    fallbackFinishDriveDelayedTask();
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void caseOrdinaryDelayedBatchIgnoresPause(void)
{
    twfSetCase("fallback server delayed fallback batch coalesces through advisory Pause");

    fallback_server_fixture_t fixture;
    fixtureSetup(&fixture);
    fixture.fallback.inject_during_payload = injectServerPause;
    fallback_server_lstate_t *ls           = lineGetState(fixture.line, fixture.node);

    twfRequire(fallbackServerSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "one")),
               "first delayed fallback payload was rejected");
    twfRequire(fallbackServerSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "-two")),
               "second delayed fallback payload was rejected");
    twfRequire(fallbackServerSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "-three")),
               "third delayed fallback payload was rejected");
    twfRequire(g_fallback_finish_task.pending, "delayed fallback batch did not schedule one task");

    fallbackFinishDriveDelayedTask();
    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "delayed batch emitted more than one Payload callback");
    twfRequireEqualText(
        (const char *) fixture.fallback.received, "one-two-three", "delayed fallback batch lost FIFO ordering");
    twfRequireEqualText(fixture.trace.seq, "u", "live fallback Pause was not forwarded exactly once");
    twfRequire(! g_fallback_finish_task.pending, "empty fallback batch scheduled another payload");

    twfRequire(fallbackServerSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "held")),
               "paused fallback payload was rejected instead of retained");
    twfRequire(g_fallback_finish_task.pending, "advisory Pause blocked fallback scheduling");
    fallbackFinishDriveDelayedTask();
    twfRequireEqualU32(fixture.fallback.payload_calls, 2, "due fallback bytes waited for Resume");
    twfRequireEqualText(fixture.trace.seq, "uu", "repeated fallback Pause was suppressed");
    fallbackServerTunnelDownStreamResume(fixture.node, fixture.line);
    fallbackServerTunnelDownStreamResume(fixture.node, fixture.line);
    twfRequireEqualText(fixture.trace.seq, "uurr", "repeated fallback Resume was suppressed");
    twfRequireEqualText(
        (const char *) fixture.fallback.received, "one-two-threeheld", "retained fallback bytes changed ordering");

    closeFromPreviousOwner(&fixture);
    twfRequireEqualU32(fixture.fallback.finish_calls, 1, "fallback was not finished after delayed batch test");
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void injectNestedPayload(fallback_finish_fixture_t *fallback, line_t *line)
{
    const uint32_t calls            = fallback->payload_calls;
    fallback->inject_during_payload = NULL;
    fallbackServerTunnelUpStreamPayload(
        fallback->node, line, fallbackFinishMakePayload(lineGetBufferPool(line), "-held"));
    twfRequireEqualU32(fallback->payload_calls, calls, "nested fallback input recursed into branch Payload");
}

static void injectPauseAndNestedPayload(fallback_finish_fixture_t *fallback, line_t *line)
{
    injectServerPause(fallback, line);
    injectNestedPayload(fallback, line);
}

static void caseZeroDelayIsInlineAndRetainedBytesDoNotOvertake(void)
{
    twfSetCase("zero-delay fallback is inline without FIFO overtaking");

    fallback_server_fixture_t fixture;
    fixtureSetupWithDelay(&fixture, 0);
    fixture.fallback.inject_during_payload = injectPauseAndNestedPayload;
    fallback_server_lstate_t *ls           = lineGetState(fixture.line, fixture.node);

    twfRequire(fallbackServerSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "inline")),
               "zero-delay fallback payload was rejected");
    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "zero-delay fallback Payload was not delivered inline");
    twfRequireEqualText(fixture.trace.seq, "u", "inline fallback Pause was not forwarded");
    twfRequire(lineIsAlive(fixture.line), "inline fallback Pause unexpectedly closed the line");
    twfRequire(g_fallback_finish_task.pending, "zero-delay retained output waited for Resume");
    twfRequireEqualU32(g_fallback_finish_task.delay_ms, 0, "zero-delay retained drain did not use zero delay");

    twfRequire(fallbackServerSendFallbackPayload(
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

static void caseZeroDelayWithoutBacklogDoesNotSchedule(void)
{
    twfSetCase("zero-delay fallback without retained input completes inline");
    fallback_server_fixture_t fixture;
    fixtureSetupWithDelay(&fixture, 0);
    fallbackServerTunnelUpStreamPayload(
        fixture.node, fixture.line, fallbackFinishMakePayload(fixture.env.pool, "inline"));
    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "zero-delay fallback did not complete inline");
    twfRequireEqualText((const char *) fixture.fallback.received, "inline", "inline fallback changed bytes");
    twfRequire(! g_fallback_finish_task.pending, "zero-delay fallback without backlog scheduled a task");
    closeFromPreviousOwner(&fixture);
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void caseAlreadyPausedCloseFlushesLocalBatch(void)
{
    twfSetCase("fallback server close flushes an accepted batch through advisory Pause");

    fallback_server_fixture_t fixture;
    fixtureSetup(&fixture);
    fallback_server_lstate_t *ls = lineGetState(fixture.line, fixture.node);

    fallbackServerTunnelDownStreamPause(fixture.node, fixture.line);
    twfRequire(fallbackServerSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "final")),
               "paused fallback payload was not retained locally");
    closeFromPreviousOwner(&fixture);

    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "close discarded accepted fallback bytes during Pause");
    twfRequireEqualText((const char *) fixture.fallback.received, "final", "close changed the accepted final batch");
    twfRequireEqualU32(fixture.fallback.finish_calls, 1, "paused fallback was not finished exactly once");
    fallbackFinishDriveDelayedTask();
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void retainInitialTranscript(fallback_server_fixture_t *fixture)
{
    fallback_server_lstate_t *ls = lineGetState(fixture->line, fixture->node);
    memoryCopy(ls->header, "prefix", 6);
    ls->header_filled = 6;
    sbuf_t *tail      = fallbackFinishMakePayload(fixture->env.pool, "-tail");
    twfRequire(bufferqueueTryPushBack(&ls->pending_up, &tail), "initial fallback suffix was refused");
    ls->input_bytes = 5;
}

static void injectInputDuringInit(fallback_finish_fixture_t *fallback, line_t *line)
{
    fallbackServerTunnelUpStreamPayload(
        fallback->node, line, fallbackFinishMakePayload(lineGetBufferPool(line), "-init"));
    twfRequireEqualU32(fallback->payload_calls, 0, "fallback replay entered unfinished branch Init");
    twfRequire(! g_fallback_finish_task.pending, "unfinished branch Init scheduled replay");
}

static void injectSourceFinish(fallback_finish_fixture_t *fallback, line_t *line)
{
    fallbackServerTunnelUpStreamFinish(fallback->node, line);
    twfRequireLineStateZeroed(line, fallback->node, "source Finish returned before node state retirement");
}

static void injectSourceClose(fallback_finish_fixture_t *fallback, line_t *line)
{
    injectSourceFinish(fallback, line);
    lineDestroy(line);
}

static void caseInitialTranscriptWithNestedInitAndPayload(void)
{
    twfSetCase("fallback initial transcript precedes nested Init and Payload input");
    fallback_server_fixture_t fixture;
    fixtureSetupUnselected(&fixture, 0);
    retainInitialTranscript(&fixture);
    fixture.fallback.inject_during_init    = injectInputDuringInit;
    fixture.fallback.inject_during_payload = injectNestedPayload;

    twfRequire(fallbackServerStartFallback(fixture.node, fixture.line), "initial fallback replay failed");
    twfRequireEqualU32(fixture.fallback.init_calls, 1, "fallback branch Init count changed");
    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "zero-delay transcript was not one inline batch");
    twfRequireEqualText(
        (const char *) fixture.fallback.received, "prefix-tail-init", "initial transcript FIFO changed");
    twfRequire(g_fallback_finish_task.pending, "nested initial replay input did not schedule a later turn");
    fallbackServerTunnelUpStreamPayload(
        fixture.node, fixture.line, fallbackFinishMakePayload(fixture.env.pool, "-later"));
    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "later input overtook retained initial replay input");
    fallbackFinishDriveDelayedTask();
    twfRequireEqualU32(fixture.fallback.payload_calls, 2, "retained initial replay input was not one batch");
    twfRequireEqualText((const char *) fixture.fallback.received, "prefix-tail-init-held-later", "nested FIFO changed");
    twfRequire(! g_fallback_finish_task.pending, "empty initial replay scheduled another task");
    closeFromPreviousOwner(&fixture);
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void caseCloseDuringUnfinishedInitDiscardsTranscript(void)
{
    twfSetCase("fallback source close during unfinished Init discards transcript");
    fallback_server_fixture_t fixture;
    fixtureSetupUnselected(&fixture, 0);
    retainInitialTranscript(&fixture);
    fixture.fallback.inject_during_init = injectSourceClose;

    lineRef(fixture.line);
    twfRequire(! fallbackServerStartFallback(fixture.node, fixture.line), "closed branch Init reported success");
    twfRequire(! lineIsAlive(fixture.line), "source close during Init retained a logically live line");
    twfRequireLineStateZeroed(fixture.line, fixture.node, "source close during Init retained node state");
    twfRequireEqualU32(fixture.fallback.payload_calls, 0, "unfinished branch Init received transcript bytes");
    twfRequireEqualU32(fixture.fallback.finish_calls, 1, "unfinished branch did not receive exactly one Finish");
    twfRequireEqualText(fixture.trace.seq, "", "Init close reflected toward its finished source");
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void caseCloseDuringPauseAfterInitFlushesTranscript(void)
{
    twfSetCase("fallback source close during replayed Pause flushes initialized transcript");
    fallback_server_fixture_t fixture;
    fixtureSetupUnselected(&fixture, 7);
    retainInitialTranscript(&fixture);
    ((fallback_server_lstate_t *) lineGetState(fixture.line, fixture.node))->response_paused = true;
    fixture.fallback.inject_during_pause                                                     = injectSourceClose;
    fixture.fallback.inject_during_payload                                                   = injectServerNonterminal;

    lineRef(fixture.line);
    twfRequire(! fallbackServerStartFallback(fixture.node, fixture.line), "closed Pause replay reported success");
    twfRequire(! lineIsAlive(fixture.line), "source close during Pause retained a logically live line");
    twfRequireLineStateZeroed(fixture.line, fixture.node, "source close during Pause retained node state");
    twfRequireEqualU32(fixture.fallback.init_calls, 1, "Pause ran before branch Init");
    twfRequireEqualU32(fixture.fallback.pause_calls, 1, "outstanding source Pause was not replayed once");
    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "completed branch Init did not permit final replay");
    twfRequireEqualText((const char *) fixture.fallback.received, "prefix-tail", "Pause close lost initial bytes");
    twfRequireEqualU32(fixture.fallback.finish_calls, 1, "Pause close did not finish the branch once");
    twfRequireEqualText(fixture.trace.seq, "", "Pause close reached its finished source");
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void caseDelayedPayloadReentrySchedulesAnotherTurn(void)
{
    twfSetCase("delayed fallback Payload reentry keeps FIFO in a separate turn");
    fallback_server_fixture_t fixture;
    fixtureSetup(&fixture);
    fixture.fallback.inject_during_payload = injectNestedPayload;
    fallbackServerTunnelUpStreamPayload(
        fixture.node, fixture.line, fallbackFinishMakePayload(fixture.env.pool, "first"));
    fallbackFinishDriveDelayedTask();
    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "delayed nested input ran within the same drain");
    twfRequire(g_fallback_finish_task.pending, "delayed nested input did not schedule another turn");
    twfRequireEqualU32(g_fallback_finish_task.delay_ms, 7, "nested input changed the configured delay");
    fallbackServerTunnelUpStreamPayload(
        fixture.node, fixture.line, fallbackFinishMakePayload(fixture.env.pool, "-later"));
    fallbackFinishDriveDelayedTask();
    twfRequireEqualU32(fixture.fallback.payload_calls, 2, "delayed nested input did not coalesce");
    twfRequireEqualText((const char *) fixture.fallback.received, "first-held-later", "delayed nested FIFO changed");
    closeFromPreviousOwner(&fixture);
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void caseScheduleRefusalClosesAndReleasesTranscript(void)
{
    twfSetCase("fallback scheduling refusal closes both directions and settles buffers");
    fallback_server_fixture_t fixture;
    fixtureSetup(&fixture);
    g_fallback_finish_task.refuse = true;
    lineRef(fixture.line);
    twfRequire(! fallbackServerSendFallbackPayload(fixture.node,
                                                   fixture.line,
                                                   lineGetState(fixture.line, fixture.node),
                                                   fallbackFinishMakePayload(fixture.env.pool, "refused")),
               "refused delayed task reported successful replay");
    twfRequire(! lineIsAlive(fixture.line), "schedule refusal did not retire the owner line");
    twfRequireLineStateZeroed(fixture.line, fixture.node, "schedule refusal retained node state");
    twfRequireEqualU32(fixture.fallback.payload_calls, 0, "schedule refusal unexpectedly delivered bytes");
    twfRequireEqualU32(fixture.fallback.finish_calls, 1, "schedule refusal did not finish the fallback branch");
    twfRequireEqualText(fixture.trace.seq, "f", "schedule refusal did not finish its previous owner once");
    twfRequire(! g_fallback_finish_task.pending, "schedule refusal retained a task reference");
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void caseStateRetiredDuringInlinePayload(void)
{
    twfSetCase("fallback inline Payload stops when node state retires before its borrowed line");
    fallback_server_fixture_t fixture;
    fixtureSetupWithDelay(&fixture, 0);
    fixture.fallback.inject_during_payload = injectSourceFinish;
    twfRequire(! fallbackServerSendFallbackPayload(fixture.node,
                                                   fixture.line,
                                                   lineGetState(fixture.line, fixture.node),
                                                   fallbackFinishMakePayload(fixture.env.pool, "final")),
               "retired node state reported successful replay");
    twfRequire(lineIsAlive(fixture.line), "borrower destroyed its source's normal line");
    twfRequireLineStateZeroed(fixture.line, fixture.node, "inline source Finish retained node state");
    twfRequireEqualU32(fixture.fallback.finish_calls, 1, "inline source Finish did not finish the branch");
    twfRequire(! g_fallback_finish_task.pending, "retired state scheduled more replay");
    lineRef(fixture.line);
    lineDestroy(fixture.line);
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void caseBranchFinishDuringInlinePayload(void)
{
    twfSetCase("fallback inline branch Finish retires node state and owner line before return");
    fallback_server_fixture_t fixture;
    fixtureSetupWithDelay(&fixture, 0);
    fixture.fallback.inject_during_payload = injectServerBranchFinish;
    lineRef(fixture.line);
    twfRequire(! fallbackServerSendFallbackPayload(fixture.node,
                                                   fixture.line,
                                                   lineGetState(fixture.line, fixture.node),
                                                   fallbackFinishMakePayload(fixture.env.pool, "final")),
               "dead line reported successful inline replay");
    twfRequire(! lineIsAlive(fixture.line), "branch Finish returned before owner line retirement");
    twfRequireLineStateZeroed(fixture.line, fixture.node, "branch Finish retained node state");
    twfRequireEqualU32(fixture.fallback.finish_calls, 0, "branch Finish was reflected toward its sender");
    twfRequireEqualText(fixture.trace.seq, "f", "branch Finish did not retire its previous owner once");
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void fallbackReplayRunServerSuite(void)
{
    caseNoPendingPayload();
    casePendingFifoFlushAndDeadTask();
    caseReentrantNonterminalCallbacksAreAbsorbed();
    caseReentrantBranchFinishIsAbsorbed();
    caseOrdinaryDelayedBatchIgnoresPause();
    caseZeroDelayIsInlineAndRetainedBytesDoNotOvertake();
    caseZeroDelayWithoutBacklogDoesNotSchedule();
    caseAlreadyPausedCloseFlushesLocalBatch();
    caseInitialTranscriptWithNestedInitAndPayload();
    caseCloseDuringUnfinishedInitDiscardsTranscript();
    caseCloseDuringPauseAfterInitFlushesTranscript();
    caseDelayedPayloadReentrySchedulesAnotherTurn();
    caseScheduleRefusalClosesAndReleasesTranscript();
    caseStateRetiredDuringInlinePayload();
    caseBranchFinishDuringInlinePayload();
}
