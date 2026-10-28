/*
 * Covers: tlsserver fallback finish lifetime; the explicit inputs, callbacks and expected results below
 * define this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: caseNoPendingPayload, casePendingFifoFlushAndDeadTask,
 * caseReentrantNonterminalCallbacksAreAbsorbed, caseReentrantBranchFinishIsAbsorbed,
 * caseOrdinaryDelayedBatchIgnoresAdvisoryPause, caseZeroDelayIsInlineThroughPause,
 * caseAlreadyPausedCloseFlushesLocalBatch, caseExactFallbackPendingCeilingFlushesCleanly; the driver
 * lists the remaining cases
 * Checks: Assertion labels include: TlsServer state survived fallback Finish; TlsServer close retained an
 * unexpected line reference; fallback did not receive one Finish; empty fallback close delivered payload
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.tlsserver_fallback_finish_lifetime_unit
 */
#include "TlsServer/structure.h"

#include "fixtures/protocols/fallback_finish_lifetime_fixture.h"

enum
{
    kTestLargeBufferSize = 64 * 1024,
    kTestLinePoolItems   = 4
};

typedef struct tlsserver_fallback_fixture_s
{
    twf_worker_env_t          env;
    twf_line_pool_t           lines;
    twf_trace_t               trace;
    twf_trace_t               protected_trace;
    fallback_finish_fixture_t fallback;
    SSL_CTX                  *ssl_ctx;
    tunnel_t                 *prev;
    tunnel_t                 *node;
    tunnel_t                 *protected_next;
    line_t                   *line;
} tlsserver_fallback_fixture_t;

static void requireTlsStateZero(fallback_finish_fixture_t *fallback, line_t *line)
{
    twfRequireLineStateZeroed(line, fallback->node, "TlsServer state survived fallback Finish");
}

static void injectTlsNonterminal(fallback_finish_fixture_t *fallback, line_t *line)
{
    tunnel_t *node = fallback->node;

    tlsserverTunnelDownStreamPayload(node, line, fallbackFinishMakePayload(lineGetBufferPool(line), "reply"));
    tlsserverTunnelDownStreamEst(node, line);
    tlsserverTunnelDownStreamPause(node, line);
    tlsserverTunnelDownStreamResume(node, line);
}

static void injectTlsBranchFinish(fallback_finish_fixture_t *fallback, line_t *line)
{
    tlsserverTunnelDownStreamFinish(fallback->node, line);
}

static void injectTlsPause(fallback_finish_fixture_t *fallback, line_t *line)
{
    tlsserverTunnelDownStreamPause(fallback->node, line);
}

static uint8_t payloadPatternByte(uint32_t index)
{
    return (uint8_t) (index % 251U);
}

static sbuf_t *makePatternPayload(buffer_pool_t *pool, uint32_t length)
{
    sbuf_t *buf = bufferpoolGetLargeBuffer(pool);
    buf         = sbufReserveSpace(buf, length);
    sbufSetLength(buf, length);

    uint8_t *data = sbufGetMutablePtr(buf);
    for (uint32_t i = 0; i < length; ++i)
    {
        data[i] = payloadPatternByte(i);
    }
    return buf;
}

static void requirePatternSpan(const uint8_t *data, uint32_t start, uint32_t length, const char *message)
{
    for (uint32_t i = 0; i < length; ++i)
    {
        twfRequire(data[i] == payloadPatternByte(start + i), message);
    }
}

static void fixtureSetupWithDelay(tlsserver_fallback_fixture_t *fixture, uint32_t delay_ms, bool select_fallback)
{
    memoryZero(fixture, sizeof(*fixture));
    twfWorkerEnvSetup(&fixture->env, kTestLargeBufferSize, 0);

    fixture->ssl_ctx = SSL_CTX_new(TLS_server_method());
    twfRequire(fixture->ssl_ctx != NULL, "failed to create the TlsServer SSL context");

    fixture->prev           = twfCreatePrevTunnel(&fixture->trace);
    fixture->node           = tunnelCreate(NULL, sizeof(tlsserver_tstate_t), sizeof(tlsserver_lstate_t));
    fixture->protected_next = twfCreateNextTunnel(&fixture->protected_trace);
    twfRequire(fixture->node != NULL, "failed to create the TlsServer tunnel");
    tunnelBind(fixture->prev, fixture->node);
    tunnelBind(fixture->node, fixture->protected_next);

    fixture->fallback.node                    = fixture->node;
    fixture->fallback.require_node_state_zero = requireTlsStateZero;
    fallbackFinishCreateBranch(&fixture->fallback);
    tlsserver_tstate_t *ts     = tunnelGetState(fixture->node);
    ts->fallback_tunnel        = fixture->fallback.fallback;
    ts->fallback_replay_config = (fallback_replay_config_t) {
        .delay_ms        = delay_ms,
        .max_batch_bytes = kTlsServerMaxFallbackPendingBytes,
        .zero_delay_mode = kFallbackReplayInlineNested,
    };

    twfLinePoolSetup(&fixture->lines, fixture->node->lstate_size, kTestLinePoolItems);
    fixture->line = twfLinePoolCreateLine(&fixture->lines);

    tlsrecordshaping_config_t record_shaping = {0};
    tlsserver_lstate_t       *ls             = lineGetState(fixture->line, fixture->node);
    twfRequire(tlsserverLinestateInitialize(ls, fixture->ssl_ctx, fixture->env.pool, &record_shaping, false),
               "failed to initialize the TlsServer fallback line");
    ls->tunnel = fixture->node;
    ls->line   = fixture->line;
    if (select_fallback)
    {
        twfRequire(tlsserverStartFallback(fixture->node, fixture->line, ls), "failed to select TLS fallback");
    }
    fallbackFinishResetScheduledTask();
}

static void fixtureSetup(tlsserver_fallback_fixture_t *fixture)
{
    fixtureSetupWithDelay(fixture, 7, true);
}

static void fixtureDestroyClosedLine(tlsserver_fallback_fixture_t *fixture)
{
    twfRequire(! g_fallback_finish_task.pending, "fixture teardown retained a delayed task");
    twfRequireNoLeakedBuffers();
    twfLinePoolTeardown(&fixture->lines);
    tunnelDestroy(fixture->fallback.fallback);
    tunnelDestroy(fixture->protected_next);
    tunnelDestroy(fixture->node);
    tunnelDestroy(fixture->prev);
    SSL_CTX_free(fixture->ssl_ctx);
    twfWorkerEnvTeardown(&fixture->env);
}

static void closeFromPreviousOwner(tlsserver_fallback_fixture_t *fixture)
{
    lineRef(fixture->line);
    tlsserverTunnelUpStreamFinish(fixture->node, fixture->line);
    lineDestroy(fixture->line);
}

static void releaseOwnerReference(tlsserver_fallback_fixture_t *fixture)
{
    twfRequireEqualU32(twfLineRefCount(fixture->line), 1, "TlsServer close retained an unexpected line reference");
    lineUnref(fixture->line);
    fixture->line = NULL;
}

static void caseNoPendingPayload(void)
{
    twfSetCase("TlsServer fallback Finish without pending payload");

    tlsserver_fallback_fixture_t fixture;
    fixtureSetup(&fixture);

    closeFromPreviousOwner(&fixture);
    twfRequireEqualU32(fixture.fallback.finish_calls, 1, "fallback did not receive one Finish");
    twfRequireEqualU32(fixture.fallback.payload_calls, 0, "empty fallback close delivered payload");
    twfRequireEqualText(fixture.trace.seq, "", "upstream Finish reflected toward its sender");
    twfRequireEqualText(fixture.protected_trace.seq, "", "fallback close touched the protected next branch");
    twfRequireLineStateZeroed(fixture.line, fixture.node, "TlsServer state was not destroyed before fallback Finish");

    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void casePendingFifoFlushAndDeadTask(void)
{
    twfSetCase("TlsServer pending fallback FIFO flushes before owner destruction");

    tlsserver_fallback_fixture_t fixture;
    fixtureSetup(&fixture);
    tlsserver_lstate_t *ls = lineGetState(fixture.line, fixture.node);

    twfRequire(tlsserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "one")),
               "first fallback payload was rejected");
    twfRequire(tlsserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "-two")),
               "second fallback payload was rejected");
    twfRequire(tlsserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "-three")),
               "third fallback payload was rejected");
    twfRequire(g_fallback_finish_task.pending, "fallback delay did not retain one task");

    closeFromPreviousOwner(&fixture);
    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "pending fallback payload was not coalesced");
    twfRequireEqualText(
        (const char *) fixture.fallback.received, "one-two-three", "fallback FIFO order changed during close");
    twfRequireEqualU32(fixture.fallback.finish_calls, 1, "fallback Finish was not settled exactly once");
    twfRequireEqualText(fixture.trace.seq, "", "fallback close reflected an event toward its sender");
    twfRequireEqualText(fixture.protected_trace.seq, "", "fallback close touched the protected next branch");

    fallbackFinishDriveDelayedTask();
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void caseReentrantNonterminalCallbacksAreAbsorbed(void)
{
    twfSetCase("TlsServer re-entrant nonterminal fallback callbacks are absorbed");

    tlsserver_fallback_fixture_t fixture;
    fixtureSetup(&fixture);
    fixture.fallback.inject_during_payload = injectTlsNonterminal;
    tlsserver_lstate_t *ls                 = lineGetState(fixture.line, fixture.node);

    twfRequire(tlsserverSendFallbackPayload(
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
    twfRequireEqualText(fixture.protected_trace.seq, "", "re-entrant fallback callback touched protected next");
    twfRequireLineStateZeroed(fixture.line, fixture.node, "TlsServer state survived the final fallback Finish");

    fallbackFinishDriveDelayedTask();
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void caseReentrantBranchFinishIsAbsorbed(void)
{
    twfSetCase("TlsServer fallback Finish during final payload is absorbed");

    tlsserver_fallback_fixture_t fixture;
    fixtureSetup(&fixture);
    fixture.fallback.inject_during_payload = injectTlsBranchFinish;
    tlsserver_lstate_t *ls                 = lineGetState(fixture.line, fixture.node);

    twfRequire(tlsserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "final")),
               "fallback payload was rejected");
    closeFromPreviousOwner(&fixture);

    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "final fallback payload was not delivered");
    twfRequireEqualU32(fixture.fallback.finish_calls, 0, "fallback received a reflected second Finish");
    twfRequireEqualText(fixture.trace.seq, "", "re-entrant fallback Finish reached the finished previous side");
    twfRequireEqualText(fixture.protected_trace.seq, "", "re-entrant fallback Finish touched protected next");
    twfRequireLineStateZeroed(fixture.line, fixture.node, "TlsServer state survived branch Finish absorption");

    fallbackFinishDriveDelayedTask();
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void caseOrdinaryDelayedBatchIgnoresAdvisoryPause(void)
{
    twfSetCase("TlsServer delayed fallback batch coalesces through advisory Pause");

    tlsserver_fallback_fixture_t fixture;
    fixtureSetup(&fixture);
    fixture.fallback.inject_during_payload = injectTlsPause;
    tlsserver_lstate_t *ls                 = lineGetState(fixture.line, fixture.node);

    twfRequire(tlsserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "one")),
               "first delayed fallback payload was rejected");
    twfRequire(tlsserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "-two")),
               "second delayed fallback payload was rejected");
    twfRequire(tlsserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "-three")),
               "third delayed fallback payload was rejected");
    twfRequire(g_fallback_finish_task.pending, "delayed fallback batch did not schedule one task");

    fallbackFinishDriveDelayedTask();
    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "delayed batch emitted more than one Payload callback");
    twfRequireEqualText(
        (const char *) fixture.fallback.received, "one-two-three", "delayed fallback batch lost FIFO ordering");
    twfRequireEqualText(fixture.trace.seq, "u", "live fallback Pause was not forwarded exactly once");
    twfRequire(! g_fallback_finish_task.pending, "paused fallback scheduled another payload from the original batch");

    twfRequire(tlsserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "held")),
               "paused fallback payload was rejected instead of retained");
    twfRequire(g_fallback_finish_task.pending, "advisory Pause blocked delayed fallback scheduling");
    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "paused fallback delivered retained bytes early");

    fallbackFinishDriveDelayedTask();
    tlsserverTunnelDownStreamResume(fixture.node, fixture.line);
    tlsserverTunnelDownStreamResume(fixture.node, fixture.line);
    twfRequireEqualText(fixture.trace.seq, "uurr", "repeated fallback Pause/Resume was not relayed");
    twfRequireEqualU32(fixture.fallback.payload_calls, 2, "due fallback bytes waited for Resume");
    twfRequireEqualText(
        (const char *) fixture.fallback.received, "one-two-threeheld", "retained fallback bytes changed ordering");

    closeFromPreviousOwner(&fixture);
    twfRequireEqualU32(fixture.fallback.finish_calls, 1, "fallback was not finished after delayed batch test");
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void injectTlsInitPayload(fallback_finish_fixture_t *fallback, line_t *line)
{
    tlsserverTunnelUpStreamPayload(fallback->node, line, fallbackFinishMakePayload(lineGetBufferPool(line), "-init"));
    twfRequireEqualU32(fallback->payload_calls, 0, "fallback drained before Init returned");
    twfRequire(! g_fallback_finish_task.pending, "Init scheduled a fallback drain");
}

static void injectTlsPausePayload(fallback_finish_fixture_t *fallback, line_t *line)
{
    tlsserverTunnelUpStreamPayload(fallback->node, line, fallbackFinishMakePayload(lineGetBufferPool(line), "-pause"));
    twfRequireEqualU32(fallback->payload_calls, 0, "Pause replay released the startup FIFO too early");
    twfRequire(! g_fallback_finish_task.pending, "Pause replay scheduled a fallback drain");
}

static void injectTlsNestedPayload(fallback_finish_fixture_t *fallback, line_t *line)
{
    fallback->inject_during_payload = NULL;
    const uint32_t calls            = fallback->payload_calls;
    tlsserverTunnelUpStreamPayload(fallback->node, line, fallbackFinishMakePayload(lineGetBufferPool(line), "-nested"));
    twfRequireEqualU32(fallback->payload_calls, calls + 1, "zero-delay nested fallback Payload was deferred");
    twfRequire(! g_fallback_finish_task.pending, "zero-delay nested fallback Payload scheduled a task");
}

static void caseZeroDelayStartupPreservesFifo(void)
{
    twfSetCase("TlsServer zero-delay startup queues Init and Pause input behind its transcript");
    tlsserver_fallback_fixture_t fixture;
    fixtureSetupWithDelay(&fixture, 0, false);
    tlsserver_lstate_t *ls = lineGetState(fixture.line, fixture.node);
    bufferstreamPush(&ls->fallback_probe, fallbackFinishMakePayload(fixture.env.pool, "first"));
    ls->pending_branch_pause             = true;
    fixture.fallback.inject_during_init  = injectTlsInitPayload;
    fixture.fallback.inject_during_pause = injectTlsPausePayload;

    twfRequire(tlsserverStartFallback(fixture.node, fixture.line, ls), "TLS fallback selection failed");
    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "startup transcript was not delivered as one batch");
    twfRequireEqualText((const char *) fixture.fallback.received,
                        "first-init-pause",
                        "startup callbacks overtook the original TLS fallback transcript");
    twfRequire(! g_fallback_finish_task.pending, "zero-delay startup left a scheduled drain");

    closeFromPreviousOwner(&fixture);
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void caseZeroDelayNestedPayloadIsInline(bool initial_batch)
{
    twfSetCase("TlsServer zero-delay nested fallback Payload stays inline");
    tlsserver_fallback_fixture_t fixture;
    fixtureSetupWithDelay(&fixture, 0, ! initial_batch);
    tlsserver_lstate_t *ls                 = lineGetState(fixture.line, fixture.node);
    fixture.fallback.inject_during_payload = injectTlsNestedPayload;
    if (initial_batch)
    {
        bufferstreamPush(&ls->fallback_probe, fallbackFinishMakePayload(fixture.env.pool, "first"));
        twfRequire(tlsserverStartFallback(fixture.node, fixture.line, ls), "TLS fallback selection failed");
    }
    else
    {
        twfRequire(tlsserverSendFallbackPayload(
                       fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "first")),
                   "live zero-delay fallback payload failed");
    }
    twfRequireEqualText((const char *) fixture.fallback.received, "first-nested", "nested fallback FIFO changed");
    twfRequireEqualU32(fixture.fallback.payload_calls, 2, "nested fallback was not delivered exactly once");
    closeFromPreviousOwner(&fixture);
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void caseZeroDelayIsInlineThroughPause(void)
{
    twfSetCase("TlsServer zero-delay fallback is inline without FIFO overtaking");

    tlsserver_fallback_fixture_t fixture;
    fixtureSetupWithDelay(&fixture, 0, true);
    fixture.fallback.inject_during_payload = injectTlsPause;
    tlsserver_lstate_t *ls                 = lineGetState(fixture.line, fixture.node);

    twfRequire(tlsserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "inline")),
               "zero-delay fallback payload was rejected");
    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "zero-delay fallback Payload was not delivered inline");
    twfRequire(! g_fallback_finish_task.pending, "zero-delay inline fallback admitted a delayed task");
    twfRequireEqualText(fixture.trace.seq, "u", "inline fallback Pause was not forwarded");
    twfRequire(lineIsAlive(fixture.line), "inline fallback Pause unexpectedly closed the line");

    /* Pause alone does not create a queue on the zero-delay path. */
    twfRequire(tlsserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "-ready")),
               "zero-delay fallback rejected bytes during Pause");
    twfRequireEqualU32(fixture.fallback.payload_calls, 2, "zero-delay fallback waited for Resume");
    twfRequire(! g_fallback_finish_task.pending, "zero-delay fallback scheduled an unnecessary task");

    closeFromPreviousOwner(&fixture);
    twfRequireEqualU32(fixture.fallback.finish_calls, 1, "fallback was not finished after zero-delay test");
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void caseAlreadyPausedCloseFlushesLocalBatch(void)
{
    twfSetCase("TlsServer close flushes final fallback bytes through advisory Pause");

    tlsserver_fallback_fixture_t fixture;
    fixtureSetup(&fixture);
    tlsserver_lstate_t *ls = lineGetState(fixture.line, fixture.node);

    tlsserverTunnelDownStreamPause(fixture.node, fixture.line);
    twfRequire(tlsserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "final")),
               "paused fallback payload was not retained locally");
    closeFromPreviousOwner(&fixture);

    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "close lost its final batch behind advisory Pause");
    twfRequireEqualText((const char *) fixture.fallback.received, "final", "close changed the final batch");
    twfRequireEqualU32(fixture.fallback.finish_calls, 1, "paused fallback was not finished exactly once");
    fallbackFinishDriveDelayedTask();
    twfRequireEqualText(fixture.protected_trace.seq, "", "paused fallback close touched protected next");
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void caseExactFallbackPendingCeilingFlushesCleanly(void)
{
    twfSetCase("TlsServer exact one MiB fallback FIFO flushes before Finish");

    tlsserver_fallback_fixture_t fixture;
    fixtureSetup(&fixture);
    tlsserver_lstate_t *ls = lineGetState(fixture.line, fixture.node);

    twfRequire(
        tlsserverSendFallbackPayload(
            fixture.node, fixture.line, ls, makePatternPayload(fixture.env.pool, kTlsServerMaxFallbackPendingBytes)),
        "exact one MiB fallback payload was rejected");
    twfRequire(g_fallback_finish_task.pending, "exact one MiB fallback payload did not schedule its delayed task");

    closeFromPreviousOwner(&fixture);
    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "exact one MiB fallback payload was not flushed once");
    twfRequireEqualU32((uint32_t) fixture.fallback.received_total_len,
                       kTlsServerMaxFallbackPendingBytes,
                       "exact one MiB fallback payload changed byte count");
    twfRequireEqualU32(fixture.fallback.received_prefix_len,
                       kFallbackFinishCaptureSpan,
                       "exact one MiB fallback prefix was not captured");
    twfRequireEqualU32(fixture.fallback.received_suffix_len,
                       kFallbackFinishCaptureSpan,
                       "exact one MiB fallback suffix was not captured");
    requirePatternSpan(
        fixture.fallback.received_prefix, 0, kFallbackFinishCaptureSpan, "exact one MiB fallback prefix changed bytes");
    requirePatternSpan(fixture.fallback.received_suffix,
                       kTlsServerMaxFallbackPendingBytes - kFallbackFinishCaptureSpan,
                       kFallbackFinishCaptureSpan,
                       "exact one MiB fallback suffix changed bytes");
    twfRequireEqualU32(fixture.fallback.finish_calls, 1, "exact one MiB fallback did not receive one Finish");
    twfRequireLineStateZeroed(fixture.line, fixture.node, "exact one MiB fallback close retained TlsServer state");
    twfRequireEqualText(fixture.protected_trace.seq, "", "exact one MiB fallback close touched protected next");

    fallbackFinishDriveDelayedTask();
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void caseFallbackLimitCountsBytesOnly(void)
{
    twfSetCase("TlsServer fallback byte allowance does not add an entry or allocation ceiling");
    tlsserver_fallback_fixture_t fixture;
    fixtureSetup(&fixture);
    tlsserver_lstate_t *ls = lineGetState(fixture.line, fixture.node);
    for (unsigned i = 0; i < 1025; ++i)
    {
        sbuf_t *payload = bufferpoolGetSmallBuffer(fixture.env.pool);
        sbufSetLength(payload, 1);
        sbufWrite(payload, "x", 1);
        twfRequire(tlsserverSendFallbackPayload(fixture.node, fixture.line, ls, payload),
                   "byte-only fallback limit rejected a legal small fragment");
    }
    closeFromPreviousOwner(&fixture);
    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "small fallback fragments did not form one final batch");
    twfRequireEqualU32((uint32_t) fixture.fallback.received_total_len, 1025, "fallback fragment count changed bytes");
    twfRequireEqualU32(fixture.fallback.finish_calls, 1, "fragmented fallback did not finish exactly once");
    fallbackFinishDriveDelayedTask();
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

static void caseSchedulingFailureClosesInitializedFallback(void)
{
    twfSetCase("TlsServer delayed fallback scheduling failure closes initialized branch");

    tlsserver_fallback_fixture_t fixture;
    fixtureSetup(&fixture);
    tlsserver_lstate_t *ls = lineGetState(fixture.line, fixture.node);

    g_fallback_finish_task.refuse = true;
    twfRequire(! tlsserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "drop")),
               "refused delayed scheduling reported success");
    g_fallback_finish_task.refuse = false;

    twfRequireEqualU32(fixture.fallback.finish_calls, 1, "fatal fallback close did not finish the initialized branch");
    twfRequireEqualU32(fixture.trace.prev_finish, 1, "fatal fallback close did not finish the previous side");
    twfRequireEqualText(fixture.protected_trace.seq, "", "scheduling failure touched protected next branch");
    twfRequireLineStateZeroed(fixture.line, fixture.node, "fatal fallback close retained TlsServer state");
    twfRequire(! g_fallback_finish_task.pending, "refused scheduling retained a delayed task reference");

    lineDestroy(fixture.line);
    fixture.line = NULL;
    fixtureDestroyClosedLine(&fixture);
}

static void caseFallbackPendingCeilingClosesLine(void)
{
    twfSetCase("TlsServer fallback delayed FIFO one byte over one MiB closes locally");

    tlsserver_fallback_fixture_t fixture;
    fixtureSetup(&fixture);
    tlsserver_lstate_t *ls = lineGetState(fixture.line, fixture.node);

    twfRequire(
        tlsserverSendFallbackPayload(
            fixture.node, fixture.line, ls, makePatternPayload(fixture.env.pool, kTlsServerMaxFallbackPendingBytes)),
        "one MiB fallback payload was rejected");
    twfRequire(! tlsserverSendFallbackPayload(fixture.node, fixture.line, ls, makePatternPayload(fixture.env.pool, 1)),
               "fallback payload one byte over one MiB was accepted");

    twfRequireEqualU32(fixture.fallback.payload_calls, 0, "overflow close delivered delayed fallback payload");
    twfRequireEqualU32(fixture.fallback.finish_calls, 1, "overflow close did not finish fallback exactly once");
    twfRequireEqualU32(fixture.trace.prev_finish, 1, "overflow close did not finish the previous side exactly once");
    twfRequireEqualText(fixture.protected_trace.seq, "", "overflow close touched protected next branch");
    twfRequireLineStateZeroed(fixture.line, fixture.node, "overflow close retained TlsServer state");

    lineDestroy(fixture.line);
    fallbackFinishDriveDelayedTask();
    fixture.line = NULL;
    fixtureDestroyClosedLine(&fixture);
}

static void caseEstablishedLineStillForwardsTransportEst(void)
{
    twfSetCase("TlsServer relays marked continuing-line Est exactly once");
    tlsserver_fallback_fixture_t fixture;
    fixtureSetup(&fixture);
    // A mapped downstream endpoint (for example Fisher) may mark before forwarding.
    lineMarkEstablished(fixture.line);
    tlsserverTunnelDownStreamEst(fixture.node, fixture.line);
    tlsserverTunnelDownStreamEst(fixture.node, fixture.line);
    twfRequireEqualU32(fixture.trace.prev_est, 1, "shared line marker suppressed or duplicated transport Est");
    closeFromPreviousOwner(&fixture);
    releaseOwnerReference(&fixture);
    fixtureDestroyClosedLine(&fixture);
}

int main(void)
{
    caseEstablishedLineStillForwardsTransportEst();
    caseNoPendingPayload();
    casePendingFifoFlushAndDeadTask();
    caseReentrantNonterminalCallbacksAreAbsorbed();
    caseReentrantBranchFinishIsAbsorbed();
    caseOrdinaryDelayedBatchIgnoresAdvisoryPause();
    caseZeroDelayIsInlineThroughPause();
    caseZeroDelayStartupPreservesFifo();
    caseZeroDelayNestedPayloadIsInline(true);
    caseZeroDelayNestedPayloadIsInline(false);
    caseAlreadyPausedCloseFlushesLocalBatch();
    caseExactFallbackPendingCeilingFlushesCleanly();
    caseFallbackLimitCountsBytesOnly();
    caseSchedulingFailureClosesInitializedFallback();
    caseFallbackPendingCeilingClosesLine();

    printf("tlsserver_fallback_finish_lifetime_test: all cases passed\n");
    return 0;
}
