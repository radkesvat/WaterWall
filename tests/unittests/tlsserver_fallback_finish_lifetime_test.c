#include "TlsServer/structure.h"

#include "fallback_finish_lifetime_fixture.h"

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
    tlsserverTunnelDownStreamInit(node, line);
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

static void fixtureSetup(tlsserver_fallback_fixture_t *fixture)
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
    ((tlsserver_tstate_t *) tunnelGetState(fixture->node))->fallback_tunnel               = fixture->fallback.fallback;
    ((tlsserver_tstate_t *) tunnelGetState(fixture->node))->fallback_intentional_delay_ms = 7;

    twfLinePoolSetup(&fixture->lines, fixture->node->lstate_size, kTestLinePoolItems);
    fixture->line = twfLinePoolCreateLine(&fixture->lines);

    tlsrecordshaping_config_t record_shaping = {0};
    tlsserver_lstate_t       *ls             = lineGetState(fixture->line, fixture->node);
    twfRequire(tlsserverLinestateInitialize(ls, fixture->ssl_ctx, fixture->env.pool, &record_shaping, false),
               "failed to initialize the TlsServer fallback line");
    ls->tunnel             = fixture->node;
    ls->line               = fixture->line;
    ls->fallback_mode      = true;
    ls->fallback_init_sent = true;
    tlsserverLinestateRelease(ls);
    tunnelUpStreamInit(fixture->fallback.fallback, fixture->line);
    fallbackFinishResetScheduledTask();
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
    lineLock(fixture->line);
    tlsserverTunnelUpStreamFinish(fixture->node, fixture->line);
    lineDestroy(fixture->line);
}

static void releaseOwnerReference(tlsserver_fallback_fixture_t *fixture)
{
    twfRequireEqualU32(twfLineRefCount(fixture->line), 1, "TlsServer close retained an unexpected line reference");
    lineUnlock(fixture->line);
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

static void caseOrdinaryDelayedBatchHonorsPause(void)
{
    twfSetCase("TlsServer delayed fallback batch coalesces and honors Pause Resume");

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
    twfRequire(! g_fallback_finish_task.pending, "paused fallback scheduled retained bytes");
    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "paused fallback delivered retained bytes early");

    tlsserverTunnelDownStreamResume(fixture.node, fixture.line);
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
    twfSetCase("TlsServer zero-delay fallback is inline without FIFO overtaking");

    tlsserver_fallback_fixture_t fixture;
    fixtureSetup(&fixture);
    ((tlsserver_tstate_t *) tunnelGetState(fixture.node))->fallback_intentional_delay_ms = 0;
    fixture.fallback.inject_during_payload                                               = injectTlsPause;
    tlsserver_lstate_t *ls = lineGetState(fixture.line, fixture.node);

    twfRequire(tlsserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "inline")),
               "zero-delay fallback payload was rejected");
    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "zero-delay fallback Payload was not delivered inline");
    twfRequire(! g_fallback_finish_task.pending, "zero-delay inline fallback admitted a delayed task");
    twfRequireEqualText(fixture.trace.seq, "u", "inline fallback Pause was not forwarded");
    twfRequire(lineIsAlive(fixture.line), "inline fallback Pause unexpectedly closed the line");
    twfRequire(((tlsserver_lstate_t *) lineGetState(fixture.line, fixture.node))->fallback_payload_paused,
               "inline fallback Pause was not published before returning");

    twfRequire(tlsserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "-held")),
               "paused zero-delay fallback payload was rejected instead of retained");
    twfRequire(! g_fallback_finish_task.pending, "paused zero-delay fallback scheduled payload");
    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "paused zero-delay fallback delivered retained bytes early");

    tlsserverTunnelDownStreamResume(fixture.node, fixture.line);
    twfRequireEqualText(fixture.trace.seq, "ur", "zero-delay fallback Resume was not forwarded");
    twfRequire(g_fallback_finish_task.pending, "zero-delay Resume did not schedule retained bytes");
    twfRequireEqualU32(g_fallback_finish_task.delay_ms, 0, "zero-delay retained drain did not use zero delay");

    twfRequire(tlsserverSendFallbackPayload(
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
    twfSetCase("TlsServer close does not bypass an already-paused fallback");

    tlsserver_fallback_fixture_t fixture;
    fixtureSetup(&fixture);
    tlsserver_lstate_t *ls = lineGetState(fixture.line, fixture.node);

    tlsserverTunnelDownStreamPause(fixture.node, fixture.line);
    twfRequire(tlsserverSendFallbackPayload(
                   fixture.node, fixture.line, ls, fallbackFinishMakePayload(fixture.env.pool, "discard")),
               "paused fallback payload was not retained locally");
    closeFromPreviousOwner(&fixture);

    twfRequireEqualU32(fixture.fallback.payload_calls, 0, "close bypassed fallback Pause with a new payload");
    twfRequireEqualU32(fixture.fallback.finish_calls, 1, "paused fallback was not finished exactly once");
    twfRequire(! g_fallback_finish_task.pending, "paused close retained a delayed task reference");
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

int main(void)
{
    caseNoPendingPayload();
    casePendingFifoFlushAndDeadTask();
    caseReentrantNonterminalCallbacksAreAbsorbed();
    caseReentrantBranchFinishIsAbsorbed();
    caseOrdinaryDelayedBatchHonorsPause();
    caseZeroDelayIsInlineAndRetainedBytesDoNotOvertake();
    caseAlreadyPausedCloseDiscardsLocalBatch();
    caseExactFallbackPendingCeilingFlushesCleanly();
    caseSchedulingFailureClosesInitializedFallback();
    caseFallbackPendingCeilingClosesLine();

    printf("tlsserver_fallback_finish_lifetime_test: all cases passed\n");
    return 0;
}
