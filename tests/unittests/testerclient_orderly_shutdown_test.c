/*
 * TesterClient runtime-verdict failure injection.
 *
 * TesterClient mixes two policies that used to look identical in the source. A
 * peer that answers with the wrong bytes is a valid runtime verdict: the driver
 * recycles the buffer it still owns, requests an orderly shutdown and returns.
 * A payload generator asked for a payload its own validated configuration can
 * never produce is broken internal state and must hard-abort instead.
 *
 * These cases prove both, plus the refused-worker-0 handoff that is the only
 * reason a verdict may ever reach abortProgramNow().
 */
#include "TesterClient/structure.h"

#include "tunnel_orderly_shutdown_harness.h"

enum
{
    kTestLargeBufferSize = 1 << 21, // the largest TesterClient stream chunk is 2 MiB
    // Packet mode validates the small-buffer size against the maximum packet
    // length before it hands out any buffer.
    kTestSmallBufferSize = kMaxAllowedPacketLength,
    kTestChunkCount      = 3,
    kTestLinePoolItems   = 4
};

typedef struct testerclient_fixture_s
{
    twf_worker_env_t env;
    twf_line_pool_t  lines;
    twf_trace_t      trace;
    tunnel_t        *prev;
    tunnel_t        *tester;
    tunnel_t        *next;
    line_t          *line;
} testerclient_fixture_t;

static void fixtureSetup(testerclient_fixture_t *fixture, bool packet_mode)
{
    memoryZero(&fixture->trace, sizeof(fixture->trace));
    twfWorkerEnvSetupWithSmallBuffers(&fixture->env, kTestLargeBufferSize, kTestSmallBufferSize, 0);

    fixture->prev   = twfCreatePrevTunnel(&fixture->trace);
    fixture->tester = tunnelCreate(NULL, sizeof(testerclient_tstate_t), sizeof(testerclient_lstate_t));
    twfRequire(fixture->tester != NULL, "failed to create the TesterClient tunnel");
    fixture->next = twfCreateNextTunnel(&fixture->trace);

    tunnelBind(fixture->prev, fixture->tester);
    tunnelBind(fixture->tester, fixture->next);

    testerclient_tstate_t *ts = tunnelGetState(fixture->tester);
    ts->chunk_count           = kTestChunkCount;
    ts->packet_mode           = packet_mode;
    ts->split_payload_burst   = kTesterClientSplitPayloadBurst;

    // A pooled line, because the owned-line failure path really does lineDestroy()
    // and that returns the line to line->pools[wid].
    twfLinePoolSetup(&fixture->lines, fixture->tester->lstate_size, kTestLinePoolItems);
    fixture->line = twfLinePoolCreateLine(&fixture->lines);

    // In stream mode the driver publishes its line in the worker slot; the
    // terminal failure path has to detach it again.
    ts->workers[lineGetWID(fixture->line)].line = packet_mode ? NULL : fixture->line;

    testerclient_lstate_t *ls = lineGetState(fixture->line, fixture->tester);
    testerclientLinestateInitialize(ls, lineGetBufferPool(fixture->line));
    ls->request_complete = true;
}

/**
 * Release whatever the case left alive. A case that already drove the owner's own
 * close finds the line dead and only returns the pool; one that also dropped the
 * last reference clears the pointer first, because the allocation is back in the
 * pool by then and reading lineIsAlive() through it would be a use-after-free.
 */
static void fixtureTeardown(testerclient_fixture_t *fixture)
{
    if (fixture->line != NULL && lineIsAlive(fixture->line))
    {
        testerclient_lstate_t *ls = lineGetState(fixture->line, fixture->tester);
        testerclientLinestateDestroy(ls);
        lineDestroy(fixture->line);
    }

    twfLinePoolTeardown(&fixture->lines);
}

/**
 * Build one response payload of @p chunk_index and corrupt a single byte, which
 * is exactly what a misbehaving peer produces.
 */
static sbuf_t *makeCorruptResponse(testerclient_fixture_t *fixture, uint8_t chunk_index)
{
    sbuf_t *buf = testerclientCreatePayload(fixture->tester,
                                            fixture->line,
                                            chunk_index,
                                            0,
                                            testerclientGetChunkSize(fixture->tester, chunk_index),
                                            kTesterClientDirectionResponse);
    twfRequire(buf != NULL, "the payload generator must never return NULL");

    uint8_t *bytes = sbufGetMutablePtr(buf);
    bytes[sbufGetLength(buf) - 1U] ^= 0xFFU;
    return buf;
}

// ---------------------------------------------------------------------------
// Category B: a packet-mode response mismatch
// ---------------------------------------------------------------------------

static void casePacketResponseMismatch(void)
{
    twfSetCase("testerclient packet response mismatch");
    tosResetProcessApi(true);

    testerclient_fixture_t fixture;
    fixtureSetup(&fixture, true);

    const uint32_t recycles_before = twfRecycleCount();
    sbuf_t        *response        = makeCorruptResponse(&fixture, 0);

    testerclientTunnelDownStreamPayload(fixture.tester, fixture.line, response);

    tosRequireAcceptedRequest(1);
    twfRequireEqualU32(twfRecycleCount() - recycles_before, 1, "the response buffer must be recycled exactly once");
    twfRequireNoLeakedBuffers();

    // Nothing may happen after the verdict.
    twfRequireEqualU32(fixture.trace.next_payload, 0, "a failed verdict must not forward a payload");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "a failed verdict must not finish the line");
    twfRequireEqualU32(fixture.trace.prev_payload, 0, "a failed verdict must not answer downstream");

    testerclient_lstate_t *ls = lineGetState(fixture.line, fixture.tester);
    twfRequireEqualU32(ls->response_rx_index, 0, "a failed verdict must not advance the response index");
    twfRequire(! ls->response_complete, "a failed verdict must not mark the response complete");

    fixtureTeardown(&fixture);
}

// ---------------------------------------------------------------------------
// Category B: a stream-mode response mismatch
// ---------------------------------------------------------------------------

static void caseStreamResponseMismatch(void)
{
    twfSetCase("testerclient stream response mismatch");
    tosResetProcessApi(true);

    testerclient_fixture_t fixture;
    fixtureSetup(&fixture, false);

    const uint32_t recycles_before = twfRecycleCount();
    sbuf_t        *response        = makeCorruptResponse(&fixture, 0);

    // The chunk is pushed into the read stream, then read back out as a chunk
    // buffer this callback owns. That extracted chunk is what must be recycled.
    testerclientTunnelDownStreamPayload(fixture.tester, fixture.line, response);

    tosRequireAcceptedRequest(1);
    twfRequireEqualU32(twfRecycleCount() - recycles_before, 1, "the extracted chunk must be recycled exactly once");
    twfRequireNoLeakedBuffers();
    twfRequireEqualU32(fixture.trace.next_payload, 0, "a failed verdict must not forward a payload");

    testerclient_lstate_t *ls = lineGetState(fixture.line, fixture.tester);
    twfRequireEqualU32(ls->response_rx_index, 0, "a failed verdict must not advance the response index");
    twfRequire(! ls->response_complete, "a failed verdict must not mark the response complete");

    fixtureTeardown(&fixture);
}

// ---------------------------------------------------------------------------
// Category B: the worker-0 handoff is refused
// ---------------------------------------------------------------------------

static void refusedHandoffBody(void *argument)
{
    discard argument;

    testerclient_fixture_t fixture;
    fixtureSetup(&fixture, true);

    sbuf_t *response = makeCorruptResponse(&fixture, 0);
    testerclientTunnelDownStreamPayload(fixture.tester, fixture.line, response);
}

static void caseRefusedHandoffAborts(void)
{
    twfSetCase("testerclient verdict with a refused worker-0 handoff");

    // Inherited by the child: requestProgramShutdown() reports that no worker-0
    // handoff is available, which is the only path to the hard fallback.
    tosResetProcessApi(false);
    tosRequireChildExit("the refused-handoff verdict", refusedHandoffBody, NULL, kTosChildFallbackAbort);

    tosResetProcessApi(true);
}

// ---------------------------------------------------------------------------
// Category B: a terminal verdict inside the owner's own Finish handler
// ---------------------------------------------------------------------------
//
// requestProgramShutdown() only schedules worker 0's teardown; this callback
// still returns and unwinds through every frame above it, and those frames keep
// reading lineIsAlive(). So the verdict does not release TesterClient from the
// owner postcondition for the line it created.

static void caseTerminalDownstreamFinishClosesOwnedLine(void)
{
    twfSetCase("testerclient terminal downstream Finish closes its owned line");
    tosResetProcessApi(true);

    testerclient_fixture_t fixture;
    fixtureSetup(&fixture, false);

    testerclient_tstate_t *ts = tunnelGetState(fixture.tester);
    testerclient_lstate_t *ls = lineGetState(fixture.line, fixture.tester);

    // The peer closed before the response was fully verified: a real verdict.
    ls->response_complete = false;

    twfRunOwnerFinish(
        fixture.tester, fixture.line, testerclientTunnelDownStreamFinish, "testerclientTunnelDownStreamFinish");

    tosRequireAcceptedRequest(1);

    // Detached before the destroy: the completion sweep schedules close tasks
    // straight off this slot.
    twfRequire(ts->workers[0].line == NULL, "the terminal failure must detach the worker slot");
    twfRequire(ts->workers[0].closed, "the terminal failure must mark the worker line closed");

    // next finished us, so nothing may go back that way.
    twfRequireEqualU32(fixture.trace.next_finish, 0, "a received downstream Finish must not be reflected upstream");
    twfRequireEqualU32(fixture.trace.next_payload, 0, "a failed verdict must not forward a payload");
    twfRequireEqualU32(fixture.trace.prev_payload, 0, "a failed verdict must not answer downstream");
    twfRequireNoLeakedBuffers();

    // That was the caller's last reference, so the allocation is back in the pool
    // and the fixture pointer is no longer readable.
    twfRequireOwnedLineReclaimed(fixture.line, "testerclientTunnelDownStreamFinish");
    fixture.line = NULL;

    fixtureTeardown(&fixture);
}

// ---------------------------------------------------------------------------
// Category D: the same Finish on a persistent worker packet line
// ---------------------------------------------------------------------------

static void packetModeFinishBody(void *argument)
{
    discard argument;

    testerclient_fixture_t fixture;
    fixtureSetup(&fixture, true);

    testerclient_lstate_t *ls = lineGetState(fixture.line, fixture.tester);
    ls->response_complete     = false;

    testerclientTunnelDownStreamFinish(fixture.tester, fixture.line);
}

static void casePacketModeFinishAborts(void)
{
    twfSetCase("testerclient packet-mode Finish is a packet-line contract violation");

    // A packet line lives for the whole process, so this branch must never reach
    // the orderly helper and must never destroy the line. The handoff is
    // available, so landing on the direct abort proves it was not consulted.
    tosResetProcessApi(true);
    tosRequireChildExit("the packet-mode Finish", packetModeFinishBody, NULL, kTosChildDirectAbort);

    tosResetProcessApi(true);
}

// ---------------------------------------------------------------------------
// Category D: an impossible payload-generator state
// ---------------------------------------------------------------------------

static void payloadGeneratorInvariantBody(void *argument)
{
    discard argument;

    testerclient_fixture_t fixture;
    fixtureSetup(&fixture, true);

    // Packet mode may never split a chunk, so asking for less than chunk 1's
    // full size is a scheduling violation rather than anything a peer can
    // provoke.
    twfRequire(testerclientGetChunkSize(fixture.tester, 1) > 1U, "chunk 1 must be splittable to drive this case");
    discard testerclientCreatePayload(fixture.tester, fixture.line, 1, 0, 1, kTesterClientDirectionRequest);
}

static void casePayloadGeneratorInvariantAborts(void)
{
    twfSetCase("testerclient impossible payload-generator state");

    // The handoff would be accepted, so reaching the abort proves the branch
    // never consults the orderly helper at all.
    tosResetProcessApi(true);
    tosRequireChildExit("the payload-generator invariant", payloadGeneratorInvariantBody, NULL, kTosChildDirectAbort);

    tosResetProcessApi(true);
}

int main(void)
{
    casePacketResponseMismatch();
    caseStreamResponseMismatch();
    caseRefusedHandoffAborts();
    caseTerminalDownstreamFinishClosesOwnedLine();
    casePacketModeFinishAborts();
    casePayloadGeneratorInvariantAborts();

    printf("testerclient_orderly_shutdown_test: all cases passed\n");
    return 0;
}
