/*
 * TesterServer runtime-verdict failure injection.
 *
 * The mirror image of the TesterClient cases: a peer that sends the wrong
 * request bytes is a runtime verdict that recycles its buffer and requests an
 * orderly shutdown, while an impossible payload-generator state and the death
 * of a persistent worker packet line are invariants that must hard-abort.
 */
#include "TesterServer/structure.h"

#include "tunnel_orderly_shutdown_harness.h"

enum
{
    kTestLargeBufferSize = 1 << 20,
    // Packet mode responses are always taken from the small pool, so it has to
    // hold a maximum-length packet.
    kTestSmallBufferSize = kMaxAllowedPacketLength,
    // Five chunks give a 64-byte packet chunk and a 32-byte stream chunk, both
    // far too wide for one corrupted byte to accidentally match another flow id.
    kTestChunkCount       = 5,
    kTestPacketChunkIndex = 4,
    kTestStreamChunkIndex = 3
};

typedef struct testerserver_fixture_s
{
    twf_worker_env_t env;
    twf_trace_t      trace;
    tunnel_t        *prev;
    tunnel_t        *tester;
    tunnel_t        *next;
    line_t          *line;
} testerserver_fixture_t;

static void fixtureSetup(testerserver_fixture_t *fixture, bool packet_mode, bool packet_stateless)
{
    memoryZero(&fixture->trace, sizeof(fixture->trace));
    twfWorkerEnvSetupWithSmallBuffers(&fixture->env, kTestLargeBufferSize, kTestSmallBufferSize, 0);

    fixture->prev   = twfCreatePrevTunnel(&fixture->trace);
    fixture->tester = tunnelCreate(NULL, sizeof(testerserver_tstate_t), sizeof(testerserver_lstate_t));
    twfRequire(fixture->tester != NULL, "failed to create the TesterServer tunnel");
    fixture->next = twfCreateNextTunnel(&fixture->trace);

    tunnelBind(fixture->prev, fixture->tester);
    tunnelBind(fixture->tester, fixture->next);

    testerserver_tstate_t *ts = tunnelGetState(fixture->tester);
    ts->chunk_count           = kTestChunkCount;
    ts->packet_mode           = packet_mode;
    ts->packet_stateless      = packet_stateless;
    ts->split_payload_burst   = 1;

    fixture->line = twfLineCreate(fixture->tester->lstate_size);

    testerserver_lstate_t *ls = lineGetState(fixture->line, fixture->tester);
    testerserverLinestateInitialize(ls, lineGetBufferPool(fixture->line));
}

static void fixtureTeardown(testerserver_fixture_t *fixture)
{
    testerserver_lstate_t *ls = lineGetState(fixture->line, fixture->tester);
    testerserverLinestateDestroy(ls);
    twfLineDestroy(fixture->line);
}

/**
 * Build a well-formed request chunk and flip one byte, which is what a
 * misbehaving peer produces.
 */
static sbuf_t *makeCorruptRequest(testerserver_fixture_t *fixture, uint8_t chunk_index)
{
    sbuf_t *buf = testerserverCreatePayload(fixture->tester,
                                            fixture->line,
                                            chunk_index,
                                            0,
                                            testerserverGetChunkSize(fixture->tester, chunk_index),
                                            kTesterServerDirectionRequest);
    twfRequire(buf != NULL, "the payload generator must never return NULL");

    uint8_t *bytes = sbufGetMutablePtr(buf);
    bytes[sbufGetLength(buf) - 1U] ^= 0xFFU;
    return buf;
}

static void requireVerdictLeftNothingBehind(testerserver_fixture_t *fixture)
{
    tosRequireAcceptedRequest(1);
    twfRequireNoLeakedBuffers();
    twfRequireEqualU32(fixture->trace.prev_payload, 0, "a failed verdict must not answer the peer");
    twfRequireEqualU32(fixture->trace.next_payload, 0, "a failed verdict must not forward upstream");

    testerserver_lstate_t *ls = lineGetState(fixture->line, fixture->tester);
    twfRequireEqualU32(bufferqueueGetBufCount(&ls->response_queue), 0, "a failed verdict must not queue a response");
    twfRequire(! ls->response_ready, "a failed verdict must not mark the request verified");
}

// ---------------------------------------------------------------------------
// Category B: a packet-mode request mismatch
// ---------------------------------------------------------------------------

static void casePacketRequestMismatch(void)
{
    twfSetCase("testerserver packet request mismatch");
    tosResetProcessApi(true);

    testerserver_fixture_t fixture;
    fixtureSetup(&fixture, true, false);

    testerserver_lstate_t *ls = lineGetState(fixture.line, fixture.tester);
    // Chunk 0 only carries the flow id, so a verifiable chunk index is needed.
    ls->request_rx_index = kTestPacketChunkIndex;

    const uint32_t recycles_before = twfRecycleCount();
    sbuf_t        *request         = makeCorruptRequest(&fixture, kTestPacketChunkIndex);

    testerserverTunnelUpStreamPayload(fixture.tester, fixture.line, request);

    twfRequireEqualU32(twfRecycleCount() - recycles_before, 1, "the request buffer must be recycled exactly once");
    requireVerdictLeftNothingBehind(&fixture);
    twfRequireEqualU32(ls->request_rx_index, kTestPacketChunkIndex, "a failed verdict must not advance the index");

    fixtureTeardown(&fixture);
}

// ---------------------------------------------------------------------------
// Category B: a stateless packet-mode request mismatch
// ---------------------------------------------------------------------------

static void caseStatelessPacketRequestMismatch(void)
{
    twfSetCase("testerserver stateless packet request mismatch");
    tosResetProcessApi(true);

    testerserver_fixture_t fixture;
    fixtureSetup(&fixture, true, true);

    const uint32_t recycles_before = twfRecycleCount();
    // The stateless path infers the chunk index from the packet size and then
    // tries every flow id, so a corrupted wide chunk cannot match any of them.
    sbuf_t *request = makeCorruptRequest(&fixture, kTestPacketChunkIndex);

    testerserverTunnelUpStreamPayload(fixture.tester, fixture.line, request);

    twfRequireEqualU32(twfRecycleCount() - recycles_before, 1, "the request buffer must be recycled exactly once");
    requireVerdictLeftNothingBehind(&fixture);

    fixtureTeardown(&fixture);
}

// ---------------------------------------------------------------------------
// Category B: a stream-mode request mismatch
// ---------------------------------------------------------------------------

static void caseStreamRequestMismatch(void)
{
    twfSetCase("testerserver stream request mismatch");
    tosResetProcessApi(true);

    testerserver_fixture_t fixture;
    fixtureSetup(&fixture, false, false);

    testerserver_lstate_t *ls = lineGetState(fixture.line, fixture.tester);
    ls->request_rx_index      = kTestStreamChunkIndex;

    const uint32_t recycles_before = twfRecycleCount();
    sbuf_t        *request         = makeCorruptRequest(&fixture, kTestStreamChunkIndex);

    // Pushed into the read stream, then read back out as a chunk this callback
    // owns; that extracted chunk is what must be recycled before the verdict.
    testerserverTunnelUpStreamPayload(fixture.tester, fixture.line, request);

    twfRequireEqualU32(twfRecycleCount() - recycles_before, 1, "the extracted chunk must be recycled exactly once");
    requireVerdictLeftNothingBehind(&fixture);
    twfRequireEqualU32(ls->request_rx_index, kTestStreamChunkIndex, "a failed verdict must not advance the index");

    fixtureTeardown(&fixture);
}

// ---------------------------------------------------------------------------
// Category B: the worker-0 handoff is refused
// ---------------------------------------------------------------------------

static void refusedHandoffBody(void *argument)
{
    discard argument;

    testerserver_fixture_t fixture;
    fixtureSetup(&fixture, true, false);

    testerserver_lstate_t *ls = lineGetState(fixture.line, fixture.tester);
    ls->request_rx_index      = kTestPacketChunkIndex;

    testerserverTunnelUpStreamPayload(
        fixture.tester, fixture.line, makeCorruptRequest(&fixture, kTestPacketChunkIndex));
}

static void caseRefusedHandoffAborts(void)
{
    twfSetCase("testerserver verdict with a refused worker-0 handoff");

    tosResetProcessApi(false);
    tosRequireChildExit("the refused-handoff verdict", refusedHandoffBody, NULL, kTosChildFallbackAbort);

    tosResetProcessApi(true);
}

// ---------------------------------------------------------------------------
// Category D: an impossible payload-generator state
// ---------------------------------------------------------------------------

static void payloadGeneratorInvariantBody(void *argument)
{
    discard argument;

    testerserver_fixture_t fixture;
    fixtureSetup(&fixture, true, false);

    // Packet mode may never split a chunk.
    twfRequire(testerserverGetChunkSize(fixture.tester, 1) > 1U, "chunk 1 must be splittable to drive this case");
    discard testerserverCreatePayload(fixture.tester, fixture.line, 1, 0, 1, kTesterServerDirectionResponse);
}

static void casePayloadGeneratorInvariantAborts(void)
{
    twfSetCase("testerserver impossible payload-generator state");

    // The handoff would be accepted, so reaching the hard abort proves this
    // branch never consults the orderly helper.
    tosResetProcessApi(true);
    tosRequireChildExit("the payload-generator invariant", payloadGeneratorInvariantBody, NULL, kTosChildDirectAbort);

    tosResetProcessApi(true);
}

// ---------------------------------------------------------------------------
// Category D: a persistent worker packet line dies during a response send
// ---------------------------------------------------------------------------

/**
 * A fake peer that kills the line while receiving the response, which is the
 * packet-line contract violation the send task must never survive.
 */
static void killLineOnPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    lineReuseBuffer(l, buf);
    l->alive = false;
}

static void packetLineDeathBody(void *argument)
{
    discard argument;

    testerserver_fixture_t fixture;
    fixtureSetup(&fixture, true, false);
    fixture.prev->fnPayloadD = killLineOnPayload;

    testerserver_lstate_t *ls = lineGetState(fixture.line, fixture.tester);
    ls->response_to_next      = false;
    bufferqueuePushBack(&ls->response_queue,
                        testerserverCreatePayload(fixture.tester,
                                                  fixture.line,
                                                  0,
                                                  0,
                                                  testerserverGetChunkSize(fixture.tester, 0),
                                                  kTesterServerDirectionResponse));

    testerserverResponseSendTask(fixture.tester, fixture.line);
}

static void casePacketLineDeathAborts(void)
{
    twfSetCase("testerserver packet line died during response send");

    tosResetProcessApi(true);
    tosRequireChildExit("the packet-line-death invariant", packetLineDeathBody, NULL, kTosChildDirectAbort);

    tosResetProcessApi(true);
}

int main(void)
{
    casePacketRequestMismatch();
    caseStatelessPacketRequestMismatch();
    caseStreamRequestMismatch();
    caseRefusedHandoffAborts();
    casePayloadGeneratorInvariantAborts();
    casePacketLineDeathAborts();

    printf("testerserver_orderly_shutdown_test: all cases passed\n");
    return 0;
}
