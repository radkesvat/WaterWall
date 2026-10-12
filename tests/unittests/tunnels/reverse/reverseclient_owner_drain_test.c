/*
 * Covers: reverseclient owner drain; the explicit inputs, callbacks and expected results below define
 * this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: testConnectingPairDrain, testActivePairDrain, testSpliceActivation, testStartupPause,
 * testActivationBeforeEst, testReentrantInitClose, testFinishBeforeDrainDoesNotDuplicateClose,
 * testCanceledIdleDeliveryPreservesPairForDrain
 * Checks: Assertion labels include: ReverseClient replaced the application buffer; ReverseClient changed
 * payload representation; ReverseClient changed application bytes; startup signal replay preserves FIFO
 * and cleanup; activation and repeated Est preserve connection accounting
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.reverseclient_owner_drain_unit
 */
#include "ReverseClient/structure.h"
#include "fixtures/splice_inventory.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

#if WW_HAVE_SPLICE
#include "fixtures/failure/buffer_disposal_probe.h"
#endif
#include "global_state.h"
#include "splice_buffer.h"
#include "worker_messages.h"

typedef enum endpoint_behavior_e
{
    kEndpointLeaveConnecting = 0,
    kEndpointEstablish,
    kEndpointCloseDuringInit
} endpoint_behavior_e;

typedef struct reverseclient_fixture_s
{
    tunnel_t           *prev;
    tunnel_t           *reverse;
    tunnel_t           *next;
    tunnel_chain_t     *chain;
    line_t             *upstream_line;
    line_t             *downstream_line;
    endpoint_behavior_e behavior;
    bool                close_downstream_init;
    sbuf_t             *expected_payload;
    bool                expected_splice;
    uint32_t            expected_prefix;
    unsigned int        payload_count;
    unsigned int        upstream_init_count;
    unsigned int        downstream_init_count;
    unsigned int        upstream_finish_count;
    unsigned int        downstream_finish_count;
    unsigned int        handshake_count;
    unsigned int        upstream_pause_count;
    unsigned int        upstream_resume_count;
    unsigned int        downstream_pause_count;
    unsigned int        downstream_resume_count;
    bool                downstream_init_returned;
    void (*during_downstream_init)(line_t *line);
    void (*on_downstream_pause)(line_t *line);
    bool                nested_during_init;
    bool                nested_overflow;
    bool                capture_application;
    uint32_t            nested_count;
    uint32_t            nested_size;
    uint32_t            delivered_buffers;
    uint32_t            delivered_bytes;
    uint8_t             application[128];
    uint32_t            application_length;
} reverseclient_fixture_t;

static reverseclient_fixture_t *g_fixture;


static const ww_lifecycle_context_t *shutdownContext(void)
{
    return wwLifecycleProcessShutdown();
}

static void nextInit(tunnel_t *next, line_t *line)
{
    discard                  next;
    reverseclient_fixture_t *fixture = g_fixture;
    fixture->upstream_line           = line;
    fixture->upstream_init_count++;

    if (fixture->behavior == kEndpointEstablish)
    {
        reverseclientTunnelDownStreamEst(fixture->reverse, line);
    }
    else if (fixture->behavior == kEndpointCloseDuringInit)
    {
        reverseclient_tstate_t *ts = tunnelGetState(fixture->reverse);
        atomicStoreRelaxed(&ts->stopping, true);
        reverseclientTunnelDownStreamFinish(fixture->reverse, line);
    }
}

static void checkPayload(line_t *line, sbuf_t *buf)
{
    if (g_fixture->expected_payload != NULL)
    {
        require(buf == g_fixture->expected_payload, "ReverseClient replaced the application buffer");
        require(sbufIsSplice(buf) == g_fixture->expected_splice &&
                    sbufGetResidentPrefixLength(buf) == g_fixture->expected_prefix,
                "ReverseClient changed payload representation");
        char bytes[7];
        sbufReadRangeToMemory(buf, bytes, sizeof(bytes));
        require(memcmp(bytes, "prebody", sizeof(bytes)) == 0, "ReverseClient changed application bytes");
        g_fixture->expected_payload = NULL;
        ++g_fixture->payload_count;
    }
    else
    {
        require(! sbufIsSplice(buf) && sbufGetLength(buf) == 1 && sbufReadUI8(buf) == 0x5A,
                "ReverseClient handshake must remain ordinary");
        ++g_fixture->handshake_count;
    }
    lineReuseBuffer(line, buf);
}

static void nextPayload(tunnel_t *next, line_t *line, sbuf_t *buf)
{
    discard next;
    require(line == g_fixture->upstream_line, "upstream payload used the wrong paired line");
    checkPayload(line, buf);
}

static void nextFinish(tunnel_t *next, line_t *line)
{
    discard next;
    discard line;
    g_fixture->upstream_finish_count++;
}

static void nextPause(tunnel_t *next, line_t *line)
{
    require(next == g_fixture->next && line == g_fixture->upstream_line, "Pause used the wrong reverse line");
    ++g_fixture->upstream_pause_count;
}

static void nextResume(tunnel_t *next, line_t *line)
{
    require(next == g_fixture->next && line == g_fixture->upstream_line, "Resume used the wrong reverse line");
    ++g_fixture->upstream_resume_count;
}

static void prevInit(tunnel_t *prev, line_t *line)
{
    discard prev;
    g_fixture->downstream_line = line;
    g_fixture->downstream_init_count++;
    if (g_fixture->close_downstream_init)
    {
        reverseclient_tstate_t *ts = tunnelGetState(g_fixture->reverse);
        atomicStoreRelaxed(&ts->stopping, true);
        reverseclientTunnelUpStreamFinish(g_fixture->reverse, line);
    }
    else if (g_fixture->nested_count != 0)
    {
        line_t *upstream = g_fixture->upstream_line;
        lineRef(upstream);
        for (uint32_t i = 0; i < g_fixture->nested_count && lineIsAlive(upstream); ++i)
        {
            sbuf_t *buf = bufferpoolGetBestFit(lineGetBufferPool(line), g_fixture->nested_size, 32);
            memorySet(sbufGetMutablePtr(buf), 'x', g_fixture->nested_size);
            sbufSetLength(buf, g_fixture->nested_size);
            reverseclientTunnelDownStreamPayload(g_fixture->reverse, upstream, buf);
        }
        lineUnref(upstream);
    }
    else if (g_fixture->nested_during_init)
    {
        uint32_t size = g_fixture->nested_overflow ? 2U * 1024U * 1024U : 4U;
        sbuf_t  *buf  = bufferpoolGetBestFit(lineGetBufferPool(line), size, 32);
        memorySet(sbufGetMutablePtr(buf), 'x', size);
        if (! g_fixture->nested_overflow)
            sbufWrite(buf, "tail", 4);
        sbufSetLength(buf, size);
        reverseclientTunnelDownStreamPayload(g_fixture->reverse, g_fixture->upstream_line, buf);
    }
    if (g_fixture->during_downstream_init)
        g_fixture->during_downstream_init(line);
    g_fixture->downstream_init_returned = true;
}

static void prevPayload(tunnel_t *prev, line_t *line, sbuf_t *buf)
{
    discard prev;
    require(line == g_fixture->downstream_line, "downstream payload used the wrong paired line");
    ++g_fixture->delivered_buffers;
    g_fixture->delivered_bytes += sbufGetLength(buf);
    if (g_fixture->capture_application)
    {
        const uint32_t length = sbufGetLength(buf);
        require(g_fixture->application_length + length <= sizeof(g_fixture->application),
                "application capture overflow");
        sbufReadRangeToMemory(buf, g_fixture->application + g_fixture->application_length, length);
        g_fixture->application_length += length;
        lineReuseBuffer(line, buf);
    }
    else if (g_fixture->expected_payload != NULL)
        checkPayload(line, buf);
    else
        lineReuseBuffer(line, buf);
}

static void prevFinish(tunnel_t *prev, line_t *line)
{
    discard prev;
    discard line;
    g_fixture->downstream_finish_count++;
}

static void prevPause(tunnel_t *prev, line_t *line)
{
    require(prev == g_fixture->prev && line == g_fixture->downstream_line, "Pause used the wrong destination line");
    ++g_fixture->downstream_pause_count;
    if (g_fixture->on_downstream_pause)
        g_fixture->on_downstream_pause(line);
}

static void prevResume(tunnel_t *prev, line_t *line)
{
    require(prev == g_fixture->prev && line == g_fixture->downstream_line, "Resume used the wrong destination line");
    ++g_fixture->downstream_resume_count;
}

static void fixtureSetup(reverseclient_fixture_t *fixture, endpoint_behavior_e behavior)
{
    memoryZero(fixture, sizeof(*fixture));
    fixture->behavior = behavior;
    fixture->expected_prefix = 7;
    g_fixture         = fixture;

    fixture->prev    = tunnelCreate(NULL, 0, 0);
    fixture->reverse = tunnelCreate(
        NULL, sizeof(reverseclient_tstate_t) + sizeof(reverseclient_thread_box_t), sizeof(reverseclient_lstate_t));
    fixture->next = tunnelCreate(NULL, 0, 0);
    require(fixture->prev != NULL && fixture->reverse != NULL && fixture->next != NULL,
            "failed to create ReverseClient owner fixture tunnels");

    fixture->next->fnInitU       = nextInit;
    fixture->next->fnPayloadU    = nextPayload;
    fixture->next->fnFinU        = nextFinish;
    fixture->next->fnPauseU      = nextPause;
    fixture->next->fnResumeU     = nextResume;
    fixture->prev->fnInitD       = prevInit;
    fixture->prev->fnPayloadD    = prevPayload;
    fixture->prev->fnFinD        = prevFinish;
    fixture->prev->fnPauseD      = prevPause;
    fixture->prev->fnResumeD     = prevResume;
    fixture->reverse->fnFinU     = reverseclientTunnelUpStreamFinish;
    fixture->reverse->fnFinD     = reverseclientTunnelDownStreamFinish;
    fixture->reverse->fnPayloadD = reverseclientTunnelDownStreamPayload;

    tunnelBind(fixture->prev, fixture->reverse);
    tunnelBind(fixture->reverse, fixture->next);

    fixture->chain                      = tunnelchainCreate(1);
    fixture->chain->sum_line_state_size = fixture->reverse->lstate_size;
    fixture->prev->chain                = fixture->chain;
    fixture->reverse->chain             = fixture->chain;
    fixture->next->chain                = fixture->chain;
    tunnelchainFinalize(fixture->chain);

    reverseclient_tstate_t *ts = tunnelGetState(fixture->reverse);
    atomic_init(&ts->stopping, false);
    atomic_init(&ts->reverse_cons, 0);
    ts->min_unused_cons     = 1;
    ts->handshake_length    = 1;
    ts->handshake_bytes     = memoryAllocate(1);
    ts->handshake_bytes[0]  = 0x5A;
    ts->starved_connections = idleTableCreate(getWorkerLoop(0));
    require(ts->starved_connections != NULL, "failed to create ReverseClient timeout index");
}

static void createFirstPair(reverseclient_fixture_t *fixture)
{
    reverseclientInitiateConnectOnWorker(fixture->reverse, 0, false);
    discard wloopProcessEvents(getWorkerLoop(0), 0);
    require(fixture->upstream_init_count == 1, "ReverseClient did not publish the first pair");
}

static reverseclient_pair_t *currentPair(reverseclient_fixture_t *fixture)
{
    reverseclient_lstate_t *ls = lineGetState(fixture->upstream_line, fixture->reverse);
    require(ls->pair != NULL, "ReverseClient pair state was not initialized");
    return ls->pair;
}

static void stageDuePair(reverseclient_fixture_t *fixture)
{
    reverseclient_pair_t *pair = currentPair(fixture);
    atomicStoreU64Explicit(&pair->idle_handle->expire_at_ms, 0, memory_order_relaxed);

    wtimer_t *driver = wtimerAdd(getWorkerLoop(0), idleCallBack, 1000U, 1);
    require(driver != NULL, "failed to create the ReverseClient idle delivery driver");
    reverseclient_tstate_t *ts = tunnelGetState(fixture->reverse);
    weventSetUserData(driver, ts->starved_connections);
    wloopUpdateTime(getWorkerLoop(0));
    idleCallBack(driver);
    weventSetUserData(driver, NULL);
    wtimerDelete(driver);
}

static void quiesceAndDrain(reverseclient_fixture_t *fixture)
{
    reverseclientTunnelOnQuiesceRequest(fixture->reverse, shutdownContext());
    workerMessagesCleanupPending(getWorker(0));
    reverseclientTunnelOnWorkerStop(fixture->reverse, 0, shutdownContext());
    require(reverseclientOwnedPairCount(fixture->reverse, 0) == 0, "ReverseClient worker drain retained an owned pair");
    require(masterpoolGetCheckedOut(fixture->chain->masterpool_line_pool) == 0,
            "ReverseClient worker drain retained an owned line");
}

static void fixtureTeardown(reverseclient_fixture_t *fixture)
{
    reverseclientTunnelOnStop(fixture->reverse, shutdownContext());
    tunnelchainDestroy(fixture->chain);
    reverseclientTunnelDestroy(fixture->reverse, shutdownContext());
    tunnelDestroy(fixture->prev);
    tunnelDestroy(fixture->next);
    g_fixture = NULL;
}

static void testConnectingPairDrain(void)
{
    reverseclient_fixture_t fixture;
    fixtureSetup(&fixture, kEndpointLeaveConnecting);
    createFirstPair(&fixture);
    require(reverseclientOwnedPairCount(fixture.reverse, 0) == 1, "connecting pair was not registered");

    quiesceAndDrain(&fixture);
    require(fixture.upstream_finish_count == 1, "connecting drain did not finish the initialized side once");
    require(fixture.downstream_finish_count == 0, "connecting drain finished an unpublished side");
    fixtureTeardown(&fixture);
}

static void testActivePairDrain(void)
{
    reverseclient_fixture_t fixture;
    fixtureSetup(&fixture, kEndpointEstablish);
    createFirstPair(&fixture);

    sbuf_t *payload = bufferpoolGetLargeBuffer(getWorkerBufferPool(0));
    sbufSetLength(payload, 64 + 7);
    getRandomBytes(sbufGetMutablePtr(payload), 64);
    reverseActivationWriteSize(sbufGetMutablePtr(payload), 64);
    memoryCopy(sbufGetMutablePtr(payload) + 64, "prebody", 7);
    fixture.expected_payload = payload;
    reverseclientTunnelDownStreamPayload(fixture.reverse, fixture.upstream_line, payload);
    require(fixture.downstream_init_count == 1, "active pair did not publish its downstream side");
    require(reverseclientOwnedPairCount(fixture.reverse, 0) == 1, "active pair left the owner registry");
    require(fixture.expected_payload == NULL, "ordinary activation payload was lost");
    payload = bufferpoolGetLargeBuffer(getWorkerBufferPool(0));
    sbufSetLength(payload, 7);
    sbufWrite(payload, "prebody", 7);
    fixture.expected_payload = payload;
    reverseclientTunnelUpStreamPayload(fixture.reverse, fixture.downstream_line, payload);
    require(fixture.expected_payload == NULL && fixture.payload_count == 2, "ordinary upstream payload was lost");

    quiesceAndDrain(&fixture);
    require(fixture.upstream_finish_count == 1 && fixture.downstream_finish_count == 1,
            "active drain did not finish both initialized sides exactly once");
    fixtureTeardown(&fixture);
}

#if WW_HAVE_SPLICE
static sbuf_t *privatePayload(void)
{
    sbuf_t *buf = bufferpoolGetSpliceBuffer(getWorkerBufferPool(0));
    require(buf != NULL, "failed to get ReverseClient splice input");
    require(write(sbufSpliceMetadata(buf).pipefd[1], "body", 4) == 4, "populate ReverseClient private pipe");
    buf->capacity = buf->l_pad + 4;
    sbufSetLength(buf, 4);
    sbufShiftLeft(buf, 3);
    sbufWrite(buf, "pre", 3);
    return buf;
}

static void testSpliceActivation(bool close_during_init)
{
    reverseclient_fixture_t fixture;
    fixtureSetup(&fixture, kEndpointEstablish);
    fixture.close_downstream_init = close_during_init;
    fixture.expected_splice       = true;
    fixture.expected_prefix       = 3;
    createFirstPair(&fixture);
    sbuf_t     *buf         = privatePayload();
    sbufShiftLeft(buf, kReverseActivationHeaderSize);
    reverseActivationWriteSize(sbufGetMutablePtr(buf), kReverseActivationHeaderSize);
    atomic_uint disposed    = 0;
    int         pipe_reader = -1;
    if (close_during_init)
    {
        pipe_reader = dup(sbufSpliceMetadata(buf).pipefd[0]);
        require(pipe_reader >= 0, "duplicate pipe reader for disposal observation");
        watchBufferDisposal(buf, &disposed);
    }
    else
        fixture.expected_payload = buf;
    reverseclientTunnelDownStreamPayload(fixture.reverse, fixture.upstream_line, buf);
    require(fixture.downstream_init_count == 1, "splice activation missed downstream Init");
    if (close_during_init)
    {
        require(atomic_load(&disposed) == 1, "Init death did not dispose held splice exactly once");
        char    byte;
        ssize_t result = read(pipe_reader, &byte, 1);
        require(result == 0 || (result == -1 && errno == EAGAIN), "Init death left pipe bytes");
        close(pipe_reader);
        require(reverseclientOwnedPairCount(fixture.reverse, 0) == 0, "Init death retained pair");
        require(masterpoolGetCheckedOut(fixture.chain->masterpool_line_pool) == 0, "Init death retained lines");
    }
    else
    {
        require(fixture.expected_payload == NULL && fixture.payload_count == 1, "activation lost payload");
        fixture.expected_payload = privatePayload();
        reverseclientTunnelDownStreamPayload(fixture.reverse, fixture.upstream_line, fixture.expected_payload);
        fixture.expected_payload = privatePayload();
        reverseclientTunnelUpStreamPayload(fixture.reverse, fixture.downstream_line, fixture.expected_payload);
        require(fixture.expected_payload == NULL && fixture.payload_count == 3, "established pair forwarding failed");
    }
    quiesceAndDrain(&fixture);
    fixtureTeardown(&fixture);
}

static void testPipeActivationPadding(void)
{
    reverseclient_fixture_t fixture;
    fixtureSetup(&fixture, kEndpointEstablish);
    fixture.expected_splice = true;
    fixture.expected_prefix = 0;
    createFirstPair(&fixture);
    uint8_t bytes[64 + 7];
    getRandomBytes(bytes, 64);
    reverseActivationWriteSize(bytes, 64);
    memoryCopy(bytes + 64, "prebody", 7);
    for (uint32_t offset = 0; offset < sizeof(bytes);)
    {
        uint32_t count = offset == 0 ? 2 : (uint32_t) sizeof(bytes) - offset;
        sbuf_t  *buf   = bufferpoolGetSpliceBuffer(getWorkerBufferPool(0));
        require(buf != NULL, "allocate pipe-backed activation");
        require(write(sbufSpliceMetadata(buf).pipefd[1], bytes + offset, count) == count, "populate pipe activation");
        buf->capacity = buf->l_pad + count;
        sbufSetLength(buf, count);
        if (offset != 0)
            fixture.expected_payload = buf;
        reverseclientTunnelDownStreamPayload(fixture.reverse, fixture.upstream_line, buf);
        offset += count;
        require(fixture.downstream_init_count == (offset == sizeof(bytes) ? 1U : 0U),
                "pipe header activated too early");
    }
    require(fixture.expected_payload == NULL && fixture.payload_count == 1,
            "pipe activation changed the application body");
    quiesceAndDrain(&fixture);
    fixtureTeardown(&fixture);
}
#endif

static sbuf_t *activationPart(const uint8_t *bytes, uint32_t count)
{
    sbuf_t *buf = bufferpoolGetBestFit(getWorkerBufferPool(0), count, 32);
    sbufWrite(buf, bytes, count);
    sbufSetLength(buf, count);
    return buf;
}

static void resumeDuringDestinationInit(line_t *line)
{
    require(line == g_fixture->downstream_line, "destination Init used the wrong line");
    reverseclientTunnelDownStreamResume(g_fixture->reverse, g_fixture->upstream_line);
}

static void payloadDuringReplayedPause(line_t *line)
{
    require(line == g_fixture->downstream_line && g_fixture->downstream_init_returned &&
                g_fixture->delivered_buffers == 0,
            "pending Pause was delivered before Init returned or after the initial body");
    reverseclientTunnelDownStreamPayload(
        g_fixture->reverse, g_fixture->upstream_line, activationPart((const uint8_t *) "last", 4));
}

static void closeDuringReplayedPause(line_t *line)
{
    payloadDuringReplayedPause(line);
    reverseclient_tstate_t *ts = tunnelGetState(g_fixture->reverse);
    atomicStoreRelaxed(&ts->stopping, true);
    reverseclientTunnelUpStreamFinish(g_fixture->reverse, line);
}

typedef enum startup_pause_case_e
{
    kStartupPauseReplay,
    kStartupPauseCancelBeforeInit,
    kStartupPauseCancelDuringInit,
    kStartupPauseClose
} startup_pause_case_e;

static void testStartupPause(startup_pause_case_e mode)
{
    reverseclient_fixture_t fixture;
    fixtureSetup(&fixture, kEndpointEstablish);
    fixture.capture_application = fixture.nested_during_init = true;
    createFirstPair(&fixture);
    reverseclientTunnelDownStreamPause(fixture.reverse, fixture.upstream_line);
    reverseclientTunnelDownStreamPause(fixture.reverse, fixture.upstream_line);
    require(fixture.downstream_pause_count == 0, "Pause reached the destination before Init");
    if (mode == kStartupPauseCancelBeforeInit)
        reverseclientTunnelDownStreamResume(fixture.reverse, fixture.upstream_line);
    else if (mode == kStartupPauseCancelDuringInit)
        fixture.during_downstream_init = resumeDuringDestinationInit;
    else
        fixture.on_downstream_pause =
            mode == kStartupPauseClose ? closeDuringReplayedPause : payloadDuringReplayedPause;
    require(fixture.downstream_resume_count == 0, "Resume reached the destination before Init");

    const uint8_t bytes[] = {0, 0, 0, 4, 'h', 'e', 'a', 'd'};
    reverseclientTunnelDownStreamPayload(fixture.reverse, fixture.upstream_line, activationPart(bytes, sizeof(bytes)));
    if (mode == kStartupPauseClose)
    {
        require(fixture.downstream_pause_count == 1 && fixture.delivered_buffers == 0 &&
                    reverseclientOwnedPairCount(fixture.reverse, 0) == 0 &&
                    masterpoolGetCheckedOut(fixture.chain->masterpool_line_pool) == 0 &&
                    fixture.upstream_finish_count == 1 && fixture.downstream_finish_count == 0,
                "Finish from replayed Pause leaked retained input, owned lines or reflected Finish");
    }
    else
    {
        const bool replay = mode == kStartupPauseReplay;
        require(fixture.downstream_pause_count == (replay ? 1U : 0U) &&
                    fixture.application_length == (replay ? 12U : 8U) &&
                    memcmp(fixture.application, "headtaillast", fixture.application_length) == 0,
                "startup Pause was lost, replayed after Resume, or reordered admitted application data");
        fixture.on_downstream_pause = NULL;
        unsigned prior_resumes      = fixture.downstream_resume_count;
        for (unsigned repeat = 0; repeat < 2; ++repeat)
        {
            reverseclientTunnelDownStreamPause(fixture.reverse, fixture.upstream_line);
            reverseclientTunnelUpStreamPause(fixture.reverse, fixture.downstream_line);
        }
        for (unsigned repeat = 0; repeat < 2; ++repeat)
        {
            reverseclientTunnelDownStreamResume(fixture.reverse, fixture.upstream_line);
            reverseclientTunnelUpStreamResume(fixture.reverse, fixture.downstream_line);
        }
        require(fixture.downstream_pause_count == (replay ? 3U : 2U) &&
                    fixture.downstream_resume_count == prior_resumes + 2 && fixture.upstream_pause_count == 2 &&
                    fixture.upstream_resume_count == 2,
                "active Pause/Resume notifications were dropped or mapped to the wrong half");
    }
    quiesceAndDrain(&fixture);
    fixtureTeardown(&fixture);
}

static void testActivationBeforeEst(bool est_between_fragments)
{
    reverseclient_fixture_t fixture;
    fixtureSetup(&fixture, kEndpointLeaveConnecting);
    fixture.capture_application = true;
    createFirstPair(&fixture);
    reverseclient_tstate_t     *ts      = tunnelGetState(fixture.reverse);
    reverseclient_thread_box_t *box     = &ts->threadlocal_pool[0];
    const uint8_t               bytes[] = {0, 0, 0, 4, 'h', 'e', 'a', 'd'};
    uint32_t                    offset  = 0;
    if (est_between_fragments)
    {
        reverseclientTunnelDownStreamPayload(fixture.reverse, fixture.upstream_line, activationPart(bytes, 2));
        require(currentPair(&fixture)->phase == kReverseClientPairConnecting && box->connecting_cons_count == 1 &&
                    box->unused_cons_count == 0 && fixture.downstream_init_count == 0,
                "partial activation changed connection accounting or opened the destination");
        reverseclientTunnelDownStreamEst(fixture.reverse, fixture.upstream_line);
        reverseclientTunnelDownStreamEst(fixture.reverse, fixture.upstream_line);
        require(box->connecting_cons_count == 0 && box->unused_cons_count == 1,
                "repeated Est changed unused connection accounting");
        offset = 2;
    }
    reverseclientTunnelDownStreamPayload(
        fixture.reverse, fixture.upstream_line, activationPart(bytes + offset, sizeof(bytes) - offset));
    require(currentPair(&fixture)->phase == kReverseClientPairActive && fixture.downstream_init_count == 1 &&
                fixture.application_length == 4 && memcmp(fixture.application, "head", 4) == 0,
            "activation depended on Est or lost its coalesced application body");
    reverseclientTunnelDownStreamEst(fixture.reverse, fixture.upstream_line);
    reverseclientTunnelDownStreamEst(fixture.reverse, fixture.upstream_line);
    require(lineIsEstablished(fixture.upstream_line) && currentPair(&fixture)->phase == kReverseClientPairActive &&
                box->connecting_cons_count == 1 && box->unused_cons_count == 0 &&
                atomicLoadRelaxed(&ts->reverse_cons) == 1 && reverseclientOwnedPairCount(fixture.reverse, 0) == 1 &&
                fixture.handshake_count == 1 && fixture.downstream_init_count == 1,
            "late/repeated Est repeated protocol work or changed active/replacement connection accounting");
    quiesceAndDrain(&fixture);
    require(box->connecting_cons_count == 0 && box->unused_cons_count == 0 && atomicLoadRelaxed(&ts->reverse_cons) == 0,
            "early activation left connection accounting after drain");
    fixtureTeardown(&fixture);
}

static void testFragmentedActivation(uint32_t size)
{
    reverseclient_fixture_t fixture;
    fixtureSetup(&fixture, kEndpointEstablish);
    createFirstPair(&fixture);
    uint8_t *bytes = memoryAllocate(size);
    getRandomBytes(bytes, size);
    reverseActivationWriteSize(bytes, size);
    /* Every header byte arrives separately; padding then crosses deliveries. */
    for (uint32_t offset = 0; offset < size;)
    {
        uint32_t count = offset < 4 ? 1 : min(137U, size - offset);
        reverseclientTunnelDownStreamPayload(
            fixture.reverse, fixture.upstream_line, activationPart(bytes + offset, count));
        offset += count;
        require(fixture.downstream_init_count == (offset == size ? 1U : 0U),
                "destination opened before activation completed");
    }
    memoryFree(bytes);
    require(fixture.downstream_init_count == 1 && fixture.payload_count == 0, "padding reached the destination");
    fixture.expected_payload = activationPart((const uint8_t *) "prebody", 7);
    reverseclientTunnelDownStreamPayload(fixture.reverse, fixture.upstream_line, fixture.expected_payload);
    require(fixture.expected_payload == NULL && fixture.payload_count == 1, "direct data after activation changed");
    quiesceAndDrain(&fixture);
    fixtureTeardown(&fixture);
}

static void testInvalidActivation(uint32_t size, bool truncated)
{
    reverseclient_fixture_t fixture;
    fixtureSetup(&fixture, kEndpointEstablish);
    createFirstPair(&fixture);
    reverseclient_tstate_t *ts = tunnelGetState(fixture.reverse);
    atomicStoreRelaxed(&ts->stopping, true);
    uint8_t header[4];
    reverseActivationWriteSize(header, size);
    reverseclientTunnelDownStreamPayload(
        fixture.reverse, fixture.upstream_line, activationPart(header, truncated ? 3 : 4));
    require(fixture.downstream_init_count == 0, "invalid/incomplete activation opened destination");
    require(reverseclientOwnedPairCount(fixture.reverse, 0) == (truncated ? 1U : 0U),
            "invalid activation did not close pair");
    quiesceAndDrain(&fixture);
    fixtureTeardown(&fixture);
}

static void testActivationInitOrdering(bool overflow)
{
    reverseclient_fixture_t fixture;
    fixtureSetup(&fixture, kEndpointEstablish);
    fixture.nested_during_init = fixture.capture_application = true;
    fixture.nested_overflow                                  = overflow;
    createFirstPair(&fixture);
    const uint8_t bytes[] = {0, 0, 0, 4, 'h', 'e', 'a', 'd'};
    reverseclientTunnelDownStreamPayload(fixture.reverse, fixture.upstream_line, activationPart(bytes, sizeof(bytes)));
    if (overflow)
        require(reverseclientOwnedPairCount(fixture.reverse, 0) == 0 && fixture.application_length == 0,
                "nested activation overflow did not close without leaking payload");
    else
        require(fixture.application_length == 8 && memcmp(fixture.application, "headtail", 8) == 0,
                "nested destination Init input overtook coalesced application data");
    quiesceAndDrain(&fixture);
    fixtureTeardown(&fixture);
}

static void testActivationBufferLimit(bool overflow, bool empty)
{
    reverseclient_fixture_t fixture;
    fixtureSetup(&fixture, kEndpointEstablish);
    fixture.nested_count = kReverseClientPendingBuffers - (overflow ? 0 : 1);
    fixture.nested_size  = empty ? 0 : 1;
    createFirstPair(&fixture);
    const uint8_t bytes[] = {0, 0, 0, 4, 'h', 'e', 'a', 'd'};
    reverseclientTunnelDownStreamPayload(fixture.reverse, fixture.upstream_line, activationPart(bytes, sizeof(bytes)));
    if (overflow && ! empty)
        require(reverseclientOwnedPairCount(fixture.reverse, 0) == 0 && fixture.delivered_buffers == 0,
                "activation accepted more than 1024 retained buffers or leaked data after refusal");
    else
        require(reverseclientOwnedPairCount(fixture.reverse, 0) == 1 &&
                    fixture.delivered_buffers == (empty ? 1 : kReverseClientPendingBuffers) &&
                    fixture.delivered_bytes == (empty ? 4 : 4 + kReverseClientPendingBuffers - 1),
                "activation refused the inclusive buffer limit, counted empty input, or lost FIFO bytes");
    quiesceAndDrain(&fixture);
    fixtureTeardown(&fixture);
}

static void testInitialBodyLimit(void)
{
    reverseclient_fixture_t fixture;
    fixtureSetup(&fixture, kEndpointEstablish);
    createFirstPair(&fixture);
    sbuf_t *buf = bufferpoolGetBestFit(getWorkerBufferPool(0), kReverseClientPendingBytes + 5, 32);
    reverseActivationWriteSize(sbufGetMutablePtr(buf), 4);
    memorySet(sbufGetMutablePtr(buf) + 4, 'x', kReverseClientPendingBytes + 1);
    sbufSetLength(buf, kReverseClientPendingBytes + 5);
    reverseclientTunnelDownStreamPayload(fixture.reverse, fixture.upstream_line, buf);
    require(reverseclientOwnedPairCount(fixture.reverse, 0) == 0 && fixture.downstream_init_count == 0 &&
                fixture.delivered_buffers == 0,
            "oversized retained initial body opened the destination or escaped its budget");
    quiesceAndDrain(&fixture);
    fixtureTeardown(&fixture);
}

static void testReentrantInitClose(void)
{
    reverseclient_fixture_t fixture;
    fixtureSetup(&fixture, kEndpointCloseDuringInit);
    createFirstPair(&fixture);

    require(reverseclientOwnedPairCount(fixture.reverse, 0) == 0,
            "reentrant Init close retained the pair registry entry");
    require(masterpoolGetCheckedOut(fixture.chain->masterpool_line_pool) == 0,
            "reentrant Init close retained an owner-created line");
    quiesceAndDrain(&fixture);
    fixtureTeardown(&fixture);
}

static void testFinishBeforeDrainDoesNotDuplicateClose(void)
{
    reverseclient_fixture_t fixture;
    fixtureSetup(&fixture, kEndpointEstablish);
    createFirstPair(&fixture);

    reverseclientTunnelOnQuiesceRequest(fixture.reverse, shutdownContext());
    reverseclientTunnelDownStreamFinish(fixture.reverse, fixture.upstream_line);
    require(reverseclientOwnedPairCount(fixture.reverse, 0) == 0, "adjacent Finish retained the pair");
    reverseclientTunnelOnWorkerStop(fixture.reverse, 0, shutdownContext());
    require(fixture.upstream_finish_count == 0 && fixture.downstream_finish_count == 0,
            "adjacent Finish reflected or worker drain duplicated it");
    fixtureTeardown(&fixture);
}

static void testCanceledIdleDeliveryPreservesPairForDrain(void)
{
    reverseclient_fixture_t fixture;
    fixtureSetup(&fixture, kEndpointLeaveConnecting);
    createFirstPair(&fixture);

    reverseclient_pair_t *pair        = currentPair(&fixture);
    idle_item_t          *idle_handle = pair->idle_handle;
    require(idle_handle != NULL, "ReverseClient did not publish its cancellation idle handle");

    stageDuePair(&fixture);
    require(pair->idle_handle == idle_handle, "expiration staging changed the ReverseClient idle handle");
    require(reverseclientOwnedPairCount(fixture.reverse, 0) == 1,
            "expiration staging removed the ReverseClient owner entry");

    quiesceAndDrain(&fixture);
    require(fixture.upstream_finish_count == 1, "canceled-delivery pair did not close exactly once during drain");
    fixtureTeardown(&fixture);
}

static void teardownGlobalState(void)
{
    worker_t *worker0 = getWorker(0);
    require(workerInstallApplicationQuiesceRequest(worker0, shutdownContext()) != kWorkerQuiesceRequestUnavailable,
            "failed to install worker-0 shutdown context");
    workerPerformQuiesce(worker0, shutdownContext());
    require(workerRequestDrain(worker0), "failed to request worker-0 drain");
    workerPerformDrain(worker0, shutdownContext());
    require(workerRequestTeardown(worker0), "failed to request worker-0 teardown");
    workerPerformTeardown(worker0);
    destroyGlobalState();
}

int main(void)
{
    testCaseSet("reverseclient_owner_drain_test");
    static char            log_off[]         = "OFF";
    ww_construction_data_t init_data         = {0};
    init_data.workers_count                  = 1;
    init_data.ram_profile                    = kRamProfileS1Memory;
    init_data.mtu_size                       = 1500;
    init_data.internal_logger_data.log_level = log_off;
    init_data.core_logger_data.log_level     = log_off;
    init_data.network_logger_data.log_level  = log_off;
    init_data.dns_logger_data.log_level      = log_off;
    require(wwStartupSucceeded(createGlobalState(init_data)), "failed to create ReverseClient owner test state");
    testSpliceInventoryInitialize(32);

    globalstateUpdateAllocationPadding(32);
#if WW_HAVE_SPLICE
    testSpliceActivation(false);
    testSpliceActivation(true);
    testPipeActivationPadding();
#endif
    testConnectingPairDrain();
    testActivePairDrain();
    testStartupPause(kStartupPauseReplay);
    testStartupPause(kStartupPauseCancelBeforeInit);
    testStartupPause(kStartupPauseCancelDuringInit);
    testStartupPause(kStartupPauseClose);
    testActivationBeforeEst(false);
    testActivationBeforeEst(true);
    testFragmentedActivation(4);
    testFragmentedActivation(64);
    testFragmentedActivation(4097);
    testFragmentedActivation(kReverseActivationMaxSize);
    testInvalidActivation(0, false);
    testInvalidActivation(3, false);
    testInvalidActivation(kReverseActivationMaxSize + 1, false);
    testInvalidActivation(UINT32_MAX, false);
    testInvalidActivation(64, true);
    testActivationInitOrdering(false);
    testActivationInitOrdering(true);
    testActivationBufferLimit(false, false);
    testActivationBufferLimit(true, false);
    testActivationBufferLimit(true, true);
    testInitialBodyLimit();
    testReentrantInitClose();
    testFinishBeforeDrainDoesNotDuplicateClose();
    testCanceledIdleDeliveryPreservesPairForDrain();

    teardownGlobalState();
    puts("ReverseClient owner drain tests passed");
    return 0;
}
