#include "ReverseClient/structure.h"

#if WW_HAVE_SPLICE
#include "buffer_disposal_probe.h"
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
    unsigned int        payload_count;
    unsigned int        upstream_init_count;
    unsigned int        downstream_init_count;
    unsigned int        upstream_finish_count;
    unsigned int        downstream_finish_count;
} reverseclient_fixture_t;

static reverseclient_fixture_t *g_fixture;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

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
                    sbufGetResidentPrefixLength(buf) == (g_fixture->expected_splice ? 3 : 7),
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
}

static void prevPayload(tunnel_t *prev, line_t *line, sbuf_t *buf)
{
    discard prev;
    require(line == g_fixture->downstream_line, "downstream payload used the wrong paired line");
    if (g_fixture->expected_payload != NULL)
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

static void fixtureSetup(reverseclient_fixture_t *fixture, endpoint_behavior_e behavior)
{
    memoryZero(fixture, sizeof(*fixture));
    fixture->behavior = behavior;
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
    fixture->prev->fnInitD       = prevInit;
    fixture->prev->fnPayloadD    = prevPayload;
    fixture->prev->fnFinD        = prevFinish;
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
    sbufSetLength(payload, 7);
    sbufWrite(payload, "prebody", 7);
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
    createFirstPair(&fixture);
    sbuf_t     *buf         = privatePayload();
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
#endif

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

static void testIdleStagingRefusalPreservesPairForDrain(void)
{
    reverseclient_fixture_t fixture;
    fixtureSetup(&fixture, kEndpointLeaveConnecting);
    createFirstPair(&fixture);

    reverseclient_pair_t *pair        = currentPair(&fixture);
    idle_item_t          *idle_handle = pair->idle_handle;
    require(idle_handle != NULL, "ReverseClient did not publish its idle handle");

    idletableTestRefuseNextInitialStagingReserve();
    stageDuePair(&fixture);
    require(pair->idle_handle == idle_handle, "staging refusal changed the ReverseClient idle handle");
    require(reverseclientOwnedPairCount(fixture.reverse, 0) == 1,
            "staging refusal removed the ReverseClient owner entry");

    quiesceAndDrain(&fixture);
    require(fixture.upstream_finish_count == 1, "staging-refused pair did not close exactly once during drain");
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
    workerDestroyPseudoWorkerResources(getWorker(getTotalWorkersCount() - 1));
    destroyGlobalState();
}

int main(void)
{
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

    globalstateUpdateAllocationPadding(32);
#if WW_HAVE_SPLICE
    testSpliceActivation(false);
    testSpliceActivation(true);
#endif
    testConnectingPairDrain();
    testActivePairDrain();
    testReentrantInitClose();
    testFinishBeforeDrainDoesNotDuplicateClose();
    testIdleStagingRefusalPreservesPairForDrain();
    testCanceledIdleDeliveryPreservesPairForDrain();

    teardownGlobalState();
    puts("ReverseClient owner drain tests passed");
    return 0;
}
