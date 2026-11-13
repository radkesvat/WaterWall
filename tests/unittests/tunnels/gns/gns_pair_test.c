/* CTest: waterwall.gns_pair_unit.
 * The real GnsClient and GnsServer tunnels in one chain between three fixture tunnels:
 *
 *     source -> GnsClient -> wire -> GnsServer -> service
 *
 * The fixture owns the application line and the UDP-facing carrier line, as a TCP listener and a UDP listener
 * would. GnsClient owns its transport line and GnsServer owns its service line. GameNetworkingSockets runs its own
 * service thread and reads its own clock, so the test runs in real time: it waits with deadlines and asserts no
 * upper bound on any duration. Covers line ownership and context, transfer, Est mapping, every Finish path,
 * Pause/Resume composition, the admission deadline, worker shutdown with and without a finished handshake, and
 * constructor errors. Every case starts and stops the library, and the whole list runs on two runtimes in one
 * process. */

#include "GnsClient/interface.h"
#include "GnsServer/interface.h"

#include "gns_runtime.h"

enum
{
    kMaxPackets = 8192,
    kChunk      = 16384,
    kWaitMs     = kGnsTestDeadlineMs,
};

typedef struct packet_s
{
    sbuf_t  *buffer;
    unsigned direction; /* 0 = client to server, 1 = server to client */
} packet_t;

typedef struct fixture_s
{
    node_t          nodes[5];
    tunnel_t       *source, *client, *wire, *server, *service;
    tunnel_chain_t *chain;
    line_t         *app;          /* created and owned by the fixture */
    line_t         *transport;    /* created by GnsClient; the fixture holds a reference only */
    line_t         *carrier;      /* created and owned by the fixture */
    line_t         *service_line; /* created by GnsServer; the fixture holds a reference only */
    packet_t        queue[kMaxPackets];
    size_t          count_packets;
    size_t          sent[2], received[2]; /* 0 = toward the service, 1 = toward the application */
    unsigned        app_finishes, app_ests, app_pauses, app_resumes;
    unsigned        service_inits, service_finishes, service_ests, service_pauses, service_resumes;
    unsigned        transport_finishes, carrier_finishes, carrier_ests;
    unsigned        wire_pauses[2], wire_resumes[2]; /* 0 = on the transport, 1 = on the carrier */
    bool            hold_wire;                       /* datagrams wait in the queue */
    bool            drop_wire;                       /* datagrams are lost */
} fixture_t;

static fixture_t *active;
static unsigned   timers_at_start;

static uint8_t patternByte(size_t offset)
{
    return (uint8_t) (offset * 29U + 17U);
}

static void checkPayload(unsigned direction, line_t *line, sbuf_t *payload)
{
    const uint8_t *bytes = sbufGetRawPtr(payload);
    for (size_t i = 0; i < sbufGetLength(payload); ++i)
    {
        gnsRequire(bytes[i] == patternByte(active->received[direction] + i), "the stream changed or was reordered");
    }
    active->received[direction] += sbufGetLength(payload);
    lineReuseBuffer(line, payload);
}

/* Fixture source: the owner of the application line. */

static void appFinish(tunnel_t *t, line_t *line)
{
    gnsRequire(t == active->source && line == active->app, "Finish reached a foreign application line");
    active->app_finishes += 1;
    lineDestroy(line);
}

static void appEst(tunnel_t *t, line_t *line)
{
    gnsRequire(t == active->source && line == active->app, "Est reached a foreign application line");
    active->app_ests += 1;
}

static void appPayload(tunnel_t *t, line_t *line, sbuf_t *payload)
{
    gnsRequire(t == active->source && line == active->app, "payload reached a foreign application line");
    checkPayload(1, line, payload);
}

static void appPause(tunnel_t *t, line_t *line)
{
    discard t;
    discard line;
    active->app_pauses += 1;
}

static void appResume(tunnel_t *t, line_t *line)
{
    discard t;
    discard line;
    active->app_resumes += 1;
}

/* Fixture wire: stands where UdpConnector and UdpListener would be. */

static void queuePacket(unsigned direction, sbuf_t *packet)
{
    if (active->drop_wire)
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(0), packet);
        return;
    }
    gnsRequire(sbufGetLength(packet) + 28U <= 1500U, "a datagram exceeds the configured send MTU");
    gnsRequire(active->count_packets < kMaxPackets, "the fixture wire overflowed");
    active->queue[active->count_packets++] = (packet_t) {.buffer = packet, .direction = direction};
}

static void flushWire(void)
{
    while (active->count_packets > 0 && ! active->hold_wire)
    {
        const size_t count = active->count_packets;
        packet_t    *batch = memoryAllocate(count * sizeof(*batch));
        memoryCopy(batch, active->queue, count * sizeof(*batch));
        active->count_packets = 0;
        for (size_t i = 0; i < count; ++i)
        {
            if (batch[i].direction == 0 && active->carrier != NULL && lineIsAlive(active->carrier))
            {
                tunnelNextUpStreamPayload(active->wire, active->carrier, batch[i].buffer);
            }
            else if (batch[i].direction == 1 && active->transport != NULL && lineIsAlive(active->transport))
            {
                tunnelPrevDownStreamPayload(active->wire, active->transport, batch[i].buffer);
            }
            else
            {
                bufferpoolReuseBuffer(getWorkerBufferPool(0), batch[i].buffer);
            }
        }
        memoryFree(batch);
    }
}

static void wireInit(tunnel_t *t, line_t *line)
{
    gnsRequire(t == active->wire && active->transport == NULL && line != active->app,
               "the client did not split its borrowed application and its owned carrier");
    gnsRequire(lineGetWID(line) == lineGetWID(active->app), "the client's carrier moved workers");
    gnsRequire(addresscontextClassifyTransport(lineGetDestinationAddressContext(line)) == kAddressContextTransportUdp,
               "the client's carrier is not marked as UDP");
    gnsRequire(addresscontextClassifyTransport(lineGetDestinationAddressContext(active->app)) ==
                   kAddressContextTransportTcp,
               "the application line is not marked as a stream");
    gnsRequire(line->routing_context.local_listener_port == 34567 && line->routing_context.peer_source_port == 45678,
               "the client's carrier lost the routing context");
    active->transport = line;
    lineRef(line);
    /* The UDP side: one incoming carrier line, owned here, opened toward the server. */
    active->carrier = lineCreate(active->chain->line_pools, 0);
    lineRef(active->carrier);
    addresscontextCopy(lineGetSourceAddressContext(active->carrier), lineGetSourceAddressContext(line));
    addresscontextCopy(lineGetDestinationAddressContext(active->carrier), lineGetDestinationAddressContext(line));
    active->carrier->routing_context.local_listener_port = 34567;
    active->carrier->routing_context.peer_source_port    = 45678;
    tunnelNextUpStreamInit(t, active->carrier);
    gnsRequire(active->service_inits == 0, "the server created a service line before the native handshake");
    if (lineIsAlive(active->carrier))
    {
        tunnelNextUpStreamEst(t, active->carrier);
    }
    if (lineIsAlive(line))
    {
        tunnelPrevDownStreamEst(t, line);
    }
}

static void wireUp(tunnel_t *t, line_t *line, sbuf_t *packet)
{
    gnsRequire(t == active->wire && line == active->transport, "the client sent on a foreign line");
    queuePacket(0, packet);
}

static void wireDown(tunnel_t *t, line_t *line, sbuf_t *packet)
{
    gnsRequire(t == active->wire && line == active->carrier, "the server sent on a foreign line");
    queuePacket(1, packet);
}

static void transportFinish(tunnel_t *t, line_t *line)
{
    gnsRequire(t == active->wire && line == active->transport, "Finish reached a foreign transport");
    active->transport_finishes += 1;
}

static void carrierFinish(tunnel_t *t, line_t *line)
{
    gnsRequire(t == active->wire && line == active->carrier, "Finish reached a foreign carrier");
    active->carrier_finishes += 1;
    lineDestroy(line);
}

static void carrierEst(tunnel_t *t, line_t *line)
{
    gnsRequire(t == active->wire && line == active->carrier, "Est reached a foreign carrier");
    active->carrier_ests += 1;
}

static void wirePause(tunnel_t *t, line_t *line)
{
    discard t;
    active->wire_pauses[line == active->carrier ? 1 : 0] += 1;
}

static void wireResume(tunnel_t *t, line_t *line)
{
    discard t;
    active->wire_resumes[line == active->carrier ? 1 : 0] += 1;
}

/* Fixture service: stands where TcpConnector would be. */

static void serviceInit(tunnel_t *t, line_t *line)
{
    gnsRequire(t == active->service && line != active->carrier && active->service_line == NULL,
               "the server reused the borrowed carrier as its service line");
    gnsRequire(lineGetWID(line) == lineGetWID(active->carrier), "the service line moved workers");
    gnsRequire(addresscontextClassifyTransport(lineGetDestinationAddressContext(line)) == kAddressContextTransportTcp,
               "the service line is not marked as a stream");
    gnsRequire(line->routing_context.local_listener_port == 34567 && line->routing_context.peer_source_port == 45678,
               "the service line lost the routing context");
    active->service_line = line;
    lineRef(line);
    active->service_inits += 1;
    tunnelPrevDownStreamEst(t, line);
}

static void serviceEst(tunnel_t *t, line_t *line)
{
    gnsRequire(t == active->service && line == active->service_line, "Est reached a foreign service line");
    active->service_ests += 1;
}

static void servicePayload(tunnel_t *t, line_t *line, sbuf_t *payload)
{
    gnsRequire(t == active->service && line == active->service_line, "payload reached a foreign service line");
    checkPayload(0, line, payload);
}

static void serviceFinish(tunnel_t *t, line_t *line)
{
    gnsRequire(t == active->service && line == active->service_line, "Finish reached a foreign service line");
    active->service_finishes += 1;
}

static void servicePause(tunnel_t *t, line_t *line)
{
    discard t;
    discard line;
    active->service_pauses += 1;
}

static void serviceResume(tunnel_t *t, line_t *line)
{
    discard t;
    discard line;
    active->service_resumes += 1;
}

/* The test runs in real time, so no timeout is short: a short one could end a session on a slow host before the
 * case reaches the step it is about. The liveness timeout never comes: a close notice that does not arrive must
 * fail the case at its deadline, not pass as a peer that timed out. */
static const char kDefaultSettings[] =
    "{\"send-rate\":20000000,\"send-buffer-limit\":65536,\"no-recv-timeout-ms\":600000}";
static const char kShortHandshake[] = "{\"send-rate\":20000000,\"timeout-initial-ms\":600}";

static void setup(fixture_t *fixture, const char *settings)
{
    memoryZero(fixture, sizeof(*fixture));
    active            = fixture;
    fixture->nodes[0] = (node_t) {.type = stringDuplicate("FixtureSource"), .flags = kNodeFlagChainHead};
    fixture->nodes[1] = nodeGnsClientGet();
    fixture->nodes[2] = (node_t) {.type = stringDuplicate("FixtureWire")};
    fixture->nodes[3] = nodeGnsServerGet();
    fixture->nodes[4] = (node_t) {.type = stringDuplicate("FixtureService"), .flags = kNodeFlagChainEnd};
    fixture->nodes[1].node_settings_json = cJSON_Parse(settings);
    fixture->nodes[3].node_settings_json = cJSON_Parse(settings);
    fixture->source                      = tunnelCreate(&fixture->nodes[0], 0, 0);
    fixture->client                      = fixture->nodes[1].createHandle(&fixture->nodes[1]);
    fixture->wire                        = tunnelCreate(&fixture->nodes[2], 0, 0);
    fixture->server                      = fixture->nodes[3].createHandle(&fixture->nodes[3]);
    fixture->service                     = tunnelCreate(&fixture->nodes[4], 0, 0);
    gnsRequire(fixture->source && fixture->client && fixture->wire && fixture->server && fixture->service,
               "paired tunnel construction failed");
    fixture->source->fnFinD      = appFinish;
    fixture->source->fnEstD      = appEst;
    fixture->source->fnPayloadD  = appPayload;
    fixture->source->fnPauseD    = appPause;
    fixture->source->fnResumeD   = appResume;
    fixture->wire->fnInitU       = wireInit;
    fixture->wire->fnPayloadU    = wireUp;
    fixture->wire->fnPayloadD    = wireDown;
    fixture->wire->fnFinU        = transportFinish;
    fixture->wire->fnFinD        = carrierFinish;
    fixture->wire->fnEstD        = carrierEst;
    fixture->wire->fnPauseU      = wirePause;
    fixture->wire->fnPauseD      = wirePause;
    fixture->wire->fnResumeU     = wireResume;
    fixture->wire->fnResumeD     = wireResume;
    fixture->service->fnInitU    = serviceInit;
    fixture->service->fnEstU     = serviceEst;
    fixture->service->fnPayloadU = servicePayload;
    fixture->service->fnFinU     = serviceFinish;
    fixture->service->fnPauseU   = servicePause;
    fixture->service->fnResumeU  = serviceResume;
    tunnel_t *tunnels[]          = {fixture->source, fixture->client, fixture->wire, fixture->server, fixture->service};
    fixture->chain               = tunnelchainCreate(1);
    uint32_t offset              = 0;
    for (unsigned i = 0; i < ARRAY_SIZE(tunnels); ++i)
    {
        if (i)
        {
            tunnelBind(tunnels[i - 1], tunnels[i]);
        }
        tunnelchainInsert(fixture->chain, tunnels[i]);
        tunnels[i]->onIndex(tunnels[i], (uint16_t) i, &offset);
    }
    tunnelchainFinalize(fixture->chain);
}

static void openApp(void)
{
    active->app = lineCreate(active->chain->line_pools, 0);
    lineRef(active->app);
    gnsRequire(addresscontextSetIpAddressPortProtocol(
                   lineGetSourceAddressContext(active->app), "127.0.0.2", 45678, IP_PROTO_TCP),
               "fixture source address setup failed");
    addresscontextDomainSetByString(lineGetDestinationAddressContext(active->app), "pair.fixture");
    addresscontextSetPort(lineGetDestinationAddressContext(active->app), 12345);
    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(active->app), IP_PROTO_TCP);
    active->app->routing_context.local_listener_port = 34567;
    active->app->routing_context.peer_source_port    = 45678;
    tunnelNextUpStreamInit(active->source, active->app);
    flushWire();
}

/* Runs what is due on the worker, which includes the wakes of the library's own thread, and moves the wire. */
static void step(void)
{
    gnsTestStep();
    flushWire();
}

static bool pumpUntil(bool (*done)(void))
{
    const uint64_t deadline = gnsTestNowMs() + kWaitMs;
    step();
    while (! done() && gnsTestNowMs() < deadline)
    {
        wwSleepMS(1);
        step();
    }
    return done();
}

/* Lets real time pass while the worker and the wire keep moving. */
static void pumpFor(unsigned milliseconds)
{
    const uint64_t end = gnsTestNowMs() + milliseconds;
    while (gnsTestNowMs() < end)
    {
        step();
        wwSleepMS(1);
    }
}

/* The worker loop's clock, which is the one the sessions read. */
static uint64_t loopNowMs(void)
{
    wloopUpdateTime(getWorkerLoop(0));
    return wloopNowMonotonicMS(getWorkerLoop(0));
}

static void sendBytes(unsigned direction, size_t size)
{
    line_t *line = direction ? active->service_line : active->app;
    gnsRequire(line != NULL && lineIsAlive(line), "sending on a retired line");
    sbuf_t *payload = bufferpoolGetBestFit(lineGetBufferPool(line), size, 0);
    for (size_t i = 0; i < size; ++i)
    {
        sbufGetMutablePtr(payload)[i] = patternByte(active->sent[direction] + i);
    }
    sbufSetLength(payload, size);
    active->sent[direction] += size;
    if (direction)
    {
        tunnelPrevDownStreamPayload(active->service, line, payload);
    }
    else
    {
        tunnelNextUpStreamPayload(active->source, line, payload);
    }
    flushWire();
}

static bool appReady(void)
{
    return active->app_pauses == active->app_resumes;
}

static bool serviceReady(void)
{
    return active->service_pauses == active->service_resumes;
}

/* Sends as a producer does: it waits while its line is paused. GNS itself has no flow control. */
static void sendChunks(unsigned direction, int count)
{
    for (int i = 0; i < count; ++i)
    {
        gnsRequire(pumpUntil(direction ? serviceReady : appReady), "a paused producer was never resumed");
        sendBytes(direction, kChunk);
    }
}

static void requireRetired(line_t *line, tunnel_t *tunnel, const char *message)
{
    if (line == NULL)
    {
        return;
    }
    gnsRequire(! lineIsAlive(line), message);
    const uint8_t *state = lineGetState(line, tunnel);
    for (size_t i = 0; i < tunnel->lstate_size; ++i)
    {
        gnsRequire(state[i] == 0, "a retired line kept node state");
    }
    lineUnref(line);
}

static void teardown(void)
{
    const ww_lifecycle_context_t *context = wwLifecycleStartupRollback();
    active->client->onQuiesceRequest(active->client, context);
    active->server->onQuiesceRequest(active->server, context);
    active->client->onWorkerQuiesce(active->client, 0, context);
    active->server->onWorkerQuiesce(active->server, 0, context);
    if (active->app != NULL && lineIsAlive(active->app))
    {
        tunnelNextUpStreamFinish(active->source, active->app);
        gnsRequire(lineIsAlive(active->app), "the client destroyed its borrowed application line");
        lineDestroy(active->app);
    }
    if (active->carrier != NULL && lineIsAlive(active->carrier))
    {
        tunnelNextUpStreamFinish(active->wire, active->carrier);
        gnsRequire(lineIsAlive(active->carrier), "the server destroyed the borrowed carrier");
        lineDestroy(active->carrier);
    }
    active->client->onWorkerStop(active->client, 0, context);
    active->server->onWorkerStop(active->server, 0, context);
    for (size_t i = 0; i < active->count_packets; ++i)
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(0), active->queue[i].buffer);
    }
    requireRetired(active->app, active->client, "the application line survived cleanup");
    requireRetired(active->transport, active->client, "the client's owned carrier survived cleanup");
    requireRetired(active->service_line, active->server, "the server's owned service line survived cleanup");
    requireRetired(active->carrier, active->server, "the borrowed carrier survived its owner's cleanup");
    /* Destroying the last GNS tunnel stops the library and its thread. */
    tunnel_t *tunnels[] = {active->source, active->client, active->wire, active->server, active->service};
    for (unsigned i = 0; i < ARRAY_SIZE(tunnels); ++i)
    {
        tunnels[i]->onDestroy(tunnels[i], context);
    }
    tunnelchainDestroy(active->chain);
    for (unsigned i = 0; i < ARRAY_SIZE(active->nodes); ++i)
    {
        cJSON_Delete(active->nodes[i].node_settings_json);
        memoryFree(active->nodes[i].type);
    }
    active = NULL;
    /* Wakes that were on their way to the sessions find them gone. */
    gnsTestStep();
}

static bool serviceOpened(void)
{
    return active->service_inits == 1;
}

static bool transferDone(void)
{
    return active->received[0] == active->sent[0] && active->received[1] == active->sent[1];
}

static bool allFinished(void)
{
    return ! lineIsAlive(active->transport) && ! lineIsAlive(active->carrier) &&
           (active->service_line == NULL || ! lineIsAlive(active->service_line));
}

static bool appFinished(void)
{
    return active->app_finishes == 1;
}

static bool carrierFinished(void)
{
    return active->carrier_finishes == 1;
}

static bool appPaused(void)
{
    return active->app_pauses == 2;
}

static bool wireHasPacket(void)
{
    return active->count_packets >= 1;
}

static bool serverAnswered(void)
{
    for (size_t i = 0; i < active->count_packets; ++i)
    {
        if (active->queue[i].direction == 1)
        {
            return true;
        }
    }
    return false;
}

static bool appResumed(void)
{
    return active->app_resumes == 2;
}

static void openPair(fixture_t *fixture, const char *settings)
{
    setup(fixture, settings);
    openApp();
    gnsRequire(active->transport != NULL && active->carrier != NULL, "the client did not open its carrier");
    gnsRequire(pumpUntil(serviceOpened), "the native handshake did not open a service line");
}

static void caseTransferAndOwnership(void)
{
    static fixture_t fixture;
    openPair(&fixture, kDefaultSettings);
    gnsRequire(fixture.app_ests >= 1, "the carrier's Est was not relayed to the application");
    gnsRequire(fixture.service_ests == 1, "the carrier's Est was not relayed to the new service line");
    gnsRequire(fixture.carrier_ests == 1, "the service line's Est was not relayed to the carrier");
    sendChunks(0, 12);
    sendChunks(1, 6);
    gnsRequire(pumpUntil(transferDone), "the transfer did not finish");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, fixture.received[0], 12 * (size_t) kChunk, "the service received less");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, fixture.received[1], 6 * (size_t) kChunk, "the application received less");
    gnsRequire(fixture.app_finishes == 0 && fixture.service_finishes == 0, "a line was finished during transfer");
    teardown();
}

static void caseApplicationFinish(void)
{
    static fixture_t fixture;
    openPair(&fixture, kDefaultSettings);
    sendChunks(0, 4);
    /* The application's owner finishes and destroys its line at once. The bytes it sent still arrive. */
    tunnelNextUpStreamFinish(fixture.source, fixture.app);
    gnsRequire(lineIsAlive(fixture.app), "the client destroyed its borrowed application line");
    lineDestroy(fixture.app);
    gnsRequire(pumpUntil(allFinished), "the close did not retire every line");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, fixture.received[0], 4 * (size_t) kChunk, "bytes sent before Finish were lost");
    gnsRequire(fixture.app_finishes == 0, "Finish was reflected to the application's owner");
    gnsRequire(fixture.service_finishes == 1, "the service did not hear the close exactly once");
    gnsRequire(fixture.carrier_finishes == 1, "the server did not finish its carrier toward the owner");
    gnsRequire(fixture.transport_finishes == 1, "the client did not finish its carrier toward the next node");
    teardown();
}

static void caseServiceFinish(void)
{
    static fixture_t fixture;
    openPair(&fixture, kDefaultSettings);
    sendChunks(1, 4);
    /* The service line belongs to the server, so it must be dead when this Finish returns. */
    tunnelPrevDownStreamFinish(fixture.service, fixture.service_line);
    gnsRequire(! lineIsAlive(fixture.service_line), "the server kept its owned service line alive after Finish");
    gnsRequire(pumpUntil(appFinished), "the application was not finished after the peer closed");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, fixture.received[1], 4 * (size_t) kChunk, "bytes sent before Finish were lost");
    gnsRequire(pumpUntil(allFinished), "the close did not retire every line");
    gnsRequire(fixture.service_finishes == 0, "Finish was reflected to the service's neighbour");
    gnsRequire(fixture.carrier_finishes == 1 && fixture.transport_finishes == 1, "a carrier was not finished once");
    teardown();
}

static void caseCarrierFinish(void)
{
    static fixture_t fixture;
    openPair(&fixture, kDefaultSettings);
    /* The UDP owner finishes the borrowed carrier: the server aborts at once and reflects nothing. */
    tunnelNextUpStreamFinish(fixture.wire, fixture.carrier);
    gnsRequire(lineIsAlive(fixture.carrier), "the server destroyed the borrowed carrier");
    gnsRequire(fixture.service_finishes == 1 && ! lineIsAlive(fixture.service_line),
               "the service line was not finished and destroyed with its carrier");
    gnsRequire(fixture.carrier_finishes == 0, "Finish was reflected to the carrier's owner");
    lineDestroy(fixture.carrier);
    /* The next node finishes the client's owned carrier: it must be dead when this Finish returns. */
    tunnelPrevDownStreamFinish(fixture.wire, fixture.transport);
    gnsRequire(! lineIsAlive(fixture.transport), "the client kept its owned carrier alive after Finish");
    gnsRequire(fixture.app_finishes == 1, "the application was not finished with its carrier");
    gnsRequire(fixture.transport_finishes == 0, "Finish was reflected to the carrier's neighbour");
    teardown();
}

static void casePressure(void)
{
    static fixture_t fixture;
    openPair(&fixture, kDefaultSettings);
    /* A full consumer on either application side stops datagram ingress on that side's carrier. */
    tunnelNextUpStreamPause(fixture.source, fixture.app);
    tunnelNextUpStreamResume(fixture.source, fixture.app);
    gnsRequire(fixture.wire_pauses[0] == 1 && fixture.wire_resumes[0] == 1,
               "application pressure was not relayed to the client's carrier");
    tunnelPrevDownStreamPause(fixture.service, fixture.service_line);
    tunnelPrevDownStreamResume(fixture.service, fixture.service_line);
    gnsRequire(fixture.wire_pauses[1] == 1 && fixture.wire_resumes[1] == 1,
               "service pressure was not relayed to the server's carrier");
    /* A full carrier pauses the producer on the application side. */
    tunnelPrevDownStreamPause(fixture.wire, fixture.transport);
    tunnelPrevDownStreamResume(fixture.wire, fixture.transport);
    gnsRequire(fixture.app_pauses == 1 && fixture.app_resumes == 1, "carrier pressure did not reach the application");
    tunnelNextUpStreamPause(fixture.wire, fixture.carrier);
    tunnelNextUpStreamResume(fixture.wire, fixture.carrier);
    gnsRequire(fixture.service_pauses == 1 && fixture.service_resumes == 1,
               "carrier pressure did not reach the service");

    /* Two reasons at once. Five chunks above a 65536-byte limit start the client's own hold. */
    fixture.hold_wire = true;
    for (int i = 0; i < 5; ++i)
    {
        sendBytes(0, kChunk);
    }
    gnsRequire(pumpUntil(appPaused) && fixture.app_pauses == 2, "the local send hold did not pause the application");
    tunnelPrevDownStreamPause(fixture.wire, fixture.transport);
    gnsRequire(fixture.app_pauses == 2, "a second reason paused the application again");
    /* Acknowledgements clear the local hold a moment after the last byte has arrived. The carrier is still paused,
     * so the application hears no resume however long the test waits; the wait only gives a wrong resume time to
     * show. */
    fixture.hold_wire = false;
    gnsRequire(pumpUntil(transferDone), "held bytes were not delivered");
    pumpFor(300);
    gnsRequire(fixture.app_resumes == 1, "clearing the local hold released the carrier's pause");
    tunnelPrevDownStreamResume(fixture.wire, fixture.transport);
    gnsRequire(pumpUntil(appResumed) && fixture.app_resumes == 2,
               "the application was not resumed once both reasons cleared");
    teardown();
}

static void caseAdmissionDeadline(void)
{
    static fixture_t fixture;
    setup(&fixture, kShortHandshake);
    fixture.drop_wire    = true;
    const uint64_t begin = loopNowMs();
    openApp();
    gnsRequire(pumpUntil(carrierFinished), "a carrier without a native connection was not finished");
    gnsRequire(loopNowMs() >= begin + 600, "the server gave up before timeout-initial-ms");
    gnsRequire(fixture.service_inits == 0, "a service line was created without a native connection");
    /* The client's connection attempt ends by GNS's own timeout. */
    gnsRequire(pumpUntil(appFinished), "the client's failed connect did not finish the application");
    gnsRequire(! lineIsAlive(fixture.transport) && fixture.transport_finishes == 1,
               "the client's carrier was not finished and destroyed");
    teardown();
}

static void caseWorkerStop(void)
{
    static fixture_t fixture;
    openPair(&fixture, kDefaultSettings);
    fixture.hold_wire = true;
    sendBytes(0, kChunk);
    const ww_lifecycle_context_t *context = wwLifecycleStartupRollback();
    fixture.client->onQuiesceRequest(fixture.client, context);
    fixture.server->onQuiesceRequest(fixture.server, context);
    fixture.client->onWorkerQuiesce(fixture.client, 0, context);
    fixture.server->onWorkerQuiesce(fixture.server, 0, context);
    gnsRequire(wloopNTimers(getWorkerLoop(0)) == timers_at_start, "worker quiescence left a session timer attached");
    fixture.client->onWorkerStop(fixture.client, 0, context);
    fixture.server->onWorkerStop(fixture.server, 0, context);
    /* Shutdown does not wait for a drain: every owned line is dead and every owner was told. */
    gnsRequire(! lineIsAlive(fixture.transport) && ! lineIsAlive(fixture.service_line),
               "an owned line survived worker stop");
    gnsRequire(fixture.app_finishes == 1 && fixture.carrier_finishes == 1,
               "a borrowed line's owner was not told at worker stop");
    gnsRequire(fixture.transport_finishes == 1 && fixture.service_finishes == 1,
               "an owned line's neighbour was not told at worker stop");
    teardown();
}

/* Worker stop while the native handshake is in flight: the client waits for an answer to its first packet, and
 * the server has answered a carrier that has no service line yet. */
static void caseWorkerStopDuringHandshake(void)
{
    static fixture_t fixture;
    setup(&fixture, kDefaultSettings);
    fixture.hold_wire = true;
    openApp();
    gnsRequire(fixture.transport != NULL && fixture.carrier != NULL, "the client did not open its carrier");
    gnsRequire(pumpUntil(wireHasPacket) && fixture.count_packets == 1 && fixture.queue[0].direction == 0,
               "the client did not send exactly one first packet");
    /* Give the server the packet and keep its answer on the wire. */
    sbuf_t *request       = fixture.queue[0].buffer;
    fixture.count_packets = 0;
    tunnelNextUpStreamPayload(fixture.wire, fixture.carrier, request);
    gnsRequire(pumpUntil(serverAnswered), "the server did not answer the client's first packet");
    gnsRequire(fixture.service_inits == 0, "the server created a service line before the native handshake");
    const ww_lifecycle_context_t *context = wwLifecycleStartupRollback();
    fixture.client->onQuiesceRequest(fixture.client, context);
    fixture.server->onQuiesceRequest(fixture.server, context);
    fixture.client->onWorkerQuiesce(fixture.client, 0, context);
    fixture.server->onWorkerQuiesce(fixture.server, 0, context);
    gnsRequire(wloopNTimers(getWorkerLoop(0)) == timers_at_start, "worker quiescence left a handshake timer attached");
    fixture.client->onWorkerStop(fixture.client, 0, context);
    fixture.server->onWorkerStop(fixture.server, 0, context);
    gnsRequire(! lineIsAlive(fixture.transport) && fixture.transport_finishes == 1,
               "the client's carrier survived a stop during the handshake");
    gnsRequire(fixture.app_finishes == 1 && fixture.carrier_finishes == 1,
               "a borrowed line's owner was not told at a stop during the handshake");
    gnsRequire(fixture.service_inits == 0 && fixture.service_finishes == 0,
               "a stop during the handshake created or finished a service line");
    teardown();
}

static void caseConstructorErrors(void)
{
    static const char *invalid[] = {"{\"send-mtu\":100}", "{\"carrier-queue-limit\":0}", "{\"send-rate\":\"x\"}"};
    for (size_t i = 0; i < ARRAY_SIZE(invalid); ++i)
    {
        node_t nodes[2] = {nodeGnsClientGet(), nodeGnsServerGet()};
        for (size_t n = 0; n < 2; ++n)
        {
            nodes[n].node_settings_json = cJSON_Parse(invalid[i]);
            gnsRequire(nodes[n].node_settings_json != NULL, "fixture JSON failed to parse");
            gnsRequire(nodes[n].createHandle(&nodes[n]) == NULL, "invalid settings built a tunnel");
            cJSON_Delete(nodes[n].node_settings_json);
            memoryFree(nodes[n].type);
        }
    }
    node_t    node   = nodeGnsServerGet();
    tunnel_t *tunnel = node.createHandle(&node);
    gnsRequire(tunnel != NULL, "a node without settings was refused");
    tunnel->onDestroy(tunnel, wwLifecycleStartupRollback());
    memoryFree(node.type);
}

int main(void)
{
    /* Two runtimes in one process: nothing of the first may be needed by, or left for, the second. */
    for (int runtime = 0; runtime < 2; ++runtime)
    {
        gnsTestRuntimeStart();
        timers_at_start = wloopNTimers(getWorkerLoop(0));
        TEST_RUN_CASE(caseTransferAndOwnership);
        TEST_RUN_CASE(caseApplicationFinish);
        TEST_RUN_CASE(caseServiceFinish);
        TEST_RUN_CASE(caseCarrierFinish);
        TEST_RUN_CASE(casePressure);
        TEST_RUN_CASE(caseAdmissionDeadline);
        TEST_RUN_CASE(caseWorkerStop);
        TEST_RUN_CASE(caseWorkerStopDuringHandshake);
        TEST_RUN_CASE(caseConstructorErrors);
        gnsRequire(wloopNTimers(getWorkerLoop(0)) == timers_at_start, "a session timer survived the fixtures");
        gnsTestRuntimeStop();
    }
    return 0;
}
