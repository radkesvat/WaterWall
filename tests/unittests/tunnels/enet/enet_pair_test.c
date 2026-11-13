/* CTest: waterwall.enet_pair_unit.
 * The real EnetClient and EnetServer tunnels in one chain between three fixture tunnels:
 *
 *     source -> EnetClient -> wire -> EnetServer -> service
 *
 * The fixture owns the application line and the UDP-facing carrier line, as a TCP listener and a UDP listener
 * would. EnetClient owns its transport line and EnetServer owns its service line. Worker timers are real; the
 * clock is replaced at link time, so time moves only when a test advances it. Covers line ownership and context,
 * transfer, Est mapping, every Finish path, Pause/Resume composition, the admission deadline, worker shutdown
 * with and without a finished handshake, and constructor errors. The whole list runs on two runtimes in one
 * process. Linux only: the clock is replaced with the linker's --wrap option. */

#include "EnetClient/interface.h"
#include "EnetServer/interface.h"

#include "enet_runtime.h"

enum
{
    kMaxPackets = 8192,
    kChunk      = 16384
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
    line_t         *transport;    /* created by EnetClient; the fixture holds a reference only */
    line_t         *carrier;      /* created and owned by the fixture */
    line_t         *service_line; /* created by EnetServer; the fixture holds a reference only */
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
static uint64_t   clock_us = 100000000ULL;
static unsigned   timers_at_start;

unsigned long long __wrap_getHRTimeUs(void);
unsigned long long __wrap_getHRTimeUs(void)
{
    return clock_us;
}

static uint8_t patternByte(size_t offset)
{
    return (uint8_t) (offset * 29U + 17U);
}

static void checkPayload(unsigned direction, line_t *line, sbuf_t *payload)
{
    const uint8_t *bytes = sbufGetRawPtr(payload);
    for (size_t i = 0; i < sbufGetLength(payload); ++i)
    {
        enetRequire(bytes[i] == patternByte(active->received[direction] + i), "the stream changed or was reordered");
    }
    active->received[direction] += sbufGetLength(payload);
    lineReuseBuffer(line, payload);
}

/* Fixture source: the owner of the application line. */

static void appFinish(tunnel_t *t, line_t *line)
{
    enetRequire(t == active->source && line == active->app, "Finish reached a foreign application line");
    active->app_finishes += 1;
    lineDestroy(line);
}

static void appEst(tunnel_t *t, line_t *line)
{
    enetRequire(t == active->source && line == active->app, "Est reached a foreign application line");
    active->app_ests += 1;
}

static void appPayload(tunnel_t *t, line_t *line, sbuf_t *payload)
{
    enetRequire(t == active->source && line == active->app, "payload reached a foreign application line");
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
    enetRequire(sbufGetLength(packet) + 28U <= 1500U, "a datagram exceeds the configured send MTU");
    enetRequire(active->count_packets < kMaxPackets, "the fixture wire overflowed");
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
    enetRequire(t == active->wire && active->transport == NULL && line != active->app,
                "the client did not split its borrowed application and its owned carrier");
    enetRequire(lineGetWID(line) == lineGetWID(active->app), "the client's carrier moved workers");
    enetRequire(addresscontextClassifyTransport(lineGetDestinationAddressContext(line)) == kAddressContextTransportUdp,
                "the client's carrier is not marked as UDP");
    enetRequire(addresscontextClassifyTransport(lineGetDestinationAddressContext(active->app)) ==
                    kAddressContextTransportTcp,
                "the application line is not marked as a stream");
    enetRequire(line->routing_context.local_listener_port == 34567 && line->routing_context.peer_source_port == 45678,
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
    enetRequire(active->service_inits == 0, "the server created a service line before the native handshake");
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
    enetRequire(t == active->wire && line == active->transport, "the client sent on a foreign line");
    queuePacket(0, packet);
}

static void wireDown(tunnel_t *t, line_t *line, sbuf_t *packet)
{
    enetRequire(t == active->wire && line == active->carrier, "the server sent on a foreign line");
    queuePacket(1, packet);
}

static void transportFinish(tunnel_t *t, line_t *line)
{
    enetRequire(t == active->wire && line == active->transport, "Finish reached a foreign transport");
    active->transport_finishes += 1;
}

static void carrierFinish(tunnel_t *t, line_t *line)
{
    enetRequire(t == active->wire && line == active->carrier, "Finish reached a foreign carrier");
    active->carrier_finishes += 1;
    lineDestroy(line);
}

static void carrierEst(tunnel_t *t, line_t *line)
{
    enetRequire(t == active->wire && line == active->carrier, "Est reached a foreign carrier");
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
    enetRequire(t == active->service && line != active->carrier && active->service_line == NULL,
                "the server reused the borrowed carrier as its service line");
    enetRequire(lineGetWID(line) == lineGetWID(active->carrier), "the service line moved workers");
    enetRequire(addresscontextClassifyTransport(lineGetDestinationAddressContext(line)) == kAddressContextTransportTcp,
                "the service line is not marked as a stream");
    enetRequire(line->routing_context.local_listener_port == 34567 && line->routing_context.peer_source_port == 45678,
                "the service line lost the routing context");
    active->service_line = line;
    lineRef(line);
    active->service_inits += 1;
    tunnelPrevDownStreamEst(t, line);
}

static void serviceEst(tunnel_t *t, line_t *line)
{
    enetRequire(t == active->service && line == active->service_line, "Est reached a foreign service line");
    active->service_ests += 1;
}

static void servicePayload(tunnel_t *t, line_t *line, sbuf_t *payload)
{
    enetRequire(t == active->service && line == active->service_line, "payload reached a foreign service line");
    checkPayload(0, line, payload);
}

static void serviceFinish(tunnel_t *t, line_t *line)
{
    enetRequire(t == active->service && line == active->service_line, "Finish reached a foreign service line");
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

static const char kDefaultSettings[] = "{\"ping-interval-ms\":100,\"no-recv-timeout-ms\":2000,"
                                       "\"close-drain-timeout-ms\":1000,\"send-buffer-limit\":65536}";

static void setup(fixture_t *fixture, const char *settings)
{
    memoryZero(fixture, sizeof(*fixture));
    active            = fixture;
    fixture->nodes[0] = (node_t) {.type = stringDuplicate("FixtureSource"), .flags = kNodeFlagChainHead};
    fixture->nodes[1] = nodeEnetClientGet();
    fixture->nodes[2] = (node_t) {.type = stringDuplicate("FixtureWire")};
    fixture->nodes[3] = nodeEnetServerGet();
    fixture->nodes[4] = (node_t) {.type = stringDuplicate("FixtureService"), .flags = kNodeFlagChainEnd};
    fixture->nodes[1].node_settings_json = cJSON_Parse(settings);
    fixture->nodes[3].node_settings_json = cJSON_Parse(settings);
    fixture->source                      = tunnelCreate(&fixture->nodes[0], 0, 0);
    fixture->client                      = fixture->nodes[1].createHandle(&fixture->nodes[1]);
    fixture->wire                        = tunnelCreate(&fixture->nodes[2], 0, 0);
    fixture->server                      = fixture->nodes[3].createHandle(&fixture->nodes[3]);
    fixture->service                     = tunnelCreate(&fixture->nodes[4], 0, 0);
    enetRequire(fixture->source && fixture->client && fixture->wire && fixture->server && fixture->service,
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
    enetRequire(addresscontextSetIpAddressPortProtocol(
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

static void advance(unsigned milliseconds)
{
    clock_us += (uint64_t) milliseconds * 1000;
    wloopUpdateTime(getWorkerLoop(0));
    discard wloopProcessEvents(getWorkerLoop(0), 0);
    flushWire();
}

static bool pumpUntil(unsigned limit_ms, bool (*done)(void))
{
    flushWire();
    for (unsigned elapsed = 0; elapsed < limit_ms && ! done(); elapsed += 5)
    {
        advance(5);
    }
    return done();
}

static void sendBytes(unsigned direction, size_t size)
{
    line_t *line = direction ? active->service_line : active->app;
    enetRequire(line != NULL && lineIsAlive(line), "sending on a retired line");
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

static void requireRetired(line_t *line, tunnel_t *tunnel, const char *message)
{
    if (line == NULL)
    {
        return;
    }
    enetRequire(! lineIsAlive(line), message);
    const uint8_t *state = lineGetState(line, tunnel);
    for (size_t i = 0; i < tunnel->lstate_size; ++i)
    {
        enetRequire(state[i] == 0, "a retired line kept node state");
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
        enetRequire(lineIsAlive(active->app), "the client destroyed its borrowed application line");
        lineDestroy(active->app);
    }
    if (active->carrier != NULL && lineIsAlive(active->carrier))
    {
        tunnelNextUpStreamFinish(active->wire, active->carrier);
        enetRequire(lineIsAlive(active->carrier), "the server destroyed the borrowed carrier");
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

static bool appResumed(void)
{
    return active->app_resumes >= 1;
}

static void openPair(fixture_t *fixture, const char *settings)
{
    setup(fixture, settings);
    openApp();
    enetRequire(active->transport != NULL && active->carrier != NULL, "the client did not open its carrier");
    enetRequire(pumpUntil(500, serviceOpened), "the native handshake did not open a service line");
}

static void caseTransferAndOwnership(void)
{
    static fixture_t fixture;
    openPair(&fixture, kDefaultSettings);
    enetRequire(fixture.app_ests >= 1, "the carrier's Est was not relayed to the application");
    enetRequire(fixture.service_ests == 1, "the carrier's Est was not relayed to the new service line");
    enetRequire(fixture.carrier_ests == 1, "the service line's Est was not relayed to the carrier");
    for (int i = 0; i < 12; ++i)
    {
        sendBytes(0, kChunk);
    }
    for (int i = 0; i < 6; ++i)
    {
        sendBytes(1, kChunk);
    }
    enetRequire(pumpUntil(3000, transferDone), "the transfer did not finish");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, fixture.received[0], 12 * (size_t) kChunk, "the service received less");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, fixture.received[1], 6 * (size_t) kChunk, "the application received less");
    enetRequire(fixture.app_finishes == 0 && fixture.service_finishes == 0, "a line was finished during transfer");
    teardown();
}

static void caseApplicationFinish(void)
{
    static fixture_t fixture;
    openPair(&fixture, kDefaultSettings);
    for (int i = 0; i < 4; ++i)
    {
        sendBytes(0, kChunk);
    }
    /* The application's owner finishes and destroys its line at once. The bytes it sent still arrive. */
    tunnelNextUpStreamFinish(fixture.source, fixture.app);
    enetRequire(lineIsAlive(fixture.app), "the client destroyed its borrowed application line");
    lineDestroy(fixture.app);
    enetRequire(pumpUntil(3000, allFinished), "the close did not retire every line");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, fixture.received[0], 4 * (size_t) kChunk, "bytes sent before Finish were lost");
    enetRequire(fixture.app_finishes == 0, "Finish was reflected to the application's owner");
    enetRequire(fixture.service_finishes == 1, "the service did not hear the close exactly once");
    enetRequire(fixture.carrier_finishes == 1, "the server did not finish its carrier toward the owner");
    enetRequire(fixture.transport_finishes == 1, "the client did not finish its carrier toward the next node");
    teardown();
}

static void caseServiceFinish(void)
{
    static fixture_t fixture;
    openPair(&fixture, kDefaultSettings);
    for (int i = 0; i < 4; ++i)
    {
        sendBytes(1, kChunk);
    }
    /* The service line belongs to the server, so it must be dead when this Finish returns. */
    tunnelPrevDownStreamFinish(fixture.service, fixture.service_line);
    enetRequire(! lineIsAlive(fixture.service_line), "the server kept its owned service line alive after Finish");
    enetRequire(pumpUntil(3000, appFinished), "the application was not finished after the peer closed");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, fixture.received[1], 4 * (size_t) kChunk, "bytes sent before Finish were lost");
    enetRequire(pumpUntil(3000, allFinished), "the close did not retire every line");
    enetRequire(fixture.service_finishes == 0, "Finish was reflected to the service's neighbour");
    enetRequire(fixture.carrier_finishes == 1 && fixture.transport_finishes == 1, "a carrier was not finished once");
    teardown();
}

static void caseCarrierFinish(void)
{
    static fixture_t fixture;
    openPair(&fixture, kDefaultSettings);
    /* The UDP owner finishes the borrowed carrier: the server aborts at once and reflects nothing. */
    tunnelNextUpStreamFinish(fixture.wire, fixture.carrier);
    enetRequire(lineIsAlive(fixture.carrier), "the server destroyed the borrowed carrier");
    enetRequire(fixture.service_finishes == 1 && ! lineIsAlive(fixture.service_line),
                "the service line was not finished and destroyed with its carrier");
    enetRequire(fixture.carrier_finishes == 0, "Finish was reflected to the carrier's owner");
    lineDestroy(fixture.carrier);
    /* The next node finishes the client's owned carrier: it must be dead when this Finish returns. */
    tunnelPrevDownStreamFinish(fixture.wire, fixture.transport);
    enetRequire(! lineIsAlive(fixture.transport), "the client kept its owned carrier alive after Finish");
    enetRequire(fixture.app_finishes == 1, "the application was not finished with its carrier");
    enetRequire(fixture.transport_finishes == 0, "Finish was reflected to the carrier's neighbour");
    teardown();
}

static void casePressure(void)
{
    static fixture_t fixture;
    openPair(&fixture, kDefaultSettings);
    /* A full consumer on either application side stops datagram ingress on that side's carrier. */
    tunnelNextUpStreamPause(fixture.source, fixture.app);
    tunnelNextUpStreamResume(fixture.source, fixture.app);
    enetRequire(fixture.wire_pauses[0] == 1 && fixture.wire_resumes[0] == 1,
                "application pressure was not relayed to the client's carrier");
    tunnelPrevDownStreamPause(fixture.service, fixture.service_line);
    tunnelPrevDownStreamResume(fixture.service, fixture.service_line);
    enetRequire(fixture.wire_pauses[1] == 1 && fixture.wire_resumes[1] == 1,
                "service pressure was not relayed to the server's carrier");
    /* A full carrier pauses the producer on the application side. */
    tunnelPrevDownStreamPause(fixture.wire, fixture.transport);
    tunnelPrevDownStreamResume(fixture.wire, fixture.transport);
    enetRequire(fixture.app_pauses == 1 && fixture.app_resumes == 1, "carrier pressure did not reach the application");
    tunnelNextUpStreamPause(fixture.wire, fixture.carrier);
    tunnelNextUpStreamResume(fixture.wire, fixture.carrier);
    enetRequire(fixture.service_pauses == 1 && fixture.service_resumes == 1,
                "carrier pressure did not reach the service");

    /* Two reasons at once. Five chunks above a 65536-byte limit start the client's own hold. */
    fixture.hold_wire = true;
    for (int i = 0; i < 5; ++i)
    {
        sendBytes(0, kChunk);
    }
    enetRequire(fixture.app_pauses == 2, "the local send hold did not pause the application");
    tunnelPrevDownStreamPause(fixture.wire, fixture.transport);
    enetRequire(fixture.app_pauses == 2, "a second reason paused the application again");
    /* Acknowledgements clear the local hold, but the carrier is still paused. */
    fixture.hold_wire = false;
    enetRequire(pumpUntil(3000, transferDone), "held bytes were not delivered");
    enetRequire(fixture.app_resumes == 1, "clearing the local hold released the carrier's pause");
    tunnelPrevDownStreamResume(fixture.wire, fixture.transport);
    enetRequire(pumpUntil(100, appResumed) && fixture.app_resumes == 2,
                "the application was not resumed once both reasons cleared");
    teardown();
}

static void caseAdmissionDeadline(void)
{
    static fixture_t fixture;
    setup(&fixture, kDefaultSettings);
    fixture.drop_wire = true;
    openApp();
    advance(1990);
    enetRequire(fixture.carrier_finishes == 0, "the server gave up before no-recv-timeout-ms");
    enetRequire(pumpUntil(100, carrierFinished), "a carrier without a native connection was not finished");
    enetRequire(fixture.service_inits == 0, "a service line was created without a native connection");
    /* The client's connect request ends by ENet's own timeout, between T and 2T. */
    enetRequire(pumpUntil(2500, appFinished), "the client's failed connect did not finish the application");
    enetRequire(! lineIsAlive(fixture.transport) && fixture.transport_finishes == 1,
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
    enetRequire(wloopNTimers(getWorkerLoop(0)) == timers_at_start, "worker quiescence left a session timer attached");
    fixture.client->onWorkerStop(fixture.client, 0, context);
    fixture.server->onWorkerStop(fixture.server, 0, context);
    /* Shutdown does not wait for a drain: every owned line is dead and every owner was told. */
    enetRequire(! lineIsAlive(fixture.transport) && ! lineIsAlive(fixture.service_line),
                "an owned line survived worker stop");
    enetRequire(fixture.app_finishes == 1 && fixture.carrier_finishes == 1,
                "a borrowed line's owner was not told at worker stop");
    enetRequire(fixture.transport_finishes == 1 && fixture.service_finishes == 1,
                "an owned line's neighbour was not told at worker stop");
    teardown();
}

/* Worker stop while the native handshake is in flight: the client waits for an answer to its connect request, and
 * the server has answered a carrier that has no service line yet. */
static void caseWorkerStopDuringHandshake(void)
{
    static fixture_t fixture;
    setup(&fixture, kDefaultSettings);
    fixture.hold_wire = true;
    openApp();
    enetRequire(fixture.transport != NULL && fixture.carrier != NULL, "the client did not open its carrier");
    enetRequire(fixture.count_packets == 1 && fixture.queue[0].direction == 0,
                "the client did not send exactly one connect request");
    /* Give the server the request and keep its answer on the wire. */
    sbuf_t *request       = fixture.queue[0].buffer;
    fixture.count_packets = 0;
    tunnelNextUpStreamPayload(fixture.wire, fixture.carrier, request);
    enetRequire(fixture.count_packets >= 1 && fixture.queue[0].direction == 1,
                "the server did not answer the connect request");
    enetRequire(fixture.service_inits == 0, "the server created a service line before the native handshake");
    const ww_lifecycle_context_t *context = wwLifecycleStartupRollback();
    fixture.client->onQuiesceRequest(fixture.client, context);
    fixture.server->onQuiesceRequest(fixture.server, context);
    fixture.client->onWorkerQuiesce(fixture.client, 0, context);
    fixture.server->onWorkerQuiesce(fixture.server, 0, context);
    enetRequire(wloopNTimers(getWorkerLoop(0)) == timers_at_start, "worker quiescence left a handshake timer attached");
    fixture.client->onWorkerStop(fixture.client, 0, context);
    fixture.server->onWorkerStop(fixture.server, 0, context);
    enetRequire(! lineIsAlive(fixture.transport) && fixture.transport_finishes == 1,
                "the client's carrier survived a stop during the handshake");
    enetRequire(fixture.app_finishes == 1 && fixture.carrier_finishes == 1,
                "a borrowed line's owner was not told at a stop during the handshake");
    enetRequire(fixture.service_inits == 0 && fixture.service_finishes == 0,
                "a stop during the handshake created or finished a service line");
    teardown();
}

static void caseConstructorErrors(void)
{
    static const char *invalid[] = {
        "{\"send-mtu\":100}", "{\"carrier-queue-limit\":0}", "{\"ping-interval-ms\":\"x\"}"};
    for (size_t i = 0; i < ARRAY_SIZE(invalid); ++i)
    {
        node_t nodes[2] = {nodeEnetClientGet(), nodeEnetServerGet()};
        for (size_t n = 0; n < 2; ++n)
        {
            nodes[n].node_settings_json = cJSON_Parse(invalid[i]);
            enetRequire(nodes[n].node_settings_json != NULL, "fixture JSON failed to parse");
            enetRequire(nodes[n].createHandle(&nodes[n]) == NULL, "invalid settings built a tunnel");
            cJSON_Delete(nodes[n].node_settings_json);
            memoryFree(nodes[n].type);
        }
    }
    node_t    node   = nodeEnetServerGet();
    tunnel_t *tunnel = node.createHandle(&node);
    enetRequire(tunnel != NULL, "a node without settings was refused");
    tunnel->onDestroy(tunnel, wwLifecycleStartupRollback());
    memoryFree(node.type);
}

int main(void)
{
    /* Two runtimes in one process: nothing of the first may be needed by, or left for, the second. */
    for (int runtime = 0; runtime < 2; ++runtime)
    {
        enetRuntimeStart();
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
        enetRequire(wloopNTimers(getWorkerLoop(0)) == timers_at_start, "a session timer survived the fixtures");
        enetRuntimeStop();
    }
    return 0;
}
