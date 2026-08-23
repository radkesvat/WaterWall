#include "PingClient/structure.h"
#include "PingServer/structure.h"

#include "tunnel_orderly_shutdown_harness.h"

enum
{
    kFlowWorkers          = 4,
    kFlowPacketCapacity   = 16,
    kFlowPacketBytes      = kMaxAllowedPacketLength,
    kFlowInnerProtocol    = 253,
    kFlowSequenceStart    = UINT16_MAX,
    kFlowClientIdentifier = 0x1111,
    kFlowServerIdentifier = 0x2222,
};

typedef struct captured_packet_s
{
    uint8_t  bytes[kFlowPacketBytes];
    uint32_t length;
} captured_packet_t;

typedef struct flow_fixture_s flow_fixture_t;

typedef struct flow_sink_s
{
    flow_fixture_t   *fixture;
    captured_packet_t packets[kFlowPacketCapacity];
    uint32_t          count;
    char              event;
    bool              destructive;
} flow_sink_t;

struct flow_fixture_s
{
    tos_worker_env_t env;
    tunnel_t        *endpoint;
    tunnel_t        *prev;
    tunnel_t        *next;
    tunnel_chain_t  *chain;
    line_t          *packet_lines[kFlowWorkers];
    flow_sink_t     *prev_sink;
    flow_sink_t     *next_sink;
    cJSON           *settings;
    node_t           node;
    char             events[32];
    uint32_t         event_count;
    bool             server;
};

static uint32_t ipv4Address(const char *text)
{
    ip4_addr_t address = {0};
    twfRequire(ip4AddrAddressToNetwork(text, &address) != 0, "test IPv4 parsing failed");
    return ip4AddrGetU32(&address);
}

static ping_wire_config_t endpointConfig(const flow_fixture_t *fixture)
{
    if (fixture->server)
    {
        return ((const pingserver_tstate_t *) tunnelGetState(fixture->endpoint))->wire;
    }
    return ((const pingclient_tstate_t *) tunnelGetState(fixture->endpoint))->wire;
}

static ping_wire_config_t peerConfig(const flow_fixture_t *fixture)
{
    const ping_wire_config_t endpoint = endpointConfig(fixture);
    return (ping_wire_config_t) {
        .local_ipv4 = endpoint.peer_ipv4,
        .peer_ipv4  = endpoint.local_ipv4,
        .identifier = fixture->server ? kFlowClientIdentifier : kFlowServerIdentifier,
        .ttl        = 48,
        .tos        = 9,
    };
}

static atomic_uint *nextSequence(flow_fixture_t *fixture)
{
    if (fixture->server)
    {
        return &((pingserver_tstate_t *) tunnelGetState(fixture->endpoint))->next_sequence;
    }
    return &((pingclient_tstate_t *) tunnelGetState(fixture->endpoint))->next_sequence;
}

static void sinkPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    flow_sink_t *sink = tunnelGetState(t);
    twfRequire(sink->count < kFlowPacketCapacity, "Ping flow sink capacity exceeded");
    twfRequire(sbufGetLength(buf) <= kFlowPacketBytes, "Ping flow sink packet is too large");

    captured_packet_t *packet = &sink->packets[sink->count++];
    packet->length            = sbufGetLength(buf);
    memoryCopy(packet->bytes, sbufGetRawPtr(buf), packet->length);

    twfRequire(sink->fixture->event_count + 1U < sizeof(sink->fixture->events), "Ping flow event trace overflow");
    sink->fixture->events[sink->fixture->event_count++] = sink->event;
    sink->fixture->events[sink->fixture->event_count]   = '\0';

    lineReuseBuffer(l, buf);
    if (sink->destructive)
    {
        lineDestroy(l);
    }
}

static tunnel_t *createSink(flow_fixture_t *fixture, char event)
{
    tunnel_t *sink = tunnelCreate(NULL, sizeof(flow_sink_t), 0);
    twfRequire(sink != NULL, "failed to create Ping flow sink");

    flow_sink_t *state = tunnelGetState(sink);
    state->fixture     = fixture;
    state->event       = event;
    sink->fnPayloadU   = sinkPayload;
    sink->fnPayloadD   = sinkPayload;
    return sink;
}

static line_t *createPacketLine(wid_t wid)
{
    line_t *line = memoryAllocateCacheAlignedZero(sizeof(line_t));
    twfRequire(line != NULL, "failed to allocate Ping packet line");
    atomic_init(&line->refc, 1);
    line->alive = true;
    line->wid   = wid;
    return line;
}

static void resetSinks(flow_fixture_t *fixture)
{
    const char prev_event = fixture->prev_sink->event;
    const char next_event = fixture->next_sink->event;
    memoryZero(fixture->prev_sink, sizeof(*fixture->prev_sink));
    memoryZero(fixture->next_sink, sizeof(*fixture->next_sink));
    fixture->prev_sink->fixture = fixture;
    fixture->next_sink->fixture = fixture;
    fixture->prev_sink->event   = prev_event;
    fixture->next_sink->event   = next_event;
    memoryZero(fixture->events, sizeof(fixture->events));
    fixture->event_count = 0;
}

static void fixtureSetup(flow_fixture_t *fixture, bool server)
{
    memoryZero(fixture, sizeof(*fixture));
    fixture->server = server;

    tosWorkerEnvSetup(&fixture->env, kFlowWorkers, 8192, kMaxAllowedPacketLength);
    for (wid_t wid = 0; wid < kFlowWorkers; ++wid)
    {
        bufferpoolUpdateAllocationPaddings(
            fixture->env.pools[wid], kPingWireEncapsulationOverhead, kPingWireEncapsulationOverhead);
    }

    const char *json  = server ? "{\"local-ipv4\":\"198.51.100.10\",\"peer-ipv4\":\"192.0.2.10\","
                                 "\"identifier\":8738,\"sequence-start\":65535,\"ttl\":64,\"tos\":3}"
                               : "{\"local-ipv4\":\"192.0.2.10\",\"peer-ipv4\":\"198.51.100.10\","
                                 "\"identifier\":4369,\"sequence-start\":65535,\"ttl\":64,\"tos\":3}";
    fixture->settings = cJSON_Parse(json);
    twfRequire(fixture->settings != NULL, "failed to parse Ping flow settings");
    fixture->node.node_settings_json = fixture->settings;

    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);

    fixture->endpoint = server ? pingserverCreate(&fixture->node) : pingclientCreate(&fixture->node);
    twfRequire(fixture->endpoint != NULL, "failed to create Ping endpoint");

    fixture->prev      = createSink(fixture, 'P');
    fixture->next      = createSink(fixture, 'N');
    fixture->prev_sink = tunnelGetState(fixture->prev);
    fixture->next_sink = tunnelGetState(fixture->next);
    tunnelBind(fixture->prev, fixture->endpoint);
    tunnelBind(fixture->endpoint, fixture->next);

    fixture->chain = memoryAllocateZero(sizeof(tunnel_chain_t) + sizeof(generic_pool_t *) * kFlowWorkers);
    twfRequire(fixture->chain != NULL, "failed to allocate Ping flow chain");
    fixture->chain->workers_count = kFlowWorkers;
    fixture->chain->packet_lines  = fixture->packet_lines;
    fixture->endpoint->chain      = fixture->chain;
    for (wid_t wid = 0; wid < kFlowWorkers; ++wid)
    {
        fixture->packet_lines[wid] = createPacketLine(wid);
    }

    fixture->endpoint->onPrepare(fixture->endpoint);
    fixture->endpoint->onStart(fixture->endpoint);
    const ww_startup_result_t result = wwStartupContextEnd(&startup);
    twfRequire(wwStartupSucceeded(result), "Ping endpoint startup failed in flow fixture");
}

static void fixtureTeardown(flow_fixture_t *fixture)
{
    for (wid_t wid = 0; wid < kFlowWorkers; ++wid)
    {
        twfRequire(lineIsAlive(fixture->packet_lines[wid]), "Ping endpoint destroyed a worker packet line");
        twfLineDestroy(fixture->packet_lines[wid]);
    }

    fixture->endpoint->onDestroy(fixture->endpoint, wwLifecycleProcessShutdown());
    tunnelDestroy(fixture->next);
    tunnelDestroy(fixture->prev);
    memoryFree(fixture->chain);
    cJSON_Delete(fixture->settings);
    tosWorkerEnvTeardown(&fixture->env);
}

static sbuf_t *makeInnerPacket(line_t *line, uint16_t length)
{
    twfRequire(length >= IP_HLEN, "test inner packet is too short");
    sbuf_t *buf = bufferpoolGetSmallBuffer(lineGetBufferPool(line));
    twfRequire(sbufGetMaximumWriteableSize(buf) >= length, "test inner packet does not fit its buffer");
    sbufSetLength(buf, length);
    memoryZero(sbufGetMutablePtr(buf), length);

    struct ip_hdr *ip = (struct ip_hdr *) sbufGetMutablePtr(buf);
    IPH_VHL_SET(ip, 4, IP_HLEN / 4U);
    IPH_LEN_SET(ip, lwip_htons(length));
    IPH_ID_SET(ip, lwip_htons(0x5151));
    IPH_TTL_SET(ip, 51);
    IPH_PROTO_SET(ip, kFlowInnerProtocol);
    ip->src.addr  = ipv4Address("10.20.0.1");
    ip->dest.addr = ipv4Address("10.20.0.2");
    for (uint16_t i = IP_HLEN; i < length; ++i)
    {
        sbufGetMutablePtr(buf)[i] = (uint8_t) (i * 7U + length);
    }
    twfRequire(calcFullPacketChecksum(sbufGetMutablePtr(buf), length), "test inner checksum build failed");
    return buf;
}

static sbuf_t *bufferFromCapture(line_t *line, const captured_packet_t *packet)
{
    sbuf_t *buf = bufferpoolGetSmallBuffer(lineGetBufferPool(line));
    twfRequire(sbufGetMaximumWriteableSize(buf) >= packet->length, "captured Ping packet does not fit its buffer");
    sbufSetLength(buf, packet->length);
    memoryCopy(sbufGetMutablePtr(buf), packet->bytes, packet->length);
    return buf;
}

static sbuf_t *replyFromRequest(flow_fixture_t *fixture, line_t *line, const captured_packet_t *packet)
{
    sbuf_t                  *reply = bufferFromCapture(line, packet);
    ping_wire_envelope_t     request;
    const ping_wire_config_t peer = peerConfig(fixture);
    twfRequire(pingwireParseInbound(sbufGetRawPtr(reply), sbufGetLength(reply), &peer, &request) ==
                   kPingWireInboundEchoRequest,
               "captured endpoint request was not a valid peer Echo Request");
    twfRequire(pingwireBuildEchoReply(reply, &peer, &request, 0x3131), "failed to build exact endpoint reply");
    return reply;
}

static sbuf_t *peerRequest(flow_fixture_t *fixture, line_t *line, uint16_t sequence)
{
    sbuf_t                  *request = makeInnerPacket(line, 92);
    const ping_wire_config_t peer    = peerConfig(fixture);
    twfRequire(pingwireBuildEchoRequest(request, &peer, sequence), "failed to build peer Echo Request");
    return request;
}

static void sendLocal(flow_fixture_t *fixture, wid_t wid, sbuf_t *buf)
{
    const wid_t previous = tosSetCurrentWorker(wid);
    if (fixture->server)
    {
        pingserverDownStreamPayload(fixture->endpoint, fixture->packet_lines[wid], buf);
    }
    else
    {
        pingclientUpStreamPayload(fixture->endpoint, fixture->packet_lines[wid], buf);
    }
    discard tosSetCurrentWorker(previous);
}

static void sendInbound(flow_fixture_t *fixture, wid_t wid, sbuf_t *buf)
{
    const wid_t previous = tosSetCurrentWorker(wid);
    if (fixture->server)
    {
        pingserverUpStreamPayload(fixture->endpoint, fixture->packet_lines[wid], buf);
    }
    else
    {
        pingclientDownStreamPayload(fixture->endpoint, fixture->packet_lines[wid], buf);
    }
    discard tosSetCurrentWorker(previous);
}

static flow_sink_t *localRequestSink(flow_fixture_t *fixture)
{
    return fixture->server ? fixture->prev_sink : fixture->next_sink;
}

static flow_sink_t *unmatchedReplySink(flow_fixture_t *fixture)
{
    return fixture->server ? fixture->next_sink : fixture->prev_sink;
}

static flow_sink_t *generatedReplySink(flow_fixture_t *fixture)
{
    return fixture->server ? fixture->prev_sink : fixture->next_sink;
}

static flow_sink_t *decodedInnerSink(flow_fixture_t *fixture)
{
    return fixture->server ? fixture->next_sink : fixture->prev_sink;
}

static void requireCapturedRequest(const captured_packet_t *packet, uint16_t expected_identifier,
                                   uint16_t expected_sequence)
{
    twfRequire(packet->length >= kPingWireEncapsulationOverhead, "captured request is too short");
    const struct icmp_echo_hdr *icmp = (const struct icmp_echo_hdr *) (packet->bytes + kPingWireIpv4HeaderLength);
    twfRequire(icmp->type == ICMP_ECHO && icmp->code == 0, "captured local packet is not an Echo Request");
    twfRequire(lwip_ntohs(icmp->id) == expected_identifier, "deterministic endpoint identifier override changed");
    twfRequire(lwip_ntohs(icmp->seqno) == expected_sequence, "endpoint emitted the wrong request sequence");
}

static void caseCrossWorkerCorrelationAndSequence(flow_fixture_t *fixture)
{
    twfSetCase(fixture->server ? "PingServer node-wide reply correlation" : "PingClient node-wide reply correlation");
    resetSinks(fixture);

    line_t            *line_a          = fixture->packet_lines[0];
    line_t            *line_b          = fixture->packet_lines[3];
    const unsigned int sequence_before = atomicLoadRelaxed(nextSequence(fixture));
    twfRequireEqualU32(sequence_before, kFlowSequenceStart, "configured first Ping sequence was not retained");

    sbuf_t *short_padding = sbufCreateWithPadding(72, 0);
    sbufSetLength(short_padding, 72);
    memoryZero(sbufGetMutablePtr(short_padding), 72);
    struct ip_hdr *short_ip = (struct ip_hdr *) sbufGetMutablePtr(short_padding);
    IPH_VHL_SET(short_ip, 4, IP_HLEN / 4U);
    IPH_LEN_SET(short_ip, lwip_htons(72));
    IPH_TTL_SET(short_ip, 64);
    IPH_PROTO_SET(short_ip, kFlowInnerProtocol);
    twfRequire(calcFullPacketChecksum(sbufGetMutablePtr(short_padding), 72), "short-padding checksum build failed");
    lineSetRecalculateChecksum(line_a, true);
    sendLocal(fixture, 0, short_padding);
    twfRequire(! lineGetRecalculateChecksum(line_a), "short-padding rejection leaked its checksum request");

    lineSetRecalculateChecksum(line_a, true);
    sendLocal(fixture, 0, makeInnerPacket(line_a, kPingWireMaxInnerPacketLength + 1U));
    twfRequire(! lineGetRecalculateChecksum(line_a), "oversize rejection leaked its checksum request");
    twfRequireEqualU32(atomicLoadRelaxed(nextSequence(fixture)),
                       sequence_before,
                       "rejected local packets consumed Ping request sequences");
    twfRequireEqualU32(localRequestSink(fixture)->count, 0, "rejected local packet escaped onto the wire");

    sendLocal(fixture, 0, makeInnerPacket(line_a, 84));
    flow_sink_t *wire = localRequestSink(fixture);
    twfRequireEqualU32(wire->count, 1, "first valid local request was not emitted");
    requireCapturedRequest(&wire->packets[0], endpointConfig(fixture).identifier, UINT16_MAX);

    sbuf_t        *reply       = replyFromRequest(fixture, line_b, &wire->packets[0]);
    const uint32_t prev_before = fixture->prev_sink->count;
    const uint32_t next_before = fixture->next_sink->count;
    sendInbound(fixture, 3, reply);
    twfRequireEqualU32(fixture->prev_sink->count, prev_before, "matching reply escaped to the previous sink");
    twfRequireEqualU32(fixture->next_sink->count, next_before, "matching reply escaped to the next sink");

    sendLocal(fixture, 0, makeInnerPacket(line_a, 85));
    twfRequireEqualU32(wire->count, 2, "wrapped request after sequence wrap was not emitted");
    requireCapturedRequest(&wire->packets[1], endpointConfig(fixture).identifier, 0);

    sendLocal(fixture, 0, makeInnerPacket(line_a, 86));
    twfRequireEqualU32(wire->count, 3, "request for mismatch test was not emitted");
    sbuf_t               *mismatch = replyFromRequest(fixture, line_b, &wire->packets[2]);
    struct icmp_echo_hdr *icmp     = (struct icmp_echo_hdr *) (sbufGetMutablePtr(mismatch) + kPingWireIpv4HeaderLength);
    icmp->id                       = lwip_htons((uint16_t) (lwip_ntohs(icmp->id) + 1U));
    twfRequire(calcFullPacketChecksum(sbufGetMutablePtr(mismatch), sbufGetLength(mismatch)),
               "mismatched reply checksum rebuild failed");
    uint8_t        expected[kFlowPacketBytes];
    const uint32_t mismatch_length = sbufGetLength(mismatch);
    memoryCopy(expected, sbufGetRawPtr(mismatch), mismatch_length);

    flow_sink_t   *unmatched        = unmatchedReplySink(fixture);
    const uint32_t unmatched_before = unmatched->count;
    sendInbound(fixture, 3, mismatch);
    twfRequireEqualU32(unmatched->count, unmatched_before + 1U, "valid mismatched reply was not passed through");
    const captured_packet_t *passed = &unmatched->packets[unmatched->count - 1U];
    twfRequire(passed->length == mismatch_length && memoryEqual(passed->bytes, expected, mismatch_length),
               "mismatched reply did not pass through unchanged");

    for (wid_t wid = 0; wid < kFlowWorkers; ++wid)
    {
        twfRequire(lineIsAlive(fixture->packet_lines[wid]), "Ping flow killed a worker packet line");
    }
}

static void casePeerRequestReplay(flow_fixture_t *fixture)
{
    twfSetCase(fixture->server ? "PingServer cross-worker peer replay" : "PingClient cross-worker peer replay");
    resetSinks(fixture);

    sbuf_t           *request = peerRequest(fixture, fixture->packet_lines[1], 77);
    captured_packet_t wire_request;
    wire_request.length = sbufGetLength(request);
    memoryCopy(wire_request.bytes, sbufGetRawPtr(request), wire_request.length);

    sendInbound(fixture, 1, request);
    const char *first_order = fixture->server ? "PN" : "NP";
    twfRequireEqualText(fixture->events, first_order, "peer request reply/delivery callback order is wrong");
    twfRequireEqualU32(generatedReplySink(fixture)->count, 1, "peer request did not receive one reply");
    twfRequireEqualU32(decodedInnerSink(fixture)->count, 1, "peer request did not deliver one inner packet");

    sendInbound(fixture, 2, bufferFromCapture(fixture->packet_lines[2], &wire_request));
    const char *duplicate_order = fixture->server ? "PNP" : "NPN";
    twfRequireEqualText(fixture->events, duplicate_order, "duplicate request callback direction is wrong");
    twfRequireEqualU32(generatedReplySink(fixture)->count, 2, "duplicate request was not acknowledged again");
    twfRequireEqualU32(decodedInnerSink(fixture)->count, 1, "duplicate request delivered its inner packet twice");

    const captured_packet_t *reply1 = &generatedReplySink(fixture)->packets[0];
    const captured_packet_t *reply2 = &generatedReplySink(fixture)->packets[1];
    const struct ip_hdr     *ip1    = (const struct ip_hdr *) reply1->bytes;
    const struct ip_hdr     *ip2    = (const struct ip_hdr *) reply2->bytes;
    twfRequire((uint16_t) (lwip_ntohs(IPH_ID(ip1)) + 1U) == lwip_ntohs(IPH_ID(ip2)),
               "duplicate request replies did not use monotonic IPv4 IDs");

    ping_wire_envelope_t     reply_view;
    const ping_wire_config_t peer = peerConfig(fixture);
    twfRequire(pingwireParseInbound(reply1->bytes, reply1->length, &peer, &reply_view) == kPingWireInboundEchoReply,
               "generated first reply was not exact peer-facing Echo Reply traffic");
}

typedef struct fatal_case_s
{
    flow_fixture_t   *fixture;
    captured_packet_t request;
    wid_t             wid;
} fatal_case_t;

static void destructiveReplyBody(void *argument)
{
    fatal_case_t *fatal = argument;
    sendInbound(
        fatal->fixture, fatal->wid, bufferFromCapture(fatal->fixture->packet_lines[fatal->wid], &fatal->request));
}

static void caseGeneratedReplyLineSurvivalGuard(flow_fixture_t *fixture)
{
    twfSetCase(fixture->server ? "PingServer generated-reply line guard" : "PingClient generated-reply line guard");
    resetSinks(fixture);
    tosResetProcessApi(true);

    sbuf_t      *request = peerRequest(fixture, fixture->packet_lines[0], 91);
    fatal_case_t fatal   = {.fixture = fixture, .wid = 0};
    fatal.request.length = sbufGetLength(request);
    memoryCopy(fatal.request.bytes, sbufGetRawPtr(request), fatal.request.length);
    lineReuseBuffer(fixture->packet_lines[0], request);

    generatedReplySink(fixture)->destructive = true;
    tosRequireChildExit("destructive generated-reply sink", destructiveReplyBody, &fatal, kTosChildDirectAbort);
    generatedReplySink(fixture)->destructive = false;
    twfRequire(lineIsAlive(fixture->packet_lines[0]), "fatal child altered the parent's packet line");
}

static void runEndpointCases(bool server)
{
    flow_fixture_t fixture;
    fixtureSetup(&fixture, server);
    caseCrossWorkerCorrelationAndSequence(&fixture);
    casePeerRequestReplay(&fixture);
    caseGeneratedReplyLineSurvivalGuard(&fixture);
    fixtureTeardown(&fixture);
}

int main(void)
{
    initWLibc();
    checkSumInit();
    twfRequire(globalstateInitializeSecureRandom(), "secure-random initialization failed");
    twfRequire(wCryptoGlobalInit() == kWCryptoOk, "crypto initialization failed");

    runEndpointCases(false);
    runEndpointCases(true);

    wCryptoGlobalCleanup();
    globalstateDestroySecureRandom();
    puts("ping_flow_test: all cases passed");
    return 0;
}
