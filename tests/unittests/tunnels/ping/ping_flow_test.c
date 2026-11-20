/*
 * Covers: ping flow; the explicit inputs, callbacks and expected results below define this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: caseCrossWorkerCorrelationAndSequence, casePeerRequestReplay, caseUnrelatedIpv4Options,
 * casePacketDiagnostics, caseGeneratedReplyLineSurvivalGuard, caseInvalidReplySettings,
 * caseDecodedTransportArrivalWorker, caseDecodedFragmentArrivalWorker, caseForeignWorkerAdmissionIrrelevant
 * Checks: Assertion labels include: Ping diagnostic exceeds capture capacity; Ping rejection did not emit
 * exactly one diagnostic; Ping rejection diagnostic is not ERROR level; Ping diagnostic omitted the
 * specific failure reason
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.ping_flow_unit
 */
#include "loggers/network_logger.h"

#include "PingClient/structure.h"
#include "PingServer/structure.h"
#include "devices/device_flow_affinity.h"
#ifdef PING_IPOVERRIDER_FIXTURE
#include "IpOverrider/structure.h"
#endif

#include "fixtures/failure/tunnel_orderly_shutdown_harness.h"

sbuf_t *__real_sbufDuplicateByPool(buffer_pool_t *pool, const sbuf_t *buffer);
sbuf_t *__wrap_sbufDuplicateByPool(buffer_pool_t *pool, const sbuf_t *buffer);

sbuf_t *__wrap_sbufDuplicateByPool(buffer_pool_t *pool, const sbuf_t *buffer)
{
    // The duplicate helper acquires from its own translation unit, bypassing
    // GNU --wrap on the individual pool getters. Record the new ownership here.
    return twfTrackAcquired(__real_sbufDuplicateByPool(pool, buffer));
}

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
    wid_t    wid;
    bool     checksum_requested;
} captured_packet_t;

typedef struct flow_fixture_s flow_fixture_t;

typedef struct flow_sink_s
{
    flow_fixture_t          *fixture;
    captured_packet_t        packets[kFlowPacketCapacity];
    const captured_packet_t *reenter_packet;
    uint32_t                 count;
    wid_t                    reenter_wid;
    char                     event;
    bool                     destructive;
    bool                     reenter_once;
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

static char     captured_log[2048];
static int      captured_log_level;
static uint32_t captured_log_count;

static void captureLog(int level, const char *text, int length)
{
    twfRequire(length > 0 && (size_t) length < sizeof(captured_log), "Ping diagnostic exceeds capture capacity");
    memoryCopy(captured_log, text, (size_t) length);
    captured_log[length] = '\0';
    captured_log_level   = level;
    ++captured_log_count;
}

static void resetDropLog(flow_fixture_t *fixture)
{
    captured_log[0]    = '\0';
    captured_log_count = 0;
    atomic_log_rate_limiter_t *limiter =
        fixture->server ? &((pingserver_tstate_t *) tunnelGetState(fixture->endpoint))->drop_log_limiter
                        : &((pingclient_tstate_t *) tunnelGetState(fixture->endpoint))->drop_log_limiter;
    atomicLogRateLimiterInitialize(limiter);
}

static void requireErrorLog(const char *reason)
{
    twfRequireEqualU32(captured_log_count, 1, "Ping rejection did not emit exactly one diagnostic");
    twfRequire(captured_log_level == LOG_LEVEL_ERROR, "Ping rejection diagnostic is not ERROR level");
    twfRequire(strstr(captured_log, reason) != NULL, "Ping diagnostic omitted the specific failure reason");
}

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

static bool endpointSendsReplies(const flow_fixture_t *fixture)
{
    if (fixture->server)
    {
        return ((const pingserver_tstate_t *) tunnelGetState(fixture->endpoint))->send_replies;
    }
    return ((const pingclient_tstate_t *) tunnelGetState(fixture->endpoint))->send_replies;
}

static ping_wire_config_t peerConfig(const flow_fixture_t *fixture)
{
    return (ping_wire_config_t) {
        .identifier = fixture->server ? kFlowClientIdentifier : kFlowServerIdentifier,
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

static void    sendInbound(flow_fixture_t *fixture, wid_t wid, sbuf_t *buf);
static sbuf_t *bufferFromCapture(line_t *line, const captured_packet_t *packet);

static void sinkPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    flow_sink_t *sink = tunnelGetState(t);
    twfRequire(sink->count < kFlowPacketCapacity, "Ping flow sink capacity exceeded");
    twfRequire(sbufGetLength(buf) <= kFlowPacketBytes, "Ping flow sink packet is too large");

    captured_packet_t *packet  = &sink->packets[sink->count++];
    packet->length             = sbufGetLength(buf);
    packet->wid                = lineGetWID(l);
    packet->checksum_requested = sbufGetRecalculateChecksum(buf);
    twfRequire(lineIsOnCurrentWorker(l), "Ping published on another worker's packet line");
    memoryCopy(packet->bytes, sbufGetRawPtr(buf), packet->length);

    twfRequire(sink->fixture->event_count + 1U < sizeof(sink->fixture->events), "Ping flow event trace overflow");
    sink->fixture->events[sink->fixture->event_count++] = sink->event;
    sink->fixture->events[sink->fixture->event_count]   = '\0';

    if (sink->reenter_once)
    {
        sink->reenter_once = false;
        sendInbound(sink->fixture,
                    sink->reenter_wid,
                    bufferFromCapture(sink->fixture->packet_lines[sink->reenter_wid], sink->reenter_packet));
    }

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
    memorySet(line->active_tunnels_mask, 0xFF, sizeof(line->active_tunnels_mask));
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

static cJSON *endpointSettings(bool server, const char *send_replies_json)
{
    const char *json =
        server ? "{\"identifier\":8738,\"sequence-start\":65535}" : "{\"identifier\":4369,\"sequence-start\":65535}";
    cJSON *settings = cJSON_Parse(json);
    twfRequire(settings != NULL, "failed to parse Ping flow settings");
    if (send_replies_json != NULL)
    {
        cJSON *send_replies = cJSON_Parse(send_replies_json);
        twfRequire(send_replies != NULL && cJSON_AddItemToObject(settings, "send-replies", send_replies),
                   "failed to add Ping reply setting");
    }
    return settings;
}

static void fixtureSetupWorkers(flow_fixture_t *fixture, bool server, const char *send_replies_json, wid_t workers)
{
    memoryZero(fixture, sizeof(*fixture));
    fixture->server = server;

    tosWorkerEnvSetup(&fixture->env, workers, 8192, kMaxAllowedPacketLength);
    for (wid_t wid = 0; wid < workers; ++wid)
    {
        bufferpoolUpdateAllocationPaddings(fixture->env.pools[wid],
                                           kPingWireEncapsulationOverhead,
                                           kPingWireEncapsulationOverhead,
                                           kPingWireEncapsulationOverhead,
                                           kPingWireEncapsulationOverhead);
    }

    fixture->settings                = endpointSettings(server, send_replies_json);
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

    fixture->chain = memoryAllocateZero(sizeof(tunnel_chain_t) + sizeof(generic_pool_t *) * workers);
    twfRequire(fixture->chain != NULL, "failed to allocate Ping flow chain");
    fixture->chain->workers_count = workers;
    fixture->chain->packet_lines  = fixture->packet_lines;
    fixture->endpoint->chain      = fixture->chain;
    for (wid_t wid = 0; wid < workers; ++wid)
    {
        fixture->packet_lines[wid] = createPacketLine(wid);
    }

    fixture->endpoint->onPrepare(fixture->endpoint);
    fixture->endpoint->onStart(fixture->endpoint);
    const ww_startup_result_t result = wwStartupContextEnd(&startup);
    twfRequire(wwStartupSucceeded(result), "Ping endpoint startup failed in flow fixture");
}

static void fixtureSetup(flow_fixture_t *fixture, bool server, const char *send_replies_json)
{
    fixtureSetupWorkers(fixture, server, send_replies_json, kFlowWorkers);
}

static void fixtureTeardown(flow_fixture_t *fixture)
{
    for (wid_t wid = 0; wid < fixture->env.count; ++wid)
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
    twfRequire(sbufGetWritableCapacity(buf) >= length, "test inner packet does not fit its buffer");
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
    twfRequire(sbufGetWritableCapacity(buf) >= packet->length, "captured Ping packet does not fit its buffer");
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

static captured_packet_t captureBuffer(const sbuf_t *buffer)
{
    captured_packet_t captured = {.length = sbufGetLength(buffer)};
    twfRequire(captured.length <= sizeof(captured.bytes), "Ping fixture capture exceeds storage");
    memoryCopy(captured.bytes, sbufGetRawPtr(buffer), captured.length);
    return captured;
}

static sbuf_t *makeTransportPacket(line_t *line, uint8_t protocol, wid_t target)
{
    sbuf_t  *buffer = makeInnerPacket(line, 64);
    uint8_t *packet = sbufGetMutablePtr(buffer);
    packet[9]       = protocol;
    memoryZero(packet + IP_HLEN, 20);
    PUT_BE16(packet + IP_HLEN + 2, 443);
    if (protocol == IP_PROTO_TCP)
    {
        packet[IP_HLEN + 12] = 0x50;
        packet[IP_HLEN + 13] = 0x18;
    }
    else
        PUT_BE16(packet + IP_HLEN + 4, 64 - IP_HLEN);
    wid_t selected = UINT8_MAX;
    for (unsigned port = 1; port <= UINT16_MAX; ++port)
    {
        PUT_BE16(packet + IP_HLEN, port);
        twfRequire(deviceFlowAffineWID(packet, sbufGetLength(buffer), &selected),
                   "transport fixture has no flow worker");
        if (selected == target)
            break;
    }
    twfRequire(selected == target && calcFullPacketChecksum(packet, sbufGetLength(buffer)),
               "failed to construct transport packet for the requested worker");
    return buffer;
}

static void wrapPeerRequest(flow_fixture_t *fixture, sbuf_t *buffer, uint16_t sequence)
{
    const ping_wire_config_t peer = peerConfig(fixture);
    twfRequire(pingwireBuildEchoRequest(buffer, &peer, sequence), "failed to wrap the transport fixture");
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
    sbufSetRecalculateChecksum(short_padding, true);
    sendLocal(fixture, 0, short_padding);

    sbuf_t *oversized = makeInnerPacket(line_a, kPingWireMaxInnerPacketLength + 1U);
    sbufSetRecalculateChecksum(oversized, true);
    sendLocal(fixture, 0, oversized);
    twfRequireEqualU32(atomicLoadRelaxed(nextSequence(fixture)),
                       sequence_before,
                       "rejected local packets consumed Ping request sequences");
    twfRequireEqualU32(localRequestSink(fixture)->count, 0, "rejected local packet escaped onto the wire");

    sendLocal(fixture, 0, makeInnerPacket(line_a, 84));
    flow_sink_t *wire = localRequestSink(fixture);
    twfRequireEqualU32(wire->count, 1, "first valid local request was not emitted");
    requireCapturedRequest(&wire->packets[0], endpointConfig(fixture).identifier, UINT16_MAX);
    twfRequire(! wire->packets[0].checksum_requested, "dropped request leaked into the next packet");

    sbuf_t        *reply       = replyFromRequest(fixture, line_b, &wire->packets[0]);
    ((struct ip_hdr *) sbufGetMutablePtr(reply))->src.addr  = ipv4Address("203.0.113.80");
    ((struct ip_hdr *) sbufGetMutablePtr(reply))->dest.addr = ipv4Address("203.0.113.90");
    twfRequire(calcIpv4HeaderChecksum(sbufGetMutablePtr(reply), sbufGetLength(reply)), "rewritten reply header failed");
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
    twfRequire(passed->wid == 3, "unmatched genuine ICMP was redistributed as decoded tunnel data");

    for (wid_t wid = 0; wid < kFlowWorkers; ++wid)
    {
        twfRequire(lineIsAlive(fixture->packet_lines[wid]), "Ping flow killed a worker packet line");
    }
}

static bool decodedOpaqueMatches(const captured_packet_t *decoded, const captured_packet_t *carrier)
{
    const uint16_t header = (uint16_t) ((carrier->bytes[0] & 15U) * 4U);
    const uint16_t total  = (uint16_t) (carrier->length - 9U);
    uint8_t        expected[kFlowPacketBytes];
    memoryCopy(expected, carrier->bytes, header);
    memoryCopy(expected + header, carrier->bytes + header + 8U, total - header);
    expected[9] = carrier->bytes[carrier->length - 1U];
    PUT_BE16(expected + 2, total);
    PUT_BE16(expected + 10, 0);
    uint32_t sum = 0;
    for (uint16_t i = 0; i < header; i += 2)
        sum += GET_BE16(expected + i);
    while (sum >> 16U)
        sum = (sum & 65535U) + (sum >> 16U);
    PUT_BE16(expected + 10, (uint16_t) ~sum);
    return decoded->length == total && memoryEqual(decoded->bytes, expected, total);
}

static void casePeerRequestReplay(flow_fixture_t *fixture)
{
    twfSetCase(fixture->server ? "PingServer cross-worker peer replay" : "PingClient cross-worker peer replay");
    resetSinks(fixture);

    ping_wire_reply_id_generator_t *reply_ids =
        fixture->server ? &((pingserver_tstate_t *) tunnelGetState(fixture->endpoint))->reply_ids
                        : &((pingclient_tstate_t *) tunnelGetState(fixture->endpoint))->reply_ids;
    const uint64_t cached_ms = UINT64_C(5000000000);
    atomicStoreU64Relaxed(&reply_ids->last_reply_ms, cached_ms - 1);
    fixture->env.loops[1]->cur_hrtime = cached_ms * 1000 + 789;
    /* Another worker may have an older cache; reply IDs must still advance. */
    fixture->env.loops[2]->cur_hrtime = (cached_ms - 100) * 1000;

    sbuf_t           *request = peerRequest(fixture, fixture->packet_lines[1], 77);
    captured_packet_t wire_request;
    wire_request.length = sbufGetLength(request);
    memoryCopy(wire_request.bytes, sbufGetRawPtr(request), wire_request.length);

    const bool send_replies = endpointSendsReplies(fixture);
    sendInbound(fixture, 1, request);
    twfRequire(atomicLoadU64Relaxed(&reply_ids->last_reply_ms) == (send_replies ? cached_ms : cached_ms - 1),
               "reply idle timing did not use the packet line's cached owner clock");
    const char *first_order = send_replies ? (fixture->server ? "PN" : "NP") : (fixture->server ? "N" : "P");
    twfRequireEqualText(fixture->events, first_order, "peer request reply/delivery callback order is wrong");
    twfRequireEqualU32(generatedReplySink(fixture)->count,
                       send_replies ? 1U : 0U,
                       "peer request reply emission did not honor send-replies");
    twfRequireEqualU32(decodedInnerSink(fixture)->count, 1, "peer request did not deliver one inner packet");
    const captured_packet_t *decoded = &decodedInnerSink(fixture)->packets[0];
    twfRequire(decoded->wid == 1 && decoded->length == wire_request.length - kPingWireEncapsulationOverhead &&
                   decodedOpaqueMatches(decoded, &wire_request),
               "opaque peer request did not preserve its arrival worker and complete inner packet");

    sendInbound(fixture, 2, bufferFromCapture(fixture->packet_lines[2], &wire_request));
    twfRequire(atomicLoadU64Relaxed(&reply_ids->last_reply_ms) == (send_replies ? cached_ms : cached_ms - 1),
               "older worker cache moved shared reply time backwards");
    const char *duplicate_order = send_replies ? (fixture->server ? "PNP" : "NPN") : (fixture->server ? "N" : "P");
    twfRequireEqualText(fixture->events, duplicate_order, "duplicate request callback direction is wrong");
    twfRequireEqualU32(generatedReplySink(fixture)->count,
                       send_replies ? 2U : 0U,
                       "duplicate request reply emission did not honor send-replies");
    twfRequireEqualU32(decodedInnerSink(fixture)->count, 1, "duplicate request delivered its inner packet twice");

    if (send_replies)
    {
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
    wloopUpdateTime(fixture->env.loops[1]);
    wloopUpdateTime(fixture->env.loops[2]);
}

static void caseDecodedTransportArrivalWorker(flow_fixture_t *fixture)
{
    twfSetCase(fixture->server ? "PingServer decoded transport arrival worker"
                               : "PingClient decoded transport arrival worker");
    const wid_t   target      = fixture->env.count == 1 ? 0 : 2;
    const wid_t   arrivals[]  = {0, (wid_t) (fixture->env.count - 1)};
    const uint8_t protocols[] = {IP_PROTO_TCP, IP_PROTO_UDP};
    for (unsigned protocol = 0; protocol < ARRAY_SIZE(protocols); ++protocol)
    {
        resetSinks(fixture);
        captured_packet_t expected      = {0};
        captured_packet_t first_request = {0};
        for (unsigned i = 0; i < ARRAY_SIZE(arrivals); ++i)
        {
            sbuf_t *request = makeTransportPacket(fixture->packet_lines[arrivals[i]], protocols[protocol], target);
            expected        = captureBuffer(request);
            wrapPeerRequest(fixture, request, (uint16_t) (1000 + protocol * 4 + i));
            if (i == 0)
                first_request = captureBuffer(request);
            sendInbound(fixture, arrivals[i], request);
            twfRequireEqualU32(generatedReplySink(fixture)->count,
                               endpointSendsReplies(fixture) ? i + 1 : 0,
                               "decoded forwarding delayed or duplicated the outer Echo Reply");
            if (endpointSendsReplies(fixture))
                twfRequire(generatedReplySink(fixture)->packets[i].wid == arrivals[i],
                           "outer Echo Reply left the arrival worker");
            twfRequireEqualU32(decodedInnerSink(fixture)->count,
                               i + 1,
                               "decoded packet left its arrival worker or deferred direct forwarding");
        }
        // Replay detection is shared across workers even though each decoded
        // packet was delivered directly on its own arrival worker.
        sendInbound(fixture, arrivals[1], bufferFromCapture(fixture->packet_lines[arrivals[1]], &first_request));
        tosPumpWorker(&fixture->env, target);
        flow_sink_t *decoded = decodedInnerSink(fixture);
        twfRequireEqualU32(decoded->count, 2, "cross-worker replay duplicated or lost a decoded transport packet");
        for (unsigned i = 0; i < decoded->count; ++i)
            twfRequire(decoded->packets[i].wid == arrivals[i] && ! decoded->packets[i].checksum_requested &&
                           decoded->packets[i].length == expected.length &&
                           memoryEqual(decoded->packets[i].bytes, expected.bytes, expected.length),
                       "decoded transport changed worker, checksum state or packet bytes");
    }
}

static void caseDecodedFragmentArrivalWorker(flow_fixture_t *fixture)
{
    twfSetCase("fragment rejection before native parsing, repair and sequence admission");
    resetSinks(fixture);
    const unsigned before      = atomicLoadRelaxed(nextSequence(fixture));
    const uint16_t fragments[] = {IP_MF, 1, (uint16_t) (IP_MF | 2)};
    for (unsigned repair = 0; repair < 2; ++repair)
        for (size_t i = 0; i < ARRAY_SIZE(fragments); ++i)
        {
            sbuf_t *native = makeInnerPacket(fixture->packet_lines[0], 21);
            PUT_BE16(sbufGetMutablePtr(native) + 6, fragments[i]);
            sbufGetMutablePtr(native)[9] = IP_PROTO_TCP;
            sbufSetRecalculateChecksum(native, repair != 0);
            sendLocal(fixture, 0, native);
            sbuf_t *carrier = peerRequest(fixture, fixture->packet_lines[3], (uint16_t) (2000 + i));
            PUT_BE16(sbufGetMutablePtr(carrier) + 6, fragments[i]);
            sbufSetRecalculateChecksum(carrier, repair != 0);
            sendInbound(fixture, 3, carrier);
        }
    twfRequireEqualU32(atomicLoadRelaxed(nextSequence(fixture)), before, "fragments reserved sequences");
    twfRequireEqualU32(fixture->prev_sink->count + fixture->next_sink->count, 0, "fragment escaped to a neighbor");
    sbuf_t                 *whole    = makeTransportPacket(fixture->packet_lines[0], IP_PROTO_UDP, 2);
    const captured_packet_t expected = captureBuffer(whole);
    wrapPeerRequest(fixture, whole, 2002);
    sendInbound(fixture, 1, whole);
    const captured_packet_t *decoded = &decodedInnerSink(fixture)->packets[0];
    twfRequire(decoded->wid == 1 && decoded->length == expected.length &&
                   memoryEqual(decoded->bytes, expected.bytes, expected.length),
               "complete packet following fragments lost");
}

static void caseForeignWorkerAdmissionIrrelevant(flow_fixture_t *fixture)
{
    twfSetCase(fixture->server ? "PingServer unrelated worker admission" : "PingClient unrelated worker admission");
    resetSinks(fixture);
    sbuf_t *request = makeTransportPacket(fixture->packet_lines[0], IP_PROTO_TCP, 2);
    wrapPeerRequest(fixture, request, 3000);
    const unsigned references = atomicLoadRelaxed(&fixture->packet_lines[2]->refc);
    workerMessagesCloseAdmission(&fixture->env.workers[2]);
    sendInbound(fixture, 0, request);
    tosPumpWorker(&fixture->env, 2);
    twfRequireEqualU32(decodedInnerSink(fixture)->count, 1, "unrelated worker admission blocked decoded delivery");
    twfRequire(decodedInnerSink(fixture)->packets[0].wid == 0, "decoder used the unrelated flow-hash worker");
    twfRequireEqualU32(atomicLoadRelaxed(&fixture->packet_lines[2]->refc),
                       references,
                       "decoded delivery borrowed an unrelated worker packet-line reference");
    twfRequire(workerMessagesOpenAdmission(&fixture->env.workers[2]), "could not reopen test worker admission");
}

static void caseUnrelatedIpv4Options(flow_fixture_t *fixture)
{
    twfSetCase(fixture->server ? "PingServer unrelated IPv4 options" : "PingClient unrelated IPv4 options");
    resetSinks(fixture);

    line_t                  *line   = fixture->packet_lines[1];
    sbuf_t                  *packet = makeInnerPacket(line, 96);
    struct ip_hdr           *ip     = (struct ip_hdr *) sbufGetMutablePtr(packet);
    IPH_VHL_SET(ip, 4, 6);
    ip->src.addr  = ipv4Address("198.51.100.10");
    ip->dest.addr = ipv4Address("192.0.2.10");
    memoryZero(sbufGetMutablePtr(packet) + IP_HLEN, 4);
    twfRequire(calcFullPacketChecksum(sbufGetMutablePtr(packet), sbufGetLength(packet)),
               "unrelated IPv4 options checksum build failed");

    sbufSetRecalculateChecksum(packet, true);
    captured_packet_t expected;
    expected.length = sbufGetLength(packet);
    memoryCopy(expected.bytes, sbufGetRawPtr(packet), expected.length);
    sendInbound(fixture, 1, packet);

    twfRequireEqualU32(generatedReplySink(fixture)->count, 0, "unrelated IPv4 packet produced an Echo Reply");
    twfRequireEqualU32(decodedInnerSink(fixture)->count, 1, "unrelated IPv4 options packet was not forwarded");
    const captured_packet_t *forwarded = &decodedInnerSink(fixture)->packets[0];
    twfRequire(forwarded->length == expected.length && memoryEqual(forwarded->bytes, expected.bytes, expected.length),
               "unrelated IPv4 options packet did not pass through unchanged");
    twfRequire(forwarded->checksum_requested, "unrelated packet lost repair intent");
}

static void caseUnmatchedReplyPayloads(flow_fixture_t *fixture)
{
    twfSetCase("valid unmatched Echo Replies preserve arbitrary payloads without native parsing");
    resetSinks(fixture);
    const ping_wire_config_t peer = peerConfig(fixture);
    discard                  peer;
    for (unsigned length = 0; length < 3; ++length)
    {
        sbuf_t *packet = peerRequest(fixture, fixture->packet_lines[3], (uint16_t) (60000 + length));
        sbufSetLength(packet, IP_HLEN + 8U + length);
        uint8_t *bytes = sbufGetMutablePtr(packet);
        PUT_BE16(bytes + 2, (uint16_t) sbufGetLength(packet));
        bytes[IP_HLEN] = 0;
        if (length)
            bytes[IP_HLEN + 8U + length - 1U] = IP_PROTO_TCP; /* deliberately too short for native TCP */
        twfRequire(pingwireRecalculateCarrierChecksums(packet), "unmatched reply checksum setup failed");
        const captured_packet_t expected = captureBuffer(packet);
        sendInbound(fixture, 3, packet);
        const captured_packet_t *forwarded = &unmatchedReplySink(fixture)->packets[length];
        twfRequire(forwarded->wid == 3 && forwarded->length == expected.length &&
                       memoryEqual(forwarded->bytes, expected.bytes, expected.length),
                   "unmatched reply changed or decoded");
    }
    twfRequireEqualU32(unmatchedReplySink(fixture)->count, 3, "unmatched reply lost");
    twfRequireEqualU32(generatedReplySink(fixture)->count, 0, "reply caused another reply");
}

static void caseChecksumRequestBoundaries(flow_fixture_t *fixture)
{
    twfSetCase(fixture->server ? "PingServer packet-local checksum boundaries"
                               : "PingClient packet-local checksum boundaries");
    resetSinks(fixture);
    line_t *line = fixture->packet_lines[0];

    sbuf_t *inner = makeInnerPacket(line, 84);
    sbufGetMutablePtr(inner)[8] ^= 1U;
    sbufSetRecalculateChecksum(inner, true);
    sendLocal(fixture, 0, inner);
    const captured_packet_t *outer = &localRequestSink(fixture)->packets[0];
    twfRequireEqualU32(localRequestSink(fixture)->count, 1, "marked inner packet was not encapsulated");
    twfRequire(! outer->checksum_requested, "inner request survived encapsulation");
    twfRequire(inet_chksum(outer->bytes, IP_HLEN) == 0, "inner checksum was not repaired before encapsulation");
    ping_wire_envelope_t     envelope = {0};
    const ping_wire_config_t peer     = peerConfig(fixture);
    twfRequire(pingwireParseInbound(outer->bytes, outer->length, &peer, &envelope) == kPingWireInboundEchoRequest,
               "inner repair changed the generated outer checksums");

    resetSinks(fixture);
    sbuf_t           *request  = peerRequest(fixture, line, 32000);
    captured_packet_t expected = captureBuffer(request);
    expected.bytes[8] ^= 1U;
    sbufGetMutablePtr(request)[8] ^= 1U;
    sbufSetRecalculateChecksum(request, true);
    sendInbound(fixture, 0, request);
    twfRequireEqualU32(decodedInnerSink(fixture)->count, 1, "marked outer packet was not repaired before validation");
    const captured_packet_t *decoded = &decodedInnerSink(fixture)->packets[0];
    twfRequire(! decoded->checksum_requested && decoded->length == expected.length - kPingWireEncapsulationOverhead &&
                   decodedOpaqueMatches(decoded, &expected),
               "outer repair request leaked into or changed the decoded inner packet");
    if (endpointSendsReplies(fixture))
    {
        twfRequireEqualU32(generatedReplySink(fixture)->count, 1, "marked request lost its generated reply");
        const captured_packet_t *reply = &generatedReplySink(fixture)->packets[0];
        twfRequire(! reply->checksum_requested &&
                       pingwireParseInbound(reply->bytes, reply->length, &peer, &envelope) == kPingWireInboundEchoReply,
                   "generated reply inherited intent or has invalid checksums");
    }
}

static void casePacketDiagnostics(flow_fixture_t *fixture)
{
    twfSetCase(fixture->server ? "PingServer packet diagnostics" : "PingClient packet diagnostics");
    resetSinks(fixture);
    line_t            *line            = fixture->packet_lines[0];
    const unsigned int sequence_before = atomicLoadRelaxed(nextSequence(fixture));

    resetDropLog(fixture);
    sbuf_t *oversized = makeInnerPacket(line, kPingWireMaxInnerPacketLength + 1U);
    sbufSetRecalculateChecksum(oversized, true);
    sendLocal(fixture, 0, oversized);
    requireErrorLog("native IPv4 packet exceeds the 1491-byte limit");
    twfRequire(
        strstr(captured_log, "packet-bytes=1492") != NULL && strstr(captured_log, "max-inner-bytes=1491") != NULL &&
            strstr(captured_log, "overhead-bytes=9") != NULL && strstr(captured_log, "max-carrier-bytes=1500") != NULL,
        "oversize diagnostic omitted sizing parameters");
    /* The existing shared five-second gate suppresses immediate repeat errors. */
    sendLocal(fixture, 0, makeInnerPacket(line, kPingWireMaxInnerPacketLength + 1U));
    twfRequireEqualU32(captured_log_count, 1, "Ping packet diagnostics lost their rate limit");

    resetDropLog(fixture);
    sbuf_t *short_headroom = sbufCreateWithPadding(72, 0);
    sbuf_t *source         = makeInnerPacket(line, 72);
    sbufSetLength(short_headroom, 72);
    memoryCopy(sbufGetMutablePtr(short_headroom), sbufGetRawPtr(source), 72);
    lineReuseBuffer(line, source);
    sendLocal(fixture, 0, short_headroom);
    requireErrorLog("insufficient left headroom for Echo header and final protocol byte");
    twfRequire(strstr(captured_log, "headroom-bytes=0") != NULL &&
                   strstr(captured_log, "required-headroom-bytes=9") != NULL,
               "headroom diagnostic omitted available/required sizing");

    resetDropLog(fixture);
    sbuf_t *malformed = makeInnerPacket(line, 72);
    IPH_LEN_SET((struct ip_hdr *) sbufGetMutablePtr(malformed), lwip_htons(71));
    sbufSetRecalculateChecksum(malformed, true);
    sendLocal(fixture, 0, malformed);
    requireErrorLog("IPv4 declared total length does not match received bytes");

    resetDropLog(fixture);
    sbuf_t *bad_ipv4 = peerRequest(fixture, line, 110);
    sbufGetMutablePtr(bad_ipv4)[8] ^= 1U;
    sendInbound(fixture, 0, bad_ipv4);
    requireErrorLog("invalid carrier IPv4 checksum");

    resetDropLog(fixture);
    sbuf_t *bad_icmp = peerRequest(fixture, line, 111);
    sbufGetMutablePtr(bad_icmp)[IP_HLEN + 8U] ^= 1U;
    sendInbound(fixture, 0, bad_icmp);
    requireErrorLog("invalid Echo carrier checksum");

    resetDropLog(fixture);
    sbuf_t *fragment = peerRequest(fixture, line, 112);
    IPH_OFFSET_SET((struct ip_hdr *) sbufGetMutablePtr(fragment), lwip_htons(IP_MF));
    twfRequire(calcIpv4HeaderChecksum(sbufGetMutablePtr(fragment), sbufGetLength(fragment)),
               "fragment diagnostic fixture checksum failed");
    sendInbound(fixture, 0, fragment);
    requireErrorLog("fragmented IPv4 datagram requires adapter reassembly before Ping");

    resetDropLog(fixture);
    sbuf_t *bad_code                                                         = peerRequest(fixture, line, 113);
    ((struct icmp_echo_hdr *) (sbufGetMutablePtr(bad_code) + IP_HLEN))->code = 1;
    twfRequire(calcFullPacketChecksum(sbufGetMutablePtr(bad_code), sbufGetLength(bad_code)),
               "ICMP code diagnostic fixture checksum failed");
    sendInbound(fixture, 0, bad_code);
    requireErrorLog("unsupported Echo code");

    resetDropLog(fixture);
    sbuf_t *bad_type                                                         = peerRequest(fixture, line, 114);
    ((struct icmp_echo_hdr *) (sbufGetMutablePtr(bad_type) + IP_HLEN))->type = ICMP_DUR;
    twfRequire(calcFullPacketChecksum(sbufGetMutablePtr(bad_type), sbufGetLength(bad_type)),
               "ICMP type diagnostic fixture checksum failed");
    sendInbound(fixture, 0, bad_type);
    requireErrorLog("unsupported carrier type");

    resetDropLog(fixture);
    sbuf_t *bad_inner                                            = peerRequest(fixture, line, 115);
    sbufGetMutablePtr(bad_inner)[sbufGetLength(bad_inner) - 1U]  = IP_PROTO_TCP;
    sbufGetMutablePtr(bad_inner)[IP_HLEN + 8U + 12U]             = 0;
    twfRequire(calcFullPacketChecksum(sbufGetMutablePtr(bad_inner), sbufGetLength(bad_inner)),
               "inner IPv4 diagnostic fixture checksum failed");
    sendInbound(fixture, 0, bad_inner);
    requireErrorLog("Echo Request has invalid native TCP, UDP, or ICMP geometry");

    twfRequireEqualU32(atomicLoadRelaxed(nextSequence(fixture)),
                       sequence_before,
                       "rejected diagnostic packets consumed sequence numbers");
    twfRequireEqualU32(
        fixture->prev_sink->count + fixture->next_sink->count, 0, "rejected diagnostic packet escaped to a neighbor");
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

static void caseGeneratedReplySuccessfulReentry(flow_fixture_t *fixture)
{
    twfSetCase(fixture->server ? "PingServer generated-reply successful reentry"
                               : "PingClient generated-reply successful reentry");
    resetSinks(fixture);

    sbuf_t           *request    = peerRequest(fixture, fixture->packet_lines[0], 91);
    captured_packet_t captured   = captureBuffer(request);
    const unsigned    references = atomicLoadRelaxed(&fixture->packet_lines[0]->refc);
    flow_sink_t      *reply_sink = generatedReplySink(fixture);
    reply_sink->reenter_packet   = &captured;
    reply_sink->reenter_wid      = 0;
    reply_sink->reenter_once     = true;

    sendInbound(fixture, 0, request);

    twfRequireEqualU32(reply_sink->count, 2, "nested duplicate request did not produce the second optional reply");
    twfRequireEqualU32(decodedInnerSink(fixture)->count, 1, "reentry changed one-time inner delivery");
    twfRequire(lineIsAlive(fixture->packet_lines[0]), "successful reentry killed the worker packet line");
    twfRequireEqualU32(atomicLoadRelaxed(&fixture->packet_lines[0]->refc),
                       references,
                       "successful reentry leaked a packet-line reference");

    const ping_wire_config_t peer = peerConfig(fixture);
    for (uint32_t i = 0; i < reply_sink->count; ++i)
    {
        ping_wire_envelope_t reply = {0};
        twfRequire(pingwireParseInbound(reply_sink->packets[i].bytes, reply_sink->packets[i].length, &peer, &reply) ==
                       kPingWireInboundEchoReply,
                   "reentry emitted an invalid Echo Reply");
        twfRequire(reply.icmp_payload_length == captured.length - IP_HLEN - 8U &&
                       memoryEqual(reply.icmp_payload, captured.bytes + IP_HLEN + 8U, reply.icmp_payload_length),
                   "reentry changed the mirrored inner packet");
    }
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

static void caseInvalidReplySettings(bool server)
{
    twfSetCase(server ? "PingServer invalid send-replies settings" : "PingClient invalid send-replies settings");
    static const char *const invalid_values[] = {"null", "0", "1", "\"true\"", "[]", "{}"};
    for (size_t i = 0; i < ARRAY_SIZE(invalid_values); ++i)
    {
        cJSON    *settings = endpointSettings(server, invalid_values[i]);
        node_t    node     = {.node_settings_json = settings};
        tunnel_t *endpoint = server ? pingserverCreate(&node) : pingclientCreate(&node);
        twfRequire(endpoint == NULL, "Ping accepted a nonboolean send-replies setting");
        cJSON_Delete(settings);
    }
}

#ifdef PING_IPOVERRIDER_FIXTURE
static uint16_t nativeResidual(const uint8_t *packet, size_t total, uint8_t protocol)
{
    const size_t header = (packet[0] & 15U) * 4U;
    const size_t length = protocol == IP_PROTO_UDP ? GET_BE16(packet + header + 4) : total - header;
    uint32_t     sum    = (uint32_t) length + protocol;
    for (size_t i = 12; i < 20; i += 2)
        sum += GET_BE16(packet + i);
    for (size_t i = 0; i + 1 < length; i += 2)
        sum += GET_BE16(packet + header + i);
    if (length & 1U)
        sum += (uint32_t) packet[header + length - 1U] << 8U;
    while (sum >> 16U)
        sum = (sum & 65535U) + (sum >> 16U);
    return (uint16_t) ~sum;
}

static void caseIpOverriderComposition(flow_fixture_t *fixture)
{
    twfSetCase("real IpOverrider rewrites encoded TCP/UDP addresses");
    tunnel_t *overrider = tunnelCreate(NULL, sizeof(ipoverrider_tstate_t), 0);
    twfRequire(overrider != NULL, "IpOverrider composition allocation failed");
    ipoverrider_tstate_t *state                                            = tunnelGetState(overrider);
    state->chance                                                          = 100;
    state->rules[kIpOverriderDirectionUp][kIpOverriderModeSource].support4 = true;
    state->rules[kIpOverriderDirectionUp][kIpOverriderModeSource].ov_4     = ipv4Address("203.0.113.10");
    state->rules[kIpOverriderDirectionUp][kIpOverriderModeDest].support4   = true;
    state->rules[kIpOverriderDirectionUp][kIpOverriderModeDest].ov_4       = ipv4Address("198.51.100.80");
    overrider->next                                                        = fixture->next;
    for (unsigned proto = 0; proto < 2; ++proto)
        for (unsigned mode = 0; mode < 3; ++mode)
        {
            resetSinks(fixture);
            const uint8_t protocol = proto ? IP_PROTO_UDP : IP_PROTO_TCP;
            sbuf_t       *packet   = makeTransportPacket(fixture->packet_lines[0], protocol, 2);
            uint8_t      *bytes    = sbufGetMutablePtr(packet);
            if (mode == 1)
                bytes[sbufGetLength(packet) - 1U] ^= 0x80;
            if (mode == 2 && proto)
                PUT_BE16(bytes + IP_HLEN + 6, 0);
            const uint16_t residual = nativeResidual(bytes, sbufGetLength(packet), protocol);
            wrapPeerRequest(fixture, packet, (uint16_t) (45000 + proto * 3 + mode));
            ipoverriderApplyUpStreamPayload(overrider, fixture->packet_lines[0], packet);
            twfRequireEqualU32(fixture->next_sink->count, 1, "IpOverrider failed to forward carrier");
            const captured_packet_t carrier = fixture->next_sink->packets[0];
            resetSinks(fixture);
            sendInbound(fixture, 0, bufferFromCapture(fixture->packet_lines[0], &carrier));
            twfRequireEqualU32(decodedInnerSink(fixture)->count, 1, "rewritten carrier failed native delivery");
            const captured_packet_t *decoded = &decodedInnerSink(fixture)->packets[0];
            twfRequire(memoryEqual(decoded->bytes + 12, carrier.bytes + 12, 8),
                       "native addresses differ from final chain policy");
            if (mode == 2 && proto)
                twfRequire(GET_BE16(decoded->bytes + IP_HLEN + 6) == 0, "IpOverrider enabled disabled UDP checksum");
            else
                twfRequire(nativeResidual(decoded->bytes, decoded->length, protocol) == residual,
                           "IpOverrider composition lost native checksum residual");
        }
    tunnelDestroy(overrider);
}
#endif

static void caseRemovedSettingsAndDefaults(bool server)
{
    const char *documents[] = {NULL, "{}"};
    for (size_t i = 0; i < ARRAY_SIZE(documents); ++i)
    {
        cJSON    *settings = documents[i] != NULL ? cJSON_Parse(documents[i]) : NULL;
        node_t    node     = {.node_settings_json = settings};
        tunnel_t *endpoint = server ? pingserverCreate(&node) : pingclientCreate(&node);
        twfRequire(endpoint != NULL && endpoint->lstate_size == 0, "omitted/empty settings rejected");
        endpoint->onDestroy(endpoint, wwLifecycleStartupRollback());
        cJSON_Delete(settings);
    }
    const char *removed[] = {"local-ipv4", "peer-ipv4", "ttl", "tos"};
    for (size_t i = 0; i < ARRAY_SIZE(removed); ++i)
    {
        cJSON *settings = cJSON_CreateObject();
        cJSON_AddItemToObject(settings, removed[i], cJSON_CreateInt64(1));
        node_t    node     = {.node_settings_json = settings};
        tunnel_t *endpoint = server ? pingserverCreate(&node) : pingclientCreate(&node);
        twfRequire(endpoint == NULL, "removed setting accepted");
        cJSON_Delete(settings);
    }
    const char *keys[]    = {"identifier", "sequence-start"};
    const char *invalid[] = {"-1", "65536", "1.5", "null", "true", "\"invalid\""};
    for (size_t k = 0; k < ARRAY_SIZE(keys); ++k)
        for (size_t v = 0; v < ARRAY_SIZE(invalid); ++v)
        {
            cJSON *settings = cJSON_CreateObject();
            cJSON_AddItemToObject(settings, keys[k], cJSON_Parse(invalid[v]));
            node_t    node     = {.node_settings_json = settings};
            tunnel_t *endpoint = server ? pingserverCreate(&node) : pingclientCreate(&node);
            twfRequire(endpoint == NULL, "invalid numeric field accepted");
            cJSON_Delete(settings);
        }
}

static void runEndpointCases(bool server, const char *send_replies_json)
{
    flow_fixture_t fixture;
    fixtureSetup(&fixture, server, send_replies_json);
    const bool expected_replies = send_replies_json != NULL && stringCompare(send_replies_json, "true") == 0;
    twfRequire(endpointSendsReplies(&fixture) == expected_replies,
               "Ping send-replies configuration did not retain its boolean value or default");
    casePacketDiagnostics(&fixture);
    caseCrossWorkerCorrelationAndSequence(&fixture);
    caseUnrelatedIpv4Options(&fixture);
    caseUnmatchedReplyPayloads(&fixture);
    caseChecksumRequestBoundaries(&fixture);
    casePeerRequestReplay(&fixture);
#ifdef PING_IPOVERRIDER_FIXTURE
    caseIpOverriderComposition(&fixture);
#endif
    caseDecodedTransportArrivalWorker(&fixture);
    caseDecodedFragmentArrivalWorker(&fixture);
    caseForeignWorkerAdmissionIrrelevant(&fixture);
    if (expected_replies)
    {
        caseGeneratedReplySuccessfulReentry(&fixture);
        caseGeneratedReplyLineSurvivalGuard(&fixture);
    }
    fixtureTeardown(&fixture);
}

int main(void)
{
    initWLibc();
    checkSumInit();
    logger_t *logger = loggerCreate();
    twfRequire(logger != NULL, "failed to create Ping diagnostic logger");
    loggerSetHandler(logger, captureLog);
    loggerSetLevel(logger, LOG_LEVEL_ERROR);
    setNetworkLogger(logger);
    twfRequire(globalstateInitializeSecureRandom(), "secure-random initialization failed");
    twfRequire(frandGlobalInit(), "fast-random global initialization failed");
    frandInit();
    twfRequire(wCryptoGlobalInit() == kWCryptoOk, "crypto initialization failed");

    for (unsigned int server = 0; server < 2; ++server)
    {
        caseRemovedSettingsAndDefaults(server != 0);
        caseInvalidReplySettings(server != 0);
        runEndpointCases(server != 0, NULL);
        runEndpointCases(server != 0, "false");
        runEndpointCases(server != 0, "true");
        flow_fixture_t single;
        fixtureSetupWorkers(&single, server != 0, "true", 1);
        caseDecodedTransportArrivalWorker(&single);
        fixtureTeardown(&single);
    }

    wCryptoGlobalCleanup();
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    networkloggerDestroy();
    puts("ping_flow_test: all cases passed");
    return 0;
}
