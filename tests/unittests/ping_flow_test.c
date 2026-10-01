#include "loggers/network_logger.h"

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

static cJSON *endpointSettings(bool server, const char *send_replies_json)
{
    const char *json     = server ? "{\"local-ipv4\":\"198.51.100.10\",\"peer-ipv4\":\"192.0.2.10\","
                                    "\"identifier\":8738,\"sequence-start\":65535,\"ttl\":64,\"tos\":3}"
                                  : "{\"local-ipv4\":\"192.0.2.10\",\"peer-ipv4\":\"198.51.100.10\","
                                    "\"identifier\":4369,\"sequence-start\":65535,\"ttl\":64,\"tos\":3}";
    cJSON      *settings = cJSON_Parse(json);
    twfRequire(settings != NULL, "failed to parse Ping flow settings");
    if (send_replies_json != NULL)
    {
        cJSON *send_replies = cJSON_Parse(send_replies_json);
        twfRequire(send_replies != NULL && cJSON_AddItemToObject(settings, "send-replies", send_replies),
                   "failed to add Ping reply setting");
    }
    return settings;
}

static void fixtureSetup(flow_fixture_t *fixture, bool server, const char *send_replies_json)
{
    memoryZero(fixture, sizeof(*fixture));
    fixture->server = server;

    tosWorkerEnvSetup(&fixture->env, kFlowWorkers, 8192, kMaxAllowedPacketLength);
    for (wid_t wid = 0; wid < kFlowWorkers; ++wid)
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
    twfRequire(decoded->length == wire_request.length - kPingWireEncapsulationOverhead &&
                   memoryEqual(decoded->bytes, wire_request.bytes + kPingWireEncapsulationOverhead, decoded->length),
               "peer request did not preserve the complete inner packet");

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

static void caseUnrelatedIpv4Options(flow_fixture_t *fixture)
{
    twfSetCase(fixture->server ? "PingServer unrelated IPv4 options" : "PingClient unrelated IPv4 options");
    resetSinks(fixture);

    line_t                  *line   = fixture->packet_lines[1];
    sbuf_t                  *packet = makeInnerPacket(line, 96);
    struct ip_hdr           *ip     = (struct ip_hdr *) sbufGetMutablePtr(packet);
    const ping_wire_config_t config = endpointConfig(fixture);
    IPH_VHL_SET(ip, 4, 6);
    ip->src.addr  = config.peer_ipv4;
    ip->dest.addr = config.local_ipv4;
    memoryZero(sbufGetMutablePtr(packet) + IP_HLEN, 4);
    twfRequire(calcFullPacketChecksum(sbufGetMutablePtr(packet), sbufGetLength(packet)),
               "unrelated IPv4 options checksum build failed");

    captured_packet_t expected;
    expected.length = sbufGetLength(packet);
    memoryCopy(expected.bytes, sbufGetRawPtr(packet), expected.length);
    sendInbound(fixture, 1, packet);

    twfRequireEqualU32(generatedReplySink(fixture)->count, 0, "unrelated IPv4 packet produced an Echo Reply");
    twfRequireEqualU32(decodedInnerSink(fixture)->count, 1, "unrelated IPv4 options packet was not forwarded");
    const captured_packet_t *forwarded = &decodedInnerSink(fixture)->packets[0];
    twfRequire(forwarded->length == expected.length && memoryEqual(forwarded->bytes, expected.bytes, expected.length),
               "unrelated IPv4 options packet did not pass through unchanged");
}

static void casePacketDiagnostics(flow_fixture_t *fixture)
{
    twfSetCase(fixture->server ? "PingServer packet diagnostics" : "PingClient packet diagnostics");
    resetSinks(fixture);
    line_t            *line            = fixture->packet_lines[0];
    const unsigned int sequence_before = atomicLoadRelaxed(nextSequence(fixture));

    resetDropLog(fixture);
    lineSetRecalculateChecksum(line, true);
    sendLocal(fixture, 0, makeInnerPacket(line, kPingWireMaxInnerPacketLength + 1U));
    requireErrorLog("IPv4 packet exceeds maximum inner size");
    twfRequire(
        strstr(captured_log, "packet-bytes=1473") != NULL && strstr(captured_log, "max-inner-bytes=1472") != NULL &&
            strstr(captured_log, "overhead-bytes=28") != NULL && strstr(captured_log, "max-carrier-bytes=1500") != NULL,
        "oversize diagnostic omitted sizing parameters");
    twfRequire(! lineGetRecalculateChecksum(line), "oversize diagnostic leaked checksum scratch state");
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
    requireErrorLog("insufficient left headroom to prepend IPv4/ICMP headers");
    twfRequire(strstr(captured_log, "headroom-bytes=0") != NULL &&
                   strstr(captured_log, "required-headroom-bytes=28") != NULL,
               "headroom diagnostic omitted available/required sizing");

    resetDropLog(fixture);
    sbuf_t *malformed = makeInnerPacket(line, 72);
    IPH_LEN_SET((struct ip_hdr *) sbufGetMutablePtr(malformed), lwip_htons(71));
    lineSetRecalculateChecksum(line, true);
    sendLocal(fixture, 0, malformed);
    requireErrorLog("IPv4 declared total length does not match received bytes");
    twfRequire(! lineGetRecalculateChecksum(line), "malformed diagnostic leaked checksum scratch state");

    resetDropLog(fixture);
    sbuf_t *bad_ipv4 = peerRequest(fixture, line, 110);
    sbufGetMutablePtr(bad_ipv4)[8] ^= 1U;
    sendInbound(fixture, 0, bad_ipv4);
    requireErrorLog("invalid outer IPv4 checksum");

    resetDropLog(fixture);
    sbuf_t *bad_icmp = peerRequest(fixture, line, 111);
    sbufGetMutablePtr(bad_icmp)[kPingWireEncapsulationOverhead] ^= 1U;
    sendInbound(fixture, 0, bad_icmp);
    requireErrorLog("invalid ICMP checksum");

    resetDropLog(fixture);
    sbuf_t *fragment = peerRequest(fixture, line, 112);
    IPH_OFFSET_SET((struct ip_hdr *) sbufGetMutablePtr(fragment), lwip_htons(IP_MF));
    twfRequire(calcIpv4HeaderChecksum(sbufGetMutablePtr(fragment), sbufGetLength(fragment)),
               "fragment diagnostic fixture checksum failed");
    sendInbound(fixture, 0, fragment);
    requireErrorLog("fragmented outer IPv4 Echo carrier");

    resetDropLog(fixture);
    sbuf_t *bad_code                                                         = peerRequest(fixture, line, 113);
    ((struct icmp_echo_hdr *) (sbufGetMutablePtr(bad_code) + IP_HLEN))->code = 1;
    twfRequire(calcFullPacketChecksum(sbufGetMutablePtr(bad_code), sbufGetLength(bad_code)),
               "ICMP code diagnostic fixture checksum failed");
    sendInbound(fixture, 0, bad_code);
    requireErrorLog("unsupported ICMP Echo code");

    resetDropLog(fixture);
    sbuf_t *bad_type                                                         = peerRequest(fixture, line, 114);
    ((struct icmp_echo_hdr *) (sbufGetMutablePtr(bad_type) + IP_HLEN))->type = ICMP_DUR;
    twfRequire(calcFullPacketChecksum(sbufGetMutablePtr(bad_type), sbufGetLength(bad_type)),
               "ICMP type diagnostic fixture checksum failed");
    sendInbound(fixture, 0, bad_type);
    requireErrorLog("unsupported ICMP type");

    resetDropLog(fixture);
    sbuf_t *bad_inner                                            = peerRequest(fixture, line, 115);
    sbufGetMutablePtr(bad_inner)[kPingWireEncapsulationOverhead] = 0x60;
    twfRequire(calcFullPacketChecksum(sbufGetMutablePtr(bad_inner), sbufGetLength(bad_inner)),
               "inner IPv4 diagnostic fixture checksum failed");
    sendInbound(fixture, 0, bad_inner);
    requireErrorLog("ICMP Echo Request payload is not one complete inner IPv4 packet");

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
    casePeerRequestReplay(&fixture);
    if (expected_replies)
    {
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
        caseInvalidReplySettings(server != 0);
        runEndpointCases(server != 0, NULL);
        runEndpointCases(server != 0, "false");
        runEndpointCases(server != 0, "true");
    }

    wCryptoGlobalCleanup();
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    networkloggerDestroy();
    puts("ping_flow_test: all cases passed");
    return 0;
}
