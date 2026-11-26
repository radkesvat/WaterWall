/*
 * Covers both IPv4 Ping nodes through their real payload callbacks on worker packet lines.
 * CTest: waterwall.ping_flow_unit
 */
#ifdef PING_IPOVERRIDER_FIXTURE
#include "IpOverrider/interface.h"
#endif
#include "PingClient/interface.h"
#include "PingServer/interface.h"
#include "fixtures/failure/tunnel_orderly_shutdown_harness.h"
#include "loggers/network_logger.h"

sbuf_t *__real_sbufDuplicateByPool(buffer_pool_t *pool, const sbuf_t *buffer);
sbuf_t *__wrap_sbufDuplicateByPool(buffer_pool_t *pool, const sbuf_t *buffer);

sbuf_t *__wrap_sbufDuplicateByPool(buffer_pool_t *pool, const sbuf_t *buffer)
{
    /* The duplicate helper uses pool getters from its own translation unit. */
    return twfTrackAcquired(__real_sbufDuplicateByPool(pool, buffer));
}

enum
{
    kWorkers      = 2,
    kIcmpHeader   = 8,
    kOverhead     = 10,
    kMaxInner     = 1490,
    kNativeHeader = 24,
};

typedef struct packet_s
{
    uint8_t  bytes[1501];
    uint32_t length;
} packet_t;

typedef struct sink_s
{
    packet_t last;
    unsigned count;
    line_t  *line;
} sink_t;

typedef struct endpoint_s
{
    node_t    node;
    tunnel_t *tunnel;
    tunnel_t *wire;
    tunnel_t *native;
} endpoint_t;

typedef struct fixture_s
{
    tos_worker_env_t env;
    tunnel_chain_t  *chain;
    endpoint_t       client;
    endpoint_t       server;
} fixture_t;

static void sinkPayload(tunnel_t *tunnel, line_t *line, sbuf_t *buffer)
{
    sink_t *sink = tunnelGetState(tunnel);
    twfRequire(lineIsAlive(line) && lineIsOnCurrentWorker(line), "wrong worker in Ping output callback");
    twfRequire(! sbufGetRecalculateChecksum(buffer), "checksum repair intent leaked into Ping output");
    twfRequire(sbufGetLength(buffer) <= sizeof(sink->last.bytes), "Ping sink input exceeds capture");
    sink->last.length = sbufGetLength(buffer);
    memoryCopy(sink->last.bytes, sbufGetRawPtr(buffer), sink->last.length);
    sink->line = line;
    ++sink->count;
    lineReuseBuffer(line, buffer);
}

static tunnel_t *createSink(void)
{
    tunnel_t *sink = tunnelCreate(NULL, sizeof(sink_t), 0);
    twfRequire(sink != NULL, "cannot allocate Ping sink");
    sink->fnPayloadU = sinkPayload;
    sink->fnPayloadD = sinkPayload;
    return sink;
}

static void createEndpoint(endpoint_t *endpoint, tunnel_chain_t *chain, bool server, const char *json)
{
    endpoint->node                    = server ? nodePingServerGet() : nodePingClientGet();
    endpoint->node.node_settings_json = json != NULL ? cJSON_Parse(json) : NULL;
    twfRequire(json == NULL || endpoint->node.node_settings_json != NULL, "invalid Ping fixture settings JSON");
    twfRequireEqualU32(endpoint->node.required_padding_left, kOverhead, "wrong advertised Ping headroom");

    endpoint->tunnel = endpoint->node.createHandle(&endpoint->node);
    twfRequire(endpoint->tunnel != NULL, "failed to create Ping endpoint");
    twfRequireEqualU32(endpoint->tunnel->lstate_size, 0, "Ping should use packet lines without line state");
    endpoint->tunnel->chain = chain;
    endpoint->wire          = createSink();
    endpoint->native        = createSink();
    tunnelBind(server ? endpoint->wire : endpoint->native, endpoint->tunnel);
    tunnelBind(endpoint->tunnel, server ? endpoint->native : endpoint->wire);
    endpoint->tunnel->onPrepare(endpoint->tunnel);
    endpoint->tunnel->onStart(endpoint->tunnel);
}

static void destroyEndpoint(endpoint_t *endpoint)
{
    endpoint->tunnel->onDestroy(endpoint->tunnel, wwLifecycleProcessShutdown());
    tunnelDestroy(endpoint->wire);
    tunnelDestroy(endpoint->native);
    cJSON_Delete(endpoint->node.node_settings_json);
    memoryFree(endpoint->node.type);
}

static void setupFixture(fixture_t *fixture, const char *client_settings, const char *server_settings)
{
    tosWorkerEnvSetup(&fixture->env, kWorkers, 8192, 1501);
    fixture->chain                       = tunnelchainCreate(kWorkers);
    fixture->chain->contains_packet_node = true;
    fixture->chain->sum_padding_left     = kOverhead;
    tunnelchainFinalize(fixture->chain);
    twfRequire(fixture->chain->finalized, "failed to finalize Ping fixture packet lines");

    createEndpoint(&fixture->client, fixture->chain, false, client_settings);
    createEndpoint(&fixture->server, fixture->chain, true, server_settings);
}

static void teardownFixture(fixture_t *fixture)
{
    destroyEndpoint(&fixture->client);
    destroyEndpoint(&fixture->server);
    for (wid_t wid = 0; wid < kWorkers; ++wid)
    {
        line_t *line = tunnelchainGetWorkerPacketLine(fixture->chain, wid);
        twfRequire(lineIsAlive(line), "Ping destroyed a chain-owned packet line");
        twfRequireEqualU32(twfLineRefCount(line), 1, "Ping leaked a packet-line reference");
    }
    twfRequireNoLeakedBuffers();
    tunnelchainDestroy(fixture->chain);
    tosWorkerEnvTeardown(&fixture->env);
}

static packet_t nativePacket(uint16_t length, uint8_t protocol)
{
    packet_t packet = {.length = length};
    packet.bytes[0] = 0x46;
    packet.bytes[1] = 0x2e;
    PUT_BE16(packet.bytes + 2, length);
    PUT_BE16(packet.bytes + 4, 0x5151);
    PUT_BE16(packet.bytes + 6, IP_DF);
    packet.bytes[8]           = 43;
    packet.bytes[9]           = protocol;
    const uint8_t addresses[] = {10, 20, 0, 1, 10, 20, 0, 2};
    memoryCopy(packet.bytes + 12, addresses, sizeof(addresses));
    packet.bytes[20] = 1; /* NOP followed by EOL and option padding. */

    uint8_t     *transport        = packet.bytes + kNativeHeader;
    const size_t transport_header = protocol == IP_PROTO_TCP ? 20U : 8U;
    PUT_BE16(transport, 1234);
    PUT_BE16(transport + 2, 5678);
    if (protocol == IP_PROTO_TCP)
    {
        transport[12] = 0x50; /* Data offset */
        transport[13] = 0x18; /* PSH + ACK */
    }
    else
    {
        PUT_BE16(transport + 4, length - kNativeHeader);
    }
    for (size_t offset = kNativeHeader + transport_header; offset < length; ++offset)
    {
        packet.bytes[offset] = (uint8_t) (offset * 7U + length);
    }
    twfRequire(calcFullPacketChecksum(packet.bytes, packet.length), "cannot compute native transport checksums");
    return packet;
}

static void dispatch(fixture_t *fixture, tunnel_t *source, wid_t wid, bool upstream, const packet_t *packet,
                     bool recalculate)
{
    const wid_t previous = tosSetCurrentWorker(wid);
    line_t     *line     = tunnelchainGetWorkerPacketLine(fixture->chain, wid);
    sbuf_t     *buf      = bufferpoolGetSmallBuffer(lineGetBufferPool(line));
    twfRequire(sbufGetWritableCapacity(buf) >= packet->length, "Ping test packet does not fit its buffer");
    sbufSetLength(buf, packet->length);
    memoryCopy(sbufGetMutablePtr(buf), packet->bytes, packet->length);
    sbufSetRecalculateChecksum(buf, recalculate);
    if (upstream)
    {
        tunnelNextUpStreamPayload(source, line, buf);
    }
    else
    {
        tunnelPrevDownStreamPayload(source, line, buf);
    }
    discard tosSetCurrentWorker(previous);
    twfRequireNoLeakedBuffers();
}

static void requirePacket(const packet_t *actual, const packet_t *expected)
{
    twfRequireEqualU32(actual->length, expected->length, "wrong restored native length");
    twfRequire(memoryEqual(actual->bytes, expected->bytes, expected->length), "native IPv4 bytes changed");
}

/* Independently verify native or carrier-body TCP/UDP checksum arithmetic. */
static uint16_t transportResidual(const uint8_t *transport, size_t length, uint8_t protocol, const uint8_t *addresses)
{
    if (protocol == IP_PROTO_UDP)
    {
        length = GET_BE16(transport + 4);
    }
    uint32_t sum = (uint32_t) length + protocol;
    if (addresses != NULL)
    {
        for (size_t i = 0; i < 8; i += 2)
        {
            sum += GET_BE16(addresses + i);
        }
    }
    for (size_t i = 0; i + 1 < length; i += 2)
    {
        sum += GET_BE16(transport + i);
    }
    if (length % 2U != 0)
    {
        sum += (uint32_t) transport[length - 1U] << 8U;
    }
    while (sum > UINT16_MAX)
    {
        sum = (sum & UINT16_MAX) + (sum >> 16U);
    }
    return (uint16_t) ~sum;
}

static void requireCarrier(const packet_t *packet, const packet_t *native, bool server, uint8_t type, uint8_t code)
{
    const uint8_t *wire = packet->bytes;
    const uint8_t *icmp = wire + kNativeHeader;
    twfRequireEqualU32(packet->length, native->length + kOverhead, "wrong carrier length");
    twfRequire(wire[0] == 0x46 && wire[9] == IP_PROTO_ICMP && GET_BE16(wire + 2) == packet->length,
               "shared IPv4 geometry or protocol is incorrect");
    twfRequire(memoryEqual(wire, native->bytes, 2) && memoryEqual(wire + 4, native->bytes + 4, 5) &&
                   memoryEqual(wire + 12, native->bytes + 12, kNativeHeader - 12),
               "carrier changed native header fields");
    twfRequire(icmp[0] == type && icmp[1] == code, "wrong outgoing ICMP type or code");
    twfRequire(calcGenericChecksum(wire, kNativeHeader, 0) == 0 &&
                   calcGenericChecksum(icmp, (uint16_t) (packet->length - kNativeHeader), 0) == 0,
               "carrier IPv4 or ICMP checksum is invalid");
    const uint8_t protocol = native->bytes[9];
    twfRequire(wire[packet->length - 2U] == protocol && wire[packet->length - 1U] == (server ? 2 : 1),
               "wrong saved protocol or sender role");

    const size_t   body_length     = native->length - kNativeHeader;
    const size_t   checksum_offset = protocol == IP_PROTO_TCP ? 16U : 6U;
    const size_t   after_checksum  = checksum_offset + 2U;
    const uint8_t *payload         = icmp + kIcmpHeader;
    const uint8_t *original        = native->bytes + kNativeHeader;
    twfRequire(memoryEqual(payload, original, checksum_offset) &&
                   memoryEqual(payload + after_checksum, original + after_checksum, body_length - after_checksum),
               "carrier changed native payload outside the transport checksum");
}

static void requireIdentity(const packet_t *packet, uint16_t identifier, uint16_t sequence)
{
    const uint8_t *icmp = packet->bytes + kNativeHeader;
    twfRequireEqualU32(GET_BE16(icmp + 4), identifier, "wrong outgoing ICMP identifier");
    twfRequireEqualU32(GET_BE16(icmp + 6), sequence, "wrong outgoing ICMP sequence");
}

static packet_t exchange(fixture_t *fixture, bool server, const packet_t *native, uint8_t type, uint8_t code)
{
    endpoint_t    *sending       = server ? &fixture->server : &fixture->client;
    endpoint_t    *receiving     = server ? &fixture->client : &fixture->server;
    sink_t        *wire          = tunnelGetState(sending->wire);
    sink_t        *native_sink   = tunnelGetState(receiving->native);
    const unsigned wire_before   = wire->count;
    const unsigned native_before = native_sink->count;
    dispatch(fixture, sending->native, 0, ! server, native, false);
    twfRequireEqualU32(wire->count, wire_before + 1, "Ping sent on the wrong chain edge");
    twfRequire(wire->line == tunnelchainGetWorkerPacketLine(fixture->chain, 0), "Ping changed the sending packet line");
    requireCarrier(&wire->last, native, server, type, code);

    const packet_t carrier      = wire->last;
    const sink_t  *reply        = tunnelGetState(receiving->wire);
    const unsigned reply_before = reply->count;
    dispatch(fixture, receiving->wire, 1, ! server, &carrier, false);
    twfRequireEqualU32(native_sink->count, native_before + 1, "asymmetric peer did not decode incoming ICMP");
    requirePacket(&native_sink->last, native);
    twfRequire(native_sink->line == tunnelchainGetWorkerPacketLine(fixture->chain, 1),
               "Ping changed the arrival packet line");
    twfRequireEqualU32(reply->count, reply_before, "Ping generated an unsolicited tunnel response");
    return carrier;
}

static void requireInboundDrop(fixture_t *fixture, endpoint_t *endpoint, bool upstream, const packet_t *packet)
{
    const sink_t  *native        = tunnelGetState(endpoint->native);
    const sink_t  *wire          = tunnelGetState(endpoint->wire);
    const unsigned native_before = native->count;
    const unsigned wire_before   = wire->count;
    dispatch(fixture, endpoint->wire, 1, upstream, packet, false);
    twfRequireEqualU32(native->count, native_before, "invalid packet escaped to native side");
    twfRequireEqualU32(wire->count, wire_before, "invalid packet escaped to wire side");
}

static void recomputeCarrier(packet_t *packet)
{
    uint8_t *icmp = packet->bytes + kNativeHeader;
    PUT_BE16(icmp + 2, 0);
    const uint16_t checksum = calcGenericChecksum(icmp, (uint16_t) (packet->length - kNativeHeader), 0);
    memoryCopy(icmp + 2, &checksum, sizeof(checksum));
    twfRequire(calcIpv4HeaderChecksum(packet->bytes, packet->length), "cannot recompute carrier IPv4 checksum");
}

static void caseInvalidCarriers(fixture_t *fixture, const packet_t *carrier)
{
    twfSetCase("Ping rejects malformed and reflected carriers");
    packet_t packet = *carrier;
    packet.bytes[kNativeHeader + kIcmpHeader + 8] ^= 1U;
    requireInboundDrop(fixture, &fixture->server, true, &packet);

    packet                           = *carrier;
    packet.bytes[packet.length - 1U] = 0;
    recomputeCarrier(&packet);
    requireInboundDrop(fixture, &fixture->server, true, &packet);

    packet = *carrier;
    PUT_BE16(packet.bytes + kNativeHeader + kIcmpHeader + 4, packet.length - kNativeHeader - kIcmpHeader);
    recomputeCarrier(&packet);
    requireInboundDrop(fixture, &fixture->server, true, &packet);

    packet = *carrier;
    memoryCopy(packet.bytes + 12, carrier->bytes + 16, 4);
    memoryCopy(packet.bytes + 16, carrier->bytes + 12, 4);
    packet.bytes[kNativeHeader]     = 0; /* An Echo Reply retaining the client's role. */
    packet.bytes[kNativeHeader + 1] = 0;
    recomputeCarrier(&packet);
    requireInboundDrop(fixture, &fixture->client, false, &packet);
}

static void caseChecksumsAndSize(fixture_t *fixture, const packet_t *original, const packet_t *carrier)
{
    twfSetCase("Ping packet-local checksum requests and size limit");
    const sink_t  *wire          = tunnelGetState(fixture->client.wire);
    const sink_t  *native        = tunnelGetState(fixture->server.native);
    const unsigned wire_before   = wire->count;
    const unsigned native_before = native->count;
    packet_t       damaged       = *original;
    damaged.bytes[10] ^= 1U;
    damaged.bytes[kNativeHeader + 6] ^= 1U;
    dispatch(fixture, fixture->client.native, 0, true, &damaged, true);
    twfRequireEqualU32(wire->count, wire_before + 1, "marked native packet was dropped instead of repaired");
    requireCarrier(&wire->last, original, false, 3, 3);
    twfRequire(
        transportResidual(
            wire->last.bytes + kNativeHeader + kIcmpHeader, original->length - kNativeHeader, IP_PROTO_UDP, NULL) == 0,
        "marked native packet did not produce a valid neutral UDP checksum");

    damaged = *carrier;
    damaged.bytes[10] ^= 1U;
    damaged.bytes[kNativeHeader + 2] ^= 1U;
    dispatch(fixture, fixture->server.wire, 1, true, &damaged, true);
    twfRequireEqualU32(native->count, native_before + 1, "marked carrier was dropped instead of repaired");
    requirePacket(&native->last, original);

    const packet_t oversized = nativePacket(kMaxInner + 1, IP_PROTO_UDP);
    dispatch(fixture, fixture->client.native, 0, true, &oversized, false);
    twfRequireEqualU32(wire->count, wire_before + 1, "oversized native packet escaped to the wire");
}

static void caseDefaultSettings(void)
{
    twfSetCase("Ping default settings on both endpoints");
    static const char *const settings[] = {NULL,
                                           "{}",
                                           "{\"icmp-type\":8,\"icmp-code\":0}",
                                           "{\"icmp-type\":\"echo-request\",\"icmp-code\":\"no-code\"}",
                                           "{\"send-replies\":false}"};
    const packet_t           native     = nativePacket(73, IP_PROTO_UDP);
    for (size_t i = 0; i < ARRAY_SIZE(settings); ++i)
    {
        fixture_t fixture = {0};
        setupFixture(&fixture, settings[i], settings[i]);
        const packet_t client = exchange(&fixture, false, &native, 8, 0);
        const packet_t server = exchange(&fixture, true, &native, 8, 0);
        requireIdentity(&client, 0, 0);
        requireIdentity(&server, 0, 0);
        teardownFixture(&fixture);
    }
}

static void caseOptionalIdentity(void)
{
    twfSetCase("Ping optional identity and sequence wrapping across workers");
    fixture_t fixture = {0};
    setupFixture(&fixture,
                 "{\"icmp-type\":3,\"icmp-code\":3,\"identifier\":4660,\"sequence-start\":65535}",
                 "{\"icmp-type\":254,\"icmp-code\":255,\"sequence-start\":41}");
    const packet_t native       = nativePacket(73, IP_PROTO_UDP);
    const packet_t client_first = exchange(&fixture, false, &native, 3, 3);
    const packet_t server_first = exchange(&fixture, true, &native, 254, 255);
    const uint16_t identifier   = GET_BE16(server_first.bytes + kNativeHeader + 4);
    requireIdentity(&client_first, 4660, UINT16_MAX);
    twfRequire(identifier != 0, "omitted optional identifier did not generate a nonzero value");
    requireIdentity(&server_first, identifier, 41);

    const sink_t  *client_wire = tunnelGetState(fixture.client.wire);
    const sink_t  *server_wire = tunnelGetState(fixture.server.wire);
    const unsigned before      = client_wire->count;
    const packet_t oversized   = nativePacket(kMaxInner + 1, IP_PROTO_UDP);
    dispatch(&fixture, fixture.client.native, 1, true, &oversized, false);
    twfRequireEqualU32(client_wire->count, before, "oversized native packet escaped to the wire");
    dispatch(&fixture, fixture.client.native, 1, true, &native, false);
    twfRequireEqualU32(client_wire->count, before + 1, "client did not encode on the second worker");
    requireCarrier(&client_wire->last, &native, false, 3, 3);
    requireIdentity(&client_wire->last, 4660, 0);
    dispatch(&fixture, fixture.server.native, 1, false, &native, false);
    requireCarrier(&server_wire->last, &native, true, 254, 255);
    requireIdentity(&server_wire->last, identifier, 42);
    teardownFixture(&fixture);
}

static void caseEchoReplies(void)
{
    twfSetCase("Ping optional Echo Replies preserve the message and return toward the sender");
    fixture_t fixture = {0};
    setupFixture(
        &fixture, "{\"identifier\":\"random\",\"send-replies\":true}", "{\"identifier\":0,\"send-replies\":true}");
    const packet_t native = nativePacket(73, IP_PROTO_UDP);
    for (unsigned direction = 0; direction < 2; ++direction)
    {
        const bool     server        = direction != 0;
        endpoint_t    *sending       = server ? &fixture.server : &fixture.client;
        endpoint_t    *receiving     = server ? &fixture.client : &fixture.server;
        const sink_t  *sending_wire  = tunnelGetState(sending->wire);
        const sink_t  *reply_wire    = tunnelGetState(receiving->wire);
        const sink_t  *native_sink   = tunnelGetState(receiving->native);
        const unsigned reply_before  = reply_wire->count;
        const unsigned native_before = native_sink->count;

        dispatch(&fixture, sending->native, 0, ! server, &native, false);
        packet_t       request    = sending_wire->last;
        const uint16_t identifier = GET_BE16(request.bytes + kNativeHeader + 4);
        requireCarrier(&request, &native, server, 8, 0);
        twfRequire(server ? identifier == 0 : identifier != 0, "explicit Ping identifier setting was not honored");
        requireIdentity(&request, identifier, 1);

        dispatch(&fixture, receiving->wire, 1, ! server, &request, false);
        twfRequireEqualU32(native_sink->count, native_before + 1, "Echo Request did not deliver native data");
        requirePacket(&native_sink->last, &native);
        twfRequireEqualU32(reply_wire->count, reply_before + 1, "Echo Reply did not return toward the sender");
        twfRequire(reply_wire->line == tunnelchainGetWorkerPacketLine(fixture.chain, 1), "Echo Reply changed workers");
        const packet_t reply = reply_wire->last;
        twfRequireEqualU32(reply.length, request.length, "Echo Reply changed the carrier length");
        twfRequire(reply.bytes[8] == 64 && reply.bytes[kNativeHeader] == 0 && reply.bytes[kNativeHeader + 1] == 0,
                   "Echo Reply has the wrong type, code or TTL");
        twfRequire(memoryEqual(reply.bytes + 12, request.bytes + 16, 4) &&
                       memoryEqual(reply.bytes + 16, request.bytes + 12, 4),
                   "Echo Reply did not reverse the address pair");
        twfRequire(memoryEqual(reply.bytes + kNativeHeader + 4,
                               request.bytes + kNativeHeader + 4,
                               reply.length - kNativeHeader - 4),
                   "Echo Reply changed the identifier, sequence or payload");
        twfRequire(calcGenericChecksum(reply.bytes, kNativeHeader, 0) == 0 &&
                       calcGenericChecksum(reply.bytes + kNativeHeader, reply.length - kNativeHeader, 0) == 0,
                   "Echo Reply has an invalid checksum");
        requireInboundDrop(&fixture, sending, server, &reply);

        request.bytes[kNativeHeader + 2] ^= 1U;
        requireInboundDrop(&fixture, receiving, ! server, &request);
        request.bytes[kNativeHeader + 1] = 1; /* Valid carrier, but only code zero is eligible for a reply. */
        recomputeCarrier(&request);
        dispatch(&fixture, receiving->wire, 1, ! server, &request, false);
        twfRequireEqualU32(native_sink->count, native_before + 2, "nonzero Echo code did not deliver native data");
        twfRequireEqualU32(reply_wire->count, reply_before + 1, "nonzero Echo code generated a reply");
    }
    teardownFixture(&fixture);
}

static void caseInvalidSettings(void)
{
    static const char *const bad[] = {
        "null",
        "[]",
        "{\"local-ipv4\":\"192.0.2.1\"}",
        "{\"peer-ipv4\":\"192.0.2.2\"}",
        "{\"icmp-type\":256}",
        "{\"icmp-code\":-1}",
        "{\"icmp-code\":0.5}",
        "{\"icmp-type\":8e0}",
        "{\"icmp-type\":\"unknown\"}",
        "{\"icmp-type\":\"Echo-request\"}",
        "{\"icmp-type\":\"echo-request\\u0000ignored\"}",
        "{\"icmp-type\\u0000ignored\":8}",
        "{\"icmp-type\":8,\"icmp-code\":\"port-unreachable\"}",
        "{\"icmp-type\":8,\"icmp-type\":8}",
        "{\"icmp-code\":0,\"icmp-code\":0}",
        "{\"identifier\":65536}",
        "{\"identifier\":-1}",
        "{\"identifier\":\"random\\u0000ignored\"}",
        "{\"sequence-start\":65536}",
        "{\"sequence-start\":1.5}",
        "{\"send-replies\":\"true\"}",
    };
    twfSetCase("Ping rejects invalid and legacy settings");
    node_t client = nodePingClientGet();
    node_t server = nodePingServerGet();
    for (size_t index = 0; index < ARRAY_SIZE(bad); ++index)
    {
        cJSON *settings = cJSON_Parse(bad[index]);
        twfRequire(settings != NULL, "test produced invalid settings JSON");
        client.node_settings_json = settings;
        server.node_settings_json = settings;
        twfRequire(client.createHandle(&client) == NULL, "PingClient accepted invalid settings");
        twfRequire(server.createHandle(&server) == NULL, "PingServer accepted invalid settings");
        cJSON_Delete(settings);
    }
    memoryFree(client.type);
    memoryFree(server.type);
}

#ifdef PING_IPOVERRIDER_FIXTURE
static void caseIpOverriderComposition(fixture_t *fixture)
{
    twfSetCase("real IpOverrider on the native and carrier sides of Ping");

    node_t native_node  = nodeIpOverriderGet();
    node_t carrier_node = nodeIpOverriderGet();
    native_node.node_settings_json =
        cJSON_Parse("{\"up\":{\"source-ip\":{\"ipv4\":\"10.70.0.1\"},\"dest-ip\":{\"ipv4\":\"10.70.0.2\"}}}");
    carrier_node.node_settings_json =
        cJSON_Parse("{\"up\":{\"source-ip\":{\"ipv4\":\"203.0.113.10\"},\"dest-ip\":{\"ipv4\":\"198.51.100.80\"}}}");
    twfRequire(native_node.node_settings_json != NULL && carrier_node.node_settings_json != NULL,
               "invalid IpOverrider fixture JSON");
    tunnel_t *native_rewrite  = native_node.createHandle(&native_node);
    tunnel_t *carrier_rewrite = carrier_node.createHandle(&carrier_node);
    twfRequire(native_rewrite != NULL && carrier_rewrite != NULL, "cannot create real IpOverrider nodes");
    tunnelBind(fixture->client.native, native_rewrite);
    tunnelBind(native_rewrite, fixture->client.tunnel);
    tunnelBind(fixture->server.wire, carrier_rewrite);
    tunnelBind(carrier_rewrite, fixture->server.tunnel);

    const sink_t *wire_sink           = tunnelGetState(fixture->client.wire);
    const sink_t *native_sink         = tunnelGetState(fixture->server.native);
    const uint8_t native_addresses[]  = {10, 70, 0, 1, 10, 70, 0, 2};
    const uint8_t carrier_addresses[] = {203, 0, 113, 10, 198, 51, 100, 80};
    const uint8_t protocols[]         = {IP_PROTO_TCP, IP_PROTO_UDP};
    enum
    {
        kValidChecksum,
        kDirtyChecksum,
        kRequestedRepair,
        kDisabledUdpChecksum,
    };
    for (size_t i = 0; i < ARRAY_SIZE(protocols); ++i)
    {
        const uint8_t  protocol        = protocols[i];
        const size_t   checksum_offset = protocol == IP_PROTO_TCP ? 16U : 6U;
        const unsigned last            = protocol == IP_PROTO_TCP ? kRequestedRepair : kDisabledUdpChecksum;
        for (unsigned mode = kValidChecksum; mode <= last; ++mode)
        {
            packet_t     native      = nativePacket(73, protocol);
            const size_t body_length = native.length - kNativeHeader;
            uint8_t     *transport   = native.bytes + kNativeHeader;
            twfRequire(transportResidual(transport, body_length, protocol, native.bytes + 12) == 0,
                       "native fixture checksum is invalid");
            if (mode == kDirtyChecksum || mode == kRequestedRepair)
            {
                transport[checksum_offset] ^= 0x80;
                twfRequire(transportResidual(transport, body_length, protocol, native.bytes + 12) != 0,
                           "fixture failed to corrupt the checksum");
            }
            if (mode == kDisabledUdpChecksum)
            {
                PUT_BE16(transport + checksum_offset, 0);
            }

            const uint16_t expected_residual =
                mode == kDirtyChecksum ? transportResidual(transport, body_length, protocol, native.bytes + 12) : 0;
            const unsigned wire_before   = wire_sink->count;
            const unsigned native_before = native_sink->count;
            dispatch(fixture, fixture->client.native, 0, true, &native, mode == kRequestedRepair);
            twfRequireEqualU32(wire_sink->count, wire_before + 1, "native rewrite did not reach the wire");
            const packet_t carrier  = wire_sink->last;
            packet_t       expected = native;
            memoryCopy(expected.bytes + 12, native_addresses, sizeof(native_addresses));
            requireCarrier(&carrier, &expected, false, 3, 3);
            const uint8_t *wire_transport = carrier.bytes + kNativeHeader + kIcmpHeader;
            if (mode == kDisabledUdpChecksum)
            {
                twfRequire(GET_BE16(wire_transport + checksum_offset) == 0, "encoding enabled a disabled UDP checksum");
            }
            else
            {
                twfRequire(transportResidual(wire_transport, body_length, protocol, NULL) == expected_residual,
                           "native rewrite and encode failed to preserve the transport residual at zero addresses");
            }

            dispatch(fixture, fixture->server.wire, 1, true, &carrier, false);
            twfRequireEqualU32(native_sink->count, native_before + 1, "carrier rewrite failed to reach native side");
            const packet_t *decoded           = &native_sink->last;
            const uint8_t  *decoded_transport = decoded->bytes + kNativeHeader;
            twfRequireEqualU32(decoded->length, native.length, "address rewrite changed the native length");
            twfRequire(memoryEqual(decoded->bytes + 12, carrier_addresses, sizeof(carrier_addresses)) &&
                           ! memoryEqual(decoded->bytes + 12, native.bytes + 12, sizeof(carrier_addresses)),
                       "native output did not use the non-inverse carrier rewrite");
            twfRequire(decoded->bytes[9] == protocol && calcGenericChecksum(decoded->bytes, kNativeHeader, 0) == 0,
                       "carrier rewrite left an invalid restored IPv4 header");
            if (mode == kDisabledUdpChecksum)
            {
                twfRequire(GET_BE16(decoded_transport + checksum_offset) == 0,
                           "rewrite enabled a disabled UDP checksum");
            }
            else
            {
                twfRequire(transportResidual(decoded_transport, body_length, protocol, decoded->bytes + 12) ==
                               expected_residual,
                           "carrier rewrite and decode failed to preserve the residual at the received addresses");
            }
        }
    }

    tunnelBind(fixture->client.native, fixture->client.tunnel);
    tunnelBind(fixture->server.wire, fixture->server.tunnel);
    native_rewrite->onDestroy(native_rewrite, wwLifecycleProcessShutdown());
    carrier_rewrite->onDestroy(carrier_rewrite, wwLifecycleProcessShutdown());
    cJSON_Delete(native_node.node_settings_json);
    cJSON_Delete(carrier_node.node_settings_json);
    memoryFree(native_node.type);
    memoryFree(carrier_node.type);
}
#endif

int main(void)
{
    initWLibc();
    checkSumInit();
    logger_t *logger = loggerCreate();
    twfRequire(logger != NULL, "failed to initialize Ping logger");
    setNetworkLogger(logger);
    twfRequire(globalstateInitializeSecureRandom(), "the operating-system random source is unavailable");
    twfRequire(frandGlobalInit(), "fast random initialization failed");
    frandInit();
    caseInvalidSettings();
    caseDefaultSettings();
    caseOptionalIdentity();
    caseEchoReplies();

    twfSetCase("Ping asymmetric transmit settings and independent data directions");
    fixture_t fixture = {0};
    setupFixture(&fixture,
                 "{\"icmp-type\":\"destination-unreachable\",\"icmp-code\":\"port-unreachable\"}",
                 "{\"icmp-type\":254,\"icmp-code\":255}");
    const packet_t native  = nativePacket(73, IP_PROTO_UDP);
    const packet_t carrier = exchange(&fixture, false, &native, 3, 3);
    const packet_t maximum = nativePacket(kMaxInner, IP_PROTO_UDP);
    discard        exchange(&fixture, true, &maximum, 254, 255);

    const sink_t  *server_native = tunnelGetState(fixture.server.native);
    const unsigned before        = server_native->count;
    dispatch(&fixture, fixture.server.wire, 1, true, &carrier, false);
    twfRequireEqualU32(server_native->count, before + 1, "repeated well-formed data was suppressed");
    requirePacket(&server_native->last, &native);

    caseInvalidCarriers(&fixture, &carrier);
    caseChecksumsAndSize(&fixture, &native, &carrier);
#ifdef PING_IPOVERRIDER_FIXTURE
    caseIpOverriderComposition(&fixture);
#endif
    teardownFixture(&fixture);
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    networkloggerDestroy();
    puts("ping_flow_test: all cases passed");
    return 0;
}
