#include "structure.h"

#include "loggers/network_logger.h"

// Kept in its own block below the logger: device_flow_affinity.h pulls in the
// internal logger, and whichever logger a translation unit sees first is the
// one every LOGx in it reports to.
#include "devices/device_flow_affinity.h"

static const uint32_t kTesterClientChunkSizes[kTesterClientChunkCount] = {
    1U,
    2U,
    4U,
    32U,
    512U,
    1024U,
    4096U,
    32768U,
    32769U,
    1 * 1024U * 1024U,
    2 * 1024U * 1024U,
};

static const uint32_t kTesterClientPacketChunkSizes[kTesterClientChunkCount] = {
    1U,
    2U,
    4U,
    32U,
    64U,
    128U,
    256U,
    512U,
    1024U,
    kMaxAllowedPacketLength - 1U,
    kMaxAllowedPacketLength,
};

static const uint32_t kTesterClientPacketIpv4ChunkSizes[kTesterClientChunkCount] = {
    21U,
    22U,
    24U,
    52U,
    84U,
    148U,
    276U,
    532U,
    1044U,
    kMaxAllowedPacketLength - 1U,
    kMaxAllowedPacketLength,
};

static const uint32_t kTesterClientPacketIpv4TransportChunkSizes[kTesterClientChunkCount] = {
    41U,
    42U,
    44U,
    52U,
    84U,
    148U,
    276U,
    532U,
    1044U,
    kMaxAllowedPacketLength - 1U,
    kMaxAllowedPacketLength,
};

enum
{
    kTesterClientPacketIpv4RequestSourcePort = 40123,
    kTesterClientPacketIpv4RequestDestPort   = 40234,
    // Minimal IPv4 header plus the two transport ports: everything the shared
    // flow-affinity hash reads for a port-carrying transport.
    kTesterClientPacketIpv4AffinityProbeSize = 24,
    kTesterClientPacketIpv4AffinityPortScan  = 4096
};

static inline uint16_t testerclientPacketIpv4HeaderLength(void)
{
    return (uint16_t) sizeof(struct ip_hdr);
}

static uint16_t testerclientPacketIpv4TransportHeaderLength(const testerclient_tstate_t *ts)
{
    switch (ts->packet_ipv4_transport)
    {
    case kTesterClientPacketIpv4TransportTcp:
        return (uint16_t) sizeof(struct tcp_hdr);
    case kTesterClientPacketIpv4TransportUdp:
        return (uint16_t) sizeof(struct udp_hdr);
    case kTesterClientPacketIpv4TransportIcmp:
        return (uint16_t) sizeof(struct icmp_echo_hdr);
    default:
        return 0;
    }
}

static uint16_t testerclientPacketIpv4PayloadOffset(const testerclient_tstate_t *ts)
{
    return testerclientPacketIpv4HeaderLength() + testerclientPacketIpv4TransportHeaderLength(ts);
}

static inline const uint32_t *testerclientGetChunkTable(tunnel_t *t)
{
    testerclient_tstate_t *ts = tunnelGetState(t);

    if (! ts->packet_mode)
    {
        return kTesterClientChunkSizes;
    }

    if (ts->packet_ipv4_mode && ts->packet_ipv4_transport != kTesterClientPacketIpv4TransportNone)
    {
        return kTesterClientPacketIpv4TransportChunkSizes;
    }

    return ts->packet_ipv4_mode ? kTesterClientPacketIpv4ChunkSizes : kTesterClientPacketChunkSizes;
}

static uint8_t testerclientFlowMarker(uint8_t flow_id, testerclient_direction_e direction)
{
    return (uint8_t) (flow_id ^ ((direction == kTesterClientDirectionResponse) ? 0xC3U : 0x3CU));
}

static uint8_t testerclientPatternByte(uint32_t offset, uint8_t chunk_index, uint8_t flow_id,
                                       testerclient_direction_e direction)
{
    // The very first byte carries the client-selected flow id so the far end can
    // derive the deterministic pattern even if adapters remap the connection to a
    // different worker.
    if (chunk_index == 0 && offset == 0)
    {
        return testerclientFlowMarker(flow_id, direction);
    }

    uint32_t value = offset;
    value ^= value >> 13;
    value *= 0x45d9f3bu;
    value ^= ((uint32_t) chunk_index + 1U) * 0x27d4eb2du;
    value ^= ((uint32_t) flow_id + 1U) * 0x165667b1u;
    value ^= (direction == kTesterClientDirectionResponse) ? 0xA5A5A5A5u : 0x5A5A5A5Au;
    value ^= value >> 16;
    return (uint8_t) value;
}

static uint8_t testerclientGetFlowId(tunnel_t *t, line_t *l)
{
    testerclient_lstate_t *ls = lineGetState(l, t);

    return ls->flow_id;
}

static void testerclientFillBytesForFlow(uint8_t flow_id, uint8_t *ptr, uint32_t payload_len, uint8_t chunk_index,
                                         uint32_t chunk_offset, testerclient_direction_e direction)
{
    for (uint32_t i = 0; i < payload_len; ++i)
    {
        ptr[i] = testerclientPatternByte(chunk_offset + i, chunk_index, flow_id, direction);
    }
}

static void testerclientFillPayloadForFlow(uint8_t flow_id, sbuf_t *buf, uint8_t chunk_index, uint32_t chunk_offset,
                                           testerclient_direction_e direction)
{
    uint32_t payload_len = sbufGetLength(buf);
    uint8_t *ptr         = sbufGetMutablePtr(buf);

    testerclientFillBytesForFlow(flow_id, ptr, payload_len, chunk_index, chunk_offset, direction);
}

static uint32_t testerclientGetExpectedPayloadLength(tunnel_t *t, uint8_t chunk_index)
{
    testerclient_tstate_t *ts         = tunnelGetState(t);
    uint32_t               chunk_size = testerclientGetChunkSize(t, chunk_index);

    if (! (ts->packet_mode && ts->packet_ipv4_mode))
    {
        return chunk_size;
    }

    return chunk_size - testerclientPacketIpv4PayloadOffset(ts);
}

static void testerclientPacketIpv4DirectionAddrs(const testerclient_tstate_t *ts, testerclient_direction_e direction,
                                                 uint32_t *src_addr, uint32_t *dest_addr)
{
    if (direction == kTesterClientDirectionRequest)
    {
        *src_addr  = ts->packet_ipv4_source_addr;
        *dest_addr = ts->packet_ipv4_dest_addr;
        return;
    }

    *src_addr  = ts->packet_ipv4_dest_addr;
    *dest_addr = ts->packet_ipv4_source_addr;
}

/*
 * Optional worker-affine request flow.
 *
 * The default synthetic flow is byte-identical on every worker, so a chain that
 * restores inner-flow worker affinity funnels all of them onto one worker and the
 * per-worker request/response state machines stop lining up. With
 * packet-ipv4->worker-affine-flow enabled, each worker instead uses the first
 * request source port whose flow selects that same worker. The flow hash is
 * symmetric, so the response direction resolves to the same worker, and both
 * testers derive the port identically from settings they already share.
 *
 * Every caller runs on the line's own event worker, which for a packet line is
 * the worker whose flow this is.
 */
static uint16_t testerclientPacketIpv4WorkerSourcePort(const testerclient_tstate_t *ts)
{
    if (! ts->packet_ipv4_worker_affine_flow)
    {
        return (uint16_t) kTesterClientPacketIpv4RequestSourcePort;
    }

    const wid_t wid = getCurrentEventWorkerWID();
    uint8_t     probe[kTesterClientPacketIpv4AffinityProbeSize];

    memoryZero(probe, sizeof(probe));
    probe[0] = 0x45;
    probe[9] = ts->packet_ipv4_protocol;
    // The hash only trusts bytes inside the declared total length, so the probe
    // has to declare its own size or its ports are not read at all.
    PUT_BE16(probe + 2, (uint16_t) kTesterClientPacketIpv4AffinityProbeSize);
    memoryCopy(probe + 12, &ts->packet_ipv4_source_addr, sizeof(ts->packet_ipv4_source_addr));
    memoryCopy(probe + 16, &ts->packet_ipv4_dest_addr, sizeof(ts->packet_ipv4_dest_addr));
    PUT_BE16(probe + 22, (uint16_t) kTesterClientPacketIpv4RequestDestPort);

    for (uint32_t offset = 0; offset < kTesterClientPacketIpv4AffinityPortScan; ++offset)
    {
        const uint16_t candidate = (uint16_t) (kTesterClientPacketIpv4RequestSourcePort + offset);
        wid_t          selected  = 0;

        if (candidate == (uint16_t) kTesterClientPacketIpv4RequestDestPort)
        {
            continue;
        }

        PUT_BE16(probe + 20, candidate);

        if (deviceFlowAffineWID(probe, sizeof(probe), &selected) && selected == wid)
        {
            return candidate;
        }
    }

    LOGF("TesterClient: no request source port in the scan window maps to worker %u", (unsigned int) wid);
    abortProgramNow(1);
}

static void testerclientPacketIpv4DirectionPorts(const testerclient_tstate_t *ts, testerclient_direction_e direction,
                                                 uint16_t *src_port, uint16_t *dest_port)
{
    const uint16_t request_source_port = testerclientPacketIpv4WorkerSourcePort(ts);

    if (direction == kTesterClientDirectionRequest)
    {
        *src_port  = request_source_port;
        *dest_port = (uint16_t) kTesterClientPacketIpv4RequestDestPort;
        return;
    }

    *src_port  = (uint16_t) kTesterClientPacketIpv4RequestDestPort;
    *dest_port = request_source_port;
}

static void testerclientWritePacketIpv4Header(testerclient_tstate_t *ts, sbuf_t *buf,
                                              testerclient_direction_e direction)
{
    uint8_t       *packet     = sbufGetMutablePtr(buf);
    struct ip_hdr *ipheader   = (struct ip_hdr *) packet;
    uint32_t       src_addr   = 0;
    uint32_t       dest_addr  = 0;
    uint16_t       packet_len = (uint16_t) sbufGetLength(buf);
    uint16_t       header_len = testerclientPacketIpv4HeaderLength();
    uint16_t       packet_id  = (uint16_t) (atomicAdd(&ts->packet_ipv4_identification, 1U) + 1U);

    testerclientPacketIpv4DirectionAddrs(ts, direction, &src_addr, &dest_addr);

    memoryZero(packet, header_len);

    IPH_VHL_SET(ipheader, 4, header_len / 4U);
    IPH_TOS_SET(ipheader, 0);
    IPH_LEN_SET(ipheader, lwip_htons(packet_len));
    IPH_ID_SET(ipheader, lwip_htons(packet_id));
    IPH_OFFSET_SET(ipheader, 0);
    IPH_TTL_SET(ipheader, ts->packet_ipv4_ttl);
    IPH_PROTO_SET(ipheader, ts->packet_ipv4_protocol);
    IPH_CHKSUM_SET(ipheader, 0);
    ipheader->src.addr  = src_addr;
    ipheader->dest.addr = dest_addr;
}

static void testerclientWritePacketIpv4Transport(testerclient_tstate_t *ts, sbuf_t *buf, uint8_t chunk_index,
                                                 testerclient_direction_e direction)
{
    uint8_t *packet        = sbufGetMutablePtr(buf);
    uint8_t *transport     = packet + testerclientPacketIpv4HeaderLength();
    uint16_t transport_len = (uint16_t) (sbufGetLength(buf) - testerclientPacketIpv4HeaderLength());
    uint16_t src_port      = 0;
    uint16_t dest_port     = 0;

    testerclientPacketIpv4DirectionPorts(ts, direction, &src_port, &dest_port);

    switch (ts->packet_ipv4_transport)
    {
    case kTesterClientPacketIpv4TransportTcp: {
        struct tcp_hdr *tcpheader = (struct tcp_hdr *) transport;

        memoryZero(tcpheader, sizeof(*tcpheader));
        tcpheader->src   = lwip_htons(src_port);
        tcpheader->dest  = lwip_htons(dest_port);
        tcpheader->seqno = lwip_htonl(0x10203040U + (uint32_t) chunk_index);
        tcpheader->ackno = lwip_htonl(0x50607080U + (uint32_t) chunk_index);
        TCPH_HDRLEN_FLAGS_SET(tcpheader, sizeof(*tcpheader) / 4U, TCP_ACK | TCP_PSH);
        tcpheader->wnd  = lwip_htons(64240U);
        tcpheader->urgp = 0;
        return;
    }
    case kTesterClientPacketIpv4TransportUdp: {
        struct udp_hdr *udpheader = (struct udp_hdr *) transport;

        memoryZero(udpheader, sizeof(*udpheader));
        udpheader->src  = lwip_htons(src_port);
        udpheader->dest = lwip_htons(dest_port);
        udpheader->len  = lwip_htons(transport_len);
        return;
    }
    case kTesterClientPacketIpv4TransportIcmp: {
        struct icmp_echo_hdr *icmpheader = (struct icmp_echo_hdr *) transport;

        memoryZero(icmpheader, sizeof(*icmpheader));
        ICMPH_TYPE_SET(icmpheader, direction == kTesterClientDirectionRequest ? ICMP_ECHO : ICMP_ER);
        ICMPH_CODE_SET(icmpheader, 0);
        icmpheader->id    = lwip_htons(0x5151U);
        icmpheader->seqno = lwip_htons(chunk_index);
        return;
    }
    default:
        return;
    }
}

static bool testerclientVerifyPacketIpv4Transport(testerclient_tstate_t *ts, sbuf_t *buf, uint8_t chunk_index,
                                                  testerclient_direction_e direction)
{
    uint8_t       *packet             = sbufGetMutablePtr(buf);
    struct ip_hdr *ipheader           = (struct ip_hdr *) packet;
    uint8_t       *transport          = packet + testerclientPacketIpv4HeaderLength();
    uint16_t       transport_len      = (uint16_t) (sbufGetLength(buf) - testerclientPacketIpv4HeaderLength());
    uint16_t       src_port           = 0;
    uint16_t       dest_port          = 0;
    uint16_t       transport_checksum = 0;

    if (ts->packet_ipv4_transport == kTesterClientPacketIpv4TransportNone)
    {
        return true;
    }

    testerclientPacketIpv4DirectionPorts(ts, direction, &src_port, &dest_port);

    switch (ts->packet_ipv4_transport)
    {
    case kTesterClientPacketIpv4TransportTcp: {
        struct tcp_hdr *tcpheader = (struct tcp_hdr *) transport;

        if (transport_len < sizeof(*tcpheader) || tcpheader->src != lwip_htons(src_port) ||
            tcpheader->dest != lwip_htons(dest_port) || TCPH_HDRLEN_BYTES(tcpheader) != sizeof(*tcpheader) ||
            TCPH_FLAGS(tcpheader) != (TCP_ACK | TCP_PSH) ||
            tcpheader->seqno != lwip_htonl(0x10203040U + (uint32_t) chunk_index) ||
            tcpheader->ackno != lwip_htonl(0x50607080U + (uint32_t) chunk_index) ||
            tcpheader->wnd != lwip_htons(64240U) || tcpheader->urgp != 0)
        {
            return false;
        }
        transport_checksum = tcpheader->chksum;
        break;
    }
    case kTesterClientPacketIpv4TransportUdp: {
        struct udp_hdr *udpheader = (struct udp_hdr *) transport;

        if (transport_len < sizeof(*udpheader) || udpheader->src != lwip_htons(src_port) ||
            udpheader->dest != lwip_htons(dest_port) || udpheader->len != lwip_htons(transport_len))
        {
            return false;
        }
        transport_checksum = udpheader->chksum;
        break;
    }
    case kTesterClientPacketIpv4TransportIcmp: {
        struct icmp_echo_hdr *icmpheader    = (struct icmp_echo_hdr *) transport;
        uint8_t               expected_type = direction == kTesterClientDirectionRequest ? ICMP_ECHO : ICMP_ER;

        if (transport_len < sizeof(*icmpheader) || icmpheader->type != expected_type || icmpheader->code != 0 ||
            icmpheader->id != lwip_htons(0x5151U) || icmpheader->seqno != lwip_htons(chunk_index))
        {
            return false;
        }
        transport_checksum = icmpheader->chksum;
        break;
    }
    default:
        return false;
    }

    uint16_t ip_checksum = IPH_CHKSUM(ipheader);
    calcFullPacketChecksum(packet, sbufGetLength(buf));

    if (IPH_CHKSUM(ipheader) != ip_checksum)
    {
        return false;
    }

    switch (ts->packet_ipv4_transport)
    {
    case kTesterClientPacketIpv4TransportTcp:
        return ((struct tcp_hdr *) transport)->chksum == transport_checksum;
    case kTesterClientPacketIpv4TransportUdp:
        return ((struct udp_hdr *) transport)->chksum == transport_checksum;
    case kTesterClientPacketIpv4TransportIcmp:
        return ((struct icmp_echo_hdr *) transport)->chksum == transport_checksum;
    default:
        return false;
    }
}

static bool testerclientDecodePacketIpv4(tunnel_t *t, sbuf_t *buf, testerclient_direction_e direction,
                                         uint8_t chunk_index, uint8_t **payload_ptr, uint32_t *payload_len)
{
    testerclient_tstate_t *ts             = tunnelGetState(t);
    const uint32_t         packet_len     = sbufGetLength(buf);
    const uint16_t         header_len     = testerclientPacketIpv4HeaderLength();
    const uint16_t         payload_offset = testerclientPacketIpv4PayloadOffset(ts);

    if (packet_len < payload_offset)
    {
        return false;
    }

    const struct ip_hdr *ipheader = (const struct ip_hdr *) sbufGetRawPtr(buf);
    if ((IPH_V(ipheader) != 4) || (IPH_HL_BYTES(ipheader) != header_len))
    {
        return false;
    }

    if ((lwip_ntohs(IPH_OFFSET(ipheader)) != 0) || (IPH_PROTO(ipheader) != ts->packet_ipv4_protocol))
    {
        return false;
    }

    if (lwip_ntohs(IPH_LEN(ipheader)) != packet_len)
    {
        return false;
    }

    uint32_t expected_src  = 0;
    uint32_t expected_dest = 0;
    testerclientPacketIpv4DirectionAddrs(ts, direction, &expected_src, &expected_dest);

    if ((ipheader->src.addr != expected_src) || (ipheader->dest.addr != expected_dest))
    {
        return false;
    }

    if (! testerclientVerifyPacketIpv4Transport(ts, buf, chunk_index, direction))
    {
        return false;
    }

    *payload_ptr = sbufGetMutablePtr(buf) + payload_offset;
    *payload_len = packet_len - payload_offset;
    return true;
}

/*
 * Category B (orderly runtime failure): the test driver has reached a verdict,
 * so the process must end, but this runs on an arbitrary worker with the caller
 * still owning its callback frame. Request an orderly shutdown and return; every
 * caller returns immediately afterwards, and worker 0 performs the real
 * teardown.
 *
 * This reports the verdict and closes nothing, so it is only correct where the
 * callback is not the one responsible for the line's closure: the payload
 * verifiers, the watchdog, and packet mode, whose line is the process-lifetime
 * worker packet line. A verdict reached inside a Finish handler for a normal line
 * this tunnel created must go through testerclientFailOwnedLine() instead.
 */
void testerclientFail(tunnel_t *t, line_t *l, const char *reason)
{
    LOGE("TesterClient: worker %u failed: %s", (unsigned int) lineGetWID(l), reason);
    discard t;

    if (! requestProgramShutdown(1))
    {
        abortProgramNow(1);
    }
}

/*
 * The same Category-B verdict, reached while holding a normal line this tunnel
 * created. requestProgramShutdown() only schedules worker 0's teardown: this
 * callback still returns and unwinds through every suspended frame above it, and
 * those frames keep reading lineIsAlive(). So the owner postcondition applies
 * unchanged - detach the worker slot, destroy the line state and mark the line
 * dead, then report the verdict.
 *
 * Never call this for packet mode: that line belongs to the chain and outlives
 * every verdict. Proactive failures pass send_upstream_finish=true so every
 * initialized neighbor releases its state. The downstream Finish handler passes
 * false because that next side is the sender and must not receive a reflection.
 */
void testerclientFailOwnedLine(tunnel_t *t, line_t *l, const char *reason, bool send_upstream_finish)
{
    testerclient_tstate_t       *ts   = tunnelGetState(t);
    testerclient_worker_state_t *slot = &ts->workers[lineGetWID(l)];
    testerclient_lstate_t       *ls   = lineGetState(l, t);

    assert(! ts->packet_mode);

    // lineDestroy() below can drop the last reference. A lock is a reference, not
    // a claim that the line is alive, so holding one keeps the allocation readable
    // long enough for the verdict helper to still name its worker.
    lineLock(l);

    // Detach before destroying: the completion sweep schedules close tasks
    // straight off this slot, and it must not find a line that is about to die.
    if (slot->line == l)
    {
        slot->line = NULL;
    }
    slot->close_scheduled = true;
    slot->closed          = true;

    testerclientLinestateDestroy(ls);

    if (send_upstream_finish && lineIsAlive(l))
    {
        tunnelNextUpStreamFinish(t, l);
    }

    if (lineIsAlive(l))
    {
        lineDestroy(l);
    }

    testerclientFail(t, l, reason);

    lineUnlock(l);
}

uint8_t testerclientGetChunkCount(tunnel_t *t)
{
    testerclient_tstate_t *ts = tunnelGetState(t);

    assert(ts->chunk_count > 0);
    assert(ts->chunk_count <= kTesterClientChunkCount);
    return ts->chunk_count;
}

uint32_t testerclientGetChunkSize(tunnel_t *t, uint8_t index)
{
    testerclient_tstate_t *ts = tunnelGetState(t);
    uint32_t               chunk_size;

    assert(index < testerclientGetChunkCount(t));
    chunk_size = testerclientGetChunkTable(t)[index];

    if (ts->packet_mode && ts->max_payload_size > 0 && chunk_size > ts->max_payload_size)
    {
        chunk_size = ts->max_payload_size;
    }

    return chunk_size;
}

uint64_t testerclientGetRemainingBytes(tunnel_t *t, uint8_t index)
{
    uint64_t        remaining   = 0;
    const uint32_t *chunk_sizes = testerclientGetChunkTable(t);

    const uint8_t chunk_count = testerclientGetChunkCount(t);

    for (uint8_t i = index; i < chunk_count; ++i)
    {
        remaining += chunk_sizes[i];
    }

    return remaining;
}

/*
 * Category D (invariant): every failure below means the generator was asked for
 * a payload that its own validated configuration and scheduling can never
 * produce, so none of them is a peer-selectable runtime verdict. They hard-abort
 * rather than request an orderly shutdown, which makes this function
 * non-nullable: callers may use the returned buffer without a NULL check.
 */
sbuf_t *testerclientCreatePayload(tunnel_t *t, line_t *l, uint8_t chunk_index, uint32_t chunk_offset,
                                  uint32_t payload_len, testerclient_direction_e direction)
{
    buffer_pool_t         *pool = lineGetBufferPool(l);
    testerclient_tstate_t *ts   = tunnelGetState(t);
    sbuf_t                *buf  = NULL;

    if (ts->packet_mode)
    {
        if (payload_len != testerclientGetChunkSize(t, chunk_index))
        {
            LOGF("TesterClient: packet-mode payload generation attempted to split a packet chunk");
            abortProgramNow(1);
        }

        if (bufferpoolGetSmallBufferSize(pool) < kMaxAllowedPacketLength)
        {
            LOGF("TesterClient: packet-mode requires enough small-buffer capacity for the maximum packet length");
            abortProgramNow(1);
        }

        buf = bufferpoolGetSmallBuffer(pool);
    }
    else if (payload_len <= bufferpoolGetSmallBufferSize(pool))
    {
        buf = bufferpoolGetSmallBuffer(pool);
    }
    else if (payload_len <= bufferpoolGetLargeBufferSize(pool))
    {
        buf = bufferpoolGetLargeBuffer(pool);
    }
    else
    {
        LOGF("TesterClient: stream-mode payload generation exceeded large buffer size");
        abortProgramNow(1);
    }

    sbufSetLength(buf, payload_len);

    if (ts->packet_mode && ts->packet_ipv4_mode)
    {
        const uint16_t payload_offset = testerclientPacketIpv4PayloadOffset(ts);

        if (payload_len <= payload_offset)
        {
            LOGF("TesterClient: packet-ipv4 chunk size is smaller than the configured packet headers");
            abortProgramNow(1);
        }

        testerclientWritePacketIpv4Header(ts, buf, direction);
        testerclientWritePacketIpv4Transport(ts, buf, chunk_index, direction);
        testerclientFillBytesForFlow(testerclientGetFlowId(t, l),
                                     sbufGetMutablePtr(buf) + payload_offset,
                                     payload_len - payload_offset,
                                     chunk_index,
                                     chunk_offset,
                                     direction);
        calcFullPacketChecksum(sbufGetMutablePtr(buf), sbufGetLength(buf));
        return buf;
    }

    testerclientFillPayloadForFlow(testerclientGetFlowId(t, l), buf, chunk_index, chunk_offset, direction);

    return buf;
}

bool testerclientVerifyChunk(tunnel_t *t, line_t *l, sbuf_t *buf, uint8_t chunk_index,
                             testerclient_direction_e direction, uint32_t *bad_offset, uint8_t *expected,
                             uint8_t *actual)
{
    testerclient_tstate_t *ts          = tunnelGetState(t);
    const uint8_t         *ptr         = sbufGetRawPtr(buf);
    uint32_t               payload_len = sbufGetLength(buf);
    uint8_t                flow_id     = testerclientGetFlowId(t, l);

    if (payload_len != testerclientGetChunkSize(t, chunk_index))
    {
        if (bad_offset != NULL)
        {
            *bad_offset = payload_len;
        }
        return false;
    }

    if (ts->packet_mode && ts->packet_ipv4_mode)
    {
        uint8_t *packet_payload = NULL;

        if (! testerclientDecodePacketIpv4(t, buf, direction, chunk_index, &packet_payload, &payload_len))
        {
            if (bad_offset != NULL)
            {
                *bad_offset = 0;
            }
            return false;
        }

        if (payload_len != testerclientGetExpectedPayloadLength(t, chunk_index))
        {
            if (bad_offset != NULL)
            {
                *bad_offset = payload_len;
            }
            return false;
        }

        ptr = packet_payload;
    }

    for (uint32_t i = 0; i < payload_len; ++i)
    {
        uint8_t expected_byte = testerclientPatternByte(i, chunk_index, flow_id, direction);
        if (ptr[i] != expected_byte)
        {
            if (bad_offset != NULL)
            {
                *bad_offset = i;
            }
            if (expected != NULL)
            {
                *expected = expected_byte;
            }
            if (actual != NULL)
            {
                *actual = ptr[i];
            }
            return false;
        }
    }

    return true;
}

void testerclientScheduleRequestSend(tunnel_t *t, line_t *l, testerclient_lstate_t *ls)
{
    if (ls->request_send_scheduled || ls->request_complete || ! ls->est_received)
    {
        return;
    }

    ls->request_send_scheduled = true;
    WW_WORKER_MESSAGE_BENCHMARK_RECORD_CONTINUATION(kWorkerMessageBenchmarkContinuationTesterSend);
    if (UNLIKELY(! lineScheduleTask(l, testerclientRequestSendTask, t)))
    {
        ls->request_send_scheduled = false;
        testerclient_tstate_t *ts  = tunnelGetState(t);
        if (ts->packet_mode)
        {
            testerclientFail(t, l, "failed to schedule request progress");
        }
        else
        {
            testerclientFailOwnedLine(t, l, "failed to schedule request progress", true);
        }
    }
}

void testerclientRequestSendTask(tunnel_t *t, line_t *l)
{
    testerclient_lstate_t *ls   = lineGetState(l, t);
    buffer_pool_t         *pool = lineGetBufferPool(l);
    testerclient_tstate_t *ts   = tunnelGetState(t);

    ls->request_send_scheduled = false;

    const uint8_t chunk_count         = testerclientGetChunkCount(t);
    uint32_t      split_payloads_sent = 0;

    while (! ls->request_paused && ls->request_tx_index < chunk_count)
    {
        uint32_t chunk_size = testerclientGetChunkSize(t, ls->request_tx_index);
        uint32_t remaining  = chunk_size - ls->request_tx_offset;
        uint32_t max_len    = bufferpoolGetLargeBufferSize(pool);

        if (ts->max_payload_size > 0 && ts->max_payload_size < max_len)
        {
            max_len = ts->max_payload_size;
        }

        if (max_len == 0)
        {
            // Category D: a buffer pool that cannot hold a single payload byte
            // is broken validated state, not a test verdict.
            LOGF("TesterClient: large buffer pool reports zero writable payload capacity");
            abortProgramNow(1);
        }

        uint32_t payload_len = (remaining < max_len) ? remaining : max_len;
        sbuf_t  *buf         = testerclientCreatePayload(
            t, l, ls->request_tx_index, ls->request_tx_offset, payload_len, kTesterClientDirectionRequest);

        ls->request_tx_offset += payload_len;
        if (ls->request_tx_offset == chunk_size)
        {
            ls->request_tx_index += 1;
            ls->request_tx_offset = 0;
        }

        if (! withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, buf))
        {
            return;
        }

        if (! ts->packet_mode && ts->max_payload_size > 0 && ! ls->request_paused && ls->request_tx_index < chunk_count)
        {
            split_payloads_sent += 1;

            if (split_payloads_sent >= ts->split_payload_burst)
            {
                ls->request_send_scheduled = true;
                if (ts->split_payload_delay_ms == 0)
                {
                    WW_WORKER_MESSAGE_BENCHMARK_RECORD_CONTINUATION(kWorkerMessageBenchmarkContinuationTesterSend);
                    if (UNLIKELY(! lineScheduleTask(l, testerclientRequestSendTask, t)))
                    {
                        ls->request_send_scheduled = false;
                        if (ts->packet_mode)
                        {
                            testerclientFail(t, l, "failed to schedule split request progress");
                        }
                        else
                        {
                            testerclientFailOwnedLine(t, l, "failed to schedule split request progress", true);
                        }
                    }
                }
                else
                {
                    WW_WORKER_MESSAGE_BENCHMARK_RECORD_CONTINUATION(kWorkerMessageBenchmarkContinuationTesterSend);
                    if (UNLIKELY(
                            ! lineScheduleDelayedTask(l, testerclientRequestSendTask, ts->split_payload_delay_ms, t)))
                    {
                        ls->request_send_scheduled = false;
                        if (ts->packet_mode)
                        {
                            testerclientFail(t, l, "failed to schedule delayed split request progress");
                        }
                        else
                        {
                            testerclientFailOwnedLine(t, l, "failed to schedule delayed split request progress", true);
                        }
                    }
                }
                return;
            }
        }
    }

    if (ls->request_tx_index == chunk_count)
    {
        ls->request_complete = true;
    }
}

void testerclientWatchdogTask(tunnel_t *t, line_t *l)
{
    testerclient_lstate_t *ls = lineGetState(l, t);

    if (! ls->response_complete)
    {
        LOGE("TesterClient: worker %u timed out after %u ms (request_complete=%d, response_index=%u)",
             (unsigned int) lineGetWID(l),
             (unsigned int) kTesterClientWatchdogMs,
             (int) ls->request_complete,
             (unsigned int) ls->response_rx_index);

        testerclientFail(t, l, "watchdog expired before response verification completed");
        return;
    }
}

static void testerclientScheduleCompletedStreamCloseOnWorker(void *worker, void *arg1, void *arg2, void *arg3)
{
    worker_t                    *real_worker = worker;
    tunnel_t                    *t           = arg1;
    testerclient_tstate_t       *ts          = tunnelGetState(t);
    testerclient_worker_state_t *slot        = &ts->workers[real_worker->wid];

    discard arg2;
    discard arg3;

    if (slot->line != NULL && slot->completed && ! slot->close_scheduled && ! slot->closed)
    {
        slot->close_scheduled = true;
        if (UNLIKELY(! lineScheduleTask(slot->line, testerclientCloseCompletedStreamTask, t)))
        {
            slot->close_scheduled = false;
            testerclientFailOwnedLine(t, slot->line, "failed to schedule completed-line close", true);
        }
    }
}

static void testerclientScheduleCompletedStreamClose(tunnel_t *t)
{
    tunnel_chain_t *tc = tunnelGetChain(t);

    for (wid_t wi = 0; wi < tc->workers_count; ++wi)
    {
        // A line and its worker slot have the same owner worker. Queue the slot
        // inspection there so a concurrent Finish cannot destroy the line
        // between a foreign worker's pointer load and lineScheduleTask().
        if (UNLIKELY(sendWorkerMessageForceQueueWithCleanup(
                         wi, testerclientScheduleCompletedStreamCloseOnWorker, NULL, t, NULL, NULL) !=
                     kWorkerMessageSubmitAccepted))
        {
            LOGE("TesterClient: failed to schedule completed-line inspection on worker %u", (unsigned int) wi);
            if (! requestProgramShutdown(1))
            {
                abortProgramNow(1);
            }
            return;
        }
    }
}

/*
 * Category A (expected successful completion). Kept separate from its callers so
 * no function mixes a success-path shutdown with an invariant hard abort: the
 * last completion frequently happens on a non-zero worker, which is exactly the
 * case the old off-main _Exit() broke by skipping every registered cleanup
 * callback. Callers commit their success markers first and return right after.
 */
static void testerclientRequestSuccessfulShutdown(tunnel_chain_t *tc)
{
    LOGI("TesterClient: all %u worker lines completed successfully", (unsigned int) tc->workers_count);

    if (! requestProgramShutdown(0))
    {
        abortProgramNow(1);
    }
}

void testerclientCloseCompletedOwnedLine(tunnel_t *t, line_t *l, bool send_upstream_finish)
{
    testerclient_tstate_t       *ts   = tunnelGetState(t);
    testerclient_worker_state_t *slot = &ts->workers[lineGetWID(l)];
    testerclient_lstate_t       *ls   = lineGetState(l, t);
    tunnel_chain_t              *tc   = tunnelGetChain(t);

    assert(! ts->packet_mode);
    assert(slot->completed);
    assert(! slot->closed);
    assert(slot->line == l);

    // Detach before destroying the line. The completion sweep runs on this
    // worker and must observe either this closed slot or a live line.
    slot->line            = NULL;
    slot->close_scheduled = true;
    slot->closed          = true;

    testerclientLinestateDestroy(ls);

    if (send_upstream_finish && lineIsAlive(l))
    {
        tunnelNextUpStreamFinish(t, l);
    }

    if (lineIsAlive(l))
    {
        lineDestroy(l);
    }

    unsigned int closed = (unsigned int) atomicIncRelaxed(&ts->closed_workers) + 1U;
    if (closed == (unsigned int) tc->workers_count)
    {
        LOGI("TesterClient: all %u worker lines closed successfully", (unsigned int) tc->workers_count);
        testerclientRequestSuccessfulShutdown(tc);
        return;
    }
}

void testerclientCloseCompletedStreamTask(tunnel_t *t, line_t *l)
{
    testerclient_tstate_t       *ts   = tunnelGetState(t);
    testerclient_worker_state_t *slot = &ts->workers[lineGetWID(l)];
    testerclient_lstate_t       *ls   = lineGetState(l, t);

    if (slot->closed)
    {
        return;
    }

    if (! ls->response_complete)
    {
        // Category D: this task is only ever scheduled for a completed worker,
        // so reaching it unverified is a scheduler-logic violation.
        LOGF("TesterClient: scheduled close before response verification completed");
        abortProgramNow(1);
    }

    if (! ls->request_complete)
    {
        slot->close_scheduled = false;
        if (lineScheduleDelayedTask(l, testerclientCloseCompletedStreamTask, kTesterClientSplitPayloadDelayMs, t))
        {
            slot->close_scheduled = true;
        }
        else
        {
            testerclientFailOwnedLine(t, l, "failed to reschedule completed-line close", true);
        }
        return;
    }

    testerclientCloseCompletedOwnedLine(t, l, true);
}

void testerclientMarkWorkerComplete(tunnel_t *t, line_t *l)
{
    testerclient_tstate_t       *ts   = tunnelGetState(t);
    testerclient_worker_state_t *slot = &ts->workers[lineGetWID(l)];
    tunnel_chain_t              *tc   = tunnelGetChain(t);
    unsigned int                 done;

    if (slot->completed)
    {
        return;
    }

    slot->completed = true;
    if (ts->packet_mode)
    {
        slot->line = NULL;
    }

    done = (unsigned int) atomicIncRelaxed(&ts->completed_workers) + 1U;

    LOGI("TesterClient: worker %u completed integrity round-trip", (unsigned int) lineGetWID(l));

    if (done == (unsigned int) tc->workers_count)
    {
        if (! ts->packet_mode)
        {
            testerclientScheduleCompletedStreamClose(t);
            return;
        }

        testerclientRequestSuccessfulShutdown(tc);
        return;
    }
}
