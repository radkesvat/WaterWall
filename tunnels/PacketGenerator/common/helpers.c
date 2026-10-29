#include "structure.h"

#include "loggers/network_logger.h"

static uint32_t packetgeneratorMix32(uint32_t value)
{
    value ^= value >> 16;
    value *= 0x7feb352du;
    value ^= value >> 15;
    value *= 0x846ca68bu;
    value ^= value >> 16;
    return value;
}

static bool packetgeneratorProtocolUsesPorts(uint8_t protocol)
{
    return protocol == IP_PROTO_TCP || protocol == IP_PROTO_UDP;
}

static uint8_t packetgeneratorGetSingleProtocolNumber(const packetgenerator_tstate_t *state)
{
    switch (state->protocol_mode)
    {
    case kPacketGeneratorProtocolTcp:
        return IP_PROTO_TCP;
    case kPacketGeneratorProtocolUdp:
        return IP_PROTO_UDP;
    case kPacketGeneratorProtocolIcmp:
        return IP_PROTO_ICMP;
    default:
        LOGF("PacketGenerator: internal error, invalid single-protocol mode %u", (unsigned int) state->protocol_mode);
        abortProgramNow(1);
    }
}

static uint16_t packetgeneratorStoredLengthForProtocol(uint8_t protocol)
{
    switch (protocol)
    {
    case IP_PROTO_TCP:
        return kPacketGeneratorTcpPacketLength;
    case IP_PROTO_UDP:
        return kPacketGeneratorUdpPacketLength;
    case IP_PROTO_ICMP:
        return kPacketGeneratorIcmpPacketLength;
    default:
        return kPacketGeneratorGenericPacketLength;
    }
}

static void packetgeneratorResolveSourceAddress(const packetgenerator_tstate_t *state, uint64_t source_index,
                                                uint32_t *src_addr_host_out, uint32_t *src_addr_network_out)
{
    uint64_t remaining = source_index;

    for (uint32_t ri = 0; ri < state->source_range_count; ++ri)
    {
        const packetgenerator_source_range_t *range = &state->source_ranges[ri];

        if (remaining < range->count)
        {
            const uint32_t src_addr_host = range->base_host + (uint32_t) remaining;
            *src_addr_host_out           = src_addr_host;
            *src_addr_network_out        = lwip_htonl(src_addr_host);
            return;
        }

        remaining -= range->count;
    }

    LOGF("PacketGenerator: internal error, source index %llu is out of range", (unsigned long long) source_index);
    abortProgramNow(1);
}

static uint16_t packetgeneratorSelectSourcePort(const packetgenerator_tstate_t *state, uint32_t src_addr_host,
                                                uint8_t protocol)
{
    if (! packetgeneratorProtocolUsesPorts(protocol))
    {
        return 0;
    }

    if (! state->src_port_random)
    {
        return state->src_port;
    }

    const uint32_t seed = packetgeneratorMix32(src_addr_host ^ state->dest_addr_host ^ (((uint32_t) protocol) << 24));
    return (uint16_t) (kPacketGeneratorRandomPortMin + (seed % kPacketGeneratorRandomPortSpan));
}

static uint16_t packetgeneratorPacketIdFromSeed(uint32_t seed)
{
    uint16_t packet_id = (uint16_t) (seed ^ (seed >> 16));
    return (packet_id == 0) ? 1U : packet_id;
}

static uint64_t packetgeneratorNowMs(void)
{
    return getHRTimeUs() / 1000U;
}

static void packetgeneratorInitIpv4Header(struct ip_hdr *ipheader, uint16_t packet_len, uint16_t packet_id,
                                          uint8_t protocol, uint32_t src_addr_network, uint32_t dest_addr_network)
{
    memoryZero(ipheader, kPacketGeneratorIpv4HeaderLength);

    IPH_VHL_SET(ipheader, 4, kPacketGeneratorIpv4HeaderLength / 4U);
    IPH_TOS_SET(ipheader, 0);
    IPH_LEN_SET(ipheader, lwip_htons(packet_len));
    IPH_ID_SET(ipheader, lwip_htons(packet_id));
    IPH_OFFSET_SET(ipheader, lwip_htons(IP_DF));
    IPH_TTL_SET(ipheader, kPacketGeneratorDefaultTtl);
    IPH_PROTO_SET(ipheader, protocol);
    IPH_CHKSUM_SET(ipheader, 0);
    ipheader->src.addr  = src_addr_network;
    ipheader->dest.addr = dest_addr_network;
}

static void packetgeneratorBuildTcpPacket(const packetgenerator_tstate_t *state, uint8_t *packet,
                                          uint32_t src_addr_host, uint32_t src_addr_network)
{
    const uint32_t  seed      = packetgeneratorMix32(src_addr_host ^ state->dest_addr_host ^ 0xC001D00Du);
    const uint16_t  src_port  = packetgeneratorSelectSourcePort(state, src_addr_host, IP_PROTO_TCP);
    struct ip_hdr  *ipheader  = (struct ip_hdr *) packet;
    struct tcp_hdr *tcpheader = (struct tcp_hdr *) (packet + kPacketGeneratorIpv4HeaderLength);

    memoryZero(packet, kPacketGeneratorTcpPacketLength);

    packetgeneratorInitIpv4Header(ipheader,
                                  kPacketGeneratorTcpPacketLength,
                                  packetgeneratorPacketIdFromSeed(seed),
                                  IP_PROTO_TCP,
                                  src_addr_network,
                                  state->dest_addr_network);

    tcpheader->src   = lwip_htons(src_port);
    tcpheader->dest  = lwip_htons(state->dest_port);
    tcpheader->seqno = lwip_htonl(packetgeneratorMix32(seed ^ 0x13579bdfu));
    tcpheader->ackno = lwip_htonl(packetgeneratorMix32(seed ^ 0x2468ace0u) | 1U);
    TCPH_HDRLEN_FLAGS_SET(tcpheader, kPacketGeneratorTcpHeaderLength / 4U, TCP_ACK);
    tcpheader->wnd  = lwip_htons(64240U);
    tcpheader->urgp = 0;

    calcFullPacketChecksum(packet, kPacketGeneratorTcpPacketLength);
}

static void packetgeneratorBuildUdpPacket(const packetgenerator_tstate_t *state, uint8_t *packet,
                                          uint32_t src_addr_host, uint32_t src_addr_network)
{
    const uint32_t  seed      = packetgeneratorMix32(src_addr_host ^ state->dest_addr_host ^ 0x55aa10ffu);
    const uint16_t  src_port  = packetgeneratorSelectSourcePort(state, src_addr_host, IP_PROTO_UDP);
    struct ip_hdr  *ipheader  = (struct ip_hdr *) packet;
    struct udp_hdr *udpheader = (struct udp_hdr *) (packet + kPacketGeneratorIpv4HeaderLength);

    memoryZero(packet, kPacketGeneratorUdpPacketLength);

    packetgeneratorInitIpv4Header(ipheader,
                                  kPacketGeneratorUdpPacketLength,
                                  packetgeneratorPacketIdFromSeed(seed),
                                  IP_PROTO_UDP,
                                  src_addr_network,
                                  state->dest_addr_network);

    udpheader->src  = lwip_htons(src_port);
    udpheader->dest = lwip_htons(state->dest_port);
    udpheader->len  = lwip_htons(kPacketGeneratorUdpHeaderLength);

    calcFullPacketChecksum(packet, kPacketGeneratorUdpPacketLength);
}

static void packetgeneratorBuildIcmpPacket(const packetgenerator_tstate_t *state, uint8_t *packet,
                                           uint32_t src_addr_host, uint32_t src_addr_network)
{
    const uint32_t        seed       = packetgeneratorMix32(src_addr_host ^ state->dest_addr_host ^ 0xa11ce55eu);
    struct ip_hdr        *ipheader   = (struct ip_hdr *) packet;
    struct icmp_echo_hdr *icmpheader = (struct icmp_echo_hdr *) (packet + kPacketGeneratorIpv4HeaderLength);

    memoryZero(packet, kPacketGeneratorIcmpPacketLength);

    packetgeneratorInitIpv4Header(ipheader,
                                  kPacketGeneratorIcmpPacketLength,
                                  packetgeneratorPacketIdFromSeed(seed),
                                  IP_PROTO_ICMP,
                                  src_addr_network,
                                  state->dest_addr_network);

    ICMPH_TYPE_SET(icmpheader, ICMP_ECHO);
    ICMPH_CODE_SET(icmpheader, 0);
    icmpheader->id    = lwip_htons((uint16_t) seed);
    icmpheader->seqno = lwip_htons((uint16_t) (seed >> 16));

    calcFullPacketChecksum(packet, kPacketGeneratorIcmpPacketLength);
}

static void packetgeneratorBuildGenericPacket(const packetgenerator_tstate_t *state, uint8_t *packet,
                                              uint32_t src_addr_host, uint32_t src_addr_network, uint8_t protocol)
{
    const uint32_t seed =
        packetgeneratorMix32(src_addr_host ^ state->dest_addr_host ^ (((uint32_t) protocol) << 24) ^ 0x91e10da5u);
    struct ip_hdr *ipheader = (struct ip_hdr *) packet;
    uint8_t       *payload  = packet + kPacketGeneratorIpv4HeaderLength;

    memoryZero(packet, kPacketGeneratorGenericPacketLength);

    packetgeneratorInitIpv4Header(ipheader,
                                  kPacketGeneratorGenericPacketLength,
                                  packetgeneratorPacketIdFromSeed(seed),
                                  protocol,
                                  src_addr_network,
                                  state->dest_addr_network);

    for (uint32_t i = 0; i < kPacketGeneratorGenericPayloadLength; ++i)
    {
        const uint32_t mixed = packetgeneratorMix32(seed + i);
        payload[i]           = (uint8_t) (mixed & 0xFFU);
    }

    calcFullPacketChecksum(packet, kPacketGeneratorGenericPacketLength);
}

static void packetgeneratorBuildPacketForProtocol(const packetgenerator_tstate_t *state, uint8_t *packet,
                                                  uint32_t src_addr_host, uint32_t src_addr_network, uint8_t protocol)
{
    switch (protocol)
    {
    case IP_PROTO_TCP:
        packetgeneratorBuildTcpPacket(state, packet, src_addr_host, src_addr_network);
        return;
    case IP_PROTO_UDP:
        packetgeneratorBuildUdpPacket(state, packet, src_addr_host, src_addr_network);
        return;
    case IP_PROTO_ICMP:
        packetgeneratorBuildIcmpPacket(state, packet, src_addr_host, src_addr_network);
        return;
    default:
        packetgeneratorBuildGenericPacket(state, packet, src_addr_host, src_addr_network, protocol);
        return;
    }
}

static uint32_t packetgeneratorGlobalDeadlineMs(const packetgenerator_tstate_t *state, uint64_t packet_index)
{
    if (state->total_packets <= 1U)
    {
        return 0;
    }

    return (uint32_t) ((packet_index * (uint64_t) state->duration_ms) / (state->total_packets - 1U));
}

static void packetgeneratorResolvePacketView(const packetgenerator_tstate_t *state, uint64_t packet_index,
                                             const uint8_t **packet_ptr_out, uint16_t *packet_len_out,
                                             uint32_t *src_addr_network_out, uint32_t *src_addr_host_out,
                                             uint8_t *protocol_out)
{
    uint64_t source_index;
    size_t   offset;
    uint8_t  protocol;
    uint16_t packet_len;

    if (state->protocol_mode == kPacketGeneratorProtocolAll)
    {
        const uint64_t packets_per_source =
            (uint64_t) state->packets_per_ip * (uint64_t) kPacketGeneratorProtocolsPerSource;
        const uint64_t source_repeat_index = packet_index % packets_per_source;
        const uint32_t repeat_index        = (uint32_t) (source_repeat_index / kPacketGeneratorProtocolsPerSource);
        const uint32_t protocol_index      = (uint32_t) (source_repeat_index % kPacketGeneratorProtocolsPerSource);

        source_index = packet_index / packets_per_source;
        protocol     = (uint8_t) protocol_index;
        packet_len   = state->protocol_lengths[protocol_index];
        offset       = ((size_t) source_index * state->bytes_per_source) +
                 ((size_t) repeat_index * state->bytes_per_source_repeat) + state->protocol_offsets[protocol_index];
    }
    else
    {
        const uint64_t packets_per_source  = (uint64_t) state->packets_per_ip;
        const uint64_t source_repeat_index = packet_index % packets_per_source;
        const uint32_t repeat_index        = (uint32_t) source_repeat_index;

        source_index = packet_index / packets_per_source;
        protocol     = packetgeneratorGetSingleProtocolNumber(state);
        packet_len   = state->fixed_packet_length;
        offset       = ((size_t) source_index * state->bytes_per_source) +
                 ((size_t) repeat_index * state->bytes_per_source_repeat);
    }

    uint32_t src_addr_host    = 0;
    uint32_t src_addr_network = 0;

    packetgeneratorResolveSourceAddress(state, source_index, &src_addr_host, &src_addr_network);

    *packet_ptr_out       = state->packet_bytes + offset;
    *packet_len_out       = packet_len;
    *src_addr_network_out = src_addr_network;
    *src_addr_host_out    = src_addr_host;
    *protocol_out         = protocol;
}

static void packetgeneratorApplyRoutingContext(const packetgenerator_tstate_t *state, line_t *l,
                                               uint32_t src_addr_network, uint32_t src_addr_host, uint8_t protocol)
{
    routing_context_t *route     = lineGetRoutingContext(l);
    ip_addr_t          src_ip    = {.type = IPADDR_TYPE_V4};
    ip_addr_t          dest_ip   = {.type = IPADDR_TYPE_V4};
    const uint16_t     src_port  = packetgeneratorSelectSourcePort(state, src_addr_host, protocol);
    const uint16_t     dest_port = packetgeneratorProtocolUsesPorts(protocol) ? state->dest_port : 0;

    src_ip.u_addr.ip4.addr  = src_addr_network;
    dest_ip.u_addr.ip4.addr = state->dest_addr_network;

    route->local_listener_port = 0;

    if (protocol == IP_PROTO_TCP || protocol == IP_PROTO_UDP || protocol == IP_PROTO_ICMP)
    {
        addresscontextSetIpPortProtocol(&route->src_ctx, &src_ip, src_port, protocol);
        addresscontextSetIpPortProtocol(&route->dest_ctx, &dest_ip, dest_port, protocol);
        return;
    }

    addresscontextSetIpPortProtocol(&route->src_ctx, &src_ip, 0, IP_PROTO_PACKET);
    addresscontextSetIpPortProtocol(&route->dest_ctx, &dest_ip, 0, IP_PROTO_PACKET);
}

static sbuf_t *packetgeneratorAllocPacketBuffer(line_t *l, uint16_t packet_len)
{
    buffer_pool_t *pool = lineGetBufferPool(l);
    sbuf_t        *buf  = NULL;

    if (packet_len <= bufferpoolGetSmallBufferSize(pool))
    {
        buf = bufferpoolGetSmallBuffer(pool);
    }
    else if (packet_len <= bufferpoolGetLargeBufferSize(pool))
    {
        buf = bufferpoolGetLargeBuffer(pool);
    }
    else
    {
        buf = sbufCreateWithPadding(packet_len, bufferpoolGetLargeBufferPadding(pool));
    }

    if (sbufGetMaximumWriteableSize(buf) < packet_len)
    {
        buf = sbufReserveSpace(buf, packet_len);
    }

    sbufSetLength(buf, packet_len);
    return buf;
}

static void packetgeneratorMarkWorkerComplete(packetgenerator_worker_state_t *slot)
{
    packetgenerator_tstate_t *state = tunnelGetState(slot->tunnel);
    const unsigned int     prev  = atomicIncRelaxed(&state->completed_workers);

    if (prev + 1U == (unsigned int) state->active_workers)
    {
        LOGI("PacketGenerator: finished transmitting %llu packets over %u ms",
             (unsigned long long) state->total_packets,
             (unsigned int) state->duration_ms);
    }
}

void packetgeneratorStopWorker(packetgenerator_worker_state_t *slot)
{
    assert(currentThreadOwnsWorker(slot->wid));

    slot->stopped = true;

    wtimer_t *timer = slot->timer;
    slot->timer     = NULL;
    if (timer != NULL)
    {
        weventSetUserData(timer, NULL);
        wtimerDelete(timer);
    }
}

static void packetgeneratorReportInitialTimerFailure(packetgenerator_worker_state_t *slot)
{
    if (UNLIKELY(! wloopNormalDispatchAllowed(getWorkerLoop(slot->wid))))
    {
        return;
    }
    LOGF("PacketGenerator: failed to create worker timer on worker %u", (unsigned int) slot->wid);
    if (! requestProgramShutdown(1))
    {
        abortProgramNow(1);
    }
}

static void packetgeneratorReportTimerRearmFailure(packetgenerator_worker_state_t *slot)
{
    if (UNLIKELY(! wloopNormalDispatchAllowed(getWorkerLoop(slot->wid))))
    {
        return;
    }
    LOGF("PacketGenerator: failed to rearm worker timer on worker %u", (unsigned int) slot->wid);
    if (! requestProgramShutdown(1))
    {
        abortProgramNow(1);
    }
}

static bool packetgeneratorArmWorkerTimer(packetgenerator_worker_state_t *slot, uint32_t delay_ms)
{
    assert(delay_ms > 0);

    if (slot->stopped)
    {
        return false;
    }

    if (slot->timer == NULL)
    {
        slot->timer = wtimerAdd(getWorkerLoop(slot->wid), packetgeneratorWorkerTimerCallback, delay_ms, 1);
        if (slot->timer == NULL)
        {
            packetgeneratorReportInitialTimerFailure(slot);
            return false;
        }

        weventSetUserData(slot->timer, slot);
        return true;
    }

    if (wtimerReset(slot->timer, delay_ms))
    {
        return true;
    }

    wtimer_t *timer = slot->timer;
    slot->timer     = NULL;
    weventSetUserData(timer, NULL);
    packetgeneratorReportTimerRearmFailure(slot);
    return false;
}

typedef enum
{
    kPacketGeneratorDeadlineReady,            // the deadline has passed, send now
    kPacketGeneratorDeadlineWaiting,          // the timer will resume this worker
    kPacketGeneratorDeadlineStopped,          // downstream closed, never send again
    kPacketGeneratorDeadlineShutdownRequested // the timer failed, stop sending
} packetgenerator_deadline_result_t;

static packetgenerator_deadline_result_t packetgeneratorWaitUntilDeadline(packetgenerator_worker_state_t *slot,
                                                                          uint32_t                        deadline_ms)
{
    packetgenerator_tstate_t *state      = tunnelGetState(slot->tunnel);
    const uint64_t            now_ms     = packetgeneratorNowMs();
    const uint64_t         elapsed_ms = (now_ms >= state->schedule_start_ms) ? (now_ms - state->schedule_start_ms) : 0;

    if (slot->stopped)
    {
        return kPacketGeneratorDeadlineStopped;
    }

    if (deadline_ms <= elapsed_ms)
    {
        return kPacketGeneratorDeadlineReady;
    }

    const uint64_t remaining_ms_u64 = (uint64_t) deadline_ms - elapsed_ms;
    const uint32_t remaining_ms     = (remaining_ms_u64 > UINT32_MAX) ? UINT32_MAX : (uint32_t) remaining_ms_u64;

    /*
     * Timer deadlines can fire a little early relative to our millisecond
     * schedule. Re-arm the same one-shot timer against the shared monotonic
     * start time so all workers stay aligned to the requested duration.
     */
    if (! packetgeneratorArmWorkerTimer(slot, (remaining_ms == 0U) ? 1U : remaining_ms))
    {
        if (slot->stopped)
        {
            return kPacketGeneratorDeadlineStopped;
        }
        return kPacketGeneratorDeadlineShutdownRequested;
    }

    return kPacketGeneratorDeadlineWaiting;
}

static void packetgeneratorSendReadyPackets(packetgenerator_worker_state_t *slot)
{
    packetgenerator_tstate_t *state = tunnelGetState(slot->tunnel);

    while (! slot->stopped && slot->next_packet_index < slot->packet_index_end)
    {
        const uint64_t current_index       = slot->next_packet_index;
        const uint32_t current_deadline_ms = packetgeneratorGlobalDeadlineMs(state, current_index);
        const uint8_t *packet_ptr          = NULL;
        uint16_t       packet_len          = 0;
        uint32_t       src_addr_network    = 0;
        uint32_t       src_addr_host       = 0;
        uint8_t        protocol            = 0;

        // Both "waiting" and "shutdown requested" must stop this loop: only a
        // reached deadline may resolve a packet view or advance the index.
        if (packetgeneratorWaitUntilDeadline(slot, current_deadline_ms) != kPacketGeneratorDeadlineReady)
        {
            return;
        }

        packetgeneratorResolvePacketView(
            state, current_index, &packet_ptr, &packet_len, &src_addr_network, &src_addr_host, &protocol);

        sbuf_t *buf = packetgeneratorAllocPacketBuffer(slot->line, packet_len);
        memoryCopy(sbufGetMutablePtr(buf), packet_ptr, packet_len);

        packetgeneratorApplyRoutingContext(state, slot->line, src_addr_network, src_addr_host, protocol);

        if (! lineCallWithRefWithBuf(slot->line, tunnelNextUpStreamPayload, slot->tunnel, buf))
        {
            LOGF("PacketGenerator: worker packet line died during payload send");
            abortProgramNow(1);
        }

        slot->next_packet_index = current_index + 1U;
        if (slot->stopped)
        {
            return;
        }
    }

    if (slot->stopped)
    {
        return;
    }

    slot->timer = NULL;
    packetgeneratorMarkWorkerComplete(slot);
}

void packetgeneratorPrepareRuntime(tunnel_t *t)
{
    packetgenerator_tstate_t *state            = tunnelGetState(t);
    tunnel_chain_t        *chain            = tunnelGetChain(t);
    size_t                 bytes_per_source = 0;

    if (t->next == NULL)
    {
        LOGF("PacketGenerator: must have a next tunnel");
        startupFailureRecord(1);
        return;
    }

    if (chain == NULL || chain->packet_lines == NULL)
    {
        LOGF("PacketGenerator: packet lines are required for this layer-3 chain head");
        startupFailureRecord(1);
        return;
    }

    if (chain->workers_count == 0)
    {
        LOGF("PacketGenerator: the chain has zero workers");
        startupFailureRecord(1);
        return;
    }

    if (state->packets_per_ip == 0)
    {
        LOGF("PacketGenerator: internal error, packets-per-ip is zero");
        startupFailureRecord(1);
        return;
    }

    if (state->protocol_mode == kPacketGeneratorProtocolAll)
    {
        uint32_t running_offset = 0;

        for (uint32_t protocol = 0; protocol < kPacketGeneratorProtocolsPerSource; ++protocol)
        {
            const uint16_t packet_len         = packetgeneratorStoredLengthForProtocol((uint8_t) protocol);
            state->protocol_lengths[protocol] = packet_len;
            state->protocol_offsets[protocol] = running_offset;
            running_offset += packet_len;
        }

        state->protocol_offsets[kPacketGeneratorProtocolsPerSource] = running_offset;
        state->bytes_per_source_repeat                           = running_offset;
    }
    else
    {
        state->fixed_packet_length =
            packetgeneratorStoredLengthForProtocol(packetgeneratorGetSingleProtocolNumber(state));
        state->bytes_per_source_repeat = state->fixed_packet_length;
    }

    if (state->bytes_per_source_repeat == 0)
    {
        LOGF("PacketGenerator: internal error, computed zero bytes per source repeat");
        startupFailureRecord(1);
        return;
    }

    if (state->packets_per_ip > 1U && state->bytes_per_source_repeat > (SIZE_MAX / (size_t) state->packets_per_ip))
    {
        LOGF("PacketGenerator: generated packet store exceeds addressable memory");
        startupFailureRecord(1);
        return;
    }

    bytes_per_source        = state->bytes_per_source_repeat * (size_t) state->packets_per_ip;
    state->bytes_per_source = bytes_per_source;

    if (state->source_count > 0 && bytes_per_source > (SIZE_MAX / (size_t) state->source_count))
    {
        LOGF("PacketGenerator: generated packet store exceeds addressable memory");
        startupFailureRecord(1);
        return;
    }

    state->total_packet_bytes = (size_t) state->source_count * bytes_per_source;

    {
        uint64_t packets_per_source = (uint64_t) state->packets_per_ip;

        if (state->protocol_mode == kPacketGeneratorProtocolAll)
        {
            if (packets_per_source > (UINT64_MAX / kPacketGeneratorProtocolsPerSource))
            {
                LOGF("PacketGenerator: total packet count would overflow");
                startupFailureRecord(1);
                return;
            }

            packets_per_source *= kPacketGeneratorProtocolsPerSource;
        }

        if (state->source_count > (UINT64_MAX / packets_per_source))
        {
            LOGF("PacketGenerator: total packet count would overflow");
            startupFailureRecord(1);
            return;
        }

        state->total_packets = state->source_count * packets_per_source;
    }

    if (state->total_packet_bytes == 0 || state->total_packets == 0)
    {
        LOGF("PacketGenerator: internal error, computed zero packets or zero bytes per source");
        startupFailureRecord(1);
        return;
    }
    const uint64_t total_packet_bytes_u64 = (uint64_t) state->total_packet_bytes;

    if (total_packet_bytes_u64 > kPacketGeneratorMaxMaterializedBytes)
    {
        LOGF("PacketGenerator: generated packet store needs %llu bytes, exceeding the %llu-byte safety cap; shrink "
             "source-ipv4-range or split traffic across multiple PacketGenerator nodes",
             (unsigned long long) total_packet_bytes_u64,
             (unsigned long long) kPacketGeneratorMaxMaterializedBytes);
        startupFailureRecord(1);
        return;
    }

    state->packet_bytes = memoryAllocate(state->total_packet_bytes);
    for (uint64_t source_index = 0; source_index < state->source_count; ++source_index)
    {
        uint32_t src_addr_host    = 0;
        uint32_t src_addr_network = 0;
        uint8_t *source_base      = state->packet_bytes + ((size_t) source_index * state->bytes_per_source);

        packetgeneratorResolveSourceAddress(state, source_index, &src_addr_host, &src_addr_network);

        for (uint32_t repeat = 0; repeat < state->packets_per_ip; ++repeat)
        {
            uint8_t *repeat_base = source_base + ((size_t) repeat * state->bytes_per_source_repeat);

            if (state->protocol_mode == kPacketGeneratorProtocolAll)
            {
                for (uint32_t protocol = 0; protocol < kPacketGeneratorProtocolsPerSource; ++protocol)
                {
                    packetgeneratorBuildPacketForProtocol(state,
                                                          repeat_base + state->protocol_offsets[protocol],
                                                          src_addr_host,
                                                          src_addr_network,
                                                          (uint8_t) protocol);
                }
            }
            else
            {
                packetgeneratorBuildPacketForProtocol(
                    state, repeat_base, src_addr_host, src_addr_network, packetgeneratorGetSingleProtocolNumber(state));
            }
        }
    }

    state->workers_count = chain->workers_count;
    state->workers        = memoryAllocateZero(sizeof(*state->workers) * state->workers_count);
    state->active_workers = state->workers_count;

    uint64_t       start_index = 0;
    const uint64_t base_count  = state->total_packets / state->workers_count;
    const uint64_t extra       = state->total_packets % state->workers_count;

    for (wid_t wi = 0; wi < state->workers_count; ++wi)
    {
        const uint64_t               assigned = base_count + ((wi < extra) ? 1ULL : 0ULL);
        packetgenerator_worker_state_t *slot     = &state->workers[wi];

        slot->tunnel             = t;
        slot->wid                = wi;
        slot->packet_index_begin = start_index;
        slot->packet_index_end   = start_index + assigned;
        slot->next_packet_index  = start_index;

        start_index += assigned;
    }

    LOGI("PacketGenerator: prepared %llu IPv4 packets (%llu bytes) across %u workers for %u ms",
         (unsigned long long) state->total_packets,
         (unsigned long long) state->total_packet_bytes,
         (unsigned int) state->workers_count,
         (unsigned int) state->duration_ms);
}

void packetgeneratorStartWorker(void *worker_ptr, void *arg1, void *arg2, void *arg3)
{
    worker_t                    *worker = worker_ptr;
    tunnel_t                    *t      = arg1;
    packetgenerator_tstate_t       *state  = tunnelGetState(t);
    packetgenerator_worker_state_t *slot   = &state->workers[worker->wid];

    discard arg2;
    discard arg3;

    if (UNLIKELY(slot->stopped))
    {
        return;
    }

    slot->line = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), worker->wid);
    if (slot->line == NULL || ! lineIsAlive(slot->line))
    {
        LOGF("PacketGenerator: worker %u packet line is not available", (unsigned int) worker->wid);
        abortProgramNow(1);
    }

    if (slot->packet_index_begin == slot->packet_index_end)
    {
        packetgeneratorMarkWorkerComplete(slot);
        return;
    }

    slot->next_packet_index = slot->packet_index_begin;
    packetgeneratorSendReadyPackets(slot);
}

void packetgeneratorWorkerTimerCallback(wtimer_t *timer)
{
    packetgenerator_worker_state_t *slot = weventGetUserdata(timer);
    assert(slot != NULL && slot->timer == timer && ! slot->stopped);

    packetgeneratorSendReadyPackets(slot);
}

void packetgeneratorHandleUnexpectedDownstreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    lineReuseBuffer(l, buf);
}
