#include "structure.h"

#include "loggers/network_logger.h"

static uint32_t packetsenderMix32(uint32_t value)
{
    value ^= value >> 16;
    value *= 0x7feb352du;
    value ^= value >> 15;
    value *= 0x846ca68bu;
    value ^= value >> 16;
    return value;
}

static bool packetsenderProtocolUsesPorts(uint8_t protocol)
{
    return protocol == IP_PROTO_TCP || protocol == IP_PROTO_UDP;
}

static uint8_t packetsenderGetSingleProtocolNumber(const packetsender_tstate_t *state)
{
    switch (state->protocol_mode)
    {
    case kPacketSenderProtocolTcp:
        return IP_PROTO_TCP;
    case kPacketSenderProtocolUdp:
        return IP_PROTO_UDP;
    case kPacketSenderProtocolIcmp:
        return IP_PROTO_ICMP;
    default:
        LOGF("PacketSender: internal error, invalid single-protocol mode %u", (unsigned int) state->protocol_mode);
        terminateProgram(1);
        return 0;
    }
}

static uint16_t packetsenderStoredLengthForProtocol(uint8_t protocol)
{
    switch (protocol)
    {
    case IP_PROTO_TCP:
        return kPacketSenderTcpPacketLength;
    case IP_PROTO_UDP:
        return kPacketSenderUdpPacketLength;
    case IP_PROTO_ICMP:
        return kPacketSenderIcmpPacketLength;
    default:
        return kPacketSenderGenericPacketLength;
    }
}

static void packetsenderResolveSourceAddress(const packetsender_tstate_t *state, uint64_t source_index,
                                             uint32_t *src_addr_host_out, uint32_t *src_addr_network_out)
{
    uint64_t remaining = source_index;

    for (uint32_t ri = 0; ri < state->source_range_count; ++ri)
    {
        const packetsender_source_range_t *range = &state->source_ranges[ri];

        if (remaining < range->count)
        {
            const uint32_t src_addr_host = range->base_host + (uint32_t) remaining;
            *src_addr_host_out           = src_addr_host;
            *src_addr_network_out        = lwip_htonl(src_addr_host);
            return;
        }

        remaining -= range->count;
    }

    LOGF("PacketSender: internal error, source index %llu is out of range", (unsigned long long) source_index);
    terminateProgram(1);
}

static uint16_t packetsenderSelectSourcePort(const packetsender_tstate_t *state, uint32_t src_addr_host,
                                             uint8_t protocol)
{
    if (! packetsenderProtocolUsesPorts(protocol))
    {
        return 0;
    }

    if (! state->src_port_random)
    {
        return state->src_port;
    }

    const uint32_t seed = packetsenderMix32(src_addr_host ^ state->dest_addr_host ^ (((uint32_t) protocol) << 24));
    return (uint16_t) (kPacketSenderRandomPortMin + (seed % kPacketSenderRandomPortSpan));
}

static uint16_t packetsenderPacketIdFromSeed(uint32_t seed)
{
    uint16_t packet_id = (uint16_t) (seed ^ (seed >> 16));
    return (packet_id == 0) ? 1U : packet_id;
}

static uint64_t packetsenderNowMs(void)
{
    return getHRTimeUs() / 1000U;
}

static void packetsenderInitIpv4Header(struct ip_hdr *ipheader, uint16_t packet_len, uint16_t packet_id,
                                       uint8_t protocol, uint32_t src_addr_network, uint32_t dest_addr_network)
{
    memoryZero(ipheader, kPacketSenderIpv4HeaderLength);

    IPH_VHL_SET(ipheader, 4, kPacketSenderIpv4HeaderLength / 4U);
    IPH_TOS_SET(ipheader, 0);
    IPH_LEN_SET(ipheader, lwip_htons(packet_len));
    IPH_ID_SET(ipheader, lwip_htons(packet_id));
    IPH_OFFSET_SET(ipheader, lwip_htons(IP_DF));
    IPH_TTL_SET(ipheader, kPacketSenderDefaultTtl);
    IPH_PROTO_SET(ipheader, protocol);
    IPH_CHKSUM_SET(ipheader, 0);
    ipheader->src.addr  = src_addr_network;
    ipheader->dest.addr = dest_addr_network;
}

static void packetsenderBuildTcpPacket(const packetsender_tstate_t *state, uint8_t *packet, uint32_t src_addr_host,
                                       uint32_t src_addr_network)
{
    const uint32_t  seed      = packetsenderMix32(src_addr_host ^ state->dest_addr_host ^ 0xC001D00Du);
    const uint16_t  src_port  = packetsenderSelectSourcePort(state, src_addr_host, IP_PROTO_TCP);
    struct ip_hdr  *ipheader  = (struct ip_hdr *) packet;
    struct tcp_hdr *tcpheader = (struct tcp_hdr *) (packet + kPacketSenderIpv4HeaderLength);

    memoryZero(packet, kPacketSenderTcpPacketLength);

    packetsenderInitIpv4Header(ipheader,
                               kPacketSenderTcpPacketLength,
                               packetsenderPacketIdFromSeed(seed),
                               IP_PROTO_TCP,
                               src_addr_network,
                               state->dest_addr_network);

    tcpheader->src   = lwip_htons(src_port);
    tcpheader->dest  = lwip_htons(state->dest_port);
    tcpheader->seqno = lwip_htonl(packetsenderMix32(seed ^ 0x13579bdfu));
    tcpheader->ackno = lwip_htonl(packetsenderMix32(seed ^ 0x2468ace0u) | 1U);
    TCPH_HDRLEN_FLAGS_SET(tcpheader, kPacketSenderTcpHeaderLength / 4U, TCP_ACK);
    tcpheader->wnd  = lwip_htons(64240U);
    tcpheader->urgp = 0;

    calcFullPacketChecksum(packet);
}

static void packetsenderBuildUdpPacket(const packetsender_tstate_t *state, uint8_t *packet, uint32_t src_addr_host,
                                       uint32_t src_addr_network)
{
    const uint32_t  seed      = packetsenderMix32(src_addr_host ^ state->dest_addr_host ^ 0x55aa10ffu);
    const uint16_t  src_port  = packetsenderSelectSourcePort(state, src_addr_host, IP_PROTO_UDP);
    struct ip_hdr  *ipheader  = (struct ip_hdr *) packet;
    struct udp_hdr *udpheader = (struct udp_hdr *) (packet + kPacketSenderIpv4HeaderLength);

    memoryZero(packet, kPacketSenderUdpPacketLength);

    packetsenderInitIpv4Header(ipheader,
                               kPacketSenderUdpPacketLength,
                               packetsenderPacketIdFromSeed(seed),
                               IP_PROTO_UDP,
                               src_addr_network,
                               state->dest_addr_network);

    udpheader->src  = lwip_htons(src_port);
    udpheader->dest = lwip_htons(state->dest_port);
    udpheader->len  = lwip_htons(kPacketSenderUdpHeaderLength);

    calcFullPacketChecksum(packet);
}

static void packetsenderBuildIcmpPacket(const packetsender_tstate_t *state, uint8_t *packet, uint32_t src_addr_host,
                                        uint32_t src_addr_network)
{
    const uint32_t        seed       = packetsenderMix32(src_addr_host ^ state->dest_addr_host ^ 0xa11ce55eu);
    struct ip_hdr        *ipheader   = (struct ip_hdr *) packet;
    struct icmp_echo_hdr *icmpheader = (struct icmp_echo_hdr *) (packet + kPacketSenderIpv4HeaderLength);

    memoryZero(packet, kPacketSenderIcmpPacketLength);

    packetsenderInitIpv4Header(ipheader,
                               kPacketSenderIcmpPacketLength,
                               packetsenderPacketIdFromSeed(seed),
                               IP_PROTO_ICMP,
                               src_addr_network,
                               state->dest_addr_network);

    ICMPH_TYPE_SET(icmpheader, ICMP_ECHO);
    ICMPH_CODE_SET(icmpheader, 0);
    icmpheader->id    = lwip_htons((uint16_t) seed);
    icmpheader->seqno = lwip_htons((uint16_t) (seed >> 16));

    calcFullPacketChecksum(packet);
}

static void packetsenderBuildGenericPacket(const packetsender_tstate_t *state, uint8_t *packet, uint32_t src_addr_host,
                                           uint32_t src_addr_network, uint8_t protocol)
{
    const uint32_t seed =
        packetsenderMix32(src_addr_host ^ state->dest_addr_host ^ (((uint32_t) protocol) << 24) ^ 0x91e10da5u);
    struct ip_hdr *ipheader = (struct ip_hdr *) packet;
    uint8_t       *payload  = packet + kPacketSenderIpv4HeaderLength;

    memoryZero(packet, kPacketSenderGenericPacketLength);

    packetsenderInitIpv4Header(ipheader,
                               kPacketSenderGenericPacketLength,
                               packetsenderPacketIdFromSeed(seed),
                               protocol,
                               src_addr_network,
                               state->dest_addr_network);

    for (uint32_t i = 0; i < kPacketSenderGenericPayloadLength; ++i)
    {
        const uint32_t mixed = packetsenderMix32(seed + i);
        payload[i]           = (uint8_t) (mixed & 0xFFU);
    }

    calcFullPacketChecksum(packet);
}

static void packetsenderBuildPacketForProtocol(const packetsender_tstate_t *state, uint8_t *packet,
                                               uint32_t src_addr_host, uint32_t src_addr_network, uint8_t protocol)
{
    switch (protocol)
    {
    case IP_PROTO_TCP:
        packetsenderBuildTcpPacket(state, packet, src_addr_host, src_addr_network);
        return;
    case IP_PROTO_UDP:
        packetsenderBuildUdpPacket(state, packet, src_addr_host, src_addr_network);
        return;
    case IP_PROTO_ICMP:
        packetsenderBuildIcmpPacket(state, packet, src_addr_host, src_addr_network);
        return;
    default:
        packetsenderBuildGenericPacket(state, packet, src_addr_host, src_addr_network, protocol);
        return;
    }
}

static uint32_t packetsenderGlobalDeadlineMs(const packetsender_tstate_t *state, uint64_t packet_index)
{
    if (state->total_packets <= 1U)
    {
        return 0;
    }

    return (uint32_t) ((packet_index * (uint64_t) state->duration_ms) / (state->total_packets - 1U));
}

static void packetsenderResolvePacketView(const packetsender_tstate_t *state, uint64_t packet_index,
                                          const uint8_t **packet_ptr_out, uint16_t *packet_len_out,
                                          uint32_t *src_addr_network_out, uint32_t *src_addr_host_out,
                                          uint8_t *protocol_out)
{
    uint64_t source_index;
    size_t   offset;
    uint8_t  protocol;
    uint16_t packet_len;

    if (state->protocol_mode == kPacketSenderProtocolAll)
    {
        const uint64_t packets_per_source =
            (uint64_t) state->packets_per_ip * (uint64_t) kPacketSenderProtocolsPerSource;
        const uint64_t source_repeat_index = packet_index % packets_per_source;
        const uint32_t repeat_index        = (uint32_t) (source_repeat_index / kPacketSenderProtocolsPerSource);
        const uint32_t protocol_index      = (uint32_t) (source_repeat_index % kPacketSenderProtocolsPerSource);

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
        protocol     = packetsenderGetSingleProtocolNumber(state);
        packet_len   = state->fixed_packet_length;
        offset       = ((size_t) source_index * state->bytes_per_source) +
                 ((size_t) repeat_index * state->bytes_per_source_repeat);
    }

    uint32_t src_addr_host    = 0;
    uint32_t src_addr_network = 0;

    packetsenderResolveSourceAddress(state, source_index, &src_addr_host, &src_addr_network);

    *packet_ptr_out       = state->packet_bytes + offset;
    *packet_len_out       = packet_len;
    *src_addr_network_out = src_addr_network;
    *src_addr_host_out    = src_addr_host;
    *protocol_out         = protocol;
}

static void packetsenderApplyRoutingContext(const packetsender_tstate_t *state, line_t *l, uint32_t src_addr_network,
                                            uint32_t src_addr_host, uint8_t protocol)
{
    routing_context_t *route     = lineGetRoutingContext(l);
    ip_addr_t          src_ip    = {.type = IPADDR_TYPE_V4};
    ip_addr_t          dest_ip   = {.type = IPADDR_TYPE_V4};
    const uint16_t     src_port  = packetsenderSelectSourcePort(state, src_addr_host, protocol);
    const uint16_t     dest_port = packetsenderProtocolUsesPorts(protocol) ? state->dest_port : 0;

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

static sbuf_t *packetsenderAllocPacketBuffer(line_t *l, uint16_t packet_len)
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

static void packetsenderMarkWorkerComplete(packetsender_worker_state_t *slot)
{
    packetsender_tstate_t *state = tunnelGetState(slot->tunnel);
    const unsigned int     prev  = atomicIncRelaxed(&state->completed_workers);

    if (prev + 1U == (unsigned int) state->active_workers)
    {
        LOGI("PacketSender: finished transmitting %llu packets over %u ms",
             (unsigned long long) state->total_packets,
             (unsigned int) state->duration_ms);
    }
}

static void packetsenderArmWorkerTimer(packetsender_worker_state_t *slot, uint32_t delay_ms)
{
    assert(delay_ms > 0);

    if (slot->timer == NULL)
    {
        slot->timer = wtimerAdd(getWorkerLoop(slot->wid), packetsenderWorkerTimerCallback, delay_ms, 1);
        if (slot->timer == NULL)
        {
            LOGF("PacketSender: failed to create worker timer on worker %u", (unsigned int) slot->wid);
            terminateProgram(1);
            return;
        }

        weventSetUserData(slot->timer, slot);
        return;
    }

    wtimerReset(slot->timer, delay_ms);
}

static bool packetsenderWaitUntilDeadline(packetsender_worker_state_t *slot, uint32_t deadline_ms)
{
    packetsender_tstate_t *state      = tunnelGetState(slot->tunnel);
    const uint64_t         now_ms     = packetsenderNowMs();
    const uint64_t         elapsed_ms = (now_ms >= state->schedule_start_ms) ? (now_ms - state->schedule_start_ms) : 0;

    if (deadline_ms <= elapsed_ms)
    {
        return false;
    }

    const uint64_t remaining_ms_u64 = (uint64_t) deadline_ms - elapsed_ms;
    const uint32_t remaining_ms     = (remaining_ms_u64 > UINT32_MAX) ? UINT32_MAX : (uint32_t) remaining_ms_u64;

    /*
     * Timer deadlines can fire a little early relative to our millisecond
     * schedule. Re-arm the same one-shot timer against the shared monotonic
     * start time so all workers stay aligned to the requested duration.
     */
    packetsenderArmWorkerTimer(slot, (remaining_ms == 0U) ? 1U : remaining_ms);
    return true;
}

static void packetsenderSendReadyPackets(packetsender_worker_state_t *slot)
{
    packetsender_tstate_t *state = tunnelGetState(slot->tunnel);

    while (slot->next_packet_index < slot->packet_index_end)
    {
        const uint64_t current_index       = slot->next_packet_index;
        const uint32_t current_deadline_ms = packetsenderGlobalDeadlineMs(state, current_index);
        const uint8_t *packet_ptr          = NULL;
        uint16_t       packet_len          = 0;
        uint32_t       src_addr_network    = 0;
        uint32_t       src_addr_host       = 0;
        uint8_t        protocol            = 0;

        if (packetsenderWaitUntilDeadline(slot, current_deadline_ms))
        {
            return;
        }

        packetsenderResolvePacketView(
            state, current_index, &packet_ptr, &packet_len, &src_addr_network, &src_addr_host, &protocol);

        sbuf_t *buf = packetsenderAllocPacketBuffer(slot->line, packet_len);
        memoryCopy(sbufGetMutablePtr(buf), packet_ptr, packet_len);

        packetsenderApplyRoutingContext(state, slot->line, src_addr_network, src_addr_host, protocol);
        lineSetRecalculateChecksum(slot->line, false);

        if (! withLineLockedWithBuf(slot->line, tunnelNextUpStreamPayload, slot->tunnel, buf))
        {
            LOGF("PacketSender: worker packet line died during payload send");
            terminateProgram(1);
            return;
        }

        slot->next_packet_index = current_index + 1U;
    }

    slot->timer = NULL;
    packetsenderMarkWorkerComplete(slot);
}

void packetsenderPrepareRuntime(tunnel_t *t)
{
    packetsender_tstate_t *state            = tunnelGetState(t);
    tunnel_chain_t        *chain            = tunnelGetChain(t);
    size_t                 bytes_per_source = 0;

    if (t->next == NULL)
    {
        LOGF("PacketSender: must have a next tunnel");
        terminateProgram(1);
    }

    if (chain == NULL || chain->packet_lines == NULL)
    {
        LOGF("PacketSender: packet lines are required for this layer-3 chain head");
        terminateProgram(1);
    }

    if (chain->workers_count == 0)
    {
        LOGF("PacketSender: the chain has zero workers");
        terminateProgram(1);
    }

    if (state->packets_per_ip == 0)
    {
        LOGF("PacketSender: internal error, packets-per-ip is zero");
        terminateProgram(1);
    }

    if (state->protocol_mode == kPacketSenderProtocolAll)
    {
        uint32_t running_offset = 0;

        for (uint32_t protocol = 0; protocol < kPacketSenderProtocolsPerSource; ++protocol)
        {
            const uint16_t packet_len         = packetsenderStoredLengthForProtocol((uint8_t) protocol);
            state->protocol_lengths[protocol] = packet_len;
            state->protocol_offsets[protocol] = running_offset;
            running_offset += packet_len;
        }

        state->protocol_offsets[kPacketSenderProtocolsPerSource] = running_offset;
        state->bytes_per_source_repeat                           = running_offset;
    }
    else
    {
        state->fixed_packet_length = packetsenderStoredLengthForProtocol(packetsenderGetSingleProtocolNumber(state));
        state->bytes_per_source_repeat = state->fixed_packet_length;
    }

    if (state->bytes_per_source_repeat == 0)
    {
        LOGF("PacketSender: internal error, computed zero bytes per source repeat");
        terminateProgram(1);
    }

    if (state->packets_per_ip > 1U && state->bytes_per_source_repeat > (SIZE_MAX / (size_t) state->packets_per_ip))
    {
        LOGF("PacketSender: generated packet store exceeds addressable memory");
        terminateProgram(1);
    }

    bytes_per_source        = state->bytes_per_source_repeat * (size_t) state->packets_per_ip;
    state->bytes_per_source = bytes_per_source;

    if (state->source_count > 0 && bytes_per_source > (SIZE_MAX / (size_t) state->source_count))
    {
        LOGF("PacketSender: generated packet store exceeds addressable memory");
        terminateProgram(1);
    }

    state->total_packet_bytes = (size_t) state->source_count * bytes_per_source;

    {
        uint64_t packets_per_source = (uint64_t) state->packets_per_ip;

        if (state->protocol_mode == kPacketSenderProtocolAll)
        {
            if (packets_per_source > (UINT64_MAX / kPacketSenderProtocolsPerSource))
            {
                LOGF("PacketSender: total packet count would overflow");
                terminateProgram(1);
            }

            packets_per_source *= kPacketSenderProtocolsPerSource;
        }

        if (state->source_count > (UINT64_MAX / packets_per_source))
        {
            LOGF("PacketSender: total packet count would overflow");
            terminateProgram(1);
        }

        state->total_packets = state->source_count * packets_per_source;
    }

    if (state->total_packet_bytes == 0 || state->total_packets == 0)
    {
        LOGF("PacketSender: internal error, computed zero packets or zero bytes per source");
        terminateProgram(1);
    }
    const uint64_t total_packet_bytes_u64 = (uint64_t) state->total_packet_bytes;

    if (total_packet_bytes_u64 > kPacketSenderMaxMaterializedBytes)
    {
        LOGF("PacketSender: generated packet store needs %llu bytes, exceeding the %llu-byte safety cap; shrink "
             "source-ip4-range or split traffic across multiple PacketSender nodes",
             (unsigned long long) total_packet_bytes_u64,
             (unsigned long long) kPacketSenderMaxMaterializedBytes);
        terminateProgram(1);
    }

    state->packet_bytes = memoryAllocate(state->total_packet_bytes);

    for (uint64_t source_index = 0; source_index < state->source_count; ++source_index)
    {
        uint32_t src_addr_host    = 0;
        uint32_t src_addr_network = 0;
        uint8_t *source_base      = state->packet_bytes + ((size_t) source_index * state->bytes_per_source);

        packetsenderResolveSourceAddress(state, source_index, &src_addr_host, &src_addr_network);

        for (uint32_t repeat = 0; repeat < state->packets_per_ip; ++repeat)
        {
            uint8_t *repeat_base = source_base + ((size_t) repeat * state->bytes_per_source_repeat);

            if (state->protocol_mode == kPacketSenderProtocolAll)
            {
                for (uint32_t protocol = 0; protocol < kPacketSenderProtocolsPerSource; ++protocol)
                {
                    packetsenderBuildPacketForProtocol(state,
                                                       repeat_base + state->protocol_offsets[protocol],
                                                       src_addr_host,
                                                       src_addr_network,
                                                       (uint8_t) protocol);
                }
            }
            else
            {
                packetsenderBuildPacketForProtocol(
                    state, repeat_base, src_addr_host, src_addr_network, packetsenderGetSingleProtocolNumber(state));
            }
        }
    }

    state->workers_count  = chain->workers_count;
    state->workers        = memoryAllocateZero(sizeof(*state->workers) * state->workers_count);
    state->active_workers = state->workers_count;

    uint64_t       start_index = 0;
    const uint64_t base_count  = state->total_packets / state->workers_count;
    const uint64_t extra       = state->total_packets % state->workers_count;

    for (wid_t wi = 0; wi < state->workers_count; ++wi)
    {
        const uint64_t               assigned = base_count + ((wi < extra) ? 1ULL : 0ULL);
        packetsender_worker_state_t *slot     = &state->workers[wi];

        slot->tunnel             = t;
        slot->wid                = wi;
        slot->packet_index_begin = start_index;
        slot->packet_index_end   = start_index + assigned;
        slot->next_packet_index  = start_index;

        start_index += assigned;
    }

    LOGI("PacketSender: prepared %llu IPv4 packets (%llu bytes) across %u workers for %u ms",
         (unsigned long long) state->total_packets,
         (unsigned long long) state->total_packet_bytes,
         (unsigned int) state->workers_count,
         (unsigned int) state->duration_ms);
}

void packetsenderStartWorker(void *worker_ptr, void *arg1, void *arg2, void *arg3)
{
    worker_t                    *worker = worker_ptr;
    tunnel_t                    *t      = arg1;
    packetsender_tstate_t       *state  = tunnelGetState(t);
    packetsender_worker_state_t *slot   = &state->workers[worker->wid];

    discard arg2;
    discard arg3;

    if (UNLIKELY(isApplicationTerminating()))
    {
        return;
    }

    slot->line = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), worker->wid);
    if (slot->line == NULL || ! lineIsAlive(slot->line))
    {
        LOGF("PacketSender: worker %u packet line is not available", (unsigned int) worker->wid);
        terminateProgram(1);
        return;
    }

    if (slot->packet_index_begin == slot->packet_index_end)
    {
        packetsenderMarkWorkerComplete(slot);
        return;
    }

    slot->next_packet_index = slot->packet_index_begin;
    packetsenderSendReadyPackets(slot);
}

void packetsenderWorkerTimerCallback(wtimer_t *timer)
{
    packetsender_worker_state_t *slot = weventGetUserdata(timer);
    if (slot == NULL || isApplicationTerminating())
    {
        return;
    }

    packetsenderSendReadyPackets(slot);
}

void packetsenderHandleUnexpectedDownstreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    lineReuseBuffer(l, buf);
}
