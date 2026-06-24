#include "structure.h"

#include "loggers/network_logger.h"

// Builds a self-contained, fully valid IPv4 heartbeat packet. Because the on-wire format is
// now a raw concatenation of IPv4 packets (no length prefix), control frames must themselves be
// valid IPv4 packets so the size-based extractor on the peer keeps its framing. The heartbeat is
// tagged with a reserved experimentation protocol number and a constant payload fill byte.
static sbuf_t *packetstostreamCreateHeartbeatPacket(line_t *packet_line, uint8_t fill_byte)
{
    sbuf_t *buf = bufferpoolGetSmallBuffer(lineGetBufferPool(packet_line));

    if (UNLIKELY(sbufGetMaximumWriteableSize(buf) < kHeartbeatPacketSize))
    {
        LOGW("PacketsToStream: dropping sensitive-mode control frame because the buffer is too small");
        lineReuseBuffer(packet_line, buf);
        return NULL;
    }

    sbufSetLength(buf, kHeartbeatPacketSize);

    uint8_t *raw = sbufGetMutablePtr(buf);
    memorySet(raw, 0, IP_HLEN);

    struct ip_hdr *iphdr = (struct ip_hdr *) raw;
    IPH_VHL_SET(iphdr, 4, IP_HLEN / 4);
    IPH_LEN_SET(iphdr, lwip_htons((uint16_t) kHeartbeatPacketSize));
    IPH_TTL_SET(iphdr, 64);
    IPH_PROTO_SET(iphdr, kHeartbeatProtocol);
    IPH_CHKSUM_SET(iphdr, 0);
    IPH_CHKSUM_SET(iphdr, inet_chksum(iphdr, IP_HLEN));

    memorySet(raw + IP_HLEN, fill_byte, kSensitivePayloadSize);

    return buf;
}

static void packetstostreamArmTimeoutTimer(tunnel_t *t, wid_t wid)
{
    packetstostream_tstate_t *ts         = tunnelGetState(t);
    wtimer_t                **timer_slot = &ts->worker_timeout_timers[wid];

    if (*timer_slot != NULL)
    {
        wtimerReset(*timer_slot, ts->tolerance_ms);
        return;
    }

    *timer_slot = wtimerAdd(getWorkerLoop(wid), packetstostreamTimeoutTimerCallback, ts->tolerance_ms, 1);
    if (*timer_slot == NULL)
    {
        LOGF("PacketsToStream: failed to create sensitive-mode timeout timer on worker %u", (unsigned int) wid);
        terminateProgram(1);
        return;
    }

    weventSetUserData(*timer_slot, t);
}

static void packetstostreamDisarmTimeoutTimer(tunnel_t *t, wid_t wid)
{
    packetstostream_tstate_t *ts = tunnelGetState(t);

    if (ts->worker_timeout_timers == NULL)
    {
        return;
    }

    wtimer_t **timer_slot = &ts->worker_timeout_timers[wid];

    if (*timer_slot == NULL)
    {
        return;
    }

    weventSetUserData(*timer_slot, NULL);
    wtimerDelete(*timer_slot);
    *timer_slot = NULL;
}

static bool packetstostreamSendSensitivePing(tunnel_t *t, line_t *packet_line, packetstostream_lstate_t *ls,
                                             line_t *stream_line)
{
    packetstostream_tstate_t *ts  = tunnelGetState(t);
    const uint64_t            now = wloopNowMS(getWorkerLoop(lineGetWID(packet_line)));
    sbuf_t                   *buf = packetstostreamCreateHeartbeatPacket(packet_line, kSensitivePingByte);
    if (buf == NULL)
    {
        return true;
    }

    ls->awaiting_pong    = true;
    ls->ping_sent_at_ms  = now;
    ls->pong_deadline_ms = now + ts->tolerance_ms;
    packetstostreamArmTimeoutTimer(t, lineGetWID(packet_line));

    if (withLineLockedWithBuf(stream_line, tunnelNextUpStreamPayload, t, buf))
    {
        return true;
    }

    if (ls->line == stream_line)
    {
        packetstostreamResetOutputLineState(t, packet_line, ls);
        packetstostreamScheduleRecreateOutputLine(t, packet_line, ls);
    }

    return false;
}

// Detects a heartbeat packet produced by packetstostreamCreateHeartbeatPacket / the peer's
// equivalent: a minimal IPv4 packet tagged with kHeartbeatProtocol whose payload is filled with
// fill_byte. Real traffic is extremely unlikely to collide with this signature.
bool packetstostreamFrameMatchesFillByte(const sbuf_t *packet, uint8_t fill_byte)
{
    if (sbufGetLength(packet) != kHeartbeatPacketSize)
    {
        return false;
    }

    const uint8_t *data = sbufGetRawPtr(packet);

    if ((data[0] >> 4) != 4 || (data[0] & 0x0FU) != (IP_HLEN / 4) || data[9] != kHeartbeatProtocol)
    {
        return false;
    }

    const uint8_t *payload = data + IP_HLEN;
    for (uint32_t i = 0; i < kSensitivePayloadSize; ++i)
    {
        if (payload[i] != fill_byte)
        {
            return false;
        }
    }

    return true;
}

bool packetstostreamReadStreamIsOverflowed(buffer_stream_t *read_stream)
{
    if (bufferstreamGetBufLen(read_stream) > kMaxBufferSize)
    {
        LOGW("PacketsToStream: read stream overflow, size: %zu, limit: %zu",
             bufferstreamGetBufLen(read_stream),
             (size_t) kMaxBufferSize);
        return true;
    }

    return false;
}

static const char *packetstostreamValidationLevelName(packetstostream_packet_validation_level_t level)
{
    switch (level)
    {
    case kPacketsToStreamPacketValidationNone:
        return "none";
    case kPacketsToStreamPacketValidationLoose:
        return "loose";
    case kPacketsToStreamPacketValidationHard:
        return "hard";
    default:
        return "unknown";
    }
}

static bool packetstostreamDropInvalidPacket(packetstostream_packet_validation_level_t level, const char *direction,
                                             const char *reason)
{
    LOGW("PacketsToStream: dropping packet during %s packet validation (%s): %s",
         direction,
         packetstostreamValidationLevelName(level),
         reason);
    return false;
}

static uint32_t packetstostreamChecksumPseudoHeader(const struct ip_hdr *iphdr, uint8_t proto, uint16_t length)
{
    uint32_t sum   = 0;
    uint32_t src_h = lwip_ntohl(iphdr->src.addr);
    uint32_t dst_h = lwip_ntohl(iphdr->dest.addr);

    sum += (src_h >> 16) & 0xFFFFU;
    sum += src_h & 0xFFFFU;
    sum += (dst_h >> 16) & 0xFFFFU;
    sum += dst_h & 0xFFFFU;
    sum += proto;
    sum += length;

    return sum;
}

static bool packetstostreamValidateIpv4PacketHeader(packetstostream_packet_validation_level_t level, sbuf_t *packet,
                                                    const char *direction, struct ip_hdr **iphdr_out,
                                                    uint16_t *header_len_out, uint16_t *total_len_out)
{
    uint32_t packet_len = sbufGetLength(packet);

    if (packet_len < sizeof(struct ip_hdr))
    {
        return packetstostreamDropInvalidPacket(level, direction, "packet is smaller than the IPv4 header");
    }

    struct ip_hdr *iphdr = (struct ip_hdr *) sbufGetMutablePtr(packet);
    if (IPH_V(iphdr) != 4)
    {
        return packetstostreamDropInvalidPacket(level, direction, "unsupported IP version");
    }

    uint16_t header_len = IPH_HL_BYTES(iphdr);
    if (header_len < IP_HLEN || header_len > IP_HLEN_MAX)
    {
        return packetstostreamDropInvalidPacket(level, direction, "invalid IPv4 header length");
    }

    if (header_len > packet_len)
    {
        return packetstostreamDropInvalidPacket(level, direction, "buffer is shorter than the IPv4 header length");
    }

    uint16_t total_len = lwip_ntohs(IPH_LEN(iphdr));
    if (total_len < header_len)
    {
        return packetstostreamDropInvalidPacket(level, direction, "IPv4 total length is smaller than the header");
    }

    if (total_len < packet_len)
    {
        return packetstostreamDropInvalidPacket(
            level, direction, "IPv4 total length is smaller than the packet buffer");
    }

    if (total_len > packet_len)
    {
        return packetstostreamDropInvalidPacket(level, direction, "buffer is shorter than the IPv4 total length");
    }

    *iphdr_out      = iphdr;
    *header_len_out = header_len;
    *total_len_out  = total_len;
    return true;
}

static bool packetstostreamValidateIpv4HeaderChecksum(packetstostream_packet_validation_level_t level,
                                                      struct ip_hdr *iphdr, uint16_t header_len, const char *direction)
{
    uint16_t original_checksum = IPH_CHKSUM(iphdr);

    IPH_CHKSUM_SET(iphdr, 0);
    uint16_t expected_checksum = inet_chksum(iphdr, header_len);
    IPH_CHKSUM_SET(iphdr, original_checksum);

    if (original_checksum != expected_checksum)
    {
        return packetstostreamDropInvalidPacket(level, direction, "invalid IPv4 header checksum");
    }

    return true;
}

static bool packetstostreamValidateTcpChecksum(packetstostream_packet_validation_level_t level, struct ip_hdr *iphdr,
                                               uint16_t header_len, uint16_t total_len, const char *direction)
{
    uint16_t transport_len = (uint16_t) (total_len - header_len);
    if (transport_len < TCP_HLEN)
    {
        return packetstostreamDropInvalidPacket(level, direction, "TCP packet is smaller than the minimum header");
    }

    uint8_t        *transport = ((uint8_t *) iphdr) + header_len;
    struct tcp_hdr *tcphdr    = (struct tcp_hdr *) transport;
    uint16_t        tcp_hlen  = TCPH_HDRLEN_BYTES(tcphdr);

    if (tcp_hlen < TCP_HLEN || tcp_hlen > transport_len)
    {
        return packetstostreamDropInvalidPacket(level, direction, "invalid TCP header length");
    }

    uint16_t original_checksum = tcphdr->chksum;
    tcphdr->chksum             = 0;
    uint16_t expected_checksum = calcGenericChecksum(
        transport, transport_len, packetstostreamChecksumPseudoHeader(iphdr, IP_PROTO_TCP, transport_len));
    tcphdr->chksum = original_checksum;

    if (original_checksum != expected_checksum)
    {
        return packetstostreamDropInvalidPacket(level, direction, "invalid TCP checksum");
    }

    return true;
}

static bool packetstostreamValidateUdpChecksum(packetstostream_packet_validation_level_t level, struct ip_hdr *iphdr,
                                               uint16_t header_len, uint16_t total_len, const char *direction)
{
    uint16_t transport_len = (uint16_t) (total_len - header_len);
    if (transport_len < UDP_HLEN)
    {
        return packetstostreamDropInvalidPacket(level, direction, "UDP packet is smaller than the minimum header");
    }

    uint8_t        *transport = ((uint8_t *) iphdr) + header_len;
    struct udp_hdr *udphdr    = (struct udp_hdr *) transport;
    uint16_t        udp_len   = lwip_ntohs(udphdr->len);

    if (udp_len < UDP_HLEN || udp_len > transport_len)
    {
        return packetstostreamDropInvalidPacket(level, direction, "invalid UDP length");
    }

    if (udphdr->chksum == 0)
    {
        return true;
    }

    uint16_t original_checksum = udphdr->chksum;
    udphdr->chksum             = 0;
    uint16_t expected_checksum =
        calcGenericChecksum(transport, udp_len, packetstostreamChecksumPseudoHeader(iphdr, IP_PROTO_UDP, udp_len));
    udphdr->chksum = original_checksum;

    if (expected_checksum == 0)
    {
        expected_checksum = 0xFFFFU;
    }

    if (original_checksum != expected_checksum)
    {
        return packetstostreamDropInvalidPacket(level, direction, "invalid UDP checksum");
    }

    return true;
}

static bool packetstostreamValidateIcmpChecksum(packetstostream_packet_validation_level_t level, struct ip_hdr *iphdr,
                                                uint16_t header_len, uint16_t total_len, const char *direction)
{
    uint16_t transport_len = (uint16_t) (total_len - header_len);
    if (transport_len < sizeof(struct icmp_hdr))
    {
        return packetstostreamDropInvalidPacket(level, direction, "ICMP packet is smaller than the minimum header");
    }

    uint8_t         *transport = ((uint8_t *) iphdr) + header_len;
    struct icmp_hdr *icmphdr   = (struct icmp_hdr *) transport;

    uint16_t original_checksum = icmphdr->chksum;
    icmphdr->chksum            = 0;
    uint16_t expected_checksum = calcGenericChecksum(transport, transport_len, 0);
    icmphdr->chksum            = original_checksum;

    if (original_checksum != expected_checksum)
    {
        return packetstostreamDropInvalidPacket(level, direction, "invalid ICMP checksum");
    }

    return true;
}

bool packetstostreamValidatePacket(packetstostream_packet_validation_level_t level, sbuf_t *packet,
                                   const char *direction)
{
    if (level == kPacketsToStreamPacketValidationNone)
    {
        return true;
    }

    struct ip_hdr *iphdr      = NULL;
    uint16_t       header_len = 0;
    uint16_t       total_len  = 0;

    if (! packetstostreamValidateIpv4PacketHeader(level, packet, direction, &iphdr, &header_len, &total_len))
    {
        return false;
    }

    if (level == kPacketsToStreamPacketValidationLoose)
    {
        return true;
    }

    if (! packetstostreamValidateIpv4HeaderChecksum(level, iphdr, header_len, direction))
    {
        return false;
    }

    uint16_t frag_field = lwip_ntohs(IPH_OFFSET(iphdr));
    if ((frag_field & (IP_MF | IP_OFFMASK)) != 0)
    {
        return true;
    }

    switch (IPH_PROTO(iphdr))
    {
    case IP_PROTO_TCP:
        return packetstostreamValidateTcpChecksum(level, iphdr, header_len, total_len, direction);
    case IP_PROTO_UDP:
        return packetstostreamValidateUdpChecksum(level, iphdr, header_len, total_len, direction);
    case IP_PROTO_ICMP:
        return packetstostreamValidateIcmpChecksum(level, iphdr, header_len, total_len, direction);
    default:
        return true;
    }
}

void packetstostreamRecalculateChecksumIfRequested(line_t *l, sbuf_t *buf)
{
    if (! lineGetRecalculateChecksum(l))
    {
        return;
    }

    if (sbufGetLength(buf) >= sizeof(struct ip_hdr))
    {
        struct ip_hdr *ipheader = (struct ip_hdr *) sbufGetMutablePtr(buf);

        if (IPH_V(ipheader) == 4)
        {
            calcFullPacketChecksum(sbufGetMutablePtr(buf));
        }
    }

    lineSetRecalculateChecksum(l, false);
}

// Light, never-trusting structural check on a candidate IPv4 header (at least IP_HLEN bytes).
// This intentionally stays cheaper than the "loose" validation level: it only proves the head
// could be an IPv4 packet whose declared size is internally consistent and within the pipeline
// packet bound, so we know how many bytes a single packet would consume.
static inline bool packetstostreamIpv4HeaderLooksValid(const uint8_t *header, uint16_t *total_len_out)
{
    const uint8_t  version    = (uint8_t) (header[0] >> 4);
    const uint8_t  header_len  = (uint8_t) ((header[0] & 0x0FU) * 4U);
    const uint16_t total_len   = (uint16_t) (((uint16_t) header[2] << 8) | (uint16_t) header[3]);

    *total_len_out = total_len;

    return version == 4 && header_len >= IP_HLEN && total_len >= header_len &&
           total_len <= (uint16_t) kMaxAllowedPacketLength;
}

// Drops leading bytes that cannot begin a valid IPv4 packet so the parser re-synchronizes on a
// garbage stream. It scans a bounded window for the next structurally-plausible IPv4 start and
// discards everything before it in one shot; if none is found it drops the inspected region while
// keeping the trailing bytes that might still be an incomplete header. Forward progress (>= 1
// byte) is always guaranteed, so no data pattern can stall the parser.
static void packetstostreamDropResyncBytes(buffer_stream_t *stream)
{
    const size_t buffered = bufferstreamGetBufLen(stream);
    const size_t window   = buffered < (size_t) kResyncScanWindow ? buffered : (size_t) kResyncScanWindow;

    uint8_t scan[kResyncScanWindow];
    bufferstreamViewBytesAt(stream, 0, scan, window);

    size_t found = 0; // offset 0 is the head we already rejected
    for (size_t i = 1; i + (size_t) IP_HLEN <= window; ++i)
    {
        uint16_t total_len;
        if (packetstostreamIpv4HeaderLooksValid(scan + i, &total_len))
        {
            found = i;
            break;
        }
    }

    const size_t drop = (found > 0) ? found : (window - ((size_t) IP_HLEN - 1));

    sbuf_t *dropped = bufferstreamReadExact(stream, drop);
    bufferpoolReuseBuffer(stream->pool, dropped);
}

// Validates an outgoing packet on the framing path. These adapters are IPv4-only, so non-IPv4
// (including IPv6) payloads are dropped. The IPv4 total length must also match the buffer length,
// otherwise forwarding it would desynchronize the size-based extractor on the peer.
bool packetstostreamIsForwardableIpv4Packet(const sbuf_t *packet)
{
    const uint32_t len = sbufGetLength(packet);

    if (UNLIKELY(len < IP_HLEN || len > (uint32_t) kMaxAllowedPacketLength))
    {
        return false;
    }

    const struct ip_hdr *iphdr = (const struct ip_hdr *) sbufGetRawPtr(packet);

    if (UNLIKELY(IPH_V(iphdr) != 4))
    {
        return false;
    }

    return LIKELY(lwip_ntohs(IPH_LEN(iphdr)) == (uint16_t) len);
}

// Extracts exactly one IPv4 packet from the stream using the IPv4 total-length field as the frame
// size. Garbage is tolerated: a structurally-invalid head triggers re-synchronization, and a head
// that merely looks valid is trusted (worst case forwards a garbage-sized packet until the stream
// happens to realign). The stream is never trusted enough to read out of bounds or stall.
bool packetstostreamTryReadIPv4Packet(buffer_stream_t *stream, sbuf_t **packet_out)
{
    assert(packet_out != NULL);
    *packet_out = NULL;

    while (true)
    {
        const size_t buffered = bufferstreamGetBufLen(stream);

        // Need a full minimum IPv4 header before any size field can be trusted.
        if (buffered < (size_t) IP_HLEN)
        {
            return false;
        }

        uint8_t header[IP_HLEN];
        bufferstreamViewBytesAt(stream, 0, header, IP_HLEN);

        uint16_t total_len;
        if (LIKELY(packetstostreamIpv4HeaderLooksValid(header, &total_len)))
        {
            if (buffered < (size_t) total_len)
            {
                // Valid head, but the rest of the packet has not arrived yet.
                return false;
            }

            *packet_out = bufferstreamReadExact(stream, total_len);
            return true;
        }

        // IPv6 / garbage / inconsistent head: re-synchronize and retry.
        packetstostreamDropResyncBytes(stream);
    }
}

void packetstostreamScheduleRecreateOutputLine(tunnel_t *t, line_t *packet_line, packetstostream_lstate_t *ls)
{
    if (ls->recreate_scheduled)
    {
        return;
    }

    ls->recreate_scheduled = true;
    lineScheduleTask(packet_line, packetstostreamRecreateOutputLineTask, t);
}

void packetstostreamResetOutputLineState(tunnel_t *t, line_t *packet_line, packetstostream_lstate_t *ls)
{
    ls->line             = NULL;
    ls->paused           = false;
    ls->awaiting_pong    = false;
    ls->ping_sent_at_ms  = 0;
    ls->pong_deadline_ms = 0;

    packetstostreamDisarmTimeoutTimer(t, lineGetWID(packet_line));

    if (ls->read_stream.pool != NULL)
    {
        bufferstreamEmpty(&ls->read_stream);
    }
}

void packetstostreamCloseOutputLineAndScheduleRecreate(tunnel_t *t, line_t *packet_line, packetstostream_lstate_t *ls)
{
    LOGW("PacketsToStream: closing output line and scheduling recreate, packet_line: %p, current stream_line: %p",
         packet_line,
         ls->line);
    line_t *stream_line = ls->line;

    packetstostreamResetOutputLineState(t, packet_line, ls);

    if (stream_line != NULL && lineIsAlive(stream_line))
    {
        lineLock(stream_line);
        tunnelNextUpStreamFinish(t, stream_line);
        if (lineIsAlive(stream_line))
        {
            lineDestroy(stream_line);
        }
        lineUnlock(stream_line);
    }

    packetstostreamScheduleRecreateOutputLine(t, packet_line, ls);
}

void packetstostreamRecreateOutputLineTask(tunnel_t *t, line_t *packet_line)
{
    packetstostream_lstate_t *ls = lineGetState(packet_line, t);

    if (! ls->recreate_scheduled)
    {
        return;
    }

    ls->recreate_scheduled = false;
    packetstostreamEnsureOutputLine(t, packet_line, ls);
}

line_t *packetstostreamEnsureOutputLine(tunnel_t *t, line_t *packet_line, packetstostream_lstate_t *ls)
{
    if (ls->read_stream.pool == NULL)
    {
        packetstostreamLinestateInitialize(ls, lineGetBufferPool(packet_line));
    }

    if (ls->line != NULL && lineIsAlive(ls->line))
    {
        return ls->line;
    }

    if (ls->recreate_scheduled)
    {
        return NULL;
    }

    ls->line   = NULL;
    ls->paused = false;
    bufferstreamEmpty(&ls->read_stream);

    line_t *new_line = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(packet_line));
    ls->line         = new_line;

    if (! withLineLocked(new_line, tunnelNextUpStreamInit, t))
    {
        if (ls->line == new_line)
        {
            ls->line = NULL;
        }
        return ls->line;
    }

    return ls->line;
}

void packetstostreamHeartbeatTimerCallback(wtimer_t *timer)
{
    tunnel_t *t = weventGetUserdata(timer);
    if (t == NULL || isApplicationTerminating())
    {
        return;
    }

    packetstostream_tstate_t *ts = tunnelGetState(t);
    if (! ts->sensitive_mode)
    {
        return;
    }

    line_t *packet_line = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), getWID());
    if (packet_line == NULL || ! lineIsAlive(packet_line))
    {
        return;
    }

    packetstostream_lstate_t *ls = lineGetState(packet_line, t);
    if (ls->read_stream.pool == NULL)
    {
        return;
    }

    if (ls->awaiting_pong)
    {
        return;
    }

    line_t *stream_line = packetstostreamEnsureOutputLine(t, packet_line, ls);
    if (stream_line == NULL)
    {
        return;
    }

    discard packetstostreamSendSensitivePing(t, packet_line, ls, stream_line);
}

void packetstostreamTimeoutTimerCallback(wtimer_t *timer)
{
    tunnel_t *t = weventGetUserdata(timer);
    if (t == NULL || isApplicationTerminating())
    {
        return;
    }

    packetstostream_tstate_t *ts  = tunnelGetState(t);
    const wid_t               wid = getWID();

    line_t *packet_line = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), getWID());
    if (packet_line == NULL || ! lineIsAlive(packet_line))
    {
        ts->worker_timeout_timers[wid] = NULL;
        return;
    }

    packetstostream_lstate_t *ls = lineGetState(packet_line, t);
    if (! ls->awaiting_pong)
    {
        ts->worker_timeout_timers[wid] = NULL;
        return;
    }

    const uint64_t now = wloopNowMS(getWorkerLoop(lineGetWID(packet_line)));
    if (now < ls->pong_deadline_ms)
    {
        const uint64_t remaining_ms_u64 = ls->pong_deadline_ms - now;
        const uint32_t remaining_ms     = (remaining_ms_u64 > UINT32_MAX) ? UINT32_MAX : (uint32_t) remaining_ms_u64;

        /*
         * The event loop can schedule timeout callbacks slightly before the
         * exact millisecond deadline because timer deadlines are tracked in
         * microseconds but some timeout values are rounded to coarser buckets.
         * Re-arm the same one-shot timer instead of clearing the slot, otherwise
         * awaiting_pong could remain stuck forever after a lost ping.
         */
        wtimerReset(timer, (remaining_ms == 0) ? 1U : remaining_ms);
        return;
    }

    ts->worker_timeout_timers[wid] = NULL;
    const uint64_t elapsed_ms =
        (ls->ping_sent_at_ms > 0 && now >= ls->ping_sent_at_ms) ? (now - ls->ping_sent_at_ms) : ts->tolerance_ms;

    LOGW("PacketsToStream: sensitive-mode ping timed out after %llums (limit=%u ms), resetting connection",
         (unsigned long long) elapsed_ms,
         (unsigned int) ts->tolerance_ms);
    packetstostreamCloseOutputLineAndScheduleRecreate(t, packet_line, ls);
}
