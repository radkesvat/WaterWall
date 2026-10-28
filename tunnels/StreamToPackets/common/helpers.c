#include "structure.h"

#include "Ipv4StreamCodec/codec.h"

#include "loggers/network_logger.h"

// Detects a heartbeat packet: a minimal IPv4 packet tagged with kHeartbeatProtocol whose payload
// is filled with fill_byte. Real traffic is extremely unlikely to collide with this signature.
bool streamtopacketsFrameMatchesFillByte(const sbuf_t *packet, uint8_t fill_byte)
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

_Static_assert((int) kStreamToPacketsPacketValidationNone == (int) kIpv4StreamValidationNone &&
                   (int) kStreamToPacketsPacketValidationLoose == (int) kIpv4StreamValidationLoose &&
                   (int) kStreamToPacketsPacketValidationHard == (int) kIpv4StreamValidationHard,
               "Node validation levels must match the shared IPv4 codec");

bool streamtopacketsValidatePacket(streamtopackets_packet_validation_level_t level, sbuf_t *packet,
                                   const char *direction)
{
    const ipv4stream_validation_level_t shared_level = (ipv4stream_validation_level_t) level;
    const char                         *reason       = ipv4streamValidatePacket(shared_level, packet);
    if (reason != NULL)
    {
        LOGW("StreamToPackets: dropping packet during %s packet validation (%s): %s",
             direction,
             ipv4streamValidationLevelName(shared_level),
             reason);
        return false;
    }
    return true;
}

bool streamtopacketsIsForwardableIpv4Packet(const sbuf_t *packet)
{
    return ipv4streamIsForwardablePacket(packet);
}

bool streamtopacketsTryReadIPv4Packet(buffer_stream_t *stream, sbuf_t **packet_out)
{
    return ipv4streamTryReadPacket(stream, packet_out);
}

/* Publish decoded bytes on the stream owner's packet line. A concurrent source
 * takeover can invalidate authorization before this boundary; recheck its token
 * immediately before the callback, without moving the borrowed normal line. */
void streamtopacketsForwardDecodedPacket(tunnel_t *t, line_t *stream_line, sbuf_t *packet, uint64_t generation)
{
    assert(lineIsOnCurrentWorker(stream_line));
    streamtopackets_tstate_t *ts          = tunnelGetState(t);
    line_t                   *packet_line = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), lineGetWID(stream_line));
    assert(packet_line != NULL);
    if (UNLIKELY(streamtopacketsPublishedGeneration(ts) != generation))
    {
        lineReuseBuffer(packet_line, packet);
        return;
    }
    tunnelNextUpStreamPayload(t, packet_line, packet);
}

// Builds and sends a heartbeat pong. The on-wire format is a raw concatenation of IPv4 packets, so
// the pong is itself a fully valid IPv4 packet tagged with kHeartbeatProtocol and a 0xDD payload.
bool streamtopacketsSendSensitivePong(tunnel_t *t, line_t *stream_line)
{
    buffer_pool_t *pool = lineGetBufferPool(stream_line);
    sbuf_t        *buf  = bufferpoolGetBestFit(pool, kHeartbeatPacketSize, bufferpoolGetLargeBufferPadding(pool));

    sbufSetLength(buf, kHeartbeatPacketSize);

    uint8_t *raw = sbufGetMutablePtr(buf);
    memoryZero(raw, IP_HLEN);

    struct ip_hdr *iphdr = (struct ip_hdr *) raw;
    IPH_VHL_SET(iphdr, 4, IP_HLEN / 4);
    IPH_LEN_SET(iphdr, lwip_htons((uint16_t) kHeartbeatPacketSize));
    IPH_TTL_SET(iphdr, 64);
    IPH_PROTO_SET(iphdr, kHeartbeatProtocol);
    IPH_CHKSUM_SET(iphdr, 0);
    IPH_CHKSUM_SET(iphdr, inet_chksum(iphdr, IP_HLEN));

    memorySet(raw + IP_HLEN, kSensitivePongByte, kSensitivePayloadSize);

    tunnelPrevDownStreamPayload(t, stream_line, buf);
    return lineIsAlive(stream_line);
}
