#include "structure.h"

#include "loggers/network_logger.h"

bool streamtopacketsFrameMatchesFillByte(const sbuf_t *packet, uint8_t fill_byte)
{
    if (sbufGetLength(packet) != kSensitivePayloadSize)
    {
        return false;
    }

    const uint8_t *data = sbufGetRawPtr(packet);

    for (uint32_t i = 0; i < kSensitivePayloadSize; ++i)
    {
        if (data[i] != fill_byte)
        {
            return false;
        }
    }

    return true;
}

bool streamtopacketsReadStreamIsOverflowed(buffer_stream_t *read_stream)
{
    if (bufferstreamGetBufLen(read_stream) > kMaxBufferSize)
    {
        LOGW("StreamToPackets: read stream overflow, size: %zu, limit: %zu", bufferstreamGetBufLen(read_stream),
             (size_t) kMaxBufferSize);
        return true;
    }

    return false;
}

bool streamtopacketsTryReadIPv4Packet(buffer_stream_t *stream, sbuf_t **packet_out)
{
    assert(packet_out != NULL);
    *packet_out = NULL;

    if (bufferstreamGetBufLen(stream) < kHeaderSize + 1)
    {
        return false;
    }

    uint8_t packet_first_bytes[kHeaderSize];
    bufferstreamViewBytesAt(stream, 0, packet_first_bytes, kHeaderSize);

    uint16_t total_packet_size_network;
    sbufByteCopy(&total_packet_size_network, packet_first_bytes, (uint32_t) sizeof(total_packet_size_network));
    uint16_t total_packet_size = ntohs(total_packet_size_network);
    
    if (total_packet_size < 1 || ((uint32_t) (total_packet_size  + kHeaderSize)) > (uint32_t) bufferstreamGetBufLen(stream))
    {
        return false;
    }

    // Read the complete packet (header + payload)
    *packet_out = bufferstreamReadExact(stream, kHeaderSize + total_packet_size);
    sbufShiftRight(*packet_out, kHeaderSize);

    return true;

}

bool streamtopacketsSendSensitivePong(tunnel_t *t, line_t *stream_line)
{
    sbuf_t *buf = bufferpoolGetSmallBuffer(lineGetBufferPool(stream_line));

    if (sbufGetLeftCapacity(buf) < kHeaderSize)
    {
        LOGW("StreamToPackets: dropping sensitive-mode pong because left padding is smaller than header size");
        lineReuseBuffer(stream_line, buf);
        return true;
    }

    sbufSetLength(buf, kSensitivePayloadSize);
    memorySet(sbufGetMutablePtr(buf), kSensitivePongByte, kSensitivePayloadSize);

    sbufShiftLeft(buf, kHeaderSize);
    sbufWriteUnAlignedUI16(buf, htons((uint16_t) kSensitivePayloadSize));

    tunnelPrevDownStreamPayload(t, stream_line, buf);
    return lineIsAlive(stream_line);
}

