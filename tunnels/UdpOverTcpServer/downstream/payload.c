#include "structure.h"

#include "loggers/network_logger.h"

/* Encode all TCP fragments into one delivery so a re-entrant Pause cannot
 * interrupt a sequence of callbacks with an unowned remainder. UDP stays one
 * datagram per frame. */
static sbuf_t *encodeLargeTcpPayload(line_t *l, sbuf_t *buf)
{
    buffer_pool_t *pool        = lineGetBufferPool(l);
    const uint32_t length      = sbufGetLength(buf);
    const uint64_t frames      = ((uint64_t) length + kMaxAllowedUDPPacketLength - 1) / kMaxAllowedUDPPacketLength;
    const uint64_t wire_length = (uint64_t) length + frames * kHeaderSize;
    sbuf_t        *encoded     = bufferpoolTryGetBestFit(pool, wire_length, bufferpoolGetLargeBufferPadding(pool));
    if (UNLIKELY(encoded == NULL))
    {
        LOGE("UdpOverTcpServer: framed TCP payload exceeds buffer capacity");
        return NULL;
    }
    const uint8_t *source   = sbufGetRawPtr(buf);
    uint8_t       *target   = sbufGetMutablePtr(encoded);
    uint32_t       consumed = 0;
    while (consumed < length)
    {
        const uint16_t chunk          = (uint16_t) min(length - consumed, (uint32_t) kMaxAllowedUDPPacketLength);
        const uint16_t network_length = htons(chunk);
        memoryCopy(target, &network_length, kHeaderSize);
        memoryCopyLarge(target + kHeaderSize, source + consumed, chunk);
        target += kHeaderSize + chunk;
        consumed += chunk;
    }
    sbufSetLength(encoded, (uint32_t) wire_length);
    sbufTransferLifetime(buf, encoded);
    bufferpoolReuseBuffer(pool, buf);
    return encoded;
}

void udpovertcpserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    uint32_t packet_length = sbufGetLength(buf);

#ifdef DEBUG
    if (sbufGetLength(buf) <= 0)
    {
        LOGF("UdpOverTcpServer: Received empty payload, this is a bug, our eventloop logic dose not allow read of size "
             "0");
        lineReuseBuffer(l, buf);
        abortProgramNow(1);
    }
#endif

    if (packet_length > kMaxAllowedUDPPacketLength)
    {
        udpovertcpserver_lstate_t *ls = lineGetState(l, t);
        if (ls->tcp_mode)
        {
            sbuf_t *encoded = encodeLargeTcpPayload(l, buf);
            if (UNLIKELY(encoded == NULL))
            {
                lineReuseBuffer(l, buf);
                udpovertcpserverLinestateDestroy(ls);
                if (lineCallWithRef(l, tunnelNextUpStreamFinish, t))
                    tunnelPrevDownStreamFinish(t, l);
                return;
            }
            tunnelPrevDownStreamPayload(t, l, encoded);
            return;
        }
        LOGW("UdpOverTcpServer: Packet length exceeds maximum allowed size: %u > %u , dropped",
             packet_length,
             kMaxAllowedUDPPacketLength);
        lineReuseBuffer(l, buf);
        return;
    }
    // safely cast to uint16_t, since kMaxAllowedUDPPacketLength is lower than 65536
    uint16_t packet_length_network = htons(packet_length);

    sbufShiftLeft(buf, sizeof(uint16_t));
    // cant gurantee the alignment of the buffer, so we use unaligned write
    sbufWriteUnAlignedUI16(buf, packet_length_network);

    tunnelPrevDownStreamPayload(t, l, buf);
}
