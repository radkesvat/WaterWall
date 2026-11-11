#include "structure.h"

#include "loggers/network_logger.h"

static bool packetTransform(tunnel_t *t, line_t *l, sbuf_t **buf, bool upstream)
{
    assert(lineIsOnCurrentWorker(l));
    assert(tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l));
    encryptionclient_tstate_t       *ts     = tunnelGetState(t);
    const bool                       encode = upstream;
    const uint8_t                   *key    = upstream ? ts->key : ts->packet_download_key;
    const size_t                     input_bytes = sbufGetLength(*buf);
    const encryption_packet_result_t result =
        encode ? encryptionEncodePacket(key, buf) : encryptionDecodePacket(key, *buf);
    if (result != kEncryptionPacketOk)
    {
        if (atomicLogRateLimiterShouldLog(&ts->packet_drop_log_limiter, 1000))
            LOGW("EncryptionClient: dropping packet during %s: %s (input_packet_bytes=%zu, "
                 "protocol_packet_limit_bytes=%u, encryption_overhead_bytes=%u)",
                 encode ? "encryption" : "decryption",
                 encryptionPacketResultName(result),
                 input_bytes,
                 (unsigned) kEncryptionPacketMaxLength,
                 (unsigned) kEncryptionPacketOverhead);
        lineReuseBuffer(l, *buf);
        return false;
    }
    return true;
}

void encryptionclientPacketUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    if (packetTransform(t, l, &buf, true))
        tunnelNextUpStreamPayload(t, l, buf);
}

void encryptionclientPacketDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    if (packetTransform(t, l, &buf, false))
        tunnelPrevDownStreamPayload(t, l, buf);
}
