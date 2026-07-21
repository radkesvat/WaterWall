#include "structure.h"

#include "loggers/network_logger.h"

enum frame_read_result_e
{
    kFrameReadNeedMore = 0,
    kFrameReadOk       = 1,
    kFrameReadInvalid  = -1,
};

static int tryReadCompleteFrame(buffer_stream_t *stream, const encryptionclient_tstate_t *ts, sbuf_t **frame_buffer)
{
    if (bufferstreamGetBufLen(stream) < kEncryptionTlsHeaderSize)
    {
        return kFrameReadNeedMore;
    }

    uint8_t header[kEncryptionTlsHeaderSize];
    bufferstreamViewBytesAt(stream, 0, header, sizeof(header));

    if (header[0] != kEncryptionTlsApplicationData || header[1] != kEncryptionTlsVersionMajor ||
        header[2] != kEncryptionTlsVersionMinor)
    {
        return kFrameReadInvalid;
    }

    uint32_t body_len = ((uint32_t) header[3] << 8) | (uint32_t) header[4];
    if (body_len < kEncryptionNonceSize + kEncryptionTagSize ||
        body_len > ts->max_frame_payload + kEncryptionNonceSize + kEncryptionTagSize ||
        body_len > kEncryptionMaxTlsRecordBody)
    {
        return kFrameReadInvalid;
    }

    uint32_t frame_len = kEncryptionTlsHeaderSize + body_len;
    if (frame_len > bufferstreamGetBufLen(stream))
    {
        return kFrameReadNeedMore;
    }

    *frame_buffer = bufferstreamReadExact(stream, frame_len);
    return kFrameReadOk;
}

static bool isOverflow(buffer_stream_t *read_stream, const encryptionclient_tstate_t *ts)
{
    size_t max_frame = (size_t) ts->max_frame_payload + kEncryptionTagSize + kEncryptionFramePrefixSize;
    size_t limit     = max_frame * 2;

    if (bufferstreamGetBufLen(read_stream) > limit)
    {
        LOGW("EncryptionClient: DownStreamPayload: read stream overflow, size: %zu, limit: %zu",
             bufferstreamGetBufLen(read_stream),
             limit);
        return true;
    }
    return false;
}

void encryptionclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    encryptionclient_tstate_t *ts = tunnelGetState(t);
    encryptionclient_lstate_t *ls = lineGetState(l, t);

    bufferstreamPush(&(ls->read_stream), buf);

    while (true)
    {
        sbuf_t *frame_buffer = NULL;
        int     read_result  = tryReadCompleteFrame(&(ls->read_stream), ts, &frame_buffer);

        if (read_result == kFrameReadNeedMore)
        {
            break;
        }

        if (read_result == kFrameReadInvalid)
        {
            LOGW("EncryptionClient: invalid encrypted frame received, closing line");
            bufferstreamEmpty(&(ls->read_stream));
            encryptionclientCloseLineBidirectional(t, l);
            return;
        }

        uint8_t *frame = sbufGetMutablePtr(frame_buffer);

        uint32_t body_len       = ((uint32_t) frame[3] << 8) | (uint32_t) frame[4];
        uint32_t ciphertext_len = body_len - kEncryptionNonceSize;

        uint8_t *nonce      = frame + kEncryptionTlsHeaderSize;
        uint8_t *ciphertext = frame + kEncryptionFramePrefixSize;

        size_t plaintext_capacity = sbufGetMaximumWriteableSize(frame_buffer) - kEncryptionFramePrefixSize;
        if (encryptionclientDecryptAead(ts->algorithm,
                                        ciphertext,
                                        plaintext_capacity,
                                        ciphertext,
                                        ciphertext_len,
                                        frame,
                                        kEncryptionTlsHeaderSize,
                                        nonce,
                                        ts->key) != kWCryptoOk)
        {
            LOGW("EncryptionClient: failed to decrypt frame, closing line");
            lineReuseBuffer(l, frame_buffer);
            bufferstreamEmpty(&(ls->read_stream));
            encryptionclientCloseLineBidirectional(t, l);
            return;
        }

        sbufShiftRight(frame_buffer, kEncryptionFramePrefixSize);
        sbufSetLength(frame_buffer, ciphertext_len - kEncryptionTagSize);

        if (! withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, frame_buffer))
        {
            return;
        }
    }

    if (isOverflow(&(ls->read_stream), ts))
    {
        bufferstreamEmpty(&(ls->read_stream));
        encryptionclientCloseLineBidirectional(t, l);
    }
}
