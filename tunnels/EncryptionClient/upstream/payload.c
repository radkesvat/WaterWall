#include "structure.h"

#include "loggers/network_logger.h"

void encryptionclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    encryptionclient_tstate_t *ts            = tunnelGetState(t);
    uint32_t                   plaintext_len = sbufGetLength(buf);

    if (plaintext_len == 0)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (plaintext_len > ts->max_frame_payload)
    {
        buffer_pool_t *pool      = lineGetBufferPool(l);
        const uint8_t *src       = sbufGetRawPtr(buf);
        uint32_t       remaining = plaintext_len;

        while (remaining > 0)
        {
            uint32_t chunk_len = min(remaining, ts->max_frame_payload);
            uint32_t frame_len = kEncryptionFramePrefixSize + chunk_len + kEncryptionTagSize;
            sbuf_t  *frame_buf = encryptionAllocFrameBuffer(pool, frame_len);

            sbufSetLength(frame_buf, chunk_len);
            memoryCopyLarge(sbufGetMutablePtr(frame_buf), src, chunk_len);

            if (encryptionEncodeFrame(ts->algorithm, ts->key, &frame_buf) != kWCryptoOk)
            {
                LOGW("EncryptionClient: failed to encrypt payload chunk, closing line");
                bufferpoolReuseBuffer(pool, frame_buf);
                bufferpoolReuseBuffer(pool, buf);
                encryptionclientCloseLineBidirectional(t, l);
                return;
            }

            src += chunk_len;
            remaining -= chunk_len;

            if (! lineCallWithRefWithBuf(l, tunnelNextUpStreamPayload, t, frame_buf))
            {
                bufferpoolReuseBuffer(pool, buf);
                return;
            }
        }

        lineReuseBuffer(l, buf);
        return;
    }

    if (encryptionEncodeFrame(ts->algorithm, ts->key, &buf) != kWCryptoOk)
    {
        LOGW("EncryptionClient: failed to encrypt payload, closing line");
        lineReuseBuffer(l, buf);
        encryptionclientCloseLineBidirectional(t, l);
        return;
    }

    tunnelNextUpStreamPayload(t, l, buf);
}
