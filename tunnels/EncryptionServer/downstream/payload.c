#include "structure.h"

#include "loggers/network_logger.h"

static sbuf_t *encryptionserverAllocFrameBuffer(buffer_pool_t *pool, uint32_t frame_len)
{
    uint32_t small_size = bufferpoolGetSmallBufferSize(pool);
    uint32_t large_size = bufferpoolGetLargeBufferSize(pool);

    if (frame_len <= small_size)
    {
        return bufferpoolGetSmallBuffer(pool);
    }

    if (frame_len <= large_size)
    {
        return bufferpoolGetLargeBuffer(pool);
    }

    return sbufCreateWithPadding(frame_len, bufferpoolGetLargeBufferPadding(pool));
}

static bool encryptionserverEncryptFrame(encryptionserver_tstate_t *ts, sbuf_t **buf, uint32_t plaintext_len)
{
    uint32_t ciphertext_len = plaintext_len + kEncryptionTagSize;
    uint32_t body_len       = kEncryptionNonceSize + ciphertext_len;
    uint32_t frame_len      = kEncryptionTlsHeaderSize + body_len;

    if (body_len > kEncryptionMaxTlsRecordBody)
    {
        return false;
    }

    if (sbufGetMaximumWriteableSize(*buf) < ciphertext_len)
    {
        *buf = sbufReserveSpace(*buf, ciphertext_len);
    }

    assert(sbufGetLeftCapacity(*buf) >= kEncryptionFramePrefixSize);

    sbufShiftLeft(*buf, kEncryptionFramePrefixSize);

    uint8_t *frame = sbufGetMutablePtr(*buf);
    frame[0]       = kEncryptionTlsApplicationData;
    frame[1]       = kEncryptionTlsVersionMajor;
    frame[2]       = kEncryptionTlsVersionMinor;
    frame[3]       = (uint8_t) (body_len >> 8);
    frame[4]       = (uint8_t) body_len;

    uint8_t *nonce = frame + kEncryptionTlsHeaderSize;
    if (UNLIKELY(! secureRandomBytes(nonce, kEncryptionNonceSize)))
    {
        return false;
    }

    uint8_t *ciphertext = frame + kEncryptionFramePrefixSize;

    size_t ciphertext_capacity = sbufGetMaximumWriteableSize(*buf) - kEncryptionFramePrefixSize;
    if (encryptionserverEncryptAead(ts->algorithm,
                                    ciphertext,
                                    ciphertext_capacity,
                                    ciphertext,
                                    plaintext_len,
                                    frame,
                                    kEncryptionTlsHeaderSize,
                                    nonce,
                                    ts->key) != kWCryptoOk)
    {
        return false;
    }

    sbufSetLength(*buf, frame_len);
    return true;
}

void encryptionserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    encryptionserver_tstate_t *ts            = tunnelGetState(t);
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
            sbuf_t  *frame_buf = encryptionserverAllocFrameBuffer(pool, frame_len);

            sbufSetLength(frame_buf, chunk_len);
            memoryCopyLarge(sbufGetMutablePtr(frame_buf), src, chunk_len);

            if (! encryptionserverEncryptFrame(ts, &frame_buf, chunk_len))
            {
                LOGW("EncryptionServer: failed to encrypt payload chunk, closing line");
                bufferpoolReuseBuffer(pool, frame_buf);
                bufferpoolReuseBuffer(pool, buf);
                encryptionserverCloseLineBidirectional(t, l);
                return;
            }

            src += chunk_len;
            remaining -= chunk_len;

            if (! withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, frame_buf))
            {
                bufferpoolReuseBuffer(pool, buf);
                return;
            }
        }

        lineReuseBuffer(l, buf);
        return;
    }

    if (! encryptionserverEncryptFrame(ts, &buf, plaintext_len))
    {
        LOGW("EncryptionServer: failed to encrypt payload, closing line");
        lineReuseBuffer(l, buf);
        encryptionserverCloseLineBidirectional(t, l);
        return;
    }

    if (! withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, buf))
    {
        return;
    }
}
