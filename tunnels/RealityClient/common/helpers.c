#include "structure.h"

#include "loggers/network_logger.h"

enum frame_read_result_e
{
    kRealityFrameNeedMore = 0,
    kRealityFrameOk       = 1,
    kRealityFrameInvalid  = -1,
};

static sbuf_t *realityclientAllocFrameBuffer(buffer_pool_t *pool, uint32_t frame_len)
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

static bool realityclientEncryptFrame(realityclient_tstate_t *ts, sbuf_t **buf, uint32_t plaintext_len)
{
    uint32_t ciphertext_len = plaintext_len + kRealityClientTagSize;
    uint32_t body_len       = kRealityClientNonceSize + ciphertext_len;
    uint32_t frame_len      = kRealityClientTlsHeaderSize + body_len;

    if (sbufGetMaximumWriteableSize(*buf) < ciphertext_len)
    {
        *buf = sbufReserveSpace(*buf, ciphertext_len);
    }

    assert(sbufGetLeftCapacity(*buf) >= kRealityClientFramePrefixSize);
    sbufShiftLeft(*buf, kRealityClientFramePrefixSize);

    uint8_t *frame = sbufGetMutablePtr(*buf);
    frame[0]       = kRealityClientTlsApplicationData;
    frame[1]       = kRealityClientTlsVersionMajor;
    frame[2]       = kRealityClientTlsVersionMinor;
    frame[3]       = (uint8_t) (body_len >> 8);
    frame[4]       = (uint8_t) body_len;

    uint8_t *nonce = frame + kRealityClientTlsHeaderSize;
    getRandomBytes(nonce, kRealityClientNonceSize);

    uint8_t *ciphertext = frame + kRealityClientFramePrefixSize;
    if (0 != realityclientEncryptAead(ts->algorithm, ciphertext, ciphertext, plaintext_len, frame,
                                      kRealityClientTlsHeaderSize, nonce, ts->key))
    {
        return false;
    }

    sbufSetLength(*buf, frame_len);
    return true;
}

static int realityclientTryReadCompleteFrame(buffer_stream_t *stream, const realityclient_tstate_t *ts,
                                             sbuf_t **frame_buffer)
{
    if (bufferstreamGetBufLen(stream) < kRealityClientTlsHeaderSize)
    {
        return kRealityFrameNeedMore;
    }

    uint8_t header[kRealityClientTlsHeaderSize];
    bufferstreamViewBytesAt(stream, 0, header, sizeof(header));

    if (header[0] != kRealityClientTlsApplicationData || header[1] != kRealityClientTlsVersionMajor ||
        header[2] != kRealityClientTlsVersionMinor)
    {
        return kRealityFrameInvalid;
    }

    uint32_t body_len = ((uint32_t) header[3] << 8) | (uint32_t) header[4];
    if (body_len < kRealityClientNonceSize + kRealityClientTagSize ||
        body_len > ts->max_frame_payload + kRealityClientNonceSize + kRealityClientTagSize ||
        body_len > kRealityClientMaxTlsRecordBody)
    {
        return kRealityFrameInvalid;
    }

    uint32_t frame_len = kRealityClientTlsHeaderSize + body_len;
    if (bufferstreamGetBufLen(stream) < frame_len)
    {
        return kRealityFrameNeedMore;
    }

    *frame_buffer = bufferstreamReadExact(stream, frame_len);
    return kRealityFrameOk;
}

bool realityclientEncryptAndSend(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    realityclient_tstate_t *ts            = tunnelGetState(t);
    uint32_t                plaintext_len = sbufGetLength(buf);

    if (plaintext_len == 0)
    {
        lineReuseBuffer(l, buf);
        return true;
    }

    if (plaintext_len > ts->max_frame_payload)
    {
        buffer_pool_t *pool      = lineGetBufferPool(l);
        const uint8_t *src       = sbufGetRawPtr(buf);
        uint32_t       remaining = plaintext_len;

        while (remaining > 0)
        {
            uint32_t chunk_len = min(remaining, ts->max_frame_payload);
            uint32_t frame_len = kRealityClientFramePrefixSize + chunk_len + kRealityClientTagSize;
            sbuf_t  *frame_buf = realityclientAllocFrameBuffer(pool, frame_len);

            sbufSetLength(frame_buf, chunk_len);
            memoryCopyLarge(sbufGetMutablePtr(frame_buf), src, chunk_len);

            if (! realityclientEncryptFrame(ts, &frame_buf, chunk_len))
            {
                LOGW("RealityClient: failed to encrypt payload chunk");
                bufferpoolReuseBuffer(pool, frame_buf);
                bufferpoolReuseBuffer(pool, buf);
                realityclientCloseLineBidirectional(t, l);
                return false;
            }

            src += chunk_len;
            remaining -= chunk_len;

            if (! withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, frame_buf))
            {
                bufferpoolReuseBuffer(pool, buf);
                return false;
            }
        }

        lineReuseBuffer(l, buf);
        return true;
    }

    if (! realityclientEncryptFrame(ts, &buf, plaintext_len))
    {
        LOGW("RealityClient: failed to encrypt payload");
        lineReuseBuffer(l, buf);
        realityclientCloseLineBidirectional(t, l);
        return false;
    }

    return withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, buf);
}

bool realityclientProcessDownstream(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    realityclient_tstate_t *ts = tunnelGetState(t);
    realityclient_lstate_t *ls = lineGetState(l, t);

    if (buf != NULL)
    {
        bufferstreamPush(&ls->read_stream, buf);
    }

    while (true)
    {
        sbuf_t *frame_buffer = NULL;
        int     read_result  = realityclientTryReadCompleteFrame(&ls->read_stream, ts, &frame_buffer);

        if (read_result == kRealityFrameNeedMore)
        {
            return true;
        }

        if (read_result == kRealityFrameInvalid)
        {
            LOGW("RealityClient: invalid Reality record received");
            bufferstreamEmpty(&ls->read_stream);
            realityclientCloseLineBidirectional(t, l);
            return false;
        }

        uint8_t *frame    = sbufGetMutablePtr(frame_buffer);
        uint32_t body_len = ((uint32_t) frame[3] << 8) | (uint32_t) frame[4];
        uint32_t ciphertext_len = body_len - kRealityClientNonceSize;

        uint8_t *nonce      = frame + kRealityClientTlsHeaderSize;
        uint8_t *ciphertext = frame + kRealityClientFramePrefixSize;

        if (0 != realityclientDecryptAead(ts->algorithm, ciphertext, ciphertext, ciphertext_len, frame,
                                          kRealityClientTlsHeaderSize, nonce, ts->key))
        {
            LOGW("RealityClient: failed to decrypt Reality record");
            lineReuseBuffer(l, frame_buffer);
            bufferstreamEmpty(&ls->read_stream);
            realityclientCloseLineBidirectional(t, l);
            return false;
        }

        sbufShiftRight(frame_buffer, kRealityClientFramePrefixSize);
        sbufSetLength(frame_buffer, ciphertext_len - kRealityClientTagSize);

        if (! withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, frame_buffer))
        {
            return false;
        }
    }
}

void realityclientTunnelstateDestroy(realityclient_tstate_t *ts)
{
    if (ts->tls_tunnel != NULL)
    {
        ts->tls_tunnel->onDestroy(ts->tls_tunnel);
        ts->tls_tunnel = NULL;
    }

    cJSON_Delete(ts->tls_settings);
    ts->tls_settings = NULL;

    memoryFree(ts->tls_node.name);
    memoryFree(ts->tls_node.type);
    memoryFree(ts->tls_node.next);
    ts->tls_node.name = NULL;
    ts->tls_node.type = NULL;
    ts->tls_node.next = NULL;

    wCryptoZero(ts->key, sizeof(ts->key));
    memoryZeroAligned32(ts, sizeof(*ts));
}

int realityclientEncryptAead(uint32_t algorithm, unsigned char *dst, const unsigned char *src, size_t src_len,
                             const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                             const unsigned char *key)
{
    if (algorithm == kRealityClientAlgorithmChaCha20Poly1305)
    {
        return chacha20poly1305Encrypt(dst, src, src_len, ad, ad_len, nonce, key);
    }

    if (algorithm == kRealityClientAlgorithmAes256Gcm)
    {
        return aes256gcmEncrypt(dst, src, src_len, ad, ad_len, nonce, key);
    }

    return -1;
}

int realityclientDecryptAead(uint32_t algorithm, unsigned char *dst, const unsigned char *src, size_t src_len,
                             const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                             const unsigned char *key)
{
    if (algorithm == kRealityClientAlgorithmChaCha20Poly1305)
    {
        return chacha20poly1305Decrypt(dst, src, src_len, ad, ad_len, nonce, key);
    }

    if (algorithm == kRealityClientAlgorithmAes256Gcm)
    {
        return aes256gcmDecrypt(dst, src, src_len, ad, ad_len, nonce, key);
    }

    return -1;
}

void realityclientCloseLineBidirectional(tunnel_t *t, line_t *l)
{
    if (! lineIsAlive(l))
    {
        return;
    }

    realityclient_lstate_t *ls = lineGetState(l, t);
    realityclientLinestateDestroy(ls);

    tunnelNextUpStreamFinish(t, l);
    tunnelPrevDownStreamFinish(t, l);
}
