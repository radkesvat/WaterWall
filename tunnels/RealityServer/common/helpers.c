#include "structure.h"

#include "loggers/network_logger.h"

enum frame_read_result_e
{
    kRealityFrameNeedMore = 0,
    kRealityFrameOk       = 1,
    kRealityFrameInvalid  = -1,
};

static sbuf_t *realityserverAllocFrameBuffer(buffer_pool_t *pool, uint32_t frame_len)
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

static sbuf_t *realityserverDuplicateBuffer(buffer_pool_t *pool, sbuf_t *buf)
{
    uint32_t len = sbufGetLength(buf);
    sbuf_t  *out = realityserverAllocFrameBuffer(pool, len);

    out = sbufReserveSpace(out, len);
    sbufSetLength(out, len);
    memoryCopyLarge(sbufGetMutablePtr(out), sbufGetRawPtr(buf), len);
    return out;
}

static bool realityserverDeriveSessionKeys(realityserver_tstate_t *ts, realityserver_lstate_t *ls)
{
    if (ls->session_keys_ready)
    {
        return true;
    }
    if (! ls->tls_capture.client_ready || ! ls->tls_capture.server_ready)
    {
        return false;
    }

    ls->binding_ready = true;
    reality_v2_session_material_t material = {0};
    if (! realityV2DeriveSessionMaterial(ts->root_key, &ls->tls_capture.binding, &material))
    {
        memoryZero(&material, sizeof(material));
        return false;
    }

    memoryCopy(ls->session_id, material.session_id, sizeof(ls->session_id));
    memoryCopy(ls->c2s_key, material.c2s_key, sizeof(ls->c2s_key));
    memoryCopy(ls->s2c_key, material.s2c_key, sizeof(ls->s2c_key));
    memoryCopy(ls->c2s_iv, material.c2s_iv, sizeof(ls->c2s_iv));
    memoryCopy(ls->s2c_iv, material.s2c_iv, sizeof(ls->s2c_iv));
    memoryZero(&material, sizeof(material));
    ls->session_keys_ready = true;
    return true;
}

static bool realityserverEncryptFrame(realityserver_tstate_t *ts, realityserver_lstate_t *ls, sbuf_t **buf,
                                      uint32_t plaintext_len)
{
    if (! ls->session_keys_ready || ! realityV2SequenceAvailable(ls->s2c_send_seq))
    {
        return false;
    }

    uint64_t sequence_number = ls->s2c_send_seq;
    uint32_t ciphertext_len = plaintext_len + kRealityServerTagSize;
    uint32_t body_len       = kRealityServerCoverPrefixSize + ciphertext_len;
    uint32_t frame_len      = kRealityServerTlsHeaderSize + body_len;

    if (sbufGetMaximumWriteableSize(*buf) < ciphertext_len)
    {
        *buf = sbufReserveSpace(*buf, ciphertext_len);
    }

    assert(sbufGetLeftCapacity(*buf) >= kRealityServerFramePrefixSize);
    sbufShiftLeft(*buf, kRealityServerFramePrefixSize);

    uint8_t *frame = sbufGetMutablePtr(*buf);
    frame[0]       = kRealityServerTlsApplicationData;
    frame[1]       = kRealityServerTlsVersionMajor;
    frame[2]       = kRealityServerTlsVersionMinor;
    frame[3]       = (uint8_t) (body_len >> 8);
    frame[4]       = (uint8_t) body_len;

    uint8_t *cover_prefix = frame + kRealityServerTlsHeaderSize;
    if (UNLIKELY(! secureRandomBytes(cover_prefix, kRealityServerCoverPrefixSize)))
    {
        return false;
    }

    uint8_t nonce[kRealityV2IvSize];
    uint8_t aad[kRealityV2RecordAadSize];
    realityV2BuildNonce(ls->s2c_iv, sequence_number, nonce);
    if (! realityV2BuildRecordAad(kRealityV2DirectionServerToClient,
                                  sequence_number,
                                  ls->session_id,
                                  frame,
                                  cover_prefix,
                                  aad))
    {
        memoryZero(nonce, sizeof(nonce));
        return false;
    }

    uint8_t *ciphertext = frame + kRealityServerFramePrefixSize;
    int result = realityserverEncryptAead(
        ts->algorithm, ciphertext, ciphertext, plaintext_len, aad, sizeof(aad), nonce, ls->s2c_key);
    memoryZero(nonce, sizeof(nonce));
    memoryZero(aad, sizeof(aad));
    if (result != 0)
    {
        return false;
    }

    ls->s2c_send_seq = sequence_number + 1;
    sbufSetLength(*buf, frame_len);
    return true;
}

static int realityserverTryReadTlsRecord(buffer_stream_t *stream, sbuf_t **record)
{
    if (bufferstreamGetBufLen(stream) < kRealityServerTlsHeaderSize)
    {
        return kRealityFrameNeedMore;
    }

    uint8_t header[kRealityServerTlsHeaderSize];
    bufferstreamViewBytesAt(stream, 0, header, sizeof(header));

    bool plausible_tls_type = header[0] == kRealityServerTlsChangeCipherSpec || header[0] == kRealityServerTlsAlert ||
                              header[0] == kRealityServerTlsHandshake || header[0] == kRealityServerTlsApplicationData;
    bool plausible_tls_version = header[1] == kRealityServerTlsVersionMajor && header[2] <= 0x04;

    if (! plausible_tls_type || ! plausible_tls_version)
    {
        return kRealityFrameInvalid;
    }

    uint32_t body_len = ((uint32_t) header[3] << 8) | (uint32_t) header[4];
    if (body_len > kRealityServerMaxTlsRecordBody)
    {
        return kRealityFrameInvalid;
    }

    uint32_t frame_len = kRealityServerTlsHeaderSize + body_len;
    if (bufferstreamGetBufLen(stream) < frame_len)
    {
        return kRealityFrameNeedMore;
    }

    *record = bufferstreamReadExact(stream, frame_len);
    return kRealityFrameOk;
}

static bool realityserverIsRealityCandidate(const realityserver_tstate_t *ts, sbuf_t *record)
{
    if (sbufGetLength(record) < kRealityServerTlsHeaderSize)
    {
        return false;
    }

    const uint8_t *frame    = sbufGetRawPtr(record);
    uint32_t       body_len = ((uint32_t) frame[3] << 8) | (uint32_t) frame[4];

    return frame[0] == kRealityServerTlsApplicationData && frame[1] == kRealityServerTlsVersionMajor &&
           frame[2] == kRealityServerTlsVersionMinor &&
           body_len >= kRealityServerCoverPrefixSize + kRealityServerTagSize &&
           body_len <= ts->max_frame_payload + kRealityServerCoverPrefixSize + kRealityServerTagSize &&
           body_len <= kRealityServerMaxTlsRecordBody;
}

static bool realityserverDecryptFrame(realityserver_tstate_t *ts, realityserver_lstate_t *ls,
                                      sbuf_t *frame_buffer)
{
    if (! ls->session_keys_ready || ! realityV2SequenceAvailable(ls->c2s_recv_seq))
    {
        return false;
    }

    uint64_t sequence_number = ls->c2s_recv_seq;
    uint8_t *frame          = sbufGetMutablePtr(frame_buffer);
    uint32_t body_len       = ((uint32_t) frame[3] << 8) | (uint32_t) frame[4];
    uint32_t ciphertext_len = body_len - kRealityServerCoverPrefixSize;

    uint8_t *cover_prefix = frame + kRealityServerTlsHeaderSize;
    uint8_t *ciphertext = frame + kRealityServerFramePrefixSize;

    uint8_t nonce[kRealityV2IvSize];
    uint8_t aad[kRealityV2RecordAadSize];
    realityV2BuildNonce(ls->c2s_iv, sequence_number, nonce);
    bool aad_ok = realityV2BuildRecordAad(kRealityV2DirectionClientToServer,
                                          sequence_number,
                                          ls->session_id,
                                          frame,
                                          cover_prefix,
                                          aad);
    int decrypt_result = aad_ok ? realityserverDecryptAead(ts->algorithm,
                                                           ciphertext,
                                                           ciphertext,
                                                           ciphertext_len,
                                                           aad,
                                                           sizeof(aad),
                                                           nonce,
                                                           ls->c2s_key)
                                : -1;
    memoryZero(nonce, sizeof(nonce));
    memoryZero(aad, sizeof(aad));
    if (decrypt_result != 0)
    {
        return false;
    }

    ls->c2s_recv_seq = sequence_number + 1;
    sbufShiftRight(frame_buffer, kRealityServerFramePrefixSize);
    sbufSetLength(frame_buffer, ciphertext_len - kRealityServerTagSize);
    return true;
}

static bool realityserverForwardToDestination(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    realityserver_tstate_t *ts = tunnelGetState(t);
    return withLineLockedWithBuf(l, tunnelUpStreamPayload, ts->destination_tunnel, buf);
}

static bool realityserverFlushBufferedToDestination(tunnel_t *t, line_t *l, realityserver_lstate_t *ls)
{
    sbuf_t *pending = bufferstreamFullRead(&ls->read_stream);
    if (pending == NULL)
    {
        return true;
    }

    return realityserverForwardToDestination(t, l, pending);
}

static bool realityserverSwitchToVisitor(tunnel_t *t, line_t *l, realityserver_lstate_t *ls)
{
    ls->mode = kRealityServerModeVisitor;
    return realityserverFlushBufferedToDestination(t, l, ls);
}

static bool realityserverSwitchToAuthorized(tunnel_t *t, line_t *l, realityserver_lstate_t *ls)
{
    realityserver_tstate_t *ts = tunnelGetState(t);

    if (ls->mode == kRealityServerModeAuthorized)
    {
        return true;
    }

    ls->mode = kRealityServerModeAuthorized;
    if (ls->destination_init_sent && ! ls->destination_up_finished)
    {
        ls->destination_up_finished            = true;
        ls->closing_destination_for_authorized = true;

        if (! withLineLocked(l, tunnelUpStreamFin, ts->destination_tunnel))
        {
            return false;
        }

        if (! lineIsAlive(l))
        {
            return false;
        }

        ls->closing_destination_for_authorized = false;
    }

    if (! ls->protected_init_sent)
    {
        ls->protected_init_sent = true;
        if (! withLineLocked(l, tunnelNextUpStreamInit, t))
        {
            return false;
        }
    }

    return true;
}

bool realityserverEncryptAndSendDownstream(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    realityserver_tstate_t *ts            = tunnelGetState(t);
    realityserver_lstate_t *ls            = lineGetState(l, t);
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
            uint32_t frame_len = kRealityServerFramePrefixSize + chunk_len + kRealityServerTagSize;
            sbuf_t  *frame_buf = realityserverAllocFrameBuffer(pool, frame_len);

            sbufSetLength(frame_buf, chunk_len);
            memoryCopyLarge(sbufGetMutablePtr(frame_buf), src, chunk_len);

            if (! realityserverEncryptFrame(ts, ls, &frame_buf, chunk_len))
            {
                LOGW("RealityServer: failed to encrypt downstream payload chunk");
                bufferpoolReuseBuffer(pool, frame_buf);
                bufferpoolReuseBuffer(pool, buf);
                realityserverCloseLineBidirectional(t, l);
                return false;
            }

            src += chunk_len;
            remaining -= chunk_len;

            if (! withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, frame_buf))
            {
                bufferpoolReuseBuffer(pool, buf);
                return false;
            }
        }

        lineReuseBuffer(l, buf);
        return true;
    }

    if (! realityserverEncryptFrame(ts, ls, &buf, plaintext_len))
    {
        LOGW("RealityServer: failed to encrypt downstream payload");
        lineReuseBuffer(l, buf);
        realityserverCloseLineBidirectional(t, l);
        return false;
    }

    return withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, buf);
}

bool realityserverProcessUpstream(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    realityserver_tstate_t *ts   = tunnelGetState(t);
    realityserver_lstate_t *ls   = lineGetState(l, t);
    buffer_pool_t          *pool = lineGetBufferPool(l);

    if (buf != NULL)
    {
        if (ls->mode == kRealityServerModePending && ! ls->client_hello_parser.complete &&
            ! realityserverTlsParserFeed(&ls->client_hello_parser,
                                         sbufGetRawPtr(buf),
                                         sbufGetLength(buf),
                                         &ls->tls_capture))
        {
            ls->mode = kRealityServerModeVisitor;
        }
        bufferstreamPush(&ls->read_stream, buf);
    }

    while (true)
    {
        if (ls->mode == kRealityServerModeVisitor)
        {
            return realityserverFlushBufferedToDestination(t, l, ls);
        }

        sbuf_t *record      = NULL;
        int     read_result = realityserverTryReadTlsRecord(&ls->read_stream, &record);

        if (read_result == kRealityFrameNeedMore)
        {
            return true;
        }

        if (read_result == kRealityFrameInvalid)
        {
            if (ls->mode == kRealityServerModeAuthorized)
            {
                LOGW("RealityServer: invalid Reality record after authorization");
                bufferstreamEmpty(&ls->read_stream);
                realityserverCloseLineBidirectional(t, l);
                return false;
            }

            return realityserverSwitchToVisitor(t, l, ls);
        }

        bool candidate = realityserverIsRealityCandidate(ts, record);
        if (! candidate)
        {
            if (ls->mode == kRealityServerModeAuthorized)
            {
                LOGW("RealityServer: non-Reality TLS record after authorization");
                lineReuseBuffer(l, record);
                bufferstreamEmpty(&ls->read_stream);
                realityserverCloseLineBidirectional(t, l);
                return false;
            }

            if (! realityserverForwardToDestination(t, l, record))
            {
                return false;
            }
            continue;
        }

        if (! ls->session_keys_ready)
        {
            if (ls->mode == kRealityServerModeAuthorized)
            {
                LOGW("RealityServer: Reality v2 session keys unavailable after authorization");
                lineReuseBuffer(l, record);
                bufferstreamEmpty(&ls->read_stream);
                realityserverCloseLineBidirectional(t, l);
                return false;
            }

            if (! realityserverForwardToDestination(t, l, record))
            {
                return false;
            }
            continue;
        }

        sbuf_t *candidate_buf = realityserverDuplicateBuffer(pool, record);
        bool    decrypt_ok    = realityserverDecryptFrame(ts, ls, candidate_buf);

        if (decrypt_ok)
        {
            lineReuseBuffer(l, record);

            if (! realityserverSwitchToAuthorized(t, l, ls))
            {
                bufferpoolReuseBuffer(pool, candidate_buf);
                return false;
            }

            if (! withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, candidate_buf))
            {
                return false;
            }
            continue;
        }

        bufferpoolReuseBuffer(pool, candidate_buf);

        if (ls->mode == kRealityServerModeAuthorized)
        {
            LOGW("RealityServer: Reality authentication failed after authorization");
            lineReuseBuffer(l, record);
            bufferstreamEmpty(&ls->read_stream);
            realityserverCloseLineBidirectional(t, l);
            return false;
        }

        ++ls->sniffing_attempts;
        if (! realityserverForwardToDestination(t, l, record))
        {
            return false;
        }

        if (ls->sniffing_attempts >= ts->sniffing_attempts)
        {
            ls->mode = kRealityServerModeVisitor;
            return realityserverFlushBufferedToDestination(t, l, ls);
        }
    }
}

bool realityserverObserveDownstreamHandshake(tunnel_t *t, line_t *l, const uint8_t *data, size_t len)
{
    realityserver_tstate_t *ts = tunnelGetState(t);
    realityserver_lstate_t *ls = lineGetState(l, t);

    if (ls->mode != kRealityServerModePending || ls->session_keys_ready)
    {
        return true;
    }

    if (! realityserverTlsParserFeed(&ls->server_hello_parser, data, len, &ls->tls_capture))
    {
        return realityserverSwitchToVisitor(t, l, ls);
    }

    if (ls->tls_capture.client_ready && ls->tls_capture.server_ready)
    {
        if (! realityserverDeriveSessionKeys(ts, ls))
        {
            return realityserverSwitchToVisitor(t, l, ls);
        }
    }
    return true;
}

void realityserverTunnelstateDestroy(realityserver_tstate_t *ts)
{
    memoryZero(ts->root_key, sizeof(ts->root_key));
    memoryZeroAligned32(ts, tunnelGetCorrectAlignedStateSize(sizeof(*ts)));
}

int realityserverEncryptAead(uint32_t algorithm, unsigned char *dst, const unsigned char *src, size_t src_len,
                             const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                             const unsigned char *key)
{
    if (algorithm == kRealityServerAlgorithmChaCha20Poly1305)
    {
        return chacha20poly1305Encrypt(dst, src, src_len, ad, ad_len, nonce, key);
    }

    if (algorithm == kRealityServerAlgorithmAes256Gcm)
    {
        return aes256gcmEncrypt(dst, src, src_len, ad, ad_len, nonce, key);
    }

    return -1;
}

int realityserverDecryptAead(uint32_t algorithm, unsigned char *dst, const unsigned char *src, size_t src_len,
                             const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                             const unsigned char *key)
{
    if (algorithm == kRealityServerAlgorithmChaCha20Poly1305)
    {
        return chacha20poly1305Decrypt(dst, src, src_len, ad, ad_len, nonce, key);
    }

    if (algorithm == kRealityServerAlgorithmAes256Gcm)
    {
        return aes256gcmDecrypt(dst, src, src_len, ad, ad_len, nonce, key);
    }

    return -1;
}

void realityserverCloseLineBidirectional(tunnel_t *t, line_t *l)
{
    if (! lineIsAlive(l))
    {
        return;
    }

    realityserver_tstate_t *ts = tunnelGetState(t);
    realityserver_lstate_t *ls = lineGetState(l, t);

    bool close_protected = ls->protected_init_sent;
    bool close_destination =
        ls->destination_init_sent && ! ls->destination_up_finished && ls->mode != kRealityServerModeAuthorized;

    realityserverLinestateDestroy(ls);

    if (close_protected)
    {
        tunnelNextUpStreamFinish(t, l);
    }
    else if (close_destination)
    {
        tunnelUpStreamFin(ts->destination_tunnel, l);
    }

    tunnelPrevDownStreamFinish(t, l);
}
