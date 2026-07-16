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

static bool realityclientEncryptFrame(realityclient_tstate_t *ts, realityclient_lstate_t *ls,
                                      buffer_pool_t *pool, uint8_t record_kind,
                                      const uint8_t *plaintext, uint32_t plaintext_len,
                                      sbuf_t **frame_buffer)
{
    if (! ls->session_keys_ready || ! realityV2SequenceAvailable(ls->c2s_send_seq) ||
        ! realityV2RecordProfileIsValid(&ls->record_profile) || frame_buffer == NULL)
    {
        return false;
    }

    reality_v2_record_descriptor_t descriptor;
    reality_v2_record_layout_t     layout;
    if (! realityV2BuildRecordDescriptor(ls->tls_version, &ls->record_profile, record_kind, &descriptor) ||
        ! realityV2CalculateDescriptorLayout(&descriptor, plaintext_len, &layout))
    {
        return false;
    }

    uint32_t frame_len = kRealityClientTlsHeaderSize + layout.wire_body_len;
    sbuf_t  *out       = realityclientAllocFrameBuffer(pool, frame_len);
    out                = sbufReserveSpace(out, frame_len);
    sbufSetLength(out, frame_len);

    uint64_t sequence_number = ls->c2s_send_seq;
    uint8_t *frame           = sbufGetMutablePtr(out);
    frame[0]       = descriptor.outer_content_type;
    frame[1]       = kRealityClientTlsVersionMajor;
    frame[2]       = kRealityClientTlsVersionMinor;
    frame[3]       = (uint8_t) (layout.wire_body_len >> 8);
    frame[4]       = (uint8_t) layout.wire_body_len;

    uint8_t *visible_prefix = frame + kRealityClientTlsHeaderSize;
    if (descriptor.profile.profile_id == kRealityV2RecordProfileTls12Gcm)
    {
        uint64_t tls_sequence;
        if (! ls->tls12_sequences_valid ||
            ! realityV2AddTlsRecordSequence(ls->tls12_next_write_sequence, sequence_number, &tls_sequence))
        {
            bufferpoolReuseBuffer(pool, out);
            return false;
        }
        realityV2WriteBe64(visible_prefix, tls_sequence);
    }
    else if (descriptor.visible_prefix_len != 0 &&
             UNLIKELY(! secureRandomBytes(visible_prefix, descriptor.visible_prefix_len)))
    {
        bufferpoolReuseBuffer(pool, out);
        return false;
    }

    uint8_t *ciphertext = visible_prefix + descriptor.visible_prefix_len;
    if (! realityV2BuildInnerPlaintext(&descriptor,
                                       plaintext,
                                       plaintext_len,
                                       ciphertext,
                                       layout.inner_plaintext_len))
    {
        bufferpoolReuseBuffer(pool, out);
        return false;
    }

    uint8_t nonce[kRealityV2IvSize];
    uint8_t aad[kRealityV2RecordAadMaxSize];
    size_t  aad_len = 0;
    realityV2BuildNonce(ls->c2s_iv, sequence_number, nonce);
    if (! realityV2BuildRecordAad(&descriptor,
                                  kRealityV2DirectionClientToServer,
                                  sequence_number,
                                  ls->session_id,
                                  frame,
                                  visible_prefix,
                                  descriptor.visible_prefix_len,
                                  aad,
                                  &aad_len))
    {
        memoryZero(nonce, sizeof(nonce));
        bufferpoolReuseBuffer(pool, out);
        return false;
    }

    int result = realityclientEncryptAead(ts->algorithm,
                                          ciphertext,
                                          ciphertext,
                                          layout.inner_plaintext_len,
                                          aad,
                                          aad_len,
                                          nonce,
                                          ls->c2s_key);
    memoryZero(nonce, sizeof(nonce));
    memoryZero(aad, sizeof(aad));
    if (result != 0)
    {
        bufferpoolReuseBuffer(pool, out);
        return false;
    }

    ls->c2s_send_seq = sequence_number + 1;
    *frame_buffer     = out;
    return true;
}

static int realityclientTryReadCompleteFrame(buffer_stream_t *stream, const realityclient_lstate_t *ls,
                                             sbuf_t **frame_buffer,
                                             reality_v2_record_descriptor_t *descriptor)
{
    if (bufferstreamGetBufLen(stream) < kRealityClientTlsHeaderSize)
    {
        return kRealityFrameNeedMore;
    }

    uint8_t header[kRealityClientTlsHeaderSize];
    bufferstreamViewBytesAt(stream, 0, header, sizeof(header));

    uint32_t body_len = ((uint32_t) header[3] << 8) | (uint32_t) header[4];
    if (! realityV2ClassifyRecord(ls->tls_version,
                                  &ls->record_profile,
                                  header,
                                  descriptor))
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
    realityclient_lstate_t *ls            = lineGetState(l, t);
    uint32_t                plaintext_len = sbufGetLength(buf);

    if (plaintext_len == 0)
    {
        lineReuseBuffer(l, buf);
        return true;
    }

    if (plaintext_len > kRealityV2MaxPlaintextFragment)
    {
        buffer_pool_t *pool      = lineGetBufferPool(l);
        const uint8_t *src       = sbufGetRawPtr(buf);
        uint32_t       remaining = plaintext_len;

        while (remaining > 0)
        {
            uint32_t chunk_len = min(remaining, (uint32_t) kRealityV2MaxPlaintextFragment);
            sbuf_t *frame_buf = NULL;
            if (! realityclientEncryptFrame(ts,
                                             ls,
                                             pool,
                                             kRealityV2RecordKindApplicationData,
                                             src,
                                             chunk_len,
                                             &frame_buf))
            {
                LOGW("RealityClient: failed to encrypt payload chunk");
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
            ls = lineGetState(l, t);
            if (ls->terminal_closing || ls->next_finished)
            {
                bufferpoolReuseBuffer(pool, buf);
                return false;
            }
        }

        lineReuseBuffer(l, buf);
        return true;
    }

    buffer_pool_t *pool      = lineGetBufferPool(l);
    sbuf_t        *frame_buf = NULL;
    if (! realityclientEncryptFrame(ts,
                                     ls,
                                     pool,
                                     kRealityV2RecordKindApplicationData,
                                     sbufGetRawPtr(buf),
                                     plaintext_len,
                                     &frame_buf))
    {
        LOGW("RealityClient: failed to encrypt payload");
        bufferpoolReuseBuffer(pool, buf);
        realityclientCloseLineBidirectional(t, l);
        return false;
    }

    bufferpoolReuseBuffer(pool, buf);
    return withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, frame_buf);
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
        sbuf_t                         *frame_buffer = NULL;
        reality_v2_record_descriptor_t descriptor;
        int read_result = realityclientTryReadCompleteFrame(&ls->read_stream,
                                                             ls,
                                                             &frame_buffer,
                                                             &descriptor);

        if (read_result == kRealityFrameNeedMore)
        {
            return true;
        }

        if (read_result == kRealityFrameInvalid)
        {
            LOGW("RealityClient: invalid Reality record received");
            bufferstreamEmpty(&ls->read_stream);
            realityclientFailAuthenticated(t, l);
            return false;
        }

        uint8_t *frame          = sbufGetMutablePtr(frame_buffer);
        uint32_t body_len       = ((uint32_t) frame[3] << 8) | (uint32_t) frame[4];
        uint32_t ciphertext_len = body_len - descriptor.visible_prefix_len;

        uint8_t *visible_prefix = frame + kRealityClientTlsHeaderSize;
        uint8_t *ciphertext     = visible_prefix + descriptor.visible_prefix_len;

        reality_v2_record_descriptor_t application_descriptor;
        bool ambiguous_tls13_kind =
            descriptor.tls_version == kRealityV2Tls13 &&
            descriptor.record_kind == kRealityV2RecordKindAlert &&
            realityV2BuildRecordDescriptor(ls->tls_version,
                                           &ls->record_profile,
                                           kRealityV2RecordKindApplicationData,
                                           &application_descriptor) &&
            application_descriptor.outer_content_type == frame[0] &&
            realityV2ValidateDescriptorBodyLength(&application_descriptor, body_len);
        uint8_t encrypted_alert_backup[kRealityV2AlertMessageSize + 1U + kRealityV2TagSize];
        if (ambiguous_tls13_kind)
        {
            if (ciphertext_len != sizeof(encrypted_alert_backup))
            {
                lineReuseBuffer(l, frame_buffer);
                bufferstreamEmpty(&ls->read_stream);
                realityclientFailAuthenticated(t, l);
                return false;
            }
            memoryCopy(encrypted_alert_backup, ciphertext, ciphertext_len);
        }

        if (! ls->session_keys_ready || ! realityV2SequenceAvailable(ls->s2c_recv_seq))
        {
            LOGW("RealityClient: downstream sequence exhausted");
            lineReuseBuffer(l, frame_buffer);
            bufferstreamEmpty(&ls->read_stream);
            realityclientFailAuthenticated(t, l);
            return false;
        }

        uint64_t sequence_number = ls->s2c_recv_seq;
        uint8_t  nonce[kRealityV2IvSize];
        uint8_t  aad[kRealityV2RecordAadMaxSize];
        size_t   aad_len = 0;
        realityV2BuildNonce(ls->s2c_iv, sequence_number, nonce);
        bool aad_ok = realityV2BuildRecordAad(&descriptor,
                                              kRealityV2DirectionServerToClient,
                                              sequence_number,
                                              ls->session_id,
                                              frame,
                                              visible_prefix,
                                              descriptor.visible_prefix_len,
                                              aad,
                                              &aad_len);
        int decrypt_result = aad_ok ? realityclientDecryptAead(ts->algorithm,
                                                               ciphertext,
                                                               ciphertext,
                                                               ciphertext_len,
                                                               aad,
                                                               aad_len,
                                                               nonce,
                                                               ls->s2c_key)
                                    : -1;

        if (decrypt_result != 0 && ambiguous_tls13_kind)
        {
            memoryCopy(ciphertext, encrypted_alert_backup, ciphertext_len);
            descriptor = application_descriptor;
            aad_len     = 0;
            memoryZero(aad, sizeof(aad));
            aad_ok = realityV2BuildRecordAad(&descriptor,
                                             kRealityV2DirectionServerToClient,
                                             sequence_number,
                                             ls->session_id,
                                             frame,
                                             visible_prefix,
                                             descriptor.visible_prefix_len,
                                             aad,
                                             &aad_len);
            decrypt_result = aad_ok ? realityclientDecryptAead(ts->algorithm,
                                                               ciphertext,
                                                               ciphertext,
                                                               ciphertext_len,
                                                               aad,
                                                               aad_len,
                                                               nonce,
                                                               ls->s2c_key)
                                    : -1;
        }
        memoryZero(nonce, sizeof(nonce));
        memoryZero(aad, sizeof(aad));
        memoryZero(encrypted_alert_backup, sizeof(encrypted_alert_backup));

        if (decrypt_result != 0)
        {
            LOGW("RealityClient: failed to decrypt Reality record");
            lineReuseBuffer(l, frame_buffer);
            bufferstreamEmpty(&ls->read_stream);
            realityclientFailAuthenticated(t, l);
            return false;
        }

        uint32_t inner_plaintext_len = ciphertext_len - kRealityClientTagSize;
        uint32_t inner_payload_offset;
        uint32_t payload_len;
        if (! realityV2ValidateInnerPlaintext(&descriptor,
                                              ciphertext,
                                              inner_plaintext_len,
                                              &inner_payload_offset,
                                              &payload_len))
        {
            LOGW("RealityClient: invalid Reality inner record");
            lineReuseBuffer(l, frame_buffer);
            bufferstreamEmpty(&ls->read_stream);
            realityclientFailAuthenticated(t, l);
            return false;
        }

        if (descriptor.record_kind == kRealityV2RecordKindAlert)
        {
            uint8_t alert;
            bool alert_ok = realityV2ParseAlert(ciphertext + inner_payload_offset, payload_len, &alert);
            if (! alert_ok)
            {
                LOGW("RealityClient: invalid authenticated Reality alert");
                lineReuseBuffer(l, frame_buffer);
                bufferstreamEmpty(&ls->read_stream);
                realityclientFailAuthenticated(t, l);
                return false;
            }
            ls->s2c_recv_seq = sequence_number + 1;
            lineReuseBuffer(l, frame_buffer);
            bufferstreamEmpty(&ls->read_stream);
            realityclientHandlePeerAlert(t, l, alert);
            return false;
        }

        ls->s2c_recv_seq = sequence_number + 1;
        uint32_t payload_offset = kRealityClientTlsHeaderSize + descriptor.visible_prefix_len +
                                  inner_payload_offset;
        sbufShiftRight(frame_buffer, payload_offset);
        sbufSetLength(frame_buffer, payload_len);

        if (! withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, frame_buffer))
        {
            return false;
        }
        ls = lineGetState(l, t);
        if (ls->terminal_closing || ls->prev_finished)
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

    memoryZero(ts->root_key, sizeof(ts->root_key));
    memoryZeroAligned32(ts, tunnelGetCorrectAlignedStateSize(sizeof(*ts)));
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

    lineLock(l);
    realityclient_lstate_t *ls = lineGetState(l, t);
    if (ls->terminal_closing)
    {
        lineUnlock(l);
        return;
    }

    bool close_next = ! ls->next_finished;
    bool close_prev = ! ls->prev_finished;
    ls->terminal_closing = true;
    realityclientLinestateDestroy(ls);

    if (close_next)
    {
        tunnelNextUpStreamFinish(t, l);
        if (! lineIsAlive(l))
        {
            lineUnlock(l);
            return;
        }
    }
    if (close_prev)
    {
        tunnelPrevDownStreamFinish(t, l);
    }
    lineUnlock(l);
}

static void realityclientFinishFromSide(tunnel_t *t, line_t *l, bool received_prev_finish)
{
    if (! lineIsAlive(l))
    {
        return;
    }

    lineLock(l);
    realityclient_lstate_t *ls = lineGetState(l, t);
    if (received_prev_finish)
    {
        ls->prev_finished = true;
    }
    else
    {
        ls->next_finished = true;
    }
    if (ls->terminal_closing)
    {
        lineUnlock(l);
        return;
    }

    ls->terminal_closing = true;
    realityclientLinestateDestroy(ls);

    if (received_prev_finish)
    {
        tunnelNextUpStreamFinish(t, l);
    }
    else
    {
        tunnelPrevDownStreamFinish(t, l);
    }
    lineUnlock(l);
}

static void realityclientSendFatalAndClose(tunnel_t *t, line_t *l)
{
    if (! lineIsAlive(l))
    {
        return;
    }

    lineLock(l);
    realityclient_lstate_t *ls = lineGetState(l, t);
    if (ls->terminal_closing)
    {
        lineUnlock(l);
        return;
    }

    ls->terminal_closing = true;

    if (ls->session_keys_ready && ! ls->next_finished && ! ls->wire_alert_sent)
    {
        uint8_t alert_bytes[kRealityV2AlertMessageSize];
        sbuf_t *frame = NULL;
        bool built = realityV2SerializeAlert(kRealityV2AlertBadRecordMac, alert_bytes) &&
                     realityclientEncryptFrame(tunnelGetState(t),
                                                ls,
                                                lineGetBufferPool(l),
                                                kRealityV2RecordKindAlert,
                                                alert_bytes,
                                                sizeof(alert_bytes),
                                                &frame);
        memoryZero(alert_bytes, sizeof(alert_bytes));
        if (built)
        {
            ls->wire_alert_sent = true;
            tunnelNextUpStreamPayload(t, l, frame);
            if (! lineIsAlive(l))
            {
                /* This close frame owns cleanup; terminal re-entry deliberately defers to it. */
                realityclientLinestateDestroy(lineGetState(l, t));
                lineUnlock(l);
                return;
            }
            ls = lineGetState(l, t);
        }
    }

    bool close_next = ! ls->next_finished;
    bool close_prev = ! ls->prev_finished;
    realityclientLinestateDestroy(ls);

    if (close_next)
    {
        tunnelNextUpStreamFinish(t, l);
        if (! lineIsAlive(l))
        {
            lineUnlock(l);
            return;
        }
    }
    if (close_prev)
    {
        tunnelPrevDownStreamFinish(t, l);
    }
    lineUnlock(l);
}

void realityclientFailAuthenticated(tunnel_t *t, line_t *l)
{
    realityclientSendFatalAndClose(t, l);
}

void realityclientHandlePeerAlert(tunnel_t *t, line_t *l, uint8_t alert)
{
    discard alert;
    realityclientCloseLineBidirectional(t, l);
}

void realityclientHandleUpstreamFinish(tunnel_t *t, line_t *l)
{
    realityclientFinishFromSide(t, l, true);
}

void realityclientHandleDownstreamFinish(tunnel_t *t, line_t *l)
{
    realityclientFinishFromSide(t, l, false);
}
