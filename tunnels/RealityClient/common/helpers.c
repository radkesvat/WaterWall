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

static int realityclientTryReadCompleteTlsRecord(buffer_stream_t *stream, sbuf_t **record)
{
    if (bufferstreamGetBufLen(stream) < kRealityClientTlsHeaderSize)
    {
        return kRealityFrameNeedMore;
    }

    uint8_t header[kRealityClientTlsHeaderSize];
    bufferstreamViewBytesAt(stream, 0, header, sizeof(header));
    bool plausible_type = header[0] == 0x14 || header[0] == 0x15 ||
                          header[0] == 0x16 || header[0] == 0x17;
    if (! plausible_type || header[1] != kRealityClientTlsVersionMajor ||
        header[2] != kRealityClientTlsVersionMinor)
    {
        return kRealityFrameInvalid;
    }

    uint32_t body_len = ((uint32_t) header[3] << 8) | header[4];
    if (body_len > kRealityClientMaxTlsRecordBody)
    {
        return kRealityFrameInvalid;
    }

    uint32_t record_len = kRealityClientTlsHeaderSize + body_len;
    if (bufferstreamGetBufLen(stream) < record_len)
    {
        return kRealityFrameNeedMore;
    }
    *record = bufferstreamReadExact(stream, record_len);
    return kRealityFrameOk;
}

static int realityclientCommonDecrypt(void *context, unsigned char *dst,
                                      const unsigned char *src, size_t src_len,
                                      const unsigned char *ad, size_t ad_len,
                                      const unsigned char *nonce, const unsigned char *key)
{
    const realityclient_tstate_t *ts = context;
    return realityclientDecryptAead(ts->algorithm, dst, src, src_len, ad, ad_len, nonce, key);
}

bool realityclientSendHandoffControl(tunnel_t *t, line_t *l, uint8_t record_kind)
{
    realityclient_tstate_t *ts = tunnelGetState(t);
    realityclient_lstate_t *ls = lineGetState(l, t);
    bool request = record_kind == kRealityV2RecordKindHandoffRequest;
    bool confirm = record_kind == kRealityV2RecordKindHandoffConfirm;
    if (! ls->session_keys_ready || ls->tls_version != kRealityV2Tls13 ||
        (request && (ls->phase != kRealityClientPhaseTls13AwaitAck ||
                     ls->handoff_request_sent || ls->c2s_send_seq != 0)) ||
        (confirm && (ls->phase != kRealityClientPhaseRealityActive ||
                     ! ls->handoff_ack_authenticated || ls->handoff_confirm_sent ||
                     ls->c2s_send_seq != 1)) || (! request && ! confirm))
    {
        return false;
    }

    uint8_t control_payload[kRealityV2ControlMaxPayload] = {0};
    uint32_t control_payload_len = 0;
    sbuf_t *frame = NULL;
    bool built = realityV2BuildControlPayload(record_kind,
                                              control_payload,
                                              sizeof(control_payload),
                                              &control_payload_len) &&
                 realityclientEncryptFrame(ts,
                                           ls,
                                           lineGetBufferPool(l),
                                           record_kind,
                                           control_payload,
                                           control_payload_len,
                                           &frame);
    memoryZero(control_payload, sizeof(control_payload));
    if (! built)
    {
        return false;
    }

    if (request)
    {
        ls->handoff_request_sent = true;
    }
    else
    {
        ls->handoff_confirm_sent = true;
    }
    return withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, frame);
}

bool realityclientFlushPendingUpstream(tunnel_t *t, line_t *l)
{
    while (lineIsAlive(l))
    {
        realityclient_lstate_t *ls = lineGetState(l, t);
        if (ls->terminal_closing || ls->phase == kRealityClientPhaseTerminal)
        {
            return false;
        }
        if (bufferqueueGetBufCount(&ls->pending_up) == 0)
        {
            return true;
        }

        sbuf_t *buf = bufferqueuePopFront(&ls->pending_up);
        if (! realityclientEncryptAndSend(t, l, buf))
        {
            return false;
        }
    }
    return false;
}

static bool realityclientCompleteTls13Handoff(tunnel_t *t, line_t *l)
{
    realityclient_tstate_t *ts = tunnelGetState(t);
    realityclient_lstate_t *ls = lineGetState(l, t);
    if (ls->phase != kRealityClientPhaseTls13AwaitAck || ! ls->handoff_request_sent ||
        ! ls->handoff_ack_authenticated || ls->handoff_confirm_sent ||
        ls->c2s_send_seq != 1 || ls->s2c_recv_seq != 1)
    {
        realityclientCloseLineBidirectional(t, l);
        return false;
    }

    sbuf_t *buffered_after_ack = bufferstreamFullRead(&ls->handoff_stream);
    if (buffered_after_ack != NULL)
    {
        bufferstreamPush(&ls->read_stream, buffered_after_ack);
    }

    if (! tlsclientTunnelCompleteTakeover(ts->tls_tunnel, l))
    {
        LOGW("RealityClient: failed to complete authenticated TLS 1.3 takeover");
        realityclientCloseLineBidirectional(t, l);
        return false;
    }

    ls = lineGetState(l, t);
    ls->phase = kRealityClientPhaseRealityActive;
    ls->handoff_completion_in_progress = true;
    if (! realityclientSendHandoffControl(t, l, kRealityV2RecordKindHandoffConfirm))
    {
        if (lineIsAlive(l))
        {
            realityclientCloseLineBidirectional(t, l);
        }
        return false;
    }
    if (! lineIsAlive(l))
    {
        return false;
    }

    ls = lineGetState(l, t);
    if (ls->terminal_closing || ls->phase != kRealityClientPhaseRealityActive ||
        ! ls->handoff_confirm_sent)
    {
        return false;
    }

    ls->downstream_est_sent = true;
    if (! withLineLocked(l, tunnelPrevDownStreamEst, t))
    {
        return false;
    }

    ls = lineGetState(l, t);
    if (ls->terminal_closing || ls->phase != kRealityClientPhaseRealityActive)
    {
        return false;
    }
    if (! realityclientFlushPendingUpstream(t, l))
    {
        return false;
    }
    if (! lineIsAlive(l))
    {
        return false;
    }

    ls = lineGetState(l, t);
    ls->handoff_completion_in_progress = false;
    return realityclientProcessDownstream(t, l, NULL);
}

bool realityclientProcessHandoffDownstream(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    realityclient_tstate_t *ts = tunnelGetState(t);
    realityclient_lstate_t *ls = lineGetState(l, t);
    if (ls->phase != kRealityClientPhaseTls13AwaitAck || ! ls->session_keys_ready ||
        ! ls->handoff_request_sent)
    {
        if (buf != NULL)
        {
            lineReuseBuffer(l, buf);
        }
        realityclientCloseLineBidirectional(t, l);
        return false;
    }

    if (buf != NULL)
    {
        bufferstreamPush(&ls->handoff_stream, buf);
    }

    /*
     * Consuming a requested KeyUpdate may synchronously emit TLS protocol
     * output.  The destination can answer that output while this stack is
     * still inside BoringSSL.  Queue such downstream records and let the
     * outer dispatcher authenticate ACK only after Consume has returned, so
     * CompleteTakeover can never free SSL/BIO state beneath it.
     */
    if (ls->handoff_cover_consume_in_progress)
    {
        return true;
    }

    while (lineIsAlive(l))
    {
        ls = lineGetState(l, t);
        if (ls->phase != kRealityClientPhaseTls13AwaitAck)
        {
            return ls->phase == kRealityClientPhaseRealityActive;
        }

        sbuf_t *record = NULL;
        int read_result = realityclientTryReadCompleteTlsRecord(&ls->handoff_stream, &record);
        if (read_result == kRealityFrameNeedMore)
        {
            return true;
        }
        if (read_result == kRealityFrameInvalid)
        {
            LOGW("RealityClient: invalid TLS record during authenticated handoff");
            bufferstreamEmpty(&ls->handoff_stream);
            realityclientCloseLineBidirectional(t, l);
            return false;
        }

        buffer_pool_t *pool = lineGetBufferPool(l);
        sbuf_t *candidate = sbufDuplicateByPool(pool, record);
        reality_v2_record_descriptor_t ack_descriptor;
        uint8_t plaintext[kRealityV2ControlMaxInnerPlaintext] = {0};
        uint32_t payload_offset = 0;
        uint32_t payload_len = 0;
        bool ack_decrypted = candidate != NULL &&
            realityV2BuildRecordDescriptor(kRealityV2Tls13,
                                           &ls->record_profile,
                                           kRealityV2RecordKindHandoffAck,
                                           &ack_descriptor) &&
            realityV2TryDecryptExpectedRecord(&ack_descriptor,
                                              kRealityV2DirectionServerToClient,
                                              ls->s2c_recv_seq,
                                              ls->session_id,
                                              ls->s2c_key,
                                              ls->s2c_iv,
                                              sbufGetRawPtr(candidate),
                                              sbufGetLength(candidate),
                                              realityclientCommonDecrypt,
                                              ts,
                                              plaintext,
                                              sizeof(plaintext),
                                              &payload_offset,
                                              &payload_len);
        if (candidate != NULL)
        {
            bufferpoolReuseBuffer(pool, candidate);
        }

        if (ack_decrypted)
        {
            bool control_ok = realityV2ParseControl(kRealityV2RecordKindHandoffAck,
                                                    plaintext + payload_offset,
                                                    payload_len);
            memoryZero(plaintext, sizeof(plaintext));
            lineReuseBuffer(l, record);
            if (! control_ok || ls->s2c_recv_seq != 0)
            {
                LOGW("RealityClient: invalid authenticated handoff ACK");
                bufferstreamEmpty(&ls->handoff_stream);
                realityclientCloseLineBidirectional(t, l);
                return false;
            }
            ls->s2c_recv_seq = 1;
            ls->handoff_ack_authenticated = true;
            return realityclientCompleteTls13Handoff(t, l);
        }
        memoryZero(plaintext, sizeof(plaintext));

        ls->handoff_cover_consume_in_progress = true;
        lineLock(l);
        tlsclient_post_handshake_result_t consume_result =
            tlsclientTunnelConsumePostHandshakeRecord(ts->tls_tunnel, l, record);
        if (! lineIsAlive(l))
        {
            lineUnlock(l);
            return false;
        }

        ls = lineGetState(l, t);
        if (ls->phase != kRealityClientPhaseTls13AwaitAck || ! ls->session_keys_ready ||
            ! ls->handoff_request_sent || ls->terminal_closing)
        {
            lineUnlock(l);
            return false;
        }
        ls->handoff_cover_consume_in_progress = false;
        lineUnlock(l);
        if (consume_result != kTlsClientPostHandshakeNeedMore)
        {
            return false;
        }
    }
    return false;
}

bool realityclientEncryptAndSend(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    realityclient_tstate_t *ts            = tunnelGetState(t);
    realityclient_lstate_t *ls            = lineGetState(l, t);
    uint32_t                plaintext_len = sbufGetLength(buf);

    if (ls->phase != kRealityClientPhaseRealityActive ||
        (ls->tls_version == kRealityV2Tls13 && ! ls->handoff_confirm_sent))
    {
        lineReuseBuffer(l, buf);
        realityclientCloseLineBidirectional(t, l);
        return false;
    }

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

    if (ls->phase != kRealityClientPhaseRealityActive ||
        (ls->tls_version == kRealityV2Tls13 && ! ls->handoff_confirm_sent))
    {
        if (buf != NULL)
        {
            lineReuseBuffer(l, buf);
        }
        realityclientCloseLineBidirectional(t, l);
        return false;
    }

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
    ls->phase = kRealityClientPhaseTerminal;
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
    ls->phase = kRealityClientPhaseTerminal;
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
    ls->phase = kRealityClientPhaseTerminal;

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
    if (! lineIsAlive(l))
    {
        return;
    }
    realityclient_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kRealityClientPhaseRealityActive)
    {
        realityclientSendFatalAndClose(t, l);
        return;
    }
    realityclientCloseLineBidirectional(t, l);
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
