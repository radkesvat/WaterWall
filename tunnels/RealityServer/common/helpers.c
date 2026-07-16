#include "structure.h"

#include "loggers/network_logger.h"

enum frame_read_result_e
{
    kRealityFrameNeedMore = 0,
    kRealityFrameOk       = 1,
    kRealityFrameInvalid  = -1,
};

static void realityserverTerminalClose(tunnel_t *t, line_t *l, uint8_t alert,
                                       bool received_prev_finish, bool received_next_finish);

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

    reality_v2_record_profile_t profile = {0};
    if (! realityV2SelectRecordProfile(ls->tls_capture.binding.tls_version,
                                       ls->tls_capture.binding.cipher_suite,
                                       &profile))
    {
        return false;
    }

    if (ls->tls_capture.binding.tls_version == kRealityV2Tls12 &&
        (! realityserverTls12RecordTrackerSetProfile(&ls->client_record_tracker, &profile) ||
         ! realityserverTls12RecordTrackerSetProfile(&ls->server_record_tracker, &profile)))
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
    ls->record_profile = profile;
    memoryZero(&material, sizeof(material));
    ls->session_keys_ready = true;
    return true;
}

static bool realityserverEncryptFrame(realityserver_tstate_t *ts, realityserver_lstate_t *ls,
                                      buffer_pool_t *pool, uint8_t record_kind,
                                      const uint8_t *plaintext, uint32_t plaintext_len,
                                      sbuf_t **frame_buffer)
{
    if (! ls->session_keys_ready || ! realityV2SequenceAvailable(ls->s2c_send_seq) ||
        ! realityV2RecordProfileIsValid(&ls->record_profile) || frame_buffer == NULL)
    {
        return false;
    }

    reality_v2_record_descriptor_t descriptor;
    reality_v2_record_layout_t     layout;
    if (! realityV2BuildRecordDescriptor(ls->tls_capture.binding.tls_version,
                                         &ls->record_profile,
                                         record_kind,
                                         &descriptor) ||
        ! realityV2CalculateDescriptorLayout(&descriptor, plaintext_len, &layout))
    {
        return false;
    }

    uint32_t frame_len = kRealityServerTlsHeaderSize + layout.wire_body_len;
    sbuf_t  *out       = realityserverAllocFrameBuffer(pool, frame_len);
    out                = sbufReserveSpace(out, frame_len);
    sbufSetLength(out, frame_len);

    uint64_t sequence_number = ls->s2c_send_seq;
    uint8_t *frame           = sbufGetMutablePtr(out);
    frame[0]       = descriptor.outer_content_type;
    frame[1]       = kRealityServerTlsVersionMajor;
    frame[2]       = kRealityServerTlsVersionMinor;
    frame[3]       = (uint8_t) (layout.wire_body_len >> 8);
    frame[4]       = (uint8_t) layout.wire_body_len;

    uint8_t *visible_prefix = frame + kRealityServerTlsHeaderSize;
    uint64_t counter_value  = 0;
    bool     counter_used   = false;
    if (descriptor.profile.profile_id == kRealityV2RecordProfileTls12Gcm)
    {
        if (ls->server_gcm_nonce_policy == kRealityServerGcmNoncePolicySequence)
        {
            if (! realityV2AddTlsRecordSequence(ls->server_tls_sequence_base,
                                                sequence_number,
                                                &counter_value))
            {
                bufferpoolReuseBuffer(pool, out);
                return false;
            }
            realityV2WriteBe64(visible_prefix, counter_value);
        }
        else if (ls->server_gcm_nonce_policy == kRealityServerGcmNoncePolicyCounter)
        {
            counter_value = ls->server_gcm_counter_next;
            if (counter_value == UINT64_MAX)
            {
                bufferpoolReuseBuffer(pool, out);
                return false;
            }
            counter_used = true;
            realityV2WriteBe64(visible_prefix, counter_value);
        }
        else if (ls->server_gcm_nonce_policy == kRealityServerGcmNoncePolicyRandom)
        {
            if (UNLIKELY(! secureRandomBytes(visible_prefix, kRealityV2Tls12GcmPrefixSize)))
            {
                bufferpoolReuseBuffer(pool, out);
                return false;
            }
        }
        else
        {
            bufferpoolReuseBuffer(pool, out);
            return false;
        }
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
    realityV2BuildNonce(ls->s2c_iv, sequence_number, nonce);
    if (! realityV2BuildRecordAad(&descriptor,
                                  kRealityV2DirectionServerToClient,
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

    int result = realityserverEncryptAead(ts->algorithm,
                                          ciphertext,
                                          ciphertext,
                                          layout.inner_plaintext_len,
                                          aad,
                                          aad_len,
                                          nonce,
                                          ls->s2c_key);
    memoryZero(nonce, sizeof(nonce));
    memoryZero(aad, sizeof(aad));
    if (result != 0)
    {
        bufferpoolReuseBuffer(pool, out);
        return false;
    }

    ls->s2c_send_seq = sequence_number + 1;
    if (counter_used)
    {
        ls->server_gcm_counter_next = counter_value + 1U;
    }
    *frame_buffer = out;
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

static bool realityserverIsRealityCandidate(const realityserver_lstate_t *ls, sbuf_t *record)
{
    if (sbufGetLength(record) < kRealityServerTlsHeaderSize)
    {
        return false;
    }

    reality_v2_record_descriptor_t descriptor;
    return realityV2ClassifyRecord(ls->tls_capture.binding.tls_version,
                                   &ls->record_profile,
                                   sbufGetRawPtr(record),
                                   &descriptor);
}

static bool realityserverDecryptFrame(realityserver_tstate_t *ts, realityserver_lstate_t *ls,
                                      sbuf_t *frame_buffer, uint8_t *record_kind, uint8_t *alert)
{
    if (! ls->session_keys_ready || ! realityV2SequenceAvailable(ls->c2s_recv_seq) ||
        record_kind == NULL || alert == NULL)
    {
        return false;
    }

    uint64_t sequence_number = ls->c2s_recv_seq;
    uint8_t *frame           = sbufGetMutablePtr(frame_buffer);
    uint32_t body_len        = ((uint32_t) frame[3] << 8) | (uint32_t) frame[4];
    reality_v2_record_descriptor_t descriptor;
    if (! realityV2ClassifyRecord(ls->tls_capture.binding.tls_version,
                                  &ls->record_profile,
                                  frame,
                                  &descriptor))
    {
        return false;
    }
    uint32_t ciphertext_len = body_len - descriptor.visible_prefix_len;

    uint8_t *visible_prefix = frame + kRealityServerTlsHeaderSize;
    uint8_t *ciphertext     = visible_prefix + descriptor.visible_prefix_len;

    reality_v2_record_descriptor_t application_descriptor;
    bool ambiguous_tls13_kind =
        descriptor.tls_version == kRealityV2Tls13 &&
        descriptor.record_kind == kRealityV2RecordKindAlert &&
        realityV2BuildRecordDescriptor(ls->tls_capture.binding.tls_version,
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
            return false;
        }
        memoryCopy(encrypted_alert_backup, ciphertext, ciphertext_len);
    }

    if (descriptor.profile.profile_id == kRealityV2RecordProfileTls12Gcm)
    {
        uint64_t expected_tls_sequence;
        if (ls->mode == kRealityServerModePending)
        {
            if (! ls->client_record_tracker.last_record_was_protected)
            {
                return false;
            }
            expected_tls_sequence = ls->client_record_tracker.last_record_sequence;
        }
        else if (! realityV2AddTlsRecordSequence(ls->client_tls_sequence_base,
                                                 sequence_number,
                                                 &expected_tls_sequence))
        {
            return false;
        }

        if (realityV2ReadBe64(visible_prefix) != expected_tls_sequence)
        {
            return false;
        }
    }

    uint8_t nonce[kRealityV2IvSize];
    uint8_t aad[kRealityV2RecordAadMaxSize];
    size_t  aad_len = 0;
    realityV2BuildNonce(ls->c2s_iv, sequence_number, nonce);
    bool aad_ok = realityV2BuildRecordAad(&descriptor,
                                          kRealityV2DirectionClientToServer,
                                          sequence_number,
                                          ls->session_id,
                                          frame,
                                          visible_prefix,
                                          descriptor.visible_prefix_len,
                                          aad,
                                          &aad_len);
    int decrypt_result = aad_ok ? realityserverDecryptAead(ts->algorithm,
                                                           ciphertext,
                                                           ciphertext,
                                                           ciphertext_len,
                                                           aad,
                                                           aad_len,
                                                           nonce,
                                                           ls->c2s_key)
                                : -1;
    if (decrypt_result != 0 && ambiguous_tls13_kind)
    {
        memoryCopy(ciphertext, encrypted_alert_backup, ciphertext_len);
        descriptor = application_descriptor;
        aad_len     = 0;
        memoryZero(aad, sizeof(aad));
        aad_ok = realityV2BuildRecordAad(&descriptor,
                                         kRealityV2DirectionClientToServer,
                                         sequence_number,
                                         ls->session_id,
                                         frame,
                                         visible_prefix,
                                         descriptor.visible_prefix_len,
                                         aad,
                                         &aad_len);
        decrypt_result = aad_ok ? realityserverDecryptAead(ts->algorithm,
                                                           ciphertext,
                                                           ciphertext,
                                                           ciphertext_len,
                                                           aad,
                                                           aad_len,
                                                           nonce,
                                                           ls->c2s_key)
                                : -1;
    }
    memoryZero(nonce, sizeof(nonce));
    memoryZero(aad, sizeof(aad));
    memoryZero(encrypted_alert_backup, sizeof(encrypted_alert_backup));
    if (decrypt_result != 0)
    {
        return false;
    }

    uint32_t inner_plaintext_len = ciphertext_len - kRealityServerTagSize;
    uint32_t inner_payload_offset;
    uint32_t payload_len;
    if (! realityV2ValidateInnerPlaintext(&descriptor,
                                          ciphertext,
                                          inner_plaintext_len,
                                          &inner_payload_offset,
                                          &payload_len))
    {
        return false;
    }

    uint8_t parsed_alert = kRealityV2AlertInvalid;
    if (descriptor.record_kind == kRealityV2RecordKindAlert &&
        ! realityV2ParseAlert(ciphertext + inner_payload_offset, payload_len, &parsed_alert))
    {
        return false;
    }

    ls->c2s_recv_seq = sequence_number + 1;
    *record_kind      = descriptor.record_kind;
    *alert            = parsed_alert;
    uint32_t payload_offset = kRealityServerTlsHeaderSize + descriptor.visible_prefix_len +
                              inner_payload_offset;
    sbufShiftRight(frame_buffer, payload_offset);
    sbufSetLength(frame_buffer, payload_len);
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
    bufferstreamEmpty(&ls->downstream_tls_observe_stream);
    return realityserverFlushBufferedToDestination(t, l, ls);
}

bool realityserverFreezeTlsCamouflage(realityserver_tstate_t *ts, realityserver_lstate_t *ls)
{
    if (ls->tls_capture.binding.tls_version != kRealityV2Tls12)
    {
        return true;
    }

    realityserver_tls12_record_tracker_t *client = &ls->client_record_tracker;
    realityserver_tls12_record_tracker_t *server = &ls->server_record_tracker;
    if (client->failed || server->failed || ! client->protected_epoch || ! server->protected_epoch ||
        ! client->saw_protected_record || ! server->saw_protected_record ||
        ! client->last_record_was_protected || client->last_record_sequence == 0 || ls->c2s_recv_seq != 1)
    {
        return false;
    }

    ls->client_tls_sequence_base = client->last_record_sequence;
    ls->server_tls_sequence_base = server->next_sequence;

    if (ls->record_profile.profile_id == kRealityV2RecordProfileTls12Gcm)
    {
        if (! realityserverResolveGcmNoncePolicy(ts->tls12_gcm_server_nonce_policy,
                                                 server,
                                                 &ls->server_gcm_nonce_policy,
                                                 &ls->server_gcm_counter_next))
        {
            return false;
        }
    }

    realityserverTls12RecordTrackerFreeze(client);
    realityserverTls12RecordTrackerFreeze(server);
    return true;
}

static bool realityserverSwitchToAuthorized(tunnel_t *t, line_t *l, realityserver_lstate_t *ls)
{
    realityserver_tstate_t *ts = tunnelGetState(t);

    if (ls->mode == kRealityServerModeAuthorized)
    {
        return true;
    }

    if (! realityserverFreezeTlsCamouflage(ts, ls))
    {
        return false;
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

    if (plaintext_len > kRealityV2MaxPlaintextFragment)
    {
        buffer_pool_t *pool      = lineGetBufferPool(l);
        const uint8_t *src       = sbufGetRawPtr(buf);
        uint32_t       remaining = plaintext_len;

        while (remaining > 0)
        {
            uint32_t chunk_len = min(remaining, (uint32_t) kRealityV2MaxPlaintextFragment);
            sbuf_t *frame_buf = NULL;
            if (! realityserverEncryptFrame(ts,
                                             ls,
                                             pool,
                                             kRealityV2RecordKindApplicationData,
                                             src,
                                             chunk_len,
                                             &frame_buf))
            {
                LOGW("RealityServer: failed to encrypt downstream payload chunk");
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
            ls = lineGetState(l, t);
            if (ls->terminal_closing || ls->prev_finished)
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
    if (! realityserverEncryptFrame(ts,
                                     ls,
                                     pool,
                                     kRealityV2RecordKindApplicationData,
                                     sbufGetRawPtr(buf),
                                     plaintext_len,
                                     &frame_buf))
    {
        LOGW("RealityServer: failed to encrypt downstream payload");
        bufferpoolReuseBuffer(pool, buf);
        realityserverCloseLineBidirectional(t, l);
        return false;
    }

    bufferpoolReuseBuffer(pool, buf);
    return withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, frame_buf);
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
                realityserverFailAuthenticated(t, l);
                return false;
            }

            return realityserverSwitchToVisitor(t, l, ls);
        }

        if (ls->mode == kRealityServerModePending && ls->session_keys_ready &&
            ls->tls_capture.binding.tls_version == kRealityV2Tls12 &&
            ! realityserverTls12RecordTrackerFeed(&ls->client_record_tracker,
                                                   sbufGetRawPtr(record),
                                                   sbufGetLength(record)))
        {
            ls->mode = kRealityServerModeVisitor;
            if (! realityserverForwardToDestination(t, l, record))
            {
                return false;
            }
            return realityserverFlushBufferedToDestination(t, l, ls);
        }

        bool candidate = realityserverIsRealityCandidate(ls, record);
        if (! candidate)
        {
            if (ls->mode == kRealityServerModeAuthorized)
            {
                LOGW("RealityServer: non-Reality TLS record after authorization");
                lineReuseBuffer(l, record);
                bufferstreamEmpty(&ls->read_stream);
                realityserverFailAuthenticated(t, l);
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
                realityserverFailAuthenticated(t, l);
                return false;
            }

            if (! realityserverForwardToDestination(t, l, record))
            {
                return false;
            }
            continue;
        }

        sbuf_t *candidate_buf = realityserverDuplicateBuffer(pool, record);
        uint8_t record_kind   = kRealityV2RecordKindInvalid;
        uint8_t alert         = kRealityV2AlertInvalid;
        bool decrypt_ok = realityserverDecryptFrame(ts, ls, candidate_buf, &record_kind, &alert);

        if (decrypt_ok)
        {
            if (! realityserverSwitchToAuthorized(t, l, ls))
            {
                bufferpoolReuseBuffer(pool, candidate_buf);
                if (lineIsAlive(l) && ls->mode == kRealityServerModePending)
                {
                    ls->mode = kRealityServerModeVisitor;
                    if (! realityserverForwardToDestination(t, l, record))
                    {
                        return false;
                    }
                    return realityserverFlushBufferedToDestination(t, l, ls);
                }
                bufferpoolReuseBuffer(pool, record);
                return false;
            }

            bufferpoolReuseBuffer(pool, record);

            if (record_kind == kRealityV2RecordKindAlert)
            {
                bufferpoolReuseBuffer(pool, candidate_buf);
                bufferstreamEmpty(&ls->read_stream);
                realityserverHandlePeerAlert(t, l, alert);
                return false;
            }

            if (! withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, candidate_buf))
            {
                return false;
            }
            ls = lineGetState(l, t);
            if (ls->terminal_closing || ls->next_finished)
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
            realityserverFailAuthenticated(t, l);
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

    if (ls->mode != kRealityServerModePending)
    {
        return true;
    }

    bool buffered_current = false;
    if (! ls->session_keys_ready && len > 0)
    {
        buffer_pool_t *pool     = lineGetBufferPool(l);
        sbuf_t        *observed = realityserverAllocFrameBuffer(pool, (uint32_t) len);
        observed                = sbufReserveSpace(observed, (uint32_t) len);
        sbufSetLength(observed, (uint32_t) len);
        memoryCopyLarge(sbufGetMutablePtr(observed), data, len);
        bufferstreamPush(&ls->downstream_tls_observe_stream, observed);
        buffered_current = true;
    }

    if (! ls->session_keys_ready &&
        ! realityserverTlsParserFeed(&ls->server_hello_parser, data, len, &ls->tls_capture))
    {
        bufferstreamEmpty(&ls->downstream_tls_observe_stream);
        return realityserverSwitchToVisitor(t, l, ls);
    }

    if (! ls->session_keys_ready && ls->tls_capture.client_ready && ls->tls_capture.server_ready)
    {
        if (! realityserverDeriveSessionKeys(ts, ls))
        {
            bufferstreamEmpty(&ls->downstream_tls_observe_stream);
            return realityserverSwitchToVisitor(t, l, ls);
        }
    }

    if (! ls->session_keys_ready)
    {
        return true;
    }

    if (ls->tls_capture.binding.tls_version != kRealityV2Tls12)
    {
        bufferstreamEmpty(&ls->downstream_tls_observe_stream);
        return true;
    }

    if (bufferstreamGetBufLen(&ls->downstream_tls_observe_stream) > 0)
    {
        sbuf_t *observed = bufferstreamFullRead(&ls->downstream_tls_observe_stream);
        bool ok = realityserverTls12RecordTrackerFeed(&ls->server_record_tracker,
                                                       sbufGetRawPtr(observed),
                                                       sbufGetLength(observed));
        lineReuseBuffer(l, observed);
        if (! ok)
        {
            return realityserverSwitchToVisitor(t, l, ls);
        }
    }
    else if (! buffered_current &&
             ! realityserverTls12RecordTrackerFeed(&ls->server_record_tracker, data, len))
    {
        return realityserverSwitchToVisitor(t, l, ls);
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
    realityserverTerminalClose(t, l, kRealityV2AlertInvalid, false, false);
}

static void realityserverTerminalClose(tunnel_t *t, line_t *l, uint8_t alert,
                                       bool received_prev_finish, bool received_next_finish)
{
    if (! lineIsAlive(l))
    {
        return;
    }

    lineLock(l);
    realityserver_tstate_t *ts = tunnelGetState(t);
    realityserver_lstate_t *ls = lineGetState(l, t);
    if (received_prev_finish)
    {
        ls->prev_finished = true;
    }
    if (received_next_finish)
    {
        ls->next_finished = true;
        if (ls->mode != kRealityServerModeAuthorized)
        {
            ls->destination_up_finished = true;
        }
    }
    if (ls->terminal_closing)
    {
        lineUnlock(l);
        return;
    }

    ls->terminal_closing = true;

    if (alert != kRealityV2AlertInvalid && ls->session_keys_ready && ! ls->prev_finished &&
        ! ls->wire_alert_sent)
    {
        uint8_t alert_bytes[kRealityV2AlertMessageSize];
        sbuf_t *frame = NULL;
        bool built = realityV2SerializeAlert(alert, alert_bytes) &&
                     realityserverEncryptFrame(ts,
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
            tunnelPrevDownStreamPayload(t, l, frame);
            if (! lineIsAlive(l))
            {
                /* This close frame owns cleanup; terminal re-entry deliberately defers to it. */
                realityserverLinestateDestroy(lineGetState(l, t));
                lineUnlock(l);
                return;
            }
            ls = lineGetState(l, t);
        }
    }

    bool close_protected = ls->mode == kRealityServerModeAuthorized && ls->protected_init_sent &&
                           ! ls->next_finished;
    bool close_destination =
        ls->destination_init_sent && ! ls->destination_up_finished && ls->mode != kRealityServerModeAuthorized;
    bool close_prev = ! ls->prev_finished;

    realityserverLinestateDestroy(ls);

    if (close_protected)
    {
        tunnelNextUpStreamFinish(t, l);
    }
    else if (close_destination)
    {
        tunnelUpStreamFin(ts->destination_tunnel, l);
    }

    if ((close_protected || close_destination) && ! lineIsAlive(l))
    {
        lineUnlock(l);
        return;
    }
    if (close_prev)
    {
        tunnelPrevDownStreamFinish(t, l);
    }
    lineUnlock(l);
}

void realityserverFailAuthenticated(tunnel_t *t, line_t *l)
{
    realityserverTerminalClose(t, l, kRealityV2AlertBadRecordMac, false, false);
}

void realityserverHandlePeerAlert(tunnel_t *t, line_t *l, uint8_t alert)
{
    if (alert == kRealityV2AlertCloseNotify)
    {
        realityserverTerminalClose(t, l, kRealityV2AlertCloseNotify, false, false);
        return;
    }
    realityserverTerminalClose(t, l, kRealityV2AlertInvalid, false, false);
}

void realityserverHandleUpstreamFinish(tunnel_t *t, line_t *l)
{
    realityserverTerminalClose(t, l, kRealityV2AlertInvalid, true, false);
}

void realityserverHandleDownstreamFinish(tunnel_t *t, line_t *l)
{
    realityserver_lstate_t *ls = lineGetState(l, t);
    uint8_t alert = ls->mode == kRealityServerModeAuthorized && ls->session_keys_ready
                        ? kRealityV2AlertCloseNotify
                        : kRealityV2AlertInvalid;
    realityserverTerminalClose(t, l, alert, false, true);
}
