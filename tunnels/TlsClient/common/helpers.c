#include "structure.h"

#include "loggers/network_logger.h"

void tlsclientCloseLineBidirectional(tunnel_t *t, line_t *l)
{
    if (! lineIsAlive(l))
    {
        return;
    }

    lineLock(l);

    tlsclient_lstate_t *ls = lineGetState(l, t);
    tlsclientLinestateDestroy(ls);

    tunnelNextUpStreamFinish(t, l);
    if (! lineIsAlive(l))
    {
        lineUnlock(l);
        return;
    }

    tunnelPrevDownStreamFinish(t, l);
    lineUnlock(l);
}

void tlsclientPrintSSLState(const SSL *ssl)
{
    const char *current_state = SSL_state_string_long(ssl);
    LOGD("TlsClient: BoringSSL State: %s", current_state);
}

void tlsclientPrintSSLError(void)
{
    BIO *bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char  *buf = NULL;
    size_t len = BIO_get_mem_data(bio, &buf);
    if (len > 0)
    {
        LOGE("TlsClient: BoringSSL Error: %.*s", (int) len, buf);
    }
    BIO_free(bio);
}
void tlsclientPrintSSLErrorAndAbort(void)
{
    tlsclientPrintSSLError();
    abort();
}

bool tlsclientDrainBioToBuffer(buffer_pool_t *pool, BIO *bio, sbuf_t **out)
{
    assert(pool != NULL && bio != NULL && out != NULL);
    *out = NULL;

    const size_t pending = BIO_ctrl_pending(bio);
    if (pending == 0)
    {
        return true;
    }

    const uint16_t padding  = bufferpoolGetLargeBufferPadding(pool);
    uint32_t       capacity = 0;
    if (pending > INT_MAX || ! sbufTryComputeCapacity(pending, padding, &capacity))
    {
        return false;
    }
    discard capacity;

    sbuf_t *buf = bufferpoolGetLargeBuffer(pool);
    buf         = sbufReserveSpace(buf, (uint32_t) pending);

    size_t offset = 0;
    while (offset < pending)
    {
        const int n = BIO_read(bio, sbufGetMutablePtr(buf) + offset, (int) (pending - offset));
        if (n <= 0)
        {
            bufferpoolReuseBuffer(pool, buf);
            return false;
        }
        offset += (size_t) n;
    }

    if (BIO_ctrl_pending(bio) != 0)
    {
        bufferpoolReuseBuffer(pool, buf);
        return false;
    }

    sbufSetLength(buf, (uint32_t) pending);
    *out = buf;
    return true;
}

static bool tlsclientDrainPendingRawBytes(line_t *l, BIO *bio, sbuf_t **pending_raw)
{
    if (pending_raw != NULL)
    {
        *pending_raw = NULL;
    }

    if (bio == NULL || pending_raw == NULL)
    {
        return true;
    }

    return tlsclientDrainBioToBuffer(lineGetBufferPool(l), bio, pending_raw);
}

static bool tlsclientRecordHeader(const uint8_t header[kTlsClientRecordHeaderSize], size_t *record_len)
{
    const uint8_t  type     = header[0];
    const uint16_t body_len = ((uint16_t) header[3] << 8U) | (uint16_t) header[4];

    if ((type != SSL3_RT_CHANGE_CIPHER_SPEC && type != SSL3_RT_ALERT && type != SSL3_RT_HANDSHAKE &&
         type != SSL3_RT_APPLICATION_DATA) ||
        header[1] != SSL3_VERSION_MAJOR || header[2] < (TLS1_VERSION & 0xff) || header[2] > (TLS1_3_VERSION & 0xff) ||
        body_len > kTlsClientMaxRecordBody)
    {
        return false;
    }

    *record_len = kTlsClientRecordHeaderSize + (size_t) body_len;
    return true;
}

static bool tlsclientRawRecordIsComplete(const sbuf_t *record)
{
    if (record == NULL || sbufGetLength(record) < kTlsClientRecordHeaderSize)
    {
        return false;
    }

    size_t record_len = 0;
    return tlsclientRecordHeader((const uint8_t *) sbufGetRawPtr(record), &record_len) &&
           record_len == sbufGetLength(record);
}

bool tlsclientTakeoverTryReadRecord(tlsclient_lstate_t *ls, sbuf_t **record, bool *invalid)
{
    assert(ls != NULL && record != NULL && invalid != NULL);
    *record  = NULL;
    *invalid = false;

    if (bufferstreamGetBufLen(&ls->takeover_stream) < kTlsClientRecordHeaderSize)
    {
        return false;
    }

    uint8_t header[kTlsClientRecordHeaderSize];
    bufferstreamViewBytesAt(&ls->takeover_stream, 0, header, sizeof(header));

    size_t record_len = 0;
    if (! tlsclientRecordHeader(header, &record_len))
    {
        *invalid = true;
        return false;
    }

    if (bufferstreamGetBufLen(&ls->takeover_stream) < record_len)
    {
        return false;
    }

    *record = bufferstreamReadExact(&ls->takeover_stream, record_len);
    return true;
}

/*
 * The takeover path supplies one externally framed TLS record at a time.
 * Vendored BoringSSL's tls_read_buffer_extend_to() reads only the requested
 * header/record length and handshake.cc discards the consumed read_buffer.
 * In TLS (unlike DTLS), BoringSSL documents that it performs no read-ahead.
 * Checking both the BIO and SSL_has_pending() therefore covers the transport
 * BIO and BoringSSL's internal decrypted/encrypted read buffer respectively.
 */
bool tlsclientSslReadBoundaryIsClean(tlsclient_lstate_t *ls)
{
    return ls->ssl != NULL && SSL_get_rbio(ls->ssl) != NULL && BIO_ctrl_pending(SSL_get_rbio(ls->ssl)) == 0 &&
           SSL_has_pending(ls->ssl) == 0;
}

size_t tlsclientRecordPaddingCallback(SSL *ssl, uint8_t type, size_t plaintext_len, size_t max_padding, void *arg)
{
    tlsclient_lstate_t *ls = arg;
    if (ls == NULL || ls->ssl != ssl || ls->resources_released || ! ls->handshake_completed || ls->tunnel == NULL ||
        SSL_version(ssl) != TLS1_3_VERSION)
    {
        return 0;
    }

    tlsclient_tstate_t         *ts                = tunnelGetState(ls->tunnel);
    tlsrecordshaping_decision_t decision          = {0};
    uint32_t                    effective_padding = 0;

    if (type == SSL3_RT_APPLICATION_DATA && plaintext_len > 0)
    {
        discard tlsrecordshapingSample(&ts->record_shaping, &ls->shaping_state, &decision);
        effective_padding =
            decision.requested_padding_bytes < max_padding ? decision.requested_padding_bytes : (uint32_t) max_padding;
        tlsrecordshapingRecordEffectivePadding(&ls->shaping_state, &decision, effective_padding);
    }

    if (! tlsrecordshapingOutputQueuePushMetadata(&ls->shaping_output, decision.delay_ms))
    {
        ls->shaping_metadata_error = true;
        return 0;
    }
    return effective_padding;
}

void tlsclientCancelShapedOutputTimer(tlsclient_lstate_t *ls)
{
    if (ls->shaping_output_timer == NULL)
    {
        return;
    }
    weventSetUserData(ls->shaping_output_timer, NULL);
    wtimerDelete(ls->shaping_output_timer);
    ls->shaping_output_timer = NULL;
}

static bool tlsclientUpdateShapingBackpressure(tunnel_t *t, line_t *l, tlsclient_lstate_t *ls)
{
    size_t queued = tlsrecordshapingOutputQueueBytes(&ls->shaping_output);
    if (! ls->shaping_producer_paused && queued >= kTlsRecordShapingQueueHighWatermark)
    {
        ls->shaping_producer_paused = true;
        if (! ls->shaping_wire_paused && ! ls->upstream_finished)
        {
            if (! withLineLocked(l, tunnelPrevDownStreamPause, t))
            {
                return false;
            }
        }
        return true;
    }

    if (ls->shaping_producer_paused && queued <= kTlsRecordShapingQueueLowWatermark)
    {
        ls->shaping_producer_paused = false;
        if (! ls->shaping_wire_paused && ! ls->upstream_finished)
        {
            if (! withLineLocked(l, tunnelPrevDownStreamResume, t))
            {
                return false;
            }
        }
    }
    return true;
}

bool tlsclientDrainShapedOutput(tunnel_t *t, line_t *l, tlsclient_lstate_t *ls, bool force)
{
    if (ls->shaping_wire_paused)
    {
        return tlsclientUpdateShapingBackpressure(t, l, ls);
    }

    uint64_t now_ms = wloopNowMS(getWorkerLoop(lineGetWID(l)));
    while (! ls->shaping_wire_paused)
    {
        sbuf_t *record = tlsrecordshapingOutputQueuePopReady(&ls->shaping_output, now_ms, force);
        if (record == NULL)
        {
            break;
        }

        if (! withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, record))
        {
            return false;
        }

        ls = lineGetState(l, t);
        if (ls->tunnel != t || ls->resources_released || ! ls->shaping_output.initialized)
        {
            return false;
        }
        now_ms = wloopNowMS(getWorkerLoop(lineGetWID(l)));
    }
    return tlsclientUpdateShapingBackpressure(t, l, ls);
}

static void tlsclientShapingOutputTimerCallback(wtimer_t *timer)
{
    tlsclient_lstate_t *ls = weventGetUserdata(timer);
    if (ls == NULL)
    {
        return;
    }

    ls->shaping_output_timer = NULL;
    tunnel_t *t              = ls->tunnel;
    line_t   *l              = ls->line;
    if (t == NULL || l == NULL || ! lineIsAlive(l) || ls->resources_released)
    {
        return;
    }

    lineLock(l);
    if (! tlsclientDrainShapedOutput(t, l, ls, false))
    {
        if (lineIsAlive(l))
        {
            bool state_is_active = ((tlsclient_lstate_t *) lineGetState(l, t))->tunnel == t;
            lineUnlock(l);
            if (state_is_active)
            {
                tlsclientCloseLineBidirectional(t, l);
            }
            return;
        }
        lineUnlock(l);
        return;
    }

    ls = lineGetState(l, t);
    if (! tlsclientScheduleShapedOutput(t, l, ls))
    {
        if (lineIsAlive(l))
        {
            bool state_is_active = ((tlsclient_lstate_t *) lineGetState(l, t))->tunnel == t;
            lineUnlock(l);
            if (state_is_active)
            {
                tlsclientCloseLineBidirectional(t, l);
            }
            return;
        }
    }
    lineUnlock(l);
}

bool tlsclientScheduleShapedOutput(tunnel_t *t, line_t *l, tlsclient_lstate_t *ls)
{
    if (ls->shaping_output_timer != NULL || ls->shaping_wire_paused ||
        tlsrecordshapingOutputQueueIsEmpty(&ls->shaping_output))
    {
        return true;
    }

    uint32_t delay_ms = 0;
    if (! tlsrecordshapingOutputQueueNextDelay(
            &ls->shaping_output, wloopNowMS(getWorkerLoop(lineGetWID(l))), &delay_ms))
    {
        return true;
    }
    if (delay_ms == 0)
    {
        return tlsclientDrainShapedOutput(t, l, ls, false);
    }

    ls->shaping_output_timer =
        wtimerAdd(getWorkerLoop(lineGetWID(l)), tlsclientShapingOutputTimerCallback, delay_ms, 1);
    if (ls->shaping_output_timer != NULL)
    {
        weventSetUserData(ls->shaping_output_timer, ls);
        return true;
    }

    if (! ls->shaping_timer_failure_logged)
    {
        LOGW("TlsClient: failed to allocate record shaping timer; draining queued ciphertext immediately");
        ls->shaping_timer_failure_logged = true;
    }
    return tlsclientDrainShapedOutput(t, l, ls, true);
}

bool tlsclientFlushSslOutput(tunnel_t *t, line_t *l, tlsclient_lstate_t *ls)
{
    BIO *wbio = ls != NULL ? ls->wbio : NULL;
    if (t == NULL || l == NULL || wbio == NULL)
    {
        return false;
    }

    tlsclient_tstate_t *ts = tunnelGetState(t);
    bool shape_output = ts->record_shaping.enabled && ls->handshake_completed && SSL_version(ls->ssl) == TLS1_3_VERSION;

    buffer_pool_t *pool = lineGetBufferPool(l);
    while (true)
    {
        sbuf_t *ssl_buf = bufferpoolGetLargeBuffer(pool);
        int     avail   = (int) sbufGetMaximumWriteableSize(ssl_buf);
        int     n       = BIO_read(wbio, sbufGetMutablePtr(ssl_buf), avail);

        if (n > 0)
        {
            sbufSetLength(ssl_buf, (uint32_t) n);
            if (shape_output)
            {
                char queue_error[kTlsRecordShapingErrorSize];
                if (! tlsrecordshapingOutputQueueFeed(
                        &ls->shaping_output, ssl_buf, wloopNowMS(getWorkerLoop(lineGetWID(l))), queue_error))
                {
                    LOGW("TlsClient: %s", queue_error);
                    return false;
                }
                continue;
            }

            if (! withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, ssl_buf))
            {
                return false;
            }

            ls = lineGetState(l, t);
            if (ls->resources_released || ls->wbio != wbio)
            {
                return false;
            }
            continue;
        }

        bufferpoolReuseBuffer(pool, ssl_buf);
        if (! BIO_should_retry(wbio))
        {
            return false;
        }
        break;
    }

    if (! shape_output)
    {
        return true;
    }
    if (ls->shaping_metadata_error)
    {
        LOGW("TlsClient: failed to enqueue TLS record shaping metadata");
        return false;
    }

    char queue_error[kTlsRecordShapingErrorSize];
    if (! tlsrecordshapingOutputQueueFinishFeed(&ls->shaping_output, queue_error))
    {
        LOGW("TlsClient: %s", queue_error);
        return false;
    }

    size_t queued = tlsrecordshapingOutputQueueBytes(&ls->shaping_output);
    if (queued > ls->shaping_state.maximum_queued_ciphertext_bytes)
    {
        ls->shaping_state.maximum_queued_ciphertext_bytes = queued;
    }

    bool force = queued >= kTlsRecordShapingQueueHardLimit;
    if (force && ls->shaping_wire_paused)
    {
        LOGW("TlsClient: record shaping queue exceeded 1 MiB while the wire side was paused");
        return false;
    }
    if (! tlsclientDrainShapedOutput(t, l, ls, force))
    {
        return false;
    }

    ls = lineGetState(l, t);
    if (tlsrecordshapingOutputQueueBytes(&ls->shaping_output) >= kTlsRecordShapingQueueHardLimit)
    {
        LOGW("TlsClient: record shaping queue could not be reduced below its 1 MiB hard limit");
        return false;
    }
    return tlsclientScheduleShapedOutput(t, l, ls);
}

static bool tlsclientFlushPostHandshakeProtocolOutput(tunnel_t *t, line_t *l, tlsclient_lstate_t *ls)
{
    /*
     * BoringSSL queues a requested TLS 1.3 KeyUpdate response internally.
     * Its public SSL_key_update contract specifies a zero-length SSL_write as
     * the way to flush queued handshake messages without application data.
     */
    int n = SSL_write(ls->ssl, NULL, 0);
    if (n < 0)
    {
        int ssl_error = SSL_get_error(ls->ssl, n);
        if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE)
        {
            return false;
        }
    }

    return tlsclientFlushSslOutput(t, l, ls);
}

bool tlsclientTunnelEnableHandshakeTakeover(tunnel_t *t)
{
    tlsclient_tstate_t *ts = tunnelGetState(t);
    if (tlsrecordshapingConfigCanDelay(&ts->record_shaping))
    {
        LOGF("TlsClient: handshake takeover cannot be combined with tls13-record-shaping delay");
        return false;
    }
    ts->handshake_takeover_enabled = true;
    return true;
}

bool tlsclientTunnelIsHandshakeCompleted(tunnel_t *t, line_t *l)
{
    tlsclient_lstate_t *ls = lineGetState(l, t);
    return ls->handshake_completed;
}

bool tlsclientTunnelGetHandshakeBinding(tunnel_t *t, line_t *l, tlsclient_handshake_binding_t *binding)
{
    if (t == NULL || l == NULL || binding == NULL)
    {
        return false;
    }

    tlsclient_lstate_t *ls = lineGetState(l, t);
    if (! ls->handshake_completed || ls->ssl == NULL || ls->resources_released ||
        ls->takeover_phase == kTlsClientTakeoverPassthrough)
    {
        return false;
    }

    tlsclient_handshake_binding_t result  = {0};
    const SSL_CIPHER             *cipher  = SSL_get_current_cipher(ls->ssl);
    int                           version = SSL_version(ls->ssl);

    if (cipher == NULL || version <= 0 || version > UINT16_MAX ||
        SSL_get_client_random(ls->ssl, result.client_random, sizeof(result.client_random)) !=
            sizeof(result.client_random) ||
        SSL_get_server_random(ls->ssl, result.server_random, sizeof(result.server_random)) !=
            sizeof(result.server_random))
    {
        memoryZero(&result, sizeof(result));
        return false;
    }

    result.tls_version  = (uint16_t) version;
    result.cipher_suite = SSL_CIPHER_get_protocol_id(cipher);
    if (result.cipher_suite == 0)
    {
        memoryZero(&result, sizeof(result));
        return false;
    }

    if (result.tls_version == TLS1_2_VERSION)
    {
        result.next_read_sequence    = SSL_get_read_sequence(ls->ssl);
        result.next_write_sequence   = SSL_get_write_sequence(ls->ssl);
        result.tls12_sequences_valid = true;
    }

    *binding = result;
    memoryZero(&result, sizeof(result));
    return true;
}

bool tlsclientTunnelDeinitAfterHandshake(tunnel_t *t, line_t *l, sbuf_t **pending_raw)
{
    tlsclient_tstate_t *ts = tunnelGetState(t);
    tlsclient_lstate_t *ls = lineGetState(l, t);

    if (pending_raw != NULL)
    {
        *pending_raw = NULL;
    }

    if (ts->handshake_takeover_enabled && ls->handshake_completed &&
        ls->takeover_phase == kTlsClientTakeoverPassthrough)
    {
        return true;
    }

    if (! ts->handshake_takeover_enabled || ! ls->handshake_completed || ls->ssl == NULL || ls->resources_released)
    {
        return false;
    }

    if (SSL_version(ls->ssl) == TLS1_3_VERSION || ls->takeover_phase != kTlsClientTakeoverHandshake ||
        ! tlsclientSslReadBoundaryIsClean(ls) || BIO_ctrl_pending(ls->wbio) != 0 ||
        ! tlsrecordshapingOutputQueueIsEmpty(&ls->shaping_output))
    {
        return false;
    }

    if (! bufferstreamIsEmpty(&ls->takeover_stream) && pending_raw != NULL)
    {
        *pending_raw = bufferstreamFullRead(&ls->takeover_stream);
    }
    else if (! tlsclientDrainPendingRawBytes(l, SSL_get_rbio(ls->ssl), pending_raw))
    {
        return false;
    }

    tlsclientLinestateRelease(ls);
    ls->handshake_completed = true;
    ls->takeover_phase      = kTlsClientTakeoverPassthrough;

    return true;
}

bool tlsclientTunnelBeginTakeoverDrain(tunnel_t *t, line_t *l, sbuf_t **pending_raw)
{
    if (pending_raw != NULL)
    {
        *pending_raw = NULL;
    }

    if (t == NULL || l == NULL || pending_raw == NULL)
    {
        return false;
    }

    tlsclient_tstate_t *ts = tunnelGetState(t);
    tlsclient_lstate_t *ls = lineGetState(l, t);

    if (! ts->handshake_takeover_enabled || ! ls->handshake_completed || ls->ssl == NULL || ls->resources_released ||
        ls->takeover_phase != kTlsClientTakeoverHandshake || SSL_version(ls->ssl) != TLS1_3_VERSION ||
        ! tlsclientSslReadBoundaryIsClean(ls) || BIO_ctrl_pending(ls->wbio) != 0 ||
        ! tlsrecordshapingOutputQueueIsEmpty(&ls->shaping_output))
    {
        return false;
    }

    /* Mark the raw-output phase before returning bytes to a re-entrant owner. */
    ls->takeover_phase = kTlsClientTakeoverDrain;
    if (! bufferstreamIsEmpty(&ls->takeover_stream))
    {
        *pending_raw = bufferstreamFullRead(&ls->takeover_stream);
    }
    return true;
}

static tlsclient_post_handshake_result_t tlsclientPostHandshakeClose(tunnel_t *t, line_t *l, bool fatal)
{
    if (lineIsAlive(l))
    {
        tlsclientCloseLineBidirectional(t, l);
    }
    return fatal ? kTlsClientPostHandshakeFatal : kTlsClientPostHandshakeClose;
}

static bool tlsclientPostHandshakeConsumeStateIsLive(const tlsclient_lstate_t *ls)
{
    return ls != NULL && ls->post_handshake_consume_in_progress && ! ls->resources_released &&
           ls->takeover_phase == kTlsClientTakeoverDrain && ls->ssl != NULL && ls->rbio != NULL && ls->wbio != NULL;
}

tlsclient_post_handshake_result_t tlsclientTunnelConsumePostHandshakeRecord(tunnel_t *t, line_t *l, sbuf_t *record)
{
    if (l == NULL || t == NULL || record == NULL)
    {
        if (record != NULL)
        {
            reuseBuffer(record);
        }
        return kTlsClientPostHandshakeFatal;
    }

    if (! lineIsAlive(l))
    {
        reuseBuffer(record);
        return kTlsClientPostHandshakeFatal;
    }

    lineLock(l);
    tlsclient_tstate_t *ts = tunnelGetState(t);
    tlsclient_lstate_t *ls = lineGetState(l, t);

    if (! ts->handshake_takeover_enabled || ! ls->handshake_completed || ls->resources_released ||
        ls->post_handshake_consume_in_progress || ls->takeover_phase != kTlsClientTakeoverDrain || ls->ssl == NULL ||
        SSL_version(ls->ssl) != TLS1_3_VERSION || ! tlsclientSslReadBoundaryIsClean(ls) ||
        ! tlsclientRawRecordIsComplete(record))
    {
        lineReuseBuffer(l, record);
        lineUnlock(l);
        return tlsclientPostHandshakeClose(t, l, true);
    }

    ls->post_handshake_consume_in_progress = true;

    int written  = BIO_write(ls->rbio, sbufGetRawPtr(record), (int) sbufGetLength(record));
    int expected = (int) sbufGetLength(record);
    lineReuseBuffer(l, record);
    record = NULL;

    if (written != expected)
    {
        ls->post_handshake_consume_in_progress = false;
        lineUnlock(l);
        return tlsclientPostHandshakeClose(t, l, true);
    }

    sbuf_t *discard_buf = bufferpoolGetLargeBuffer(lineGetBufferPool(l));
    int     avail       = (int) sbufGetMaximumWriteableSize(discard_buf);

    while (true)
    {
        int n = SSL_read(ls->ssl, sbufGetMutablePtr(discard_buf), avail);
        if (n > 0)
        {
            if (! tlsclientFlushSslOutput(t, l, ls))
            {
                reuseBuffer(discard_buf);
                if (! lineIsAlive(l))
                {
                    lineUnlock(l);
                    return kTlsClientPostHandshakeFatal;
                }

                ls = lineGetState(l, t);
                if (! tlsclientPostHandshakeConsumeStateIsLive(ls))
                {
                    lineUnlock(l);
                    return kTlsClientPostHandshakeFatal;
                }
                ls->post_handshake_consume_in_progress = false;
                lineUnlock(l);
                return tlsclientPostHandshakeClose(t, l, true);
            }

            ls = lineGetState(l, t);
            if (! tlsclientPostHandshakeConsumeStateIsLive(ls))
            {
                reuseBuffer(discard_buf);
                lineUnlock(l);
                return kTlsClientPostHandshakeFatal;
            }
            continue;
        }

        int ssl_error = SSL_get_error(ls->ssl, n);
        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
        {
            if (! tlsclientFlushPostHandshakeProtocolOutput(t, l, ls))
            {
                reuseBuffer(discard_buf);
                if (! lineIsAlive(l))
                {
                    lineUnlock(l);
                    return kTlsClientPostHandshakeFatal;
                }

                ls = lineGetState(l, t);
                if (! tlsclientPostHandshakeConsumeStateIsLive(ls))
                {
                    lineUnlock(l);
                    return kTlsClientPostHandshakeFatal;
                }
                ls->post_handshake_consume_in_progress = false;
                lineUnlock(l);
                return tlsclientPostHandshakeClose(t, l, true);
            }

            ls = lineGetState(l, t);
            if (! tlsclientPostHandshakeConsumeStateIsLive(ls))
            {
                reuseBuffer(discard_buf);
                lineUnlock(l);
                return kTlsClientPostHandshakeFatal;
            }

            if (ssl_error == SSL_ERROR_WANT_WRITE)
            {
                continue;
            }

            bool clean = tlsclientSslReadBoundaryIsClean(ls);
            reuseBuffer(discard_buf);
            ls->post_handshake_consume_in_progress = false;
            if (! clean)
            {
                lineUnlock(l);
                return tlsclientPostHandshakeClose(t, l, true);
            }
            lineUnlock(l);
            return kTlsClientPostHandshakeNeedMore;
        }

        reuseBuffer(discard_buf);
        bool clean_close                       = ssl_error == SSL_ERROR_ZERO_RETURN;
        ls->post_handshake_consume_in_progress = false;
        lineUnlock(l);
        return tlsclientPostHandshakeClose(t, l, ! clean_close);
    }
}

bool tlsclientTunnelCompleteTakeover(tunnel_t *t, line_t *l)
{
    if (t == NULL || l == NULL)
    {
        return false;
    }

    tlsclient_tstate_t *ts = tunnelGetState(t);
    tlsclient_lstate_t *ls = lineGetState(l, t);
    if (! ts->handshake_takeover_enabled || ! ls->handshake_completed || ls->resources_released ||
        ls->post_handshake_consume_in_progress || ls->takeover_phase != kTlsClientTakeoverDrain ||
        ! bufferstreamIsEmpty(&ls->takeover_stream) || ls->ssl == NULL || SSL_version(ls->ssl) != TLS1_3_VERSION ||
        ! tlsclientSslReadBoundaryIsClean(ls) || BIO_ctrl_pending(ls->wbio) != 0 ||
        ! tlsrecordshapingOutputQueueIsEmpty(&ls->shaping_output))
    {
        return false;
    }

    tlsclientLinestateRelease(ls);
    ls->handshake_completed = true;
    ls->takeover_phase      = kTlsClientTakeoverPassthrough;
    return true;
}

bool tlsclientConfigureSslForConnect(SSL *ssl, BIO *rbio, BIO *wbio, const char *sni,
                                     const uint8_t *ech_grease_override_payload, size_t ech_grease_override_payload_len)
{
    SSL_set_connect_state(ssl);
    SSL_set_bio(ssl, rbio, wbio);

    if (SSL_set_tlsext_host_name(ssl, sni) != 1)
    {
        return false;
    }

    const int verify_mode = SSL_get_verify_mode(ssl);
    if (verify_mode < 0)
    {
        return false;
    }

    if ((verify_mode & SSL_VERIFY_PEER) != 0)
    {
        SSL_set_hostflags(ssl, X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);
        if (SSL_set1_host(ssl, sni) != 1)
        {
            return false;
        }
    }

    if (ech_grease_override_payload != NULL && ech_grease_override_payload_len > 0)
    {
        if (SSL_set1_ech_grease_override_payload(ssl, ech_grease_override_payload, ech_grease_override_payload_len) !=
            1)
        {
            return false;
        }
    }

    return true;
}

bool tlsclientCreateClientHelloFromContext(SSL_CTX *ssl_ctx, const char *sni,
                                           const uint8_t *ech_grease_override_payload,
                                           size_t ech_grease_override_payload_len, const uint8_t *alpn_wire,
                                           size_t alpn_wire_len, sbuf_t **out)
{
    if (ssl_ctx == NULL || sni == NULL || out == NULL)
    {
        return false;
    }

    *out = NULL;

    const size_t sni_len = stringLength(sni);
    if (sni_len == 0 || sni_len > kTlsClientMaxSniLength)
    {
        return false;
    }

    /*
     * The scratch line state and the drained ClientHello both come from the
     * calling worker's pool, so this needs an ordinary event worker. An
     * unregistered thread or the lwIP pseudo-worker fails cleanly here instead
     * of borrowing worker 0's pool.
     */
    if (! currentThreadIsEventWorker())
    {
        return false;
    }
    buffer_pool_t *pool = getCurrentEventWorkerBufferPool();

    STACK_ALLOCATE_CACHE_ALIGNED(tlsclient_lstate_t, ls);
    memoryZero(ls, sizeof(*ls));
    const tlsrecordshaping_config_t no_record_shaping = {0};
    if (! tlsclientLinestateInitializeWithShaping(
            ls, ssl_ctx, pool, alpn_wire, alpn_wire_len, &no_record_shaping, false))
    {
        // the temporary line state released itself already, *out stays NULL
        return false;
    }

    if (! tlsclientConfigureSslForConnect(
            ls->ssl, ls->rbio, ls->wbio, sni, ech_grease_override_payload, ech_grease_override_payload_len))
    {
        tlsclientLinestateDestroy(ls);
        return false;
    }

    int            n      = SSL_connect(ls->ssl);
    enum sslstatus status = getSslStatus(ls->ssl, n);

    if (status == kSslstatusFail)
    {
        tlsclientLinestateDestroy(ls);
        return false;
    }

    const bool drained = tlsclientDrainBioToBuffer(pool, ls->wbio, out);
    tlsclientLinestateDestroy(ls);
    return drained && *out != NULL;
}

bool tlsclientCreateEchGreaseInnerClientHello(tlsclient_tstate_t *ts, wid_t wid, sbuf_t **out)
{
    if (ts == NULL || out == NULL)
    {
        return false;
    }

    *out = NULL;

    if (ts->ech_grease_sni_override == NULL)
    {
        return true;
    }

    // Per-event-worker context array: the caller must be the event worker that
    // owns `wid`, and `wid` must index a getWorkersCount()-sized array.
    if (wid >= getWorkersCount() || ! currentThreadIsEventWorkerWID(wid))
    {
        return false;
    }

    if (ts->threadlocal_ech_grease_inner_ssl_contexts == NULL ||
        ts->threadlocal_ech_grease_inner_ssl_contexts[wid] == NULL)
    {
        return false;
    }

    return tlsclientCreateClientHelloFromContext(ts->threadlocal_ech_grease_inner_ssl_contexts[wid],
                                                 ts->ech_grease_sni_override,
                                                 NULL,
                                                 0,
                                                 ts->alpn_wire,
                                                 ts->alpn_wire_len,
                                                 out);
}

static void tlsclientFreeSslContextPool(SSL_CTX ***contexts)
{
    if (contexts == NULL || *contexts == NULL)
    {
        return;
    }

    int worker_count = getWorkersCount();
    for (int i = 0; i < worker_count; ++i)
    {
        if ((*contexts)[i] != NULL)
        {
            SSL_CTX_free((*contexts)[i]);
        }
    }

    memoryFree(*contexts);
    *contexts = NULL;
}

void tlsclientTunnelstateDestroy(tlsclient_tstate_t *ts)
{
    if (ts == NULL)
    {
        return;
    }

    tlsclientFreeSslContextPool(&ts->threadlocal_ssl_contexts);
    tlsclientFreeSslContextPool(&ts->threadlocal_ech_grease_inner_ssl_contexts);

    memoryFree(ts->alpn_wire);
    memoryFree(ts->sni);
    memoryFree(ts->ech_grease_sni_override);

    ts->alpn_wire                                 = NULL;
    ts->alpn_wire_len                             = 0;
    ts->sni                                       = NULL;
    ts->ech_grease_sni_override                   = NULL;
    ts->verify                                    = false;
    ts->verbose                                   = false;
    ts->x25519mlkem768_enabled                    = false;
    ts->threadlocal_ech_grease_inner_ssl_contexts = NULL;
}
