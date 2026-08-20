#include "structure.h"

#include "loggers/network_logger.h"

int tlsserverOnServername(SSL *ssl, int *ad, void *arg)
{
    tlsserver_tstate_t *ts = arg;
    const char         *sni;

    if (ts->expected_sni == NULL)
    {
        return SSL_TLSEXT_ERR_OK;
    }

    sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

    if (sni == NULL || stricmp(sni, ts->expected_sni) != 0)
    {
        LOGW("TlsServer: rejected TLS connection due to SNI mismatch, expected=\"%s\", got=\"%s\"",
             ts->expected_sni,
             sni != NULL ? sni : "<none>");
        *ad = SSL_AD_UNRECOGNIZED_NAME;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    if (ts->verbose)
    {
        LOGD("TlsServer: accepted SNI \"%s\"", sni);
    }

    return SSL_TLSEXT_ERR_OK;
}

int tlsserverOnAlpnSelect(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in,
                          unsigned int inlen, void *arg)
{
    discard                             ssl;
    tlsserver_tstate_t                 *ts     = arg;
    const struct tlsserver_alpn_item_s *alpns  = ts->alpns;
    unsigned int                        length = ts->alpns_length;

    if (length == 0)
    {
        alpns  = ts->select_alpns;
        length = ts->select_alpns_length;
    }

    for (unsigned int i = 0; i < length; ++i)
    {
        unsigned int client_offset = 0;

        while (client_offset < inlen)
        {
            unsigned int current_len = in[client_offset];
            if (current_len == 0 || client_offset + 1U + current_len > inlen)
            {
                LOGW("TlsServer: rejected TLS connection due to malformed ALPN extension");
#ifdef SSL_AD_DECODE_ERROR
                return SSL_TLSEXT_ERR_ALERT_FATAL;
#else
                return SSL_TLSEXT_ERR_NOACK;
#endif
            }

            const unsigned char *cur = &in[client_offset + 1];

            if (alpns[i].name_length == current_len && memoryCompare(cur, alpns[i].name, current_len) == 0)
            {
                *out    = cur;
                *outlen = (unsigned char) current_len;
                if (ts->verbose)
                {
                    LOGD("TlsServer: selected ALPN \"%.*s\"", (int) current_len, (const char *) cur);
                }
                return SSL_TLSEXT_ERR_OK;
            }

            client_offset += 1U + current_len;
        }
    }

    if (ts->verbose)
    {
        LOGD("TlsServer: no configured ALPN matched the client offer; continuing without ALPN");
    }
    return SSL_TLSEXT_ERR_NOACK;
}

void tlsserverPrintSSLState(const SSL *ssl)
{
    LOGD("TlsServer: OpenSSL State: %s", SSL_state_string_long(ssl));
}

void tlsserverPrintSSLError(void)
{
    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == NULL)
    {
        LOGE("TlsServer: failed to allocate BIO for OpenSSL error printing");
        return;
    }

    ERR_print_errors(bio);

    char  *buf = NULL;
    size_t len = BIO_get_mem_data(bio, &buf);
    if (len > 0)
    {
        LOGE("TlsServer: OpenSSL Error: %.*s", (int) len, buf);
    }
    else
    {
        LOGD("TlsServer: OpenSSL error queue is empty");
    }
    BIO_free(bio);
}

void tlsserverTunnelstateDestroy(tlsserver_tstate_t *ts)
{
    if (ts->threadlocal_ssl_contexts != NULL)
    {
        int worker_count = getWorkersCount();
        for (int i = 0; i < worker_count; ++i)
        {
            if (ts->threadlocal_ssl_contexts[i] != NULL)
            {
                SSL_CTX_free(ts->threadlocal_ssl_contexts[i]);
            }
        }
        memoryFree(ts->threadlocal_ssl_contexts);
        ts->threadlocal_ssl_contexts = NULL;
    }

    if (ts->alpns != NULL)
    {
        for (unsigned int i = 0; i < ts->alpns_length; ++i)
        {
            memoryFree(ts->alpns[i].name);
        }
        memoryFree(ts->alpns);
        ts->alpns = NULL;
    }

    ts->alpns_length = 0;

    if (ts->select_alpns != NULL)
    {
        for (unsigned int i = 0; i < ts->select_alpns_length; ++i)
        {
            memoryFree(ts->select_alpns[i].name);
        }
        memoryFree(ts->select_alpns);
        ts->select_alpns = NULL;
    }

    ts->select_alpns_length = 0;

    memoryFree(ts->expected_sni);
    memoryFree(ts->cert_file);
    memoryFree(ts->key_file);
    memoryFree(ts->ciphers);
    ts->expected_sni = NULL;
    ts->cert_file    = NULL;
    ts->key_file     = NULL;
    ts->ciphers      = NULL;
}

size_t tlsserverRecordPaddingCallback(SSL *ssl, int type, size_t len, void *arg)
{
    discard arg;

    tlsserver_lstate_t *ls = SSL_get_app_data(ssl);
    if (ls == NULL || ls->ssl != ssl || ls->resources_released || ! ls->handshake_completed || ls->tunnel == NULL ||
        SSL_version(ssl) != TLS1_3_VERSION)
    {
        return 0;
    }

    tlsserver_tstate_t         *ts                = tunnelGetState(ls->tunnel);
    tlsrecordshaping_decision_t decision          = {0};
    uint32_t                    effective_padding = 0;

    if (type == SSL3_RT_APPLICATION_DATA && len > 0)
    {
        discard tlsrecordshapingSample(&ts->record_shaping, &ls->shaping_state, &decision);

        size_t legal_padding = len < SSL3_RT_MAX_PLAIN_LENGTH ? SSL3_RT_MAX_PLAIN_LENGTH - len : 0;
        effective_padding    = decision.requested_padding_bytes < legal_padding ? decision.requested_padding_bytes
                                                                                : (uint32_t) legal_padding;
        tlsrecordshapingRecordEffectivePadding(&ls->shaping_state, &decision, effective_padding);
    }

    if (! tlsrecordshapingOutputQueuePushPendingMetadata(&ls->shaping_output, decision.delay_ms))
    {
        ls->shaping_metadata_error = true;
        return 0;
    }
    return effective_padding;
}

void tlsserverRecordMessageCallback(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl,
                                    void *arg)
{
    discard version;
    discard arg;

    tlsserver_lstate_t *ls = SSL_get_app_data(ssl);
    if (write_p != 1 || content_type != SSL3_RT_HEADER || buf == NULL || len != SSL3_RT_HEADER_LENGTH || ls == NULL ||
        ls->ssl != ssl || ls->resources_released || ! ls->handshake_completed || ls->tunnel == NULL ||
        SSL_version(ssl) != TLS1_3_VERSION)
    {
        return;
    }

    const uint8_t *header = buf;
    if (header[0] != SSL3_RT_APPLICATION_DATA || header[1] != SSL3_VERSION_MAJOR ||
        header[2] != (TLS1_2_VERSION & 0xff))
    {
        return;
    }

    uint32_t fallback_delay_ms = 0;
    if (! tlsrecordshapingOutputQueueHasPendingMetadata(&ls->shaping_output))
    {
        if (ls->shaping_metadata_error)
        {
            return;
        }

        if (ls->shaping_writing_application)
        {
            /*
             * OpenSSL skips its padding callback when TLSInnerPlaintext has no
             * remaining padding capacity. The record-header callback is still
             * delivered, so a full application record samples its delay here,
             * consumes scope, and records zero effective padding.
             */
            tlsserver_tstate_t         *ts       = tunnelGetState(ls->tunnel);
            tlsrecordshaping_decision_t decision = {0};
            discard                     tlsrecordshapingSample(&ts->record_shaping, &ls->shaping_state, &decision);
            tlsrecordshapingRecordEffectivePadding(&ls->shaping_state, &decision, 0);
            fallback_delay_ms = decision.delay_ms;
        }
    }

    if (! tlsrecordshapingOutputQueueCommitMetadata(&ls->shaping_output, fallback_delay_ms))
    {
        ls->shaping_metadata_error = true;
    }
}

void tlsserverCancelShapedOutputTimer(tlsserver_lstate_t *ls)
{
    if (ls->shaping_output_timer == NULL)
    {
        return;
    }

    weventSetUserData(ls->shaping_output_timer, NULL);
    wtimerDelete(ls->shaping_output_timer);
    ls->shaping_output_timer = NULL;
}

static bool tlsserverUpdateShapingBackpressure(tunnel_t *t, line_t *l, tlsserver_lstate_t *ls)
{
    size_t queued = tlsrecordshapingOutputQueueBytes(&ls->shaping_output);
    if (! ls->shaping_producer_paused && queued >= kTlsRecordShapingQueueHighWatermark)
    {
        ls->shaping_producer_paused = true;
        if (! ls->shaping_wire_paused && ! ls->upstream_finished && ! ls->downstream_finishing)
        {
            if (! withLineLocked(l, tunnelNextUpStreamPause, t))
            {
                return false;
            }
        }
        return true;
    }

    if (ls->shaping_producer_paused && queued <= kTlsRecordShapingQueueLowWatermark)
    {
        ls->shaping_producer_paused = false;
        if (! ls->shaping_wire_paused && ! ls->upstream_finished && ! ls->downstream_finishing)
        {
            if (! withLineLocked(l, tunnelNextUpStreamResume, t))
            {
                return false;
            }
        }
    }
    return true;
}

bool tlsserverDrainShapedOutput(tunnel_t *t, line_t *l, tlsserver_lstate_t *ls, bool force)
{
    if (ls->shaping_wire_paused)
    {
        return tlsserverUpdateShapingBackpressure(t, l, ls);
    }

    uint64_t now_ms = wloopNowMS(getWorkerLoop(lineGetWID(l)));
    while (! ls->shaping_wire_paused)
    {
        sbuf_t *record = tlsrecordshapingOutputQueuePopReady(&ls->shaping_output, now_ms, force);
        if (record == NULL)
        {
            break;
        }

        if (! withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, record))
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

    return tlsserverUpdateShapingBackpressure(t, l, ls);
}

static void tlsserverShapingOutputTimerCallback(wtimer_t *timer)
{
    tlsserver_lstate_t *ls = weventGetUserdata(timer);
    assert(ls != NULL && ls->shaping_output_timer == timer);

    tunnel_t *t = ls->tunnel;
    line_t   *l = ls->line;
    assert(t != NULL && l != NULL && lineIsAlive(l) && ! ls->resources_released);

    ls->shaping_output_timer = NULL;

    lineLock(l);
    if (! tlsserverDrainShapedOutput(t, l, ls, false))
    {
        if (lineIsAlive(l))
        {
            bool state_is_active = ((tlsserver_lstate_t *) lineGetState(l, t))->tunnel == t;
            lineUnlock(l);
            if (state_is_active)
            {
                tlsserverCloseLineFatal(t, l);
            }
            return;
        }
        lineUnlock(l);
        return;
    }

    ls = lineGetState(l, t);
    if (! tlsserverTryCompleteDeferredFinish(t, l, ls))
    {
        lineUnlock(l);
        return;
    }

    if (! tlsserverScheduleShapedOutput(t, l, ls))
    {
        if (lineIsAlive(l))
        {
            bool state_is_active = ((tlsserver_lstate_t *) lineGetState(l, t))->tunnel == t;
            lineUnlock(l);
            if (state_is_active)
            {
                tlsserverCloseLineFatal(t, l);
            }
            return;
        }
    }
    lineUnlock(l);
}

bool tlsserverScheduleShapedOutput(tunnel_t *t, line_t *l, tlsserver_lstate_t *ls)
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
        return tlsserverDrainShapedOutput(t, l, ls, false);
    }

    ls->shaping_output_timer =
        wtimerAdd(getWorkerLoop(lineGetWID(l)), tlsserverShapingOutputTimerCallback, delay_ms, 1);
    if (ls->shaping_output_timer != NULL)
    {
        weventSetUserData(ls->shaping_output_timer, ls);
        return true;
    }

    if (! ls->shaping_timer_failure_logged)
    {
        LOGW("TlsServer: failed to allocate record shaping timer; draining queued ciphertext immediately");
        ls->shaping_timer_failure_logged = true;
    }
    return tlsserverDrainShapedOutput(t, l, ls, true);
}

bool tlsserverTryCompleteDeferredFinish(tunnel_t *t, line_t *l, tlsserver_lstate_t *ls)
{
    if (! ls->downstream_finish_deferred || ! tlsrecordshapingOutputQueueIsEmpty(&ls->shaping_output))
    {
        return true;
    }

    tlsserverLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
    return false;
}

bool tlsserverFlushSslOutput(tunnel_t *t, line_t *l, tlsserver_lstate_t *ls)
{
    tlsserver_tstate_t *ts = tunnelGetState(t);
    bool shape_output = ts->record_shaping.enabled && ls->handshake_completed && SSL_version(ls->ssl) == TLS1_3_VERSION;

    while (true)
    {
        sbuf_t *ssl_buf = bufferpoolGetLargeBuffer(lineGetBufferPool(l));
        int     avail   = (int) sbufGetMaximumWriteableSize(ssl_buf);
        int     n       = BIO_read(SSL_get_wbio(ls->ssl), sbufGetMutablePtr(ssl_buf), avail);

        if (n > 0)
        {
            sbufSetLength(ssl_buf, n);
            if (ls->verbose)
            {
                LOGD("TlsServer: worker %u flushing %d TLS bytes downstream", (unsigned int) lineGetWID(l), n);
            }
            if (shape_output)
            {
                char queue_error[kTlsRecordShapingErrorSize];
                if (! tlsrecordshapingOutputQueueFeed(
                        &ls->shaping_output, ssl_buf, wloopNowMS(getWorkerLoop(lineGetWID(l))), queue_error))
                {
                    LOGW("TlsServer: %s", queue_error);
                    return false;
                }
                continue;
            }

            if (! withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, ssl_buf))
            {
                LOGW("TlsServer: line closed while flushing TLS bytes downstream");
                return false;
            }
            continue;
        }

        lineReuseBuffer(l, ssl_buf);

        if (! BIO_should_retry(SSL_get_wbio(ls->ssl)))
        {
            LOGW("TlsServer: TLS write BIO failed while flushing output");
            tlsserverPrintSSLError();
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
        LOGW("TlsServer: failed to enqueue TLS record shaping metadata");
        return false;
    }

    char queue_error[kTlsRecordShapingErrorSize];
    if (! tlsrecordshapingOutputQueueFinishFeed(&ls->shaping_output, queue_error))
    {
        LOGW("TlsServer: %s", queue_error);
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
        LOGW("TlsServer: record shaping queue exceeded 8 MiB while the wire side was paused");
        return false;
    }
    if (! tlsserverDrainShapedOutput(t, l, ls, force))
    {
        return false;
    }

    ls = lineGetState(l, t);
    if (tlsrecordshapingOutputQueueBytes(&ls->shaping_output) >= kTlsRecordShapingQueueHardLimit)
    {
        LOGW("TlsServer: record shaping queue could not be reduced below its 8 MiB hard limit");
        return false;
    }
    return tlsserverScheduleShapedOutput(t, l, ls);
}

bool tlsserverEncryptAndSendApplicationData(tunnel_t *t, line_t *l, tlsserver_lstate_t *ls, sbuf_t *buf)
{
    int len = (int) sbufGetLength(buf);
    if (ls->verbose)
    {
        LOGD("TlsServer: worker %u encrypting %d cleartext bytes for downstream", (unsigned int) lineGetWID(l), len);
    }

    while (len > 0)
    {
        ls->shaping_writing_application = true;
        int n                           = SSL_write(ls->ssl, sbufGetRawPtr(buf), len);
        ls->shaping_writing_application = false;
        enum sslstatus status           = getSslStatus(ls->ssl, n);

        if (n > 0)
        {
            sbufShiftRight(buf, n);
            len -= n;

            if (! tlsserverFlushSslOutput(t, l, ls))
            {
                reuseBuffer(buf);
                return false;
            }
        }

        if (status == kSslstatusFail)
        {
            LOGW("TlsServer: SSL_write failed while encrypting cleartext payload");
            tlsserverPrintSSLError();
            reuseBuffer(buf);
            return false;
        }

        if (n < 0)
        {
            // WANT_READ/WANT_WRITE can never be satisfied inside this
            // synchronous mem-BIO loop; spinning here would hang the worker
            LOGW("TlsServer: SSL_write made no progress while encrypting cleartext payload");
            reuseBuffer(buf);
            return false;
        }

        if (n == 0)
        {
            if (ls->verbose)
            {
                LOGD("TlsServer: SSL_write produced no progress while encrypting cleartext payload");
            }
            break;
        }
    }

    lineReuseBuffer(l, buf);
    return true;
}

bool tlsserverFlushPendingDownQueue(tunnel_t *t, line_t *l, tlsserver_lstate_t *ls)
{
    size_t pending_count = bufferqueueGetBufCount(&ls->pending_down);
    if (pending_count > 0)
    {
        if (ls->verbose)
        {
            LOGD("TlsServer: worker %u flushing %u queued downstream payload buffers after handshake",
                 (unsigned int) lineGetWID(l),
                 (unsigned int) pending_count);
        }
    }

    while (bufferqueueGetBufCount(&ls->pending_down) > 0)
    {
        sbuf_t *buf = bufferqueuePopFront(&ls->pending_down);
        if (! tlsserverEncryptAndSendApplicationData(t, l, ls, buf))
        {
            return false;
        }
    }

    return true;
}

bool tlsserverStartProtectedBranch(tunnel_t *t, line_t *l, tlsserver_lstate_t *ls)
{
    if (ls->protected_init_sent)
    {
        return true;
    }

    ls->protected_init_sent = true;
    return withLineLocked(l, tunnelNextUpStreamInit, t);
}

static size_t tlsserverFallbackPendingCount(const tlsserver_lstate_t *ls)
{
    return ls->fallback_pending_up != NULL ? bufferqueueGetBufCount(ls->fallback_pending_up) : 0;
}

static buffer_queue_t *tlsserverEnsureFallbackPendingQueue(tlsserver_lstate_t *ls)
{
    if (ls->fallback_pending_up == NULL)
    {
        ls->fallback_pending_up  = memoryAllocate(sizeof(*ls->fallback_pending_up));
        *ls->fallback_pending_up = bufferqueueCreate(2);
    }

    return ls->fallback_pending_up;
}

static void tlsserverForwardPendingFallbackFinish(tunnel_t *t, line_t *l, tlsserver_lstate_t *ls)
{
    tlsserver_tstate_t *ts       = tunnelGetState(t);
    tunnel_t           *fallback = ts->fallback_tunnel;

    if (! ls->fallback_up_finish_pending || tlsserverFallbackPendingCount(ls) > 0 || fallback == NULL ||
        ls->fallback_up_finished)
    {
        return;
    }

    ls->fallback_up_finished = true;
    tlsserverLinestateDestroy(ls);
    tunnelUpStreamFin(fallback, l);
}

static void tlsserverDelayedFallbackPayloadTask(tunnel_t *t, line_t *l)
{
    tlsserver_tstate_t *ts = tunnelGetState(t);
    tlsserver_lstate_t *ls = lineGetState(l, t);

    ls->fallback_delay_scheduled = false;

    size_t queued = tlsserverFallbackPendingCount(ls);
    while (queued > 0)
    {
        queued -= 1;

        sbuf_t   *buf      = bufferqueuePopFront(ls->fallback_pending_up);
        tunnel_t *fallback = ts->fallback_tunnel;
        if (fallback == NULL || ! ls->fallback_mode || ls->fallback_up_finished)
        {
            lineReuseBuffer(l, buf);
        }
        else
        {
            tunnelUpStreamPayload(fallback, l, buf);
        }

        if (! lineIsAlive(l))
        {
            return;
        }

        ls = lineGetState(l, t);
    }

    if (tlsserverFallbackPendingCount(ls) > 0 && ! ls->fallback_delay_scheduled)
    {
        ls->fallback_delay_scheduled = true;
        if (UNLIKELY(! lineScheduleDelayedTask(
                l,
                tlsserverDelayedFallbackPayloadTask,
                fastRandJittered32(ts->fallback_intentional_delay_ms, ts->fallback_intentional_delay_jitter_ms),
                t)))
        {
            ls->fallback_delay_scheduled = false;
            tlsserverCloseLineFatal(t, l);
        }
        return;
    }

    tlsserverForwardPendingFallbackFinish(t, l, ls);
}

bool tlsserverSendFallbackPayload(tunnel_t *t, line_t *l, tlsserver_lstate_t *ls, sbuf_t *buf)
{
    tlsserver_tstate_t *ts       = tunnelGetState(t);
    tunnel_t           *fallback = ts->fallback_tunnel;

    if (fallback == NULL || ! ls->fallback_mode || ls->fallback_up_finished || ls->fallback_up_finish_pending)
    {
        lineReuseBuffer(l, buf);
        return false;
    }

    if (ts->fallback_intentional_delay_ms == 0)
    {
        tunnelUpStreamPayload(fallback, l, buf);
        return lineIsAlive(l);
    }

    buffer_queue_t *pending = tlsserverEnsureFallbackPendingQueue(ls);
    bufferqueuePushBack(pending, buf);

    if (! ls->fallback_delay_scheduled)
    {
        ls->fallback_delay_scheduled = true;
        if (UNLIKELY(! lineScheduleDelayedTask(
                l,
                tlsserverDelayedFallbackPayloadTask,
                fastRandJittered32(ts->fallback_intentional_delay_ms, ts->fallback_intentional_delay_jitter_ms),
                t)))
        {
            ls->fallback_delay_scheduled = false;
            tlsserverCloseLineFatal(t, l);
            return false;
        }
    }

    return true;
}

static void tlsserverHandshakeDeadlineTimerCallback(wtimer_t *timer)
{
    tlsserver_lstate_t *ls = weventGetUserdata(timer);
    assert(ls != NULL && ls->handshake_deadline_timer == timer && ls->handshake_deadline_armed &&
           ! ls->handshake_completed && ! ls->fallback_mode && ls->ssl != NULL && ls->line != NULL &&
           ls->tunnel != NULL && lineIsAlive(ls->line));

    ls->handshake_deadline_timer = NULL;

    LOGW("TlsServer: TLS handshake timed out before completion");
    tlsserverCloseLineFatal(ls->tunnel, ls->line);
}

void tlsserverDisarmHandshakeDeadline(tlsserver_lstate_t *ls)
{
    ls->handshake_deadline_armed = false;
    if (ls->handshake_deadline_timer == NULL)
    {
        return;
    }

    weventSetUserData(ls->handshake_deadline_timer, NULL);
    wtimerDelete(ls->handshake_deadline_timer);
    ls->handshake_deadline_timer = NULL;
}

bool tlsserverArmHandshakeDeadline(tunnel_t *t, line_t *l, tlsserver_lstate_t *ls)
{
    tlsserver_tstate_t *ts = tunnelGetState(t);

    if (ts->handshake_timeout_ms == 0)
    {
        // no deadline is configured, there is nothing to arm
        return true;
    }

    tlsserverDisarmHandshakeDeadline(ls);

    ls->tunnel = t;
    ls->line   = l;

    wtimer_t *timer =
        wtimerAdd(getWorkerLoop(lineGetWID(l)), tlsserverHandshakeDeadlineTimerCallback, ts->handshake_timeout_ms, 1);

    if (timer == NULL)
    {
        // the deadline stays disarmed and no userdata is published; the caller closes this line
        LOGE("TlsServer: failed to create the TLS handshake deadline timer for this line");
        return false;
    }

    ls->handshake_deadline_timer = timer;
    ls->handshake_deadline_armed = true;

    weventSetUserData(timer, ls);

    return true;
}

bool tlsserverStartFallback(tunnel_t *t, line_t *l, tlsserver_lstate_t *ls)
{
    tlsserver_tstate_t *ts = tunnelGetState(t);

    if (UNLIKELY(ts->fallback_tunnel == NULL))
    {
        return false;
    }

    sbuf_t *first = bufferstreamFullRead(&ls->fallback_probe);

    lineLock(l);

    ls->fallback_mode = true;
    tlsserverDisarmHandshakeDeadline(ls);
    tlsserverLinestateRelease(ls);

    if (! ls->fallback_init_sent)
    {
        ls->fallback_init_sent = true;
        tunnelUpStreamInit(ts->fallback_tunnel, l);
    }

    if (lineIsAlive(l) && first != NULL && ls->fallback_mode)
    {
        discard tlsserverSendFallbackPayload(t, l, ls, first);
        first = NULL;
    }

    if (first != NULL)
    {
        lineReuseBuffer(l, first);
    }

    bool alive = lineIsAlive(l);
    lineUnlock(l);
    return alive;
}

bool tlsserverSendCloseNotify(tunnel_t *t, line_t *l, tlsserver_lstate_t *ls)
{
    if (ls->resources_released || ls->ssl == NULL || ! ls->handshake_completed)
    {
        if (ls->verbose)
        {
            LOGD("TlsServer: skipping close_notify (released=%d, ssl=%p, handshake=%d)",
                 (int) ls->resources_released,
                 (void *) ls->ssl,
                 (int) ls->handshake_completed);
        }
        return true;
    }

    if (ls->verbose)
    {
        LOGD("TlsServer: worker %u sending TLS close_notify", (unsigned int) lineGetWID(l));
    }

    int shutdown_result = SSL_shutdown(ls->ssl);

    if (! tlsserverFlushSslOutput(t, l, ls))
    {
        LOGW("TlsServer: failed while flushing close_notify");
        return false;
    }

    if (shutdown_result >= 0 || (SSL_get_shutdown(ls->ssl) & SSL_SENT_SHUTDOWN) != 0)
    {
        if (ls->verbose)
        {
            LOGD("TlsServer: close_notify sent successfully");
        }
        return true;
    }

    LOGW("TlsServer: SSL_shutdown did not send close_notify (result=%d)", shutdown_result);
    return false;
}

void tlsserverCloseLineFatal(tunnel_t *t, line_t *l)
{
    if (! lineIsAlive(l))
    {
        tlsserver_tstate_t *ts = tunnelGetState(t);
        if (ts->verbose)
        {
            LOGD("TlsServer: fatal close requested after line was already closed");
        }
        return;
    }

    tlsserver_lstate_t *ls         = lineGetState(l, t);
    bool                close_next = ls->protected_init_sent && ! ls->upstream_finished;
    bool                close_prev = ! ls->downstream_finishing;

    LOGW("TlsServer: closing line after fatal TLS failure (close_next=%d, close_prev=%d)",
         (int) close_next,
         (int) close_prev);

    tlsserverLinestateDestroy(ls);

    if (close_next)
    {
        tunnelNextUpStreamFinish(t, l);
    }

    if (lineIsAlive(l) && close_prev)
    {
        tunnelPrevDownStreamFinish(t, l);
    }
}
