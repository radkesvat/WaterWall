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
             ts->expected_sni, sni != NULL ? sni : "<none>");
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
    discard ssl;
    tlsserver_tstate_t *ts     = arg;
    for (unsigned int i = 0; i < ts->alpns_length; ++i)
    {
        unsigned int client_offset = 0;

        while (client_offset < inlen)
        {
            unsigned int current_len = in[client_offset];
            if (client_offset + 1U + current_len > inlen)
            {
                LOGW("TlsServer: rejected TLS connection due to malformed ALPN extension");
#ifdef SSL_AD_DECODE_ERROR
                return SSL_TLSEXT_ERR_ALERT_FATAL;
#else
                return SSL_TLSEXT_ERR_NOACK;
#endif
            }

            const unsigned char *cur        = &in[client_offset + 1];

            if (ts->alpns[i].name_length == current_len &&
                memoryCompare(cur, ts->alpns[i].name, current_len) == 0)
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

    LOGW("TlsServer: rejected TLS connection due to ALPN mismatch");
#ifdef SSL_AD_NO_APPLICATION_PROTOCOL
    return SSL_TLSEXT_ERR_ALERT_FATAL;
#else
    return SSL_TLSEXT_ERR_NOACK;
#endif
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

    memoryFree(ts->expected_sni);
    memoryFree(ts->cert_file);
    memoryFree(ts->key_file);
    memoryFree(ts->ciphers);
    ts->expected_sni = NULL;
    ts->cert_file = NULL;
    ts->key_file  = NULL;
    ts->ciphers   = NULL;
}

bool tlsserverFlushSslOutput(tunnel_t *t, line_t *l, tlsserver_lstate_t *ls)
{
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
        return true;
    }
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
        int            n      = SSL_write(ls->ssl, sbufGetRawPtr(buf), len);
        enum sslstatus status = getSslStatus(ls->ssl, n);

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
                 (unsigned int) lineGetWID(l), (unsigned int) pending_count);
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

static uint32_t tlsserverFallbackDelayWithJitter(const tlsserver_tstate_t *ts)
{
    uint32_t delay_ms  = ts->fallback_intentional_delay_ms;
    uint32_t jitter_ms = ts->fallback_intentional_delay_jitter_ms;

    if (delay_ms == 0 || jitter_ms == 0)
    {
        return delay_ms;
    }

    uint32_t lower = jitter_ms >= delay_ms ? 0 : delay_ms - jitter_ms;
    uint32_t upper = UINT32_MAX - delay_ms < jitter_ms ? UINT32_MAX : delay_ms + jitter_ms;
    uint64_t span  = (uint64_t) upper - (uint64_t) lower + 1ULL;

    return lower + (uint32_t) (fastRand64() % span);
}

static void tlsserverForwardPendingFallbackFinish(tunnel_t *t, line_t *l, tlsserver_lstate_t *ls)
{
    tlsserver_tstate_t *ts       = tunnelGetState(t);
    tunnel_t           *fallback = ts->fallback_tunnel;

    if (! ls->fallback_up_finish_pending || tlsserverFallbackPendingCount(ls) > 0 ||
        fallback == NULL || ls->fallback_up_finished)
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
        lineScheduleDelayedTask(l, tlsserverDelayedFallbackPayloadTask, tlsserverFallbackDelayWithJitter(ts), t);
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
        lineScheduleDelayedTask(l, tlsserverDelayedFallbackPayloadTask, tlsserverFallbackDelayWithJitter(ts), t);
    }

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
                 (int) ls->resources_released, (void *) ls->ssl, (int) ls->handshake_completed);
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
         (int) close_next, (int) close_prev);

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
