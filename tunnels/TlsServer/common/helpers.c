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
    bool                close_next = ! ls->upstream_finished;
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
