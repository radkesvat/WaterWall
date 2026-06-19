#include "structure.h"

#include "loggers/network_logger.h"

enum tlsserver_handshake_result_e
{
    kTlsServerHandshakeFatal    = -1,
    kTlsServerHandshakeWantMore = 0,
    kTlsServerHandshakeProgress = 1,
    kTlsServerHandshakeFallback = 2,
};

enum tlsserver_probe_classification_e
{
    kTlsServerProbeNeedMore,
    kTlsServerProbePlaintext,
    kTlsServerProbeTlsLike
};

static void tlsserverLogHandshakeComplete(line_t *l, tlsserver_lstate_t *ls)
{
    const SSL           *ssl    = ls->ssl;
    const char          *sni    = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    const unsigned char *alpn   = NULL;
    unsigned int         alpn_l = 0;

    SSL_get0_alpn_selected(ssl, &alpn, &alpn_l);

    if (alpn_l > 0)
    {
        LOGD("TlsServer: worker %u TLS handshake complete (version=%s, cipher=%s, sni=\"%s\", alpn=\"%.*s\")",
             (unsigned int) lineGetWID(l), SSL_get_version(ssl), SSL_get_cipher_name(ssl),
             sni != NULL ? sni : "<none>", (int) alpn_l, (const char *) alpn);
        return;
    }

    LOGD("TlsServer: worker %u TLS handshake complete (version=%s, cipher=%s, sni=\"%s\", alpn=<none>)",
         (unsigned int) lineGetWID(l), SSL_get_version(ssl), SSL_get_cipher_name(ssl),
         sni != NULL ? sni : "<none>");
}

static bool tlsserverPendingOutputStartsServerHello(tlsserver_lstate_t *ls)
{
    BIO *wbio = SSL_get_wbio(ls->ssl);
    if (wbio == NULL)
    {
        return false;
    }

    char *data = NULL;
    long  len  = BIO_get_mem_data(wbio, &data);
    if (data == NULL || len < 6)
    {
        return false;
    }

    const uint8_t *record = (const uint8_t *) data;

    return record[0] == 0x16 && record[1] == 0x03 && record[2] <= 0x04 && record[5] == 0x02;
}

static enum tlsserver_probe_classification_e tlsserverClassifyFallbackProbe(tlsserver_lstate_t *ls, sbuf_t *buf)
{
    if (ls->fallback_probe_tls_like)
    {
        return kTlsServerProbeTlsLike;
    }

    const size_t saved_len = bufferstreamGetBufLen(&ls->fallback_probe);
    const size_t buf_len   = sbufGetLength(buf);

    if (saved_len >= 2)
    {
        return bufferstreamViewByteAt(&ls->fallback_probe, 0) == 0x16 &&
                       bufferstreamViewByteAt(&ls->fallback_probe, 1) == 0x03
                   ? kTlsServerProbeTlsLike
                   : kTlsServerProbePlaintext;
    }

    if (saved_len == 1)
    {
        if (bufferstreamViewByteAt(&ls->fallback_probe, 0) != 0x16)
        {
            return kTlsServerProbePlaintext;
        }
        if (buf_len == 0)
        {
            return kTlsServerProbeNeedMore;
        }
        const uint8_t *data = sbufGetRawPtr(buf);
        return data[0] == 0x03 ? kTlsServerProbeTlsLike : kTlsServerProbePlaintext;
    }

    if (buf_len == 0)
    {
        return kTlsServerProbeNeedMore;
    }

    const uint8_t *data = sbufGetRawPtr(buf);
    if (data[0] != 0x16)
    {
        return kTlsServerProbePlaintext;
    }
    if (buf_len < 2)
    {
        return kTlsServerProbeNeedMore;
    }
    return data[1] == 0x03 ? kTlsServerProbeTlsLike : kTlsServerProbePlaintext;
}

static int tlsserverPerformHandshake(tunnel_t *t, line_t *l, tlsserver_lstate_t *ls)
{
    tlsserver_tstate_t *ts     = tunnelGetState(t);
    int                 n      = SSL_accept(ls->ssl);
    enum sslstatus      status = getSslStatus(ls->ssl, n);
    int                 sslerr = SSL_get_error(ls->ssl, n);

    if (ls->verbose)
    {
        LOGD("TlsServer: worker %u SSL_accept returned %d (ssl_error=%d, state=\"%s\")",
             (unsigned int) lineGetWID(l), n, sslerr, SSL_state_string_long(ls->ssl));
    }

    if (! ls->tls_committed && tlsserverPendingOutputStartsServerHello(ls))
    {
        ls->tls_committed = true;
        bufferstreamEmpty(&ls->fallback_probe);

        if (! tlsserverStartProtectedBranch(t, l, ls))
        {
            return kTlsServerHandshakeFatal;
        }
    }

    if (status == kSslstatusFail && ! ls->tls_committed && ts->fallback_tunnel != NULL)
    {
        if (! ls->fallback_probe_tls_like && bufferstreamIsEmpty(&ls->fallback_probe))
        {
            if (ls->verbose)
            {
                LOGD("TlsServer: OpenSSL rejected non-TLS bytes before ServerHello; switching to fallback");
            }
            return kTlsServerHandshakeFallback;
        }

        LOGW("TlsServer: OpenSSL rejected TLS-looking bytes before ServerHello; closing connection");
        discard tlsserverFlushSslOutput(t, l, ls);
        return kTlsServerHandshakeFatal;
    }

    if (! tlsserverFlushSslOutput(t, l, ls))
    {
        LOGW("TlsServer: TLS handshake failed while flushing handshake output");
        return kTlsServerHandshakeFatal;
    }

    if (SSL_is_init_finished(ls->ssl))
    {
        ls->handshake_completed = true;
        tlsserverDisarmHandshakeDeadline(ls);
        tlsserverLogHandshakeComplete(l, ls);

        if (! tlsserverFlushPendingDownQueue(t, l, ls))
        {
            return kTlsServerHandshakeFatal;
        }
    }

    if (status == kSslstatusFail)
    {
        LOGW("TlsServer: SSL_accept failed (ssl_error=%d, state=\"%s\")", sslerr, SSL_state_string_long(ls->ssl));
        tlsserverPrintSSLError();
        return kTlsServerHandshakeFatal;
    }

    if (! ls->handshake_completed && status == kSslstatusWantIo && sslerr == SSL_ERROR_WANT_READ)
    {
        if (ls->verbose)
        {
            LOGD("TlsServer: worker %u TLS handshake wants more upstream bytes", (unsigned int) lineGetWID(l));
        }
        return kTlsServerHandshakeWantMore;
    }

    return kTlsServerHandshakeProgress;
}

static bool tlsserverReadDecryptedData(tunnel_t *t, line_t *l, tlsserver_lstate_t *ls)
{
    while (true)
    {
        sbuf_t *data_buf = bufferpoolGetLargeBuffer(lineGetBufferPool(l));
        int     avail    = (int) sbufGetMaximumWriteableSize(data_buf);
        int     n        = SSL_read(ls->ssl, sbufGetMutablePtr(data_buf), avail);

        if (n > 0)
        {
            sbufSetLength(data_buf, n);
            if (ls->verbose)
            {
                LOGD("TlsServer: worker %u decrypted %d TLS application bytes", (unsigned int) lineGetWID(l), n);
            }

            if (! tlsserverFlushSslOutput(t, l, ls))
            {
                reuseBuffer(data_buf);
                return false;
            }

            if (! withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, data_buf))
            {
                LOGW("TlsServer: line closed while forwarding decrypted application bytes upstream");
                return false;
            }
            continue;
        }

        lineReuseBuffer(l, data_buf);

        if (! tlsserverFlushSslOutput(t, l, ls))
        {
            return false;
        }

        switch (SSL_get_error(ls->ssl, n))
        {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            return true;
        case SSL_ERROR_ZERO_RETURN:
            if (ls->verbose)
            {
                LOGD("TlsServer: worker %u received TLS close_notify from peer", (unsigned int) lineGetWID(l));
            }
            if (ls->upstream_finished)
            {
                return true;
            }

            ls->upstream_finished = true;
            if (ls->verbose)
            {
                LOGD("TlsServer: forwarding upstream Finish after peer close_notify");
            }
            return withLineLocked(l, tunnelNextUpStreamFinish, t);
        default:
            LOGW("TlsServer: SSL_read failed while decrypting upstream TLS bytes (ssl_error=%d)",
                 SSL_get_error(ls->ssl, n));
            tlsserverPrintSSLError();
            return false;
        }
    }
}

void tlsserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tlsserver_tstate_t *ts = tunnelGetState(t);
    tlsserver_lstate_t *ls = lineGetState(l, t);

    if (ls->fallback_mode)
    {
        tunnel_t *fallback = ts->fallback_tunnel;
        if (UNLIKELY(fallback == NULL || ls->fallback_up_finished || ls->fallback_up_finish_pending))
        {
            lineReuseBuffer(l, buf);
            return;
        }
        discard tlsserverSendFallbackPayload(t, l, ls, buf);
        return;
    }

    lineLock(l);

    if (ls->verbose)
    {
        LOGD("TlsServer: worker %u received %u upstream TLS bytes", (unsigned int) lineGetWID(l),
             (unsigned int) sbufGetLength(buf));
    }

    if (! ls->tls_committed && ts->fallback_tunnel != NULL && sbufGetLength(buf) > 0)
    {
        enum tlsserver_probe_classification_e probe_result = tlsserverClassifyFallbackProbe(ls, buf);

        if (probe_result == kTlsServerProbePlaintext)
        {
            bool alive = tlsserverStartFallback(t, l, ls);
            if (! alive)
            {
                lineReuseBuffer(l, buf);
                lineUnlock(l);
                return;
            }

            ls = lineGetState(l, t);
            discard tlsserverSendFallbackPayload(t, l, ls, buf);
            lineUnlock(l);
            return;
        }

        if (probe_result == kTlsServerProbeTlsLike)
        {
            ls->fallback_probe_tls_like = true;
            bufferstreamEmpty(&ls->fallback_probe);
        }
        else
        {
            sbuf_t *probe = sbufDuplicateByPool(lineGetBufferPool(l), buf);
            bufferstreamPush(&ls->fallback_probe, probe);
        }
    }

    while (sbufGetLength(buf) > 0)
    {
        int n = BIO_write(SSL_get_rbio(ls->ssl), sbufGetRawPtr(buf), (int) sbufGetLength(buf));

        if (n <= 0)
        {
            LOGW("TlsServer: failed to write upstream TLS bytes into OpenSSL read BIO");
            tlsserverPrintSSLError();
            reuseBuffer(buf);
            if (lineIsAlive(l))
            {
                lineUnlock(l);
                tlsserverPrintSSLState(ls->ssl);
                tlsserverCloseLineFatal(t, l);
                return;
            }
            lineUnlock(l);
            return;
        }

        sbufShiftRight(buf, n);
        if (ls->verbose)
        {
            LOGD("TlsServer: worker %u fed %d TLS bytes into OpenSSL", (unsigned int) lineGetWID(l), n);
        }

        while (! ls->handshake_completed)
        {
            int handshake_result = tlsserverPerformHandshake(t, l, ls);

            if (handshake_result == kTlsServerHandshakeFallback)
            {
                lineReuseBuffer(l, buf);
                bool alive = tlsserverStartFallback(t, l, ls);
                discard alive;
                lineUnlock(l);
                return;
            }

            if (handshake_result == kTlsServerHandshakeFatal)
            {
                reuseBuffer(buf);
                if (lineIsAlive(l))
                {
                    lineUnlock(l);
                    tlsserverPrintSSLState(ls->ssl);
                    tlsserverCloseLineFatal(t, l);
                    return;
                }
                lineUnlock(l);
                return;
            }

            if (handshake_result == kTlsServerHandshakeWantMore)
            {
                break;
            }
        }

        if (ls->handshake_completed && ! tlsserverReadDecryptedData(t, l, ls))
        {
            reuseBuffer(buf);
            if (lineIsAlive(l))
            {
                lineUnlock(l);
                tlsserverPrintSSLState(ls->ssl);
                tlsserverCloseLineFatal(t, l);
                return;
            }
            lineUnlock(l);
            return;
        }
    }

    lineReuseBuffer(l, buf);
    lineUnlock(l);
}
