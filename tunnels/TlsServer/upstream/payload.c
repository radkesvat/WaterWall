#include "structure.h"

#include "loggers/network_logger.h"

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

static int tlsserverPerformHandshake(tunnel_t *t, line_t *l, tlsserver_lstate_t *ls)
{
    int            n      = SSL_accept(ls->ssl);
    enum sslstatus status = getSslStatus(ls->ssl, n);
    int            sslerr = SSL_get_error(ls->ssl, n);

    if (ls->verbose)
    {
        LOGD("TlsServer: worker %u SSL_accept returned %d (ssl_error=%d, state=\"%s\")",
             (unsigned int) lineGetWID(l), n, sslerr, SSL_state_string_long(ls->ssl));
    }

    if (! tlsserverFlushSslOutput(t, l, ls))
    {
        LOGW("TlsServer: TLS handshake failed while flushing handshake output");
        return -1;
    }

    if (SSL_is_init_finished(ls->ssl))
    {
        ls->handshake_completed = true;
        tlsserverLogHandshakeComplete(l, ls);

        if (! tlsserverFlushPendingDownQueue(t, l, ls))
        {
            return -1;
        }
    }

    if (status == kSslstatusFail)
    {
        LOGW("TlsServer: SSL_accept failed (ssl_error=%d, state=\"%s\")", sslerr, SSL_state_string_long(ls->ssl));
        tlsserverPrintSSLError();
        return -1;
    }

    if (! ls->handshake_completed && status == kSslstatusWantIo && sslerr == SSL_ERROR_WANT_READ)
    {
        if (ls->verbose)
        {
            LOGD("TlsServer: worker %u TLS handshake wants more upstream bytes", (unsigned int) lineGetWID(l));
        }
        return 0;
    }

    return 1;
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
            ls->peer_close_notify_received = true;
            if (ls->verbose)
            {
                LOGD("TlsServer: worker %u received TLS close_notify from peer", (unsigned int) lineGetWID(l));
            }
            if (ls->next_finished)
            {
                return true;
            }

            ls->next_finished = true;
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
    tlsserver_lstate_t *ls = lineGetState(l, t);

    lineLock(l);

    if (ls->verbose)
    {
        LOGD("TlsServer: worker %u received %u upstream TLS bytes", (unsigned int) lineGetWID(l),
             (unsigned int) sbufGetLength(buf));
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

            if (handshake_result < 0)
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

            if (handshake_result == 0)
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
