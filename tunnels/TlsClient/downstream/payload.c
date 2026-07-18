#include "structure.h"

#include "loggers/network_logger.h"

static inline bool flushWriteQueue(tunnel_t *t, line_t *l, tlsclient_lstate_t *ls)
{
    while (bufferqueueGetBufCount(&(ls->bq)) > 0)
    {
        sbuf_t *buf = bufferqueuePopFront(&(ls->bq));
        if (! withLineLockedWithBuf(l, tunnelUpStreamPayload, t, buf))
        {
            return false;
        }
    }
    return true;
}

static inline bool flushSSLOutput(tunnel_t *t, line_t *l, tlsclient_lstate_t *ls)
{
    return tlsclientFlushSslOutput(t, l, ls);
}

static inline int performHandshake(tunnel_t *t, line_t *l, tlsclient_lstate_t *ls)
{
    int            n      = SSL_connect(ls->ssl);
    enum sslstatus status = getSslStatus(ls->ssl, n);

    if (status == kSslstatusFail)
    {
        if (X509_V_OK != SSL_get_verify_result(ls->ssl))
        {
            long        verify_result = SSL_get_verify_result(ls->ssl);
            const char *verify_reason = X509_verify_cert_error_string(verify_result);
            LOGE("TlsClient: downstream payload failed: boringssl says certificate verification failed "
                 "(verify_result=%ld, reason=%s)",
                 verify_result,
                 verify_reason != NULL ? verify_reason : "unknown");
        }
        else
        {
            LOGW("TlsClient: downstream payload failed: boringssl state is printed below");
        }
        tlsclientPrintSSLError();
        return -1; // Error
    }

    if (status == kSslstatusWantIo)
    {
        // Check if SSL wants to read more data from input BIO
        int ssl_error = SSL_get_error(ls->ssl, n);
        if (ssl_error == SSL_ERROR_WANT_READ)
        {
            return 0; // Need more input data, break outer loop
        }
        // For SSL_ERROR_WANT_WRITE, we will flush output
    }

    // Flush anything SSL_connect() generated
    if (! flushSSLOutput(t, l, ls))
    {
        return -1; // Error (includes line not alive)
    }

    if (SSL_is_init_finished(ls->ssl))
    {
        LOGD("TlsClient: Tls handshake complete");
        ls->handshake_completed = true;

        // write the data that we previously wanted to encrypt and send
        // yes, after the handshake is complete we can safely call SSL_write
        if (! flushWriteQueue(t, l, ls))
        {
            return -1; // Error (includes line not alive)
        }
    }

    return 1; // Continue handshake
}

static int performTakeoverHandshake(tunnel_t *t, line_t *l, tlsclient_lstate_t *ls)
{
    while (true)
    {
        int            n      = SSL_connect(ls->ssl);
        enum sslstatus status = getSslStatus(ls->ssl, n);

        if (status == kSslstatusFail)
        {
            if (X509_V_OK != SSL_get_verify_result(ls->ssl))
            {
                long        verify_result = SSL_get_verify_result(ls->ssl);
                const char *verify_reason = X509_verify_cert_error_string(verify_result);
                LOGE("TlsClient: takeover handshake failed certificate verification "
                     "(verify_result=%ld, reason=%s)",
                     verify_result,
                     verify_reason != NULL ? verify_reason : "unknown");
            }
            tlsclientPrintSSLError();
            return -1;
        }

        if (! flushSSLOutput(t, l, ls))
        {
            return lineIsAlive(l) ? -1 : -2;
        }

        if (SSL_is_init_finished(ls->ssl))
        {
            /*
             * One complete record was the only ciphertext made available to
             * BoringSSL. Verify both its transport BIO and internal TLS read
             * buffer are empty before publishing the handoff boundary.
             */
            if (! tlsclientSslReadBoundaryIsClean(ls))
            {
                LOGW("TlsClient: completing takeover record was not fully consumed");
                return -1;
            }

            ls->handshake_completed = true;
            if (! ls->handshake_est_sent)
            {
                ls->handshake_est_sent = true;
                tunnelPrevDownStreamEst(t, l);
                if (! lineIsAlive(l))
                {
                    return -2;
                }
            }

            if (ls->takeover_phase != kTlsClientTakeoverDrain &&
                ls->takeover_phase != kTlsClientTakeoverPassthrough)
            {
                LOGW("TlsClient: takeover owner did not begin or complete the negotiated handoff");
                return -1;
            }
            return 1;
        }

        if (status == kSslstatusWantIo)
        {
            int ssl_error = SSL_get_error(ls->ssl, n);
            if (ssl_error == SSL_ERROR_WANT_READ)
            {
                return 0;
            }
            continue;
        }

        LOGW("TlsClient: SSL_connect returned success before the handshake completed");
        return -1;
    }
}

static void processTakeoverHandshakePayload(tunnel_t *t, line_t *l, tlsclient_lstate_t *ls, sbuf_t *buf)
{
    lineLock(l);
    bufferstreamPush(&ls->takeover_stream, buf);

    while (true)
    {
        sbuf_t *record  = NULL;
        bool    invalid = false;
        if (! tlsclientTakeoverTryReadRecord(ls, &record, &invalid))
        {
            if (! invalid)
            {
                lineUnlock(l);
                return;
            }
            goto failed;
        }

        int expected = (int) sbufGetLength(record);
        int written  = BIO_write(ls->rbio, sbufGetRawPtr(record), expected);
        lineReuseBuffer(l, record);
        if (written != expected)
        {
            goto failed;
        }

        int handshake_result = performTakeoverHandshake(t, l, ls);
        if (handshake_result == -2)
        {
            lineUnlock(l);
            return;
        }
        if (handshake_result < 0)
        {
            goto failed;
        }
        if (handshake_result > 0)
        {
            lineUnlock(l);
            return;
        }

        if (! tlsclientSslReadBoundaryIsClean(ls))
        {
            LOGW("TlsClient: takeover handshake record left unread ciphertext in BoringSSL");
            goto failed;
        }
    }

failed:
    if (! lineIsAlive(l))
    {
        lineUnlock(l);
        return;
    }
    LOGW("TlsClient: downstream takeover handshake failed: boringssl state is printed below");
    if (ls->ssl != NULL)
    {
        tlsclientPrintSSLState(ls->ssl);
    }
    lineUnlock(l);
    tlsclientCloseLineBidirectional(t, l);
}

static inline bool processEncryptedData(tunnel_t *t, line_t *l, tlsclient_lstate_t *ls)
{
    int n;
    do
    {
        sbuf_t *ssl_buf = bufferpoolGetLargeBuffer(lineGetBufferPool(l));
        int     avail   = (int) sbufGetMaximumWriteableSize(ssl_buf);
        n               = BIO_read(ls->wbio, sbufGetMutablePtr(ssl_buf), avail);

        if (n > 0)
        {
            sbufSetLength(ssl_buf, n);
            tunnelNextUpStreamPayload(t, l, ssl_buf);
            if (! lineIsAlive(l))
            {
                return false;
            }
        }
        else if (! BIO_should_retry(ls->wbio))
        {
            lineReuseBuffer(l, ssl_buf);
            return false;
        }
        else
        {
            lineReuseBuffer(l, ssl_buf);
        }
    } while (n > 0);

    return true;
}

static inline bool readDecryptedData(tunnel_t *t, line_t *l, tlsclient_lstate_t *ls)
{
    int            n;
    enum sslstatus status;

    /* The encrypted data is now in the input bio so now we can perform actual
     * read of unencrypted data. */
    do
    {
        sbuf_t *data_buf = bufferpoolGetLargeBuffer(lineGetBufferPool(l));

        int avail = (int) sbufGetMaximumWriteableSize(data_buf);
        n         = SSL_read(ls->ssl, sbufGetMutablePtr(data_buf), avail);

        if (n > 0)
        {
            sbufSetLength(data_buf, n);
            tunnelPrevDownStreamPayload(t, l, data_buf);
            if (! lineIsAlive(l))
            {
                return false;
            }
        }
        else
        {
            lineReuseBuffer(l, data_buf);
            status = getSslStatus(ls->ssl, n);
            if (status == kSslstatusFail)
            {
                return false;
            }
        }
    } while (n > 0);

    return true;
}

static inline bool flushSslProtocolMessages(tunnel_t *t, line_t *l, tlsclient_lstate_t *ls)
{
    // Optional: flush any SSL protocol messages generated during SSL_read
    return flushSSLOutput(t, l, ls);
}

void tlsclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tlsclient_tstate_t *ts = tunnelGetState(t);
    tlsclient_lstate_t *ls = lineGetState(l, t);
    int                 n;

    if (ls->takeover_phase == kTlsClientTakeoverDrain ||
        ls->takeover_phase == kTlsClientTakeoverPassthrough)
    {
        tunnelPrevDownStreamPayload(t, l, buf);
        return;
    }

    if (ts->handshake_takeover_enabled && ! ls->handshake_completed)
    {
        processTakeoverHandshakePayload(t, l, ls, buf);
        return;
    }

    lineLock(l);
    while (sbufGetLength(buf) > 0)
    {
        n = BIO_write(ls->rbio, sbufGetRawPtr(buf), (int) sbufGetLength(buf));

        if (n <= 0)
        {
            /* if BIO write fails, assume unrecoverable */
            lineReuseBuffer(l, buf);
            goto failed;
        }
        sbufShiftRight(buf, n);

        while (! ls->handshake_completed)
        {
            int handshake_result = performHandshake(t, l, ls);

            if (handshake_result == -1)
            {
                lineReuseBuffer(l, buf);
                goto failed;
            }

            if (handshake_result == 0)
            {
                break; // Need more data (kSslstatusWantIo)
            }

            if (handshake_result == 2)
            {
                lineReuseBuffer(l, buf);
                lineUnlock(l);
                return;
            }

            // handshake_result == 1, continue or handshake completed
        }

        if (! processEncryptedData(t, l, ls))
        {
            lineReuseBuffer(l, buf);
            goto failed;
        }

        if (! readDecryptedData(t, l, ls))
        {
            lineReuseBuffer(l, buf);
            goto failed;
        }

        if (! flushSslProtocolMessages(t, l, ls))
        {
            lineReuseBuffer(l, buf);
            if (! lineIsAlive(l))
            {
                lineUnlock(l);
                return;
            }
            lineUnlock(l);
            LOGW("TlsClient: downstream payload failed while flushing TLS protocol output");
            tlsclientCloseLineBidirectional(t, l);
            return;
        }
    }

    // done with socket data
    lineReuseBuffer(l, buf);
    lineUnlock(l);
    return;

failed:
    if (! lineIsAlive(l))
    {
        lineUnlock(l);
        return;
    }

    LOGW("TlsClient: downstream payload failed: boringssl state is printed below");
    if (ls->ssl != NULL)
    {
        tlsclientPrintSSLState(ls->ssl);
    }

    lineUnlock(l);
    tlsclientCloseLineBidirectional(t, l);
}
