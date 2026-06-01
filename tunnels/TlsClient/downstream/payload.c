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
    int r;
    do
    {
        sbuf_t *ssl_buf = bufferpoolGetLargeBuffer(lineGetBufferPool(l));
        int     avail   = (int) sbufGetMaximumWriteableSize(ssl_buf);
        r               = BIO_read(ls->wbio, sbufGetMutablePtr(ssl_buf), avail);
        if (r > 0)
        {
            sbufSetLength(ssl_buf, r);
            tunnelNextUpStreamPayload(t, l, ssl_buf);
            if (! lineIsAlive(l))
            {
                return false;
            }
        }
        else
        {
            lineReuseBuffer(l, ssl_buf);
            break;
        }
    } while (r > 0);
    return true;
}

static inline int performHandshake(tunnel_t *t, line_t *l, tlsclient_lstate_t *ls)
{
    tlsclient_tstate_t *ts = tunnelGetState(t);
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

        if (ts->handshake_takeover_enabled)
        {
            if (! ls->handshake_est_sent)
            {
                ls->handshake_est_sent = true;
                tunnelPrevDownStreamEst(t, l);
                if (! lineIsAlive(l))
                {
                    return -1;
                }
            }

            if (! ls->passthrough)
            {
                LOGW("TlsClient: handshake takeover was requested but the owner did not deinitialize TLS");
                return -1;
            }

            return 2;
        }

        // write the data that we previously wanted to encrypt and send
        // yes, after the handshake is complete we can safely call SSL_write
        if (! flushWriteQueue(t, l, ls))
        {
            return -1; // Error (includes line not alive)
        }
    }

    return 1; // Continue handshake
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
    tlsclient_lstate_t *ls = lineGetState(l, t);
    int                 n;

    if (ls->passthrough)
    {
        tunnelPrevDownStreamPayload(t, l, buf);
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

        if (ls->passthrough)
        {
            lineReuseBuffer(l, buf);
            lineUnlock(l);
            return;
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
            lineUnlock(l);
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

    lineUnlock(l);

    LOGW("TlsClient: downstream payload failed: boringssl state is printed below");
    if (ls->ssl != NULL)
    {
        tlsclientPrintSSLState(ls->ssl);
    }

    tlsclientLinestateDestroy(ls);
    tunnelNextUpStreamFinish(t, l);
    tunnelPrevDownStreamFinish(t, l);
}
