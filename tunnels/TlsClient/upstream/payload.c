#include "structure.h"

#include "loggers/network_logger.h"

void tlsclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tlsclient_lstate_t *ls = lineGetState(l, t);

    if (! ls->handshake_completed)
    {
        bufferqueuePushBack(&(ls->bq), buf);
        return;
    }

    enum sslstatus status;

    int len = (int) sbufGetLength(buf);

    lineLock(l);

    // Write data to SSL, handle output, and propagate upstream until all data is sent or an error occurs.
    while (len > 0)
    {
        int n  = SSL_write(ls->ssl, sbufGetRawPtr(buf), len);
        status = getSslStatus(ls->ssl, n);

        if (n > 0)
        {
            /* the waiting bytes that have been used by SSL */
            sbufShiftRight(buf, n);
            len -= n;
            /* take the output of the SSL object and queue it for socket write */
            do
            {
                sbuf_t *ssl_buf = bufferpoolGetLargeBuffer(lineGetBufferPool(l));
                int     avail   = (int) sbufGetRightCapacity(ssl_buf);
                n               = BIO_read(ls->wbio, sbufGetMutablePtr(ssl_buf), avail);

                if (n > 0)
                {
                    sbufSetLength(ssl_buf, n);

                    tunnelNextUpStreamPayload(t, l, ssl_buf);

                    if (! lineIsAlive(l))
                    {
                        bufferpoolReuseBuffer(lineGetBufferPool(l), buf);
                        lineUnlock(l);
                        return;
                    }
                }
                else if (! BIO_should_retry(ls->wbio))
                {
                    // If BIO_should_retry() is false then the cause is an error condition.
                    bufferpoolReuseBuffer(lineGetBufferPool(l), ssl_buf);
                    bufferpoolReuseBuffer(lineGetBufferPool(l), buf);
                    goto failed;
                }
                else
                {
                    bufferpoolReuseBuffer(lineGetBufferPool(l), ssl_buf);
                }
            } while (n > 0);
        }

        if (status == kSslstatusFail)
        {
            bufferpoolReuseBuffer(lineGetBufferPool(l), buf);
            goto failed;
        }

        if (n == 0)
        {
            break;
        }
    }
    lineUnlock(l);
    bufferpoolReuseBuffer(lineGetBufferPool(l), buf);

    return;

failed:
    lineUnlock(l);

    LOGW("TlsClient: upstream Payload failed: boringssl state is printed below");
    tlsclientPrintSSLState(ls->ssl);

    tlsclientLinestateDestroy(ls);

    tunnelNextUpStreamFinish(t, l);
    tunnelPrevDownStreamFinish(t, l);
}
