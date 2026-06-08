#include "structure.h"
#include "race.h"
#include "sni_pool.h"

#include "loggers/network_logger.h"

void tlsclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tlsclient_lstate_t *ls = lineGetState(l, t);

    if (tlsclientRaceIsMainLine(ls))
    {
        if (ls->race_selected_child != NULL && lineIsAlive(ls->race_selected_child))
        {
            discard withLineLockedWithBuf(ls->race_selected_child, tlsclientTunnelUpStreamPayload, t, buf);
            return;
        }

        if (ls->race_selected_child != NULL)
        {
            lineReuseBuffer(l, buf);
            tlsclientRaceCloseMainLine(t, l);
            return;
        }

        bufferqueuePushBack(&ls->race_pending_up, buf);
        if (bufferqueueGetBufLen(&ls->race_pending_up) > kTlsClientRaceMaxPendingUpBytes)
        {
            LOGW("TlsClient: pending upstream payload exceeded %u bytes while waiting for SNI race winner",
                 (unsigned int) kTlsClientRaceMaxPendingUpBytes);
            tlsclientRaceCloseMainLine(t, l);
        }
        return;
    }

    if (ls->passthrough)
    {
        tunnelNextUpStreamPayload(t, l, buf);
        return;
    }

    if (! ls->handshake_completed)
    {
        bufferqueuePushBack(&(ls->bq), buf);
        return;
    }

    enum sslstatus status;

    int len = (int) sbufGetLength(buf);

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
                int     avail   = (int) sbufGetMaximumWriteableSize(ssl_buf);
                n               = BIO_read(ls->wbio, sbufGetMutablePtr(ssl_buf), avail);

                if (n > 0)
                {
                    sbufSetLength(ssl_buf, n);

                    if (! withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, ssl_buf))
                    {
                        reuseBuffer(buf);
                        return;
                    }
                }
                else if (! BIO_should_retry(ls->wbio))
                {
                    // If BIO_should_retry() is false then the cause is an error condition.
                    lineReuseBuffer(l, ssl_buf);
                    lineReuseBuffer(l, buf);
                    goto failed;
                }
                else
                {
                    lineReuseBuffer(l, ssl_buf);
                }
            } while (n > 0);
        }

        if (status == kSslstatusFail)
        {
            lineReuseBuffer(l, buf);
            goto failed;
        }

        if (n == 0)
        {
            break;
        }
    }
    lineReuseBuffer(l, buf);

    return;

failed:

    LOGW("TlsClient: upstream Payload failed: boringssl state is printed below");
    if (ls->ssl != NULL)
    {
        tlsclientPrintSSLState(ls->ssl);
    }

    tlsclientRecordSniFailureForLine(t, ls);

    if (tlsclientRaceIsChildLine(ls))
    {
        tlsclientRaceCloseChildLine(t, l, false);
        return;
    }

    if (tlsclientRaceIsMainLine(ls))
    {
        tlsclientRaceCloseMainLine(t, l);
        return;
    }

    tlsclientReleaseActiveSniLine(t, ls);
    tlsclientLinestateDestroy(ls);
    tunnelNextUpStreamFinish(t, l);
    tunnelPrevDownStreamFinish(t, l);
}
