#include "structure.h"

#include "loggers/network_logger.h"

void tlsclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    tlsclient_tstate_t *ts = tunnelGetState(t);
    tlsclient_lstate_t *ls = lineGetState(l, t);

    tlsclientLinestateInitialize(ls, ts->threadlocal_ssl_contexts[lineGetWID(l)]);

    SSL_set_connect_state(ls->ssl); /* sets ssl to work in client mode. */
    SSL_set_bio(ls->ssl, ls->rbio, ls->wbio);
    SSL_set_tlsext_host_name(ls->ssl, ts->sni);

    lineLock(l);

    tunnelNextUpStreamInit(t, l);

    if (! lineIsAlive(l))
    {
        lineUnlock(l);
        return;
    }
    lineUnlock(l);

    tlsclientPrintSSLState(ls->ssl);

    int n = SSL_connect(ls->ssl);

    tlsclientPrintSSLState(ls->ssl);

    enum sslstatus status = getSslStatus(ls->ssl, n);

    /* Did SSL request to write bytes? */
    if (status == kSslstatusWantIo)
    {
        sbuf_t *buf   = bufferpoolGetLargeBuffer(lineGetBufferPool(l));
        int     avail = (int) sbufGetRightCapacity(buf);

        while (true)
        {
            n = BIO_read(ls->wbio, sbufGetMutablePtr(buf), avail);
            if (n > 0)
            {
                sbufSetLength(buf, n);
                tunnelNextUpStreamPayload(t, l, buf);
                return;
            }

            if (! BIO_should_retry(ls->wbio))
            {
                // If BIO_should_retry() is false then the cause is an error condition.
                bufferpoolReuseBuffer(lineGetBufferPool(l), buf);
                goto failed;
            }
            else
            {
                continue; // retry reading
            }
        }
    }
    else if (status == kSslstatusFail)
    {
        goto failed;
    }

    LOGF("TlsClient: unreachable");
    terminateProgram(1);

failed:
    LOGW("TlsClient: upstream init failed: boringssl state is printed below");
    tlsclientPrintSSLState(ls->ssl);

    tlsclientLinestateDestroy(ls);
    tunnelNextUpStreamFinish(t, l);
    tunnelPrevDownStreamFinish(t, l);
}
