#include "structure.h"

#include "loggers/network_logger.h"

void tlsclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    tlsclient_tstate_t *ts = tunnelGetState(t);
    tlsclient_lstate_t *ls = lineGetState(l, t);
    sbuf_t             *ech_payload = NULL;

    tlsclientLinestateInitialize(ls, ts->threadlocal_ssl_contexts[lineGetWID(l)]);

    if (! tlsclientCreateEchGreaseInnerClientHello(ts, lineGetWID(l), &ech_payload))
    {
        goto failed_before_next_init;
    }

    if (! tlsclientConfigureSslForConnect(
            ls->ssl,
            ls->rbio,
            ls->wbio,
            ts->sni,
            ech_payload != NULL ? (const uint8_t *) sbufGetRawPtr(ech_payload) : NULL,
            ech_payload != NULL ? sbufGetLength(ech_payload) : 0))
    {
        goto failed_before_next_init;
    }

    if (ech_payload != NULL)
    {
        lineReuseBuffer(l, ech_payload);
        ech_payload = NULL;
    }

    if (! withLineLocked(l, tunnelNextUpStreamInit, t))
    {
        return;
    }

    if (ts->verbose)
    {
        tlsclientPrintSSLState(ls->ssl);
    }

    int n = SSL_connect(ls->ssl);

    if (ts->verbose)
    {
        tlsclientPrintSSLState(ls->ssl);
    }

    enum sslstatus status = getSslStatus(ls->ssl, n);

    /* Did SSL request to write bytes? */
    if (status == kSslstatusWantIo)
    {
        sbuf_t *buf   = bufferpoolGetLargeBuffer(lineGetBufferPool(l));
        int     avail = (int) sbufGetMaximumWriteableSize(buf);

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
                lineReuseBuffer(l, buf);
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

    tlsclientCloseLineBidirectional(t, l);
    return;

failed_before_next_init:
    if (ech_payload != NULL)
    {
        lineReuseBuffer(l, ech_payload);
    }

    LOGW("TlsClient: upstream init failed: boringssl state is printed below");
    tlsclientPrintSSLState(ls->ssl);

    tlsclientLinestateDestroy(ls);
    // the next tunnel never received Init for this line, so only the
    // downstream side may be closed here
    tunnelPrevDownStreamFinish(t, l);
}
