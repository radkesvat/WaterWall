#include "structure.h"

#include "loggers/network_logger.h"

void tlsclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    tlsclient_tstate_t *ts          = tunnelGetState(t);
    tlsclient_lstate_t *ls          = lineGetState(l, t);
    sbuf_t             *ech_payload = NULL;

    if (! tlsclientLinestateInitializeWithShaping(ls,
                                                  ts->threadlocal_ssl_contexts[lineGetWID(l)],
                                                  lineGetBufferPool(l),
                                                  ts->alpn_wire,
                                                  ts->alpn_wire_len,
                                                  &ts->record_shaping,
                                                  ts->verbose))
    {
        // there is no SSL object to print a state for, and the line state is already released and zeroed;
        // the next tunnel never received Init for this line, so only the downstream side may be closed here
        LOGW("TlsClient: upstream init failed: boringssl line state could not be allocated");
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    ls->tunnel = t;
    ls->line   = l;

    if (! tlsclientCreateEchGreaseInnerClientHello(ts, lineGetWID(l), &ech_payload))
    {
        goto failed_before_next_init;
    }

    if (! tlsclientConfigureSslForConnect(ls->ssl,
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
        // the initial flight can be larger than any pool buffer, so the complete pending
        // length is drained into one exactly sized buffer instead of a single BIO_read
        sbuf_t *buf = NULL;
        if (! tlsclientDrainBioToBuffer(lineGetBufferPool(l), ls->wbio, &buf) || buf == NULL)
        {
            goto failed;
        }

        // the line is not touched after this forward, so no lock/lineIsAlive recheck is needed
        tunnelNextUpStreamPayload(t, l, buf);
        return;
    }

    if (status == kSslstatusFail)
    {
        goto failed;
    }

    LOGF("TlsClient: unreachable");
    abortProgramNow(1);

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
