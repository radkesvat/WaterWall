#include "structure.h"
#include "race.h"
#include "sni_pool.h"

#include "loggers/network_logger.h"

static void tlsclientCloseAfterInitFailure(tunnel_t *t, line_t *l, tlsclient_lstate_t *ls)
{
    tlsclientRecordSniFailureForLine(t, ls);

    if (tlsclientRaceIsChildLine(ls))
    {
        tlsclientRaceCloseChildLine(t, l, false);
        return;
    }

    tlsclientReleaseActiveSniLine(t, ls);
    tlsclientLinestateDestroy(ls);
    tunnelNextUpStreamFinish(t, l);
    tunnelPrevDownStreamFinish(t, l);
}

void tlsclientPerformUpStreamInit(tunnel_t *t, line_t *l)
{
    tlsclient_tstate_t *ts = tunnelGetState(t);
    tlsclient_lstate_t *ls = lineGetState(l, t);
    sbuf_t             *ech_payload = NULL;
    const char         *sni         = NULL;

    if (tlsclientRaceIsChildLine(ls))
    {
        tlsclientLinestateSetupSsl(ls, ts->threadlocal_ssl_contexts[lineGetWID(l)]);
        tlsclientApplySelectedSniRoute(ts, ls, l);
        sni = ls->selected_sni;
    }
    else
    {
        tlsclientLinestateInitialize(ls, ts->threadlocal_ssl_contexts[lineGetWID(l)]);
        tlsclientSelectSniForLine(ts, ls, l);
        sni = ls->selected_sni;
    }

    ls->handshake_start_ms = getTimeOfDayMS();

    if (! tlsclientCreateEchGreaseInnerClientHello(ts, lineGetWID(l), &ech_payload))
    {
        goto failed;
    }

    if (! tlsclientConfigureSslForConnect(
            ls->ssl,
            ls->rbio,
            ls->wbio,
            sni,
            ech_payload != NULL ? (const uint8_t *) sbufGetRawPtr(ech_payload) : NULL,
            ech_payload != NULL ? sbufGetLength(ech_payload) : 0))
    {
        goto failed;
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

    tlsclientPrintSSLState(ls->ssl);

    int n = SSL_connect(ls->ssl);

    tlsclientPrintSSLState(ls->ssl);

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
                discard withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, buf);
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
    if (ech_payload != NULL)
    {
        lineReuseBuffer(l, ech_payload);
    }

    LOGW("TlsClient: upstream init failed for SNI \"%s\": boringssl state is printed below",
         sni != NULL ? sni : "<none>");
    if (ls->ssl != NULL)
    {
        tlsclientPrintSSLState(ls->ssl);
    }

    tlsclientCloseAfterInitFailure(t, l, ls);
}

void tlsclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    tlsclient_tstate_t *ts = tunnelGetState(t);

    if (tlsclientRaceIsEnabled(ts))
    {
        tlsclientRaceUpStreamInit(t, l);
        return;
    }

    tlsclientPerformUpStreamInit(t, l);
}
