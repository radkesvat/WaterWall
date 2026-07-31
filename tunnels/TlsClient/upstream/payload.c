#include "structure.h"

#include "loggers/network_logger.h"

void tlsclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tlsclient_lstate_t *ls = lineGetState(l, t);

    if (ls->takeover_phase == kTlsClientTakeoverDrain || ls->takeover_phase == kTlsClientTakeoverPassthrough)
    {
        tunnelNextUpStreamPayload(t, l, buf);
        return;
    }

    if (! ls->handshake_completed)
    {
        bufferqueuePushBack(&(ls->bq), buf);
        return;
    }

    lineLock(l);
    int len = (int) sbufGetLength(buf);
    while (len > 0)
    {
        int            n      = SSL_write(ls->ssl, sbufGetRawPtr(buf), len);
        enum sslstatus status = getSslStatus(ls->ssl, n);

        if (n > 0)
        {
            sbufShiftRight(buf, n);
            len -= n;

            if (! tlsclientFlushSslOutput(t, l, ls))
            {
                lineReuseBuffer(l, buf);
                if (! lineIsAlive(l))
                {
                    lineUnlock(l);
                    return;
                }
                goto failed;
            }
            ls = lineGetState(l, t);
        }

        if (status == kSslstatusFail)
        {
            lineReuseBuffer(l, buf);
            goto failed;
        }

        if (n <= 0)
        {
            lineReuseBuffer(l, buf);
            goto failed;
        }
    }
    lineReuseBuffer(l, buf);
    lineUnlock(l);
    return;

failed:
    LOGW("TlsClient: upstream Payload failed: boringssl state is printed below");
    if (ls->ssl != NULL)
    {
        tlsclientPrintSSLState(ls->ssl);
    }

    lineUnlock(l);
    tlsclientCloseLineBidirectional(t, l);
}
