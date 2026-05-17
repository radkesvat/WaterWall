#include "structure.h"

#include "loggers/network_logger.h"

void tlsserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tlsserver_lstate_t *ls = lineGetState(l, t);

    lineLock(l);

    if (ls->verbose)
    {
        LOGD("TlsServer: worker %u received %u downstream cleartext bytes", (unsigned int) lineGetWID(l),
             (unsigned int) sbufGetLength(buf));
    }

    if (! ls->handshake_completed)
    {
        if (ls->verbose)
        {
            LOGD("TlsServer: worker %u queueing downstream payload until TLS handshake completes",
                 (unsigned int) lineGetWID(l));
        }
        bufferqueuePushBack(&ls->pending_down, buf);
        lineUnlock(l);
        return;
    }

    if (! tlsserverEncryptAndSendApplicationData(t, l, ls, buf))
    {
        if (lineIsAlive(l))
        {
            LOGW("TlsServer: failed to encrypt downstream payload; closing line");
            lineUnlock(l);
            tlsserverPrintSSLState(ls->ssl);
            tlsserverCloseLineFatal(t, l);
            return;
        }
        LOGW("TlsServer: line closed while encrypting downstream payload");
        lineUnlock(l);
        return;
    }

    lineUnlock(l);
}
