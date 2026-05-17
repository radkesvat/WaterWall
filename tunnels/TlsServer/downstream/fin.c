#include "structure.h"

#include "loggers/network_logger.h"

void tlsserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    tlsserver_lstate_t *ls = lineGetState(l, t);

    lineLock(l);

    if (ls->verbose)
    {
        LOGD("TlsServer: worker %u received downstream Finish (next_finished=%d, prev_finished=%d)",
             (unsigned int) lineGetWID(l), (int) ls->next_finished, (int) ls->prev_finished);
    }

    if (ls->prev_finished)
    {
        if (ls->verbose)
        {
            LOGD("TlsServer: downstream Finish already forwarded; ignoring duplicate");
        }
        lineUnlock(l);
        return;
    }

    ls->prev_finished = true;

    if (! tlsserverSendCloseNotify(t, l, ls))
    {
        if (lineIsAlive(l))
        {
            LOGW("TlsServer: close_notify failed; forwarding downstream Finish without TLS shutdown alert");
            tlsserverPrintSSLState(ls->ssl);
            tlsserverLinestateDestroy(ls);
            tunnelPrevDownStreamFinish(t, l);
            lineUnlock(l);
            return;
        }

        LOGW("TlsServer: line closed while sending close_notify");
        tlsserverLinestateDestroy(ls);
        lineUnlock(l);
        return;
    }

    if (ls->verbose)
    {
        LOGD("TlsServer: destroying TLS state and forwarding downstream Finish");
    }
    tlsserverLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);

    lineUnlock(l);
}
