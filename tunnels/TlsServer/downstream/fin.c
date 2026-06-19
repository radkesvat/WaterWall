#include "structure.h"

#include "loggers/network_logger.h"

void tlsserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    tlsserver_lstate_t *ls = lineGetState(l, t);

    if (ls->fallback_mode)
    {
        tlsserverLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    lineLock(l);

    if (ls->verbose)
    {
        LOGD("TlsServer: worker %u received downstream Finish (upstream_finished=%d)",
             (unsigned int) lineGetWID(l), (int) ls->upstream_finished);
    }

    ls->upstream_finished    = true;
    ls->downstream_finishing = true;

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
