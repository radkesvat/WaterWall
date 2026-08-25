#include "structure.h"

#include "loggers/network_logger.h"

void tlsserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    tlsserver_lstate_t *ls = lineGetState(l, t);

    if (ls->fallback_close_draining)
    {
        // The previous side already finished before the final fallback Payload;
        // record this branch close instead of reflecting it or finishing twice.
        ls->fallback_branch_finished_during_drain = true;
        return;
    }

    if (ls->fallback_mode)
    {
        tlsserverLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    lineRef(l);

    if (ls->verbose)
    {
        LOGD("TlsServer: worker %u received downstream Finish (upstream_finished=%d)",
             (unsigned int) lineGetWID(l),
             (int) ls->upstream_finished);
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
            lineUnref(l);
            return;
        }

        LOGW("TlsServer: line closed while sending close_notify");
        lineUnref(l);
        return;
    }

    if (! lineIsAlive(l))
    {
        lineUnref(l);
        return;
    }

    ls                  = lineGetState(l, t);
    bool output_pending = ls->shaping_output.initialized &&
                          ! tlsrecordshapingOutputQueueIsEmpty(&ls->shaping_output);
    if (ls->shaping_retired && ls->ssl != NULL)
    {
        output_pending = BIO_ctrl_pending(SSL_get_wbio(ls->ssl)) != 0;
    }
    if (output_pending)
    {
        ls->downstream_finish_deferred = true;
        if (ls->verbose)
        {
            LOGD("TlsServer: deferring downstream Finish until queued TLS ciphertext drains");
        }
        lineUnref(l);
        return;
    }

    if (ls->verbose)
    {
        LOGD("TlsServer: destroying TLS state and forwarding downstream Finish");
    }
    tlsserverLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);

    lineUnref(l);
}
