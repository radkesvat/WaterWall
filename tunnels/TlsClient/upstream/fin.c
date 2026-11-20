#include "structure.h"

#include "loggers/network_logger.h"

void tlsclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    lineRef(l);

    tlsclient_lstate_t *ls = lineGetState(l, t);

    if (ls->upstream_finished)
    {
        lineUnref(l);
        return;
    }

    ls->upstream_finished = true;
    tlsclientCancelShapedOutputTimer(ls);

    if (ls->shaping_output.initialized && ! tlsrecordshapingOutputQueueIsEmpty(&ls->shaping_output))
    {
        if (! tlsclientDrainShapedOutput(t, l, ls, true))
        {
            if (! lineIsAlive(l))
            {
                lineUnref(l);
                return;
            }

            ls = lineGetState(l, t);
            if (ls->tunnel != t)
            {
                lineUnref(l);
                return;
            }
            LOGW("TlsClient: could not synchronously drain final shaped ciphertext; discarding the remainder");
            goto finish;
        }

        if (! lineIsAlive(l))
        {
            lineUnref(l);
            return;
        }
        ls = lineGetState(l, t);
        if (ls->tunnel != t)
        {
            lineUnref(l);
            return;
        }
    }

    if (ls->ssl != NULL && ! tlsclientDrainFinalPlaintext(t, l))
    {
        if (! lineIsAlive(l) || ls->tunnel != t)
        {
            lineUnref(l);
            return;
        }
        LOGW("TlsClient: could not synchronously drain final plaintext; discarding the remainder");
    }

finish:
    // Direct close policy: free TLS resources without SSL_shutdown(), so no
    // close_notify is generated toward the wire side.
    // We do this to mimic chrome, which does not send close_notify when the connection is closed by the user.
    tlsclientLinestateDestroy(ls);

    tunnelNextUpStreamFinish(t, l);
    lineUnref(l);
}
