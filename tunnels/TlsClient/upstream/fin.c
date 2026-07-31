#include "structure.h"

#include "loggers/network_logger.h"

void tlsclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    lineLock(l);

    tlsclient_lstate_t *ls = lineGetState(l, t);

    ls->upstream_finished = true;
    tlsclientCancelShapedOutputTimer(ls);

    if (ls->shaping_output.initialized && ! tlsrecordshapingOutputQueueIsEmpty(&ls->shaping_output))
    {
        if (! ls->shaping_wire_paused && ! tlsclientDrainShapedOutput(t, l, ls, true))
        {
            if (! lineIsAlive(l))
            {
                lineUnlock(l);
                return;
            }

            ls = lineGetState(l, t);
            if (ls->tunnel != t)
            {
                lineUnlock(l);
                return;
            }
            LOGW("TlsClient: could not synchronously drain final shaped ciphertext; discarding the remainder");
        }

        if (! lineIsAlive(l))
        {
            lineUnlock(l);
            return;
        }
        ls = lineGetState(l, t);
        if (ls->tunnel != t)
        {
            lineUnlock(l);
            return;
        }
    }

    // Direct close policy: free TLS resources without SSL_shutdown(), so no
    // close_notify is generated toward the wire side.
    // We do this to mimic chrome, which does not send close_notify when the connection is closed by the user.
    tlsclientLinestateDestroy(ls);

    tunnelNextUpStreamFinish(t, l);
    lineUnlock(l);
}
