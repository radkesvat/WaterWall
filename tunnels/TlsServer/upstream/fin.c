#include "structure.h"

#include "loggers/network_logger.h"

void tlsserverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    tlsserver_lstate_t *ls = lineGetState(l, t);

    lineLock(l);

    if (ls->verbose)
    {
        LOGD("TlsServer: worker %u received upstream Finish (next_finished=%d, prev_finished=%d)",
             (unsigned int) lineGetWID(l), (int) ls->next_finished, (int) ls->prev_finished);
    }

    if (ls->prev_finished)
    {
        ls->next_finished = true;
        if (ls->verbose)
        {
            LOGD("TlsServer: suppressing upstream Finish because downstream side is already closing");
        }
        lineUnlock(l);
        return;
    }

    if (! ls->next_finished)
    {
        ls->next_finished = true;
        if (ls->verbose)
        {
            LOGD("TlsServer: destroying TLS state and forwarding upstream Finish");
        }
        tlsserverLinestateDestroy(ls);
        tunnelNextUpStreamFinish(t, l);
    }
    else
    {
        if (ls->verbose)
        {
            LOGD("TlsServer: upstream Finish already forwarded; destroying TLS state");
        }
        tlsserverLinestateDestroy(ls);
    }

    lineUnlock(l);
}
