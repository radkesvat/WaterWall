#include "structure.h"

#include "loggers/network_logger.h"

void tlsserverTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    tlsserver_lstate_t *ls = lineGetState(l, t);

    if (ls->next_finished)
    {
        if (ls->verbose)
        {
            LOGD("TlsServer: suppressing upstream Resume because upstream side is already finished");
        }
        return;
    }

    tunnelNextUpStreamResume(t, l);
}
