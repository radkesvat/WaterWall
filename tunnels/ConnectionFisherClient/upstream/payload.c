#include "structure.h"

#include "loggers/network_logger.h"

void connectionfisherclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    connectionfisherclient_lstate_t *ls = lineGetState(l, t);

    if (ls->role == kConnectionFisherClientRoleMain)
    {
        if (ls->selected_child != NULL)
        {
            (void) withLineLockedWithBuf(ls->selected_child, tunnelNextUpStreamPayload, t, buf);
            return;
        }

        bufferqueuePushBack(&ls->pending_up, buf);
        if (bufferqueueGetBufLen(&ls->pending_up) > kConnectionFisherMaxPendingUpBytes)
        {
            LOGW("ConnectionFisherClient: pending upstream payload exceeded %u bytes while waiting for a fished child line",
                 (unsigned int) kConnectionFisherMaxPendingUpBytes);
            connectionfisherclientCloseMainLine(t, l);
        }
        return;
    }

    if (ls->role == kConnectionFisherClientRoleChild)
    {
        tunnelNextUpStreamPayload(t, l, buf);
        return;
    }

    lineReuseBuffer(l, buf);
}
