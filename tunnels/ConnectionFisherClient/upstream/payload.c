#include "structure.h"

#include "loggers/network_logger.h"

void connectionfisherclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    connectionfisherclient_lstate_t *ls = lineGetState(l, t);

    if (ls->role == kConnectionFisherClientRoleMain)
    {
        if (ls->selected_child != NULL && ! ls->selecting_child && ! ls->pumping_up &&
            bufferqueueGetBufCount(&ls->pending_up) == 0)
        {
            discard lineCallWithRefWithBuf(ls->selected_child, tunnelNextUpStreamPayload, t, buf);
            return;
        }

        if (UNLIKELY(sbufGetLength(buf) == 0))
        {
            lineReuseBuffer(l, buf);
            return;
        }
        if (UNLIKELY(sbufGetLength(buf) > kConnectionFisherMaxPendingUpBytes - bufferqueueGetBufLen(&ls->pending_up) ||
                     ! bufferqueueTryPushBack(&ls->pending_up, &buf)))
        {
            lineReuseBuffer(l, buf);
            LOGW(
                "ConnectionFisherClient: pending upstream payload exceeded its 1 MiB budget or queue admission failed");
            connectionfisherclientCloseMainLine(t, l);
            return;
        }
        if (UNLIKELY(! connectionfisherclientSyncMainSource(t, l)))
            return;
        if (ls->selected_child != NULL)
            discard connectionfisherclientFlushPendingToSelected(t, l, ls->selected_child);
        return;
    }

    if (ls->role == kConnectionFisherClientRoleChild)
    {
        tunnelNextUpStreamPayload(t, l, buf);
        return;
    }

    lineReuseBuffer(l, buf);
}
