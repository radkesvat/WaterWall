#include "structure.h"

#include "loggers/network_logger.h"

void connectionfisherclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    connectionfisherclient_lstate_t *ls = lineGetState(l, t);

    if (ls->role == kConnectionFisherClientRoleMain)
    {
        if (ls->selected_child != NULL && ! ls->selecting_child && ! ls->pumping_up &&
            bufferqueueGetEntryCount(&ls->pending_up) == 0)
        {
            discard lineCallWithRefWithBuf(ls->selected_child, tunnelNextUpStreamPayload, t, buf);
            return;
        }

        if (UNLIKELY(sbufGetLength(buf) == 0))
        {
            lineReuseBuffer(l, buf);
            return;
        }
        if (UNLIKELY(sbufGetLength(buf) > kConnectionFisherMaxPendingUpBytes - bufferqueueGetLength(&ls->pending_up) ||
                     bufferqueueGetCharge(&ls->pending_up) > kConnectionFisherMaxPendingCharge ||
                     sbufGetQueueCharge(buf) >
                         kConnectionFisherMaxPendingCharge - bufferqueueGetCharge(&ls->pending_up) ||
                     ! bufferqueueTryPushBack(&ls->pending_up, &buf)))
        {
            const size_t pending_bytes   = bufferqueueGetLength(&ls->pending_up);
            const size_t pending_charge  = bufferqueueGetCharge(&ls->pending_up);
            const size_t incoming_bytes  = sbufGetLength(buf);
            const size_t incoming_charge = sbufGetQueueCharge(buf);
            LOGW("ConnectionFisherClient: closing connection: pending upstream payload %s "
                 "(queued_bytes=%zu, incoming_bytes=%zu, limit_bytes=%u, queued_charge_bytes=%zu, "
                 "incoming_charge_bytes=%zu, limit_charge_bytes=%u)",
                 incoming_bytes > kConnectionFisherMaxPendingUpBytes - pending_bytes ? "byte limit exceeded"
                 : pending_charge > kConnectionFisherMaxPendingCharge ||
                         incoming_charge > kConnectionFisherMaxPendingCharge - pending_charge
                     ? "storage charge limit exceeded"
                     : "queue admission failed",
                 pending_bytes,
                 incoming_bytes,
                 (unsigned) kConnectionFisherMaxPendingUpBytes,
                 pending_charge,
                 incoming_charge,
                 (unsigned) kConnectionFisherMaxPendingCharge);
            lineReuseBuffer(l, buf);
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
