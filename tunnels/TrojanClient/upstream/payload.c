#include "structure.h"

/* Each accepted payload completes synchronously, including through Pause.
 * There is no application FIFO or Est gate: the transport owns connecting writes. */
void trojanclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    trojanclient_lstate_t *ls     = lineGetState(l, t);
    uint32_t               length = sbufGetLength(buf);
    if (UNLIKELY(ls->phase == kTrojanClientPhaseClosed || ls->kind == kTrojanClientLineKindUdpCarrier ||
                 (ls->kind == kTrojanClientLineKindUdpApplication && (length > kTrojanClientUdpMaxPacket)) ||
                 (ls->kind == kTrojanClientLineKindDirect && ! ls->request_sent && length == 0)))
    {
        lineReuseBuffer(l, buf);
        return;
    }
    line_t                *next    = ls->kind == kTrojanClientLineKindUdpApplication ? ls->carrier_line : l;
    trojanclient_lstate_t *next_ls = lineGetState(next, t);
    if (! next_ls->request_sent)
    {
        if (UNLIKELY(! trojanclientSendInitialRequest(t, next, next_ls, buf)))
            trojanclientCloseLine(t, next, kTrojanClientCloseInternal);
        return;
    }
    if (ls->kind == kTrojanClientLineKindUdpApplication)
    {
        if (UNLIKELY(! trojanclientWrapUdpPayload(l, &buf, &ls->target_addr)))
        {
            lineReuseBuffer(l, buf);
            trojanclientCloseLine(t, next, kTrojanClientCloseInternal);
            return;
        }
    }
    tunnelNextUpStreamPayload(t, next, buf);
}
