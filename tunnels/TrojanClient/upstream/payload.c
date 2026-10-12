#include "internal.h"

/* Each accepted payload completes synchronously, including through Pause.
 * There is no application FIFO or Est gate: the transport owns connecting writes. */
void trojanclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    trojanclient_lstate_t *ls     = lineGetState(l, t);
    uint32_t               length = sbufGetLength(buf);
    if (UNLIKELY(ls->phase == kTrojanClientPhaseClosed || ls->kind == kTrojanClientLineKindUdpCarrier ||
                 (ls->kind == kTrojanClientLineKindUdpApplication && (length > kTrojanClientUdpMaxPacket)) ||
                 (ls->kind == kTrojanClientLineKindDirect && length == 0)))
    {
        lineReuseBuffer(l, buf);
        return;
    }
    if (ls->kind == kTrojanClientLineKindDirect)
    {
        if (UNLIKELY(! trojanclientSendInitialRequest(t, l, ls, buf)))
            trojanclientCloseLine(t, l, kTrojanClientCloseInternal);
        return; // Subsequent TCP payloads bypass this tunnel.
    }
    line_t                *next    = ls->carrier_line;
    trojanclient_lstate_t *next_ls = lineGetState(next, t);
    if (! next_ls->request_sent)
    {
        if (UNLIKELY(! trojanclientSendInitialRequest(t, next, next_ls, buf)))
            trojanclientCloseLine(t, next, kTrojanClientCloseInternal);
        return;
    }
    if (UNLIKELY(! trojanclientWrapUdpPayload(l, &buf, &ls->target_addr)))
    {
        lineReuseBuffer(l, buf);
        trojanclientCloseLine(t, next, kTrojanClientCloseInternal);
        return;
    }
    tunnelNextUpStreamPayload(t, next, buf);
}
