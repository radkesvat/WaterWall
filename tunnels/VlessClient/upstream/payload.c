#include "structure.h"

/* Each accepted payload completes synchronously, including through Pause.
 * There is no application FIFO or Est gate: the transport owns connecting writes. */
void vlessclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    vlessclient_lstate_t *ls     = lineGetState(l, t);
    uint32_t              length = sbufGetLength(buf);
    if (UNLIKELY(
            ls->phase == kVlessClientPhaseClosed || ls->kind == kVlessClientLineKindUdpCarrier ||
            (ls->kind == kVlessClientLineKindUdpApplication && (length > kVlessClientUdpMaxPacket || length == 0)) ||
            (ls->kind == kVlessClientLineKindDirect && ! ls->request_sent && length == 0)))
    {
        lineReuseBuffer(l, buf);
        return;
    }
    line_t               *next    = ls->kind == kVlessClientLineKindUdpApplication ? ls->carrier_line : l;
    vlessclient_lstate_t *next_ls = lineGetState(next, t);
    if (! next_ls->request_sent)
    {
        if (UNLIKELY(! vlessclientSendInitialRequest(t, next, next_ls, buf)))
            vlessclientCloseLine(t, next, kVlessClientCloseInternal);
        return;
    }
    if (ls->kind == kVlessClientLineKindUdpApplication)
    {
        vlessclientWrapUdpPayload(l, &buf);
    }
    tunnelNextUpStreamPayload(t, next, buf);
}
