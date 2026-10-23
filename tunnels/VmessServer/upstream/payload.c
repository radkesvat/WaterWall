#include "auth.h"
#include "internal.h"

void vmessserverTunnelUpStreamPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    vmessserver_lstate_t *ls = lineGetState(line, t);
    if (ls->phase == kVmessServerPhaseClosing || ls->closing_output || ls->next_finished ||
        ls->line_kind == kVmessServerLineKindUdpRemote)
    {
        lineReuseBuffer(line, buf);
        return;
    }
    if (ls->phase == kVmessServerPhaseFallback)
    {
        discard vmessserverSendFallbackPayload(t, line, ls, buf);
        return;
    }
    size_t size = sbufGetLength(buf);
    if (size == 0)
    {
        lineReuseBuffer(line, buf);
        return;
    }
    if (ls->phase == kVmessServerPhaseWaitInitial &&
        (size > 65536 - ls->unauth_bytes || bufferqueueGetBufCount(&ls->pending_up) + (ls->input_head != NULL) >= 256 ||
         ! vmessserverAuthAdmitInput(ls, size)))
        goto refused;
    if (size > kVmessServerMaxPendingBytes - ls->input_bytes || ! bufferqueueTryPushBack(&ls->pending_up, &buf))
        goto refused;
    ls->input_bytes += size;
    vmessserverProcessInput(t, line);
    return;
refused:
    lineReuseBuffer(line, buf);
    vmessserverCloseLineBidirectional(t, line);
}
