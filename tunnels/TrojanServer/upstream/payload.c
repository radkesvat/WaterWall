#include "internal.h"

/* Client -> selected branch: initial/UDP bytes enter the owned pending_up FIFO
 * for trojanserverPump() to parse through common/input.c. CONNECT bypasses this
 * node after setup; TCP reentry before bypass joins the outer pump's FIFO.
 * Fallback transfers ownership to trojanserverSendFallbackPayload()
 * in common/fallback.c for immediate delivery or retention behind older replay. */
void trojanserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    trojanserver_lstate_t *ls = lineGetState(l, t);
    if (UNLIKELY(ls->phase == kTrojanServerPhaseClosing))
    {
        lineReuseBuffer(l, buf);
        return;
    }
    /* Owned backends receive upstream callbacks through next, not this node. */
    assert(ls->line_kind != kTrojanServerLineKindUdpRemote);
    if (ls->branch == kTrojanServerBranchFallback)
    {
        discard trojanserverSendFallbackPayload(t, l, ls, buf);
        return;
    }
    if (ls->phase == kTrojanServerPhaseWaitInitial || trojanserverIsUdp(ls))
    {
        if (! ls->first_payload_seen)
        {
            ls->first_payload_seen = true;
            ls->short_password     = sbufGetLength(buf) < 56;
        }
        uint32_t length = sbufGetLength(buf);
        if (length == 0 && ! ls->short_password)
        {
            lineReuseBuffer(l, buf);
            return;
        }
        if (UNLIKELY(length > kTrojanServerMaxWireBytes - ls->input_bytes ||
                     ! bufferqueueTryPushBack(&ls->pending_up, &buf)))
        {
            lineReuseBuffer(l, buf);
            trojanserverCloseLineBidirectional(t, l);
            return;
        }
        ls->input_bytes += length;
        trojanserverPump(t, l);
        return;
    }
    assert(ls->pumping || ls->branch_initializing);
    if (UNLIKELY(! trojanserverQueuePayload(&ls->pending_up, &buf)))
    {
        lineReuseBuffer(l, buf);
        trojanserverCloseLineBidirectional(t, l);
        return;
    }
}
