#include "structure.h"

/* Each reply is one admitted synchronous handoff. Neither transport Est nor
 * consumer Pause creates a protocol barrier or an association output backlog. */
void trojanserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    trojanserver_lstate_t *ls = lineGetState(l, t);
    if (UNLIKELY(ls->phase == kTrojanServerPhaseClosing))
    {
        lineReuseBuffer(l, buf);
        return;
    }
    if (ls->line_kind == kTrojanServerLineKindUdpRemote)
    {
        line_t                *client_l = ls->client_line;
        trojanserver_lstate_t *client   = lineGetState(client_l, t);
        if (UNLIKELY(client->phase == kTrojanServerPhaseClosing))
        {
            lineReuseBuffer(l, buf);
            return;
        }
        if (UNLIKELY(! trojanserverWrapUdpPayload(l, &buf)))
        {
            lineReuseBuffer(l, buf);
            trojanserverCloseLineBidirectional(t, l);
            return;
        }
        /* Client close can detach and destroy this exact backend during output. */
        lineRef(l);
        lineRef(client_l);
        tunnelPrevDownStreamPayload(t, client_l, buf);
        lineUnref(client_l);
        lineUnref(l);
        return;
    }
    if (ls->phase == kTrojanServerPhaseWaitInitial || trojanserverIsUdp(ls))
    {
        lineReuseBuffer(l, buf);
        return;
    }
    tunnelPrevDownStreamPayload(t, l, buf);
}
