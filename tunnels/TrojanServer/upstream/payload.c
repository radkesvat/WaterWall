#include "structure.h"

void trojanserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    trojanserver_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->phase == kTrojanServerPhaseClosing))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (UNLIKELY(ls->branch == kTrojanServerBranchFallback))
    {
        tunnel_t *fallback = ((trojanserver_tstate_t *) tunnelGetState(t))->fallback_tunnel;
        if (UNLIKELY(fallback == NULL))
        {
            lineReuseBuffer(l, buf);
            trojanserverCloseLineBidirectional(t, l);
            return;
        }
        tunnelUpStreamPayload(fallback, l, buf);
        return;
    }

    if (ls->phase == kTrojanServerPhaseTcpConnecting || ls->phase == kTrojanServerPhaseTcpEstablished)
    {
        tunnelNextUpStreamPayload(t, l, buf);
        return;
    }

    bool reject_short_password =
        ls->phase == kTrojanServerPhaseWaitInitial && bufferstreamIsEmpty(&ls->in_stream);

    bufferstreamPush(&ls->in_stream, buf);
    trojanserverDrainInput(t, l, ls, reject_short_password);
}
