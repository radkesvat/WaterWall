#include "internal.h"

void vlessserverTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    vlessserver_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->phase == kVlessServerPhaseClosing))
    {
        return;
    }

    if (ls->line_kind == kVlessServerLineKindUdpRemote)
    {
        vlessserverSetUdpBackendPaused(t, l, false);
        return;
    }

    if (ls->phase == kVlessServerPhaseUdpWaitPacket || ls->phase == kVlessServerPhaseUdpConnecting ||
        ls->phase == kVlessServerPhaseUdpEstablished)
    {
        return;
    }

    if (ls->phase == kVlessServerPhaseFallback)
    {
        ls->fallback_payload_paused = false;
        if (UNLIKELY(! vlessserverScheduleFallbackPayloadDrain(t, l, ls)))
        {
            vlessserverCloseLineBidirectional(t, l);
            return;
        }
        if (! lineIsAlive(l))
        {
            return;
        }
    }

    tunnelPrevDownStreamResume(t, l);
}
