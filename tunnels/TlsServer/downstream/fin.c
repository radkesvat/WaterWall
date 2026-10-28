#include "structure.h"

void tlsserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    tlsserver_lstate_t *ls = lineGetState(l, t);

    if (fallbackReplayAbsorbBranchFinish(&ls->fallback))
    {
        return;
    }

    if (ls->fallback_mode)
    {
        tlsserverLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    tlsserverFinishTlsOutput(t, l);
}
