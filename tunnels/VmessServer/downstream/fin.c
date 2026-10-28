#include "internal.h"

void vmessserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    vmessserver_lstate_t *ls = lineGetState(l, t);

    if (fallbackReplayAbsorbBranchFinish(&ls->fallback))
        return;

    vmessserverCloseLineFromDownstream(t, l);
}
