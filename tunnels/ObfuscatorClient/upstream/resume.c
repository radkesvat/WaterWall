#include "structure.h"
void obfuscatorclientTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    if (! tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l))
    {
        obfuscatorclient_lstate_t *ls = lineGetState(l, t);
        ls->paused                    = false;
        if (! lineCallWithRef(l, obfuscatorclientDrainStream, t))
            return;
        if (ls->paused)
            return;
    }
    tunnelNextUpStreamResume(t, l);
}
