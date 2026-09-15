#include "structure.h"
void obfuscatorserverTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    if (! tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l))
    {
        obfuscatorserver_lstate_t *ls = lineGetState(l, t);
        ls->paused                    = false;
        if (! lineCallWithRef(l, obfuscatorserverDrainStream, t))
            return;
        if (ls->paused)
            return;
    }
    tunnelNextUpStreamResume(t, l);
}
