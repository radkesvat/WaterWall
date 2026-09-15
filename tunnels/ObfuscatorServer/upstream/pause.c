#include "structure.h"
void obfuscatorserverTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    if (! tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l))
        ((obfuscatorserver_lstate_t *) lineGetState(l, t))->paused = true;
    tunnelNextUpStreamPause(t, l);
}
