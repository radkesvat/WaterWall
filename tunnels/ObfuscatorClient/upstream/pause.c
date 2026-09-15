#include "structure.h"
void obfuscatorclientTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    if (! tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l))
        ((obfuscatorclient_lstate_t *) lineGetState(l, t))->paused = true;
    tunnelNextUpStreamPause(t, l);
}
