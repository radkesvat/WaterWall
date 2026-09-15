#include "structure.h"
void obfuscatorserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    /* Packet lines carry no per-connection receive state. */
    if (! tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l))
        obfuscatorserverLinestateDestroy(lineGetState(l, t));
    tunnelPrevDownStreamFinish(t, l);
}
