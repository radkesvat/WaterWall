#include "structure.h"
void obfuscatorserverTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    /* Packet lines carry no per-connection receive state. */
    if (! tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l))
        obfuscatorserverLinestateInitialize(lineGetState(l, t), l);
    tunnelPrevDownStreamInit(t, l);
}
