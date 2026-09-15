#include "structure.h"
void obfuscatorserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    /* Packet lines carry no per-connection receive state. */
    if (! tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l))
        obfuscatorserverLinestateInitialize(lineGetState(l, t), l);
    tunnelNextUpStreamInit(t, l);
}
