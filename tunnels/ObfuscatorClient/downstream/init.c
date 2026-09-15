#include "structure.h"
void obfuscatorclientTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    /* Packet lines carry no per-connection receive state. */
    if (! tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l))
        obfuscatorclientLinestateInitialize(lineGetState(l, t), l);
    tunnelPrevDownStreamInit(t, l);
}
