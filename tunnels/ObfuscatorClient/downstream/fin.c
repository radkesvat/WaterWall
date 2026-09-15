#include "structure.h"
void obfuscatorclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    /* Packet lines carry no per-connection receive state. */
    if (! tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l))
        obfuscatorclientLinestateDestroy(lineGetState(l, t));
    tunnelPrevDownStreamFinish(t, l);
}
