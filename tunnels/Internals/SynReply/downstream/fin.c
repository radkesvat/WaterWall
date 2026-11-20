#include "interface.h"

void synreplyTunnelDownStreamFinish(tunnel_t *t, line_t *line)
{
    assert(tunnelchainIsWorkerPacketLine(tunnelGetChain(t), line));
    tunnelBypassLine(t, line);
    tunnelPrevDownStreamFinish(t, line);
}
