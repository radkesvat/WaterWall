#include "interface.h"

void synreplyTunnelUpStreamFinish(tunnel_t *t, line_t *line)
{
    assert(tunnelchainIsWorkerPacketLine(tunnelGetChain(t), line));
    tunnelBypassLine(t, line);
    tunnelNextUpStreamFinish(t, line);
}
