#include "structure.h"

#include "loggers/network_logger.h"

void packetstostreamTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    line_t                 *packet_line = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), lineGetWID(l));
    packetstostream_lstate_t *ls        = lineGetState(packet_line, t);

    if (ls->line == l && ! ls->paused)
    {
        ls->paused = true;
        tunnelPrevDownStreamPause(t, packet_line);
    }
}
