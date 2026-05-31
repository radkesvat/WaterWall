#include "structure.h"

#include "loggers/network_logger.h"

void packetstostreamTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    line_t                 *packet_line = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), lineGetWID(l));
    packetstostream_lstate_t *ls        = lineGetState(packet_line, t);

    if (ls->line == l && ls->paused)
    {
        ls->paused = false;
        tunnelPrevDownStreamResume(t, packet_line);
    }
}
