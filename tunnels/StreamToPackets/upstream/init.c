#include "structure.h"

#include "loggers/network_logger.h"

void streamtopacketsTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    line_t                   *packet_line = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), lineGetWID(l));
    streamtopackets_lstate_t *packet_ls   = lineGetState(packet_line, t);
    streamtopackets_lstate_t *line_ls     = lineGetState(l, t);

    if (line_ls->read_stream.pool == NULL)
    {
        streamtopacketsLinestateInitialize(line_ls, lineGetBufferPool(l));
    }

    packet_ls->paused = false;
    packet_ls->line   = l;

    discard withLineLocked(l, tunnelPrevDownStreamEst, t);
}
