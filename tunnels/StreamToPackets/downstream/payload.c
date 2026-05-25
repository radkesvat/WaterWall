#include "structure.h"

#include "loggers/network_logger.h"

void streamtopacketsTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    line_t                   *packet_line = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), lineGetWID(l));
    streamtopackets_lstate_t *ls          = lineGetState(packet_line, t);

    if (ls->paused || ls->line == NULL || ! lineIsAlive(ls->line) || sbufGetLength(buf) > kMaxAllowedPacketLength)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    streamtopacketsRecalculateChecksumIfRequested(l, buf);

    uint32_t packet_length = sbufGetLength(buf);

    // safely cast to uint16_t, since kMaxAllowedPacketLength is lower than 65536
    uint16_t packet_length_network = htons(packet_length);

    sbufShiftLeft(buf, sizeof(uint16_t));
    // cant gurantee the alignment of the buffer, so we use unaligned write
    sbufWriteUnAlignedUI16(buf, packet_length_network);

    tunnelPrevDownStreamPayload(t, ls->line, buf);
}
