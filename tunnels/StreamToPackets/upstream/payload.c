#include "structure.h"

#include "loggers/network_logger.h"

void streamtopacketsTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    streamtopackets_tstate_t *ts          = tunnelGetState(t);
    line_t                   *packet_line = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), lineGetWID(l));
    streamtopackets_lstate_t *line_ls     = lineGetState(l, t);

    if (line_ls->read_stream.pool == NULL)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    bufferstreamPush(&(line_ls->read_stream), buf);

    if (streamtopacketsReadStreamIsOverflowed(&(line_ls->read_stream)))
    {
        bufferstreamEmpty(&(line_ls->read_stream));
        return;
    }

    lineLock(l);

    while (true)
    {
        sbuf_t *packet_buffer = NULL;

        if (! streamtopacketsTryReadIPv4Packet(&(line_ls->read_stream), &packet_buffer))
        {
            break;
        }

        if (ts->sensitive_mode && streamtopacketsFrameMatchesFillByte(packet_buffer, kSensitivePingByte))
        {
            LOGD("StreamToPackets: received sensitive-mode ping, sending pong");
            lineReuseBuffer(l, packet_buffer);
            if (! streamtopacketsSendSensitivePong(t, l))
            {
                lineUnlock(l);
                return;
            }
            continue;
        }

        if (! streamtopacketsValidatePacket(ts->packet_validation_level, packet_buffer, "upstream"))
        {
            lineReuseBuffer(l, packet_buffer);
            continue;
        }

        tunnelNextUpStreamPayload(t, packet_line, packet_buffer);

        if (! lineIsAlive(l))
        {
            lineUnlock(l);
            return;
        }
    }

    lineUnlock(l);
}
