#include "structure.h"

#include "loggers/network_logger.h"

void streamtopacketsTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    streamtopackets_tstate_t *ts      = tunnelGetState(t);
    streamtopackets_lstate_t *line_ls = lineGetState(l, t);

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

            /*
             * A valid heartbeat is protocol proof, so it activates a candidate
             * and may trigger a source takeover. Authorize before replying, and
             * do not touch local state after the pong callback when it closes the
             * line. A ping is control traffic and never reaches a packet worker.
             */
            if (streamtopacketsAuthorizeLine(t, l) == 0)
            {
                LOGD("StreamToPackets: dropping a sensitive-mode ping from an unauthorized stream line");
                lineUnlock(l);
                return;
            }

            if (! streamtopacketsSendSensitivePong(t, l))
            {
                lineUnlock(l);
                return;
            }
            continue;
        }

        if (! streamtopacketsValidatePacket(ts->packet_validation_level, packet_buffer, "upstream"))
        {
            // Malformed bytes and failed validation are never protocol proof, so
            // they can neither activate a candidate nor trigger a takeover.
            lineReuseBuffer(l, packet_buffer);
            continue;
        }

        const uint64_t generation = streamtopacketsAuthorizeLine(t, l);

        if (generation == 0)
        {
            LOGD("StreamToPackets: dropping a packet from a line that does not own the active source");
            lineReuseBuffer(l, packet_buffer);
            continue;
        }

        // The outer connection's worker is unrelated to the inner flow's worker,
        // so affinity is restored from the decoded packet itself.
        streamtopacketsForwardDecodedPacket(t, l, packet_buffer, generation);

        if (! lineIsAlive(l) || line_ls->read_stream.pool == NULL)
        {
            lineUnlock(l);
            return;
        }
    }

    lineUnlock(l);
}
