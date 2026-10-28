#include "structure.h"

#include "loggers/network_logger.h"

void streamtopacketsTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    streamtopackets_tstate_t *ts      = tunnelGetState(t);
    streamtopackets_lstate_t *line_ls = lineGetState(l, t);

    const ipv4stream_input_result_t admission = ipv4streamInputAdmit(&line_ls->read_input, &line_ls->read_stream, buf);
    if (admission == kIpv4StreamInputRejected)
    {
        lineReuseBuffer(l, buf);
        LOGW("StreamToPackets: nested input limit exceeded, closing carrier");
        streamtopacketsUnregisterLine(t, l);
        streamtopacketsLinestateDestroy(line_ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }
    if (admission != kIpv4StreamInputDrain)
        return;

    lineRef(l);

    while (true)
    {
        sbuf_t *packet_buffer = NULL;

        if (! streamtopacketsTryReadIPv4Packet(&(line_ls->read_stream), &packet_buffer))
        {
            if (ipv4streamInputAdvance(&line_ls->read_input, &line_ls->read_stream))
                continue;
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
                /* This carrier is no longer authorized. Drop its pending input
                 * while leaving retirement to its existing owner/eviction path. */
                bufferstreamEmpty(&line_ls->read_stream);
                ipv4streamInputReset(&line_ls->read_input);
                lineUnref(l);
                return;
            }

            if (! streamtopacketsSendSensitivePong(t, l))
            {
                lineUnref(l);
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

        // Keep the stream worker and recheck source authorization before packet
        // publication. Stateful packet consumers establish their own affinity.
        streamtopacketsForwardDecodedPacket(t, l, packet_buffer, generation);

        if (! lineIsAlive(l) || line_ls->read_stream.pool == NULL)
        {
            lineUnref(l);
            return;
        }
    }

    lineUnref(l);
}
