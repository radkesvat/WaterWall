#include "structure.h"

#include "loggers/network_logger.h"

void packetstostreamTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    packetstostream_tstate_t *ts          = tunnelGetState(t);
    line_t                   *packet_line = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), lineGetWID(l));
    packetstostream_lstate_t *ls          = lineGetState(packet_line, t);

    if (ls->line != l || ls->read_stream.pool == NULL)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    bufferstreamPush(&(ls->read_stream), buf);

    if (packetstostreamReadStreamIsOverflowed(&(ls->read_stream)))
    {
        bufferstreamEmpty(&(ls->read_stream));
        return;
    }

    /*
     * Delivering a decoded packet runs an inter-tunnel callback that can close
     * this stream line re-entrantly, so hold a reference across the extraction
     * loop and re-check the line's logical state before touching parser state
     * again. The parser, heartbeat and output-line recreation state stay owned by
     * this stream line's worker; only the decoded packets are re-affinitized.
     */
    lineLock(l);

    while (true)
    {
        sbuf_t *packet_buffer = NULL;

        if (! packetstostreamTryReadIPv4Packet(&(ls->read_stream), &packet_buffer))
        {
            break;
        }

        if (ts->sensitive_mode && packetstostreamFrameMatchesFillByte(packet_buffer, kSensitivePongByte))
        {
            const uint64_t now        = wloopNowMS(getWorkerLoop(lineGetWID(packet_line)));
            const uint64_t elapsed_ms = (ls->awaiting_pong && ls->ping_sent_at_ms > 0 && now >= ls->ping_sent_at_ms)
                                            ? (now - ls->ping_sent_at_ms)
                                            : 0;

            LOGD("PacketsToStream: received sensitive-mode pong after %llums (limit=%u ms)",
                 (unsigned long long) elapsed_ms,
                 (unsigned int) ts->tolerance_ms);
            lineReuseBuffer(l, packet_buffer);

            if (ls->awaiting_pong && elapsed_ms >= ts->tolerance_ms)
            {
                LOGW("PacketsToStream: sensitive-mode pong exceeded tolerance after %llums, resetting connection",
                     (unsigned long long) elapsed_ms);
                packetstostreamCloseOutputLineAndScheduleRecreate(t, packet_line, ls);
                lineUnlock(l);
                return;
            }

            ls->awaiting_pong    = false;
            ls->ping_sent_at_ms  = 0;
            ls->pong_deadline_ms = 0;
            continue;
        }

        if (! packetstostreamValidatePacket(ts->packet_validation_level, packet_buffer, "downstream"))
        {
            lineReuseBuffer(l, packet_buffer);
            continue;
        }

        /*
         * The peer may return any inner flow on any of its stream lines, so this
         * outer line's worker cannot decide packet-side ownership. Re-affinitize
         * from the inner tuple instead of assuming packet_line[lineGetWID(l)].
         */
        packetstostreamForwardDecodedPacket(t, l, packet_buffer);

        if (! lineIsAlive(l) || ls->line != l || ls->read_stream.pool == NULL)
        {
            lineUnlock(l);
            return;
        }
    }

    lineUnlock(l);
}
