#include "structure.h"

#include "loggers/network_logger.h"

static sbuf_t *packetstostreamCreateSensitiveFrame(line_t *packet_line, uint8_t fill_byte)
{
    sbuf_t *buf = bufferpoolGetSmallBuffer(lineGetBufferPool(packet_line));

    if (sbufGetLeftCapacity(buf) < kHeaderSize)
    {
        LOGW("PacketsToStream: dropping sensitive-mode control frame because left padding is smaller than header size");
        lineReuseBuffer(packet_line, buf);
        return NULL;
    }

    sbufSetLength(buf, kSensitivePayloadSize);
    memorySet(sbufGetMutablePtr(buf), fill_byte, kSensitivePayloadSize);

    sbufShiftLeft(buf, kHeaderSize);
    sbufWriteUnAlignedUI16(buf, htons((uint16_t) kSensitivePayloadSize));

    return buf;
}

static void packetstostreamArmTimeoutTimer(tunnel_t *t, wid_t wid)
{
    packetstostream_tstate_t *ts = tunnelGetState(t);
    wtimer_t                **timer_slot = &ts->worker_timeout_timers[wid];

    if (*timer_slot != NULL)
    {
        wtimerReset(*timer_slot, ts->tolerance_ms);
        return;
    }

    *timer_slot = wtimerAdd(getWorkerLoop(wid), packetstostreamTimeoutTimerCallback, ts->tolerance_ms, 1);
    if (*timer_slot == NULL)
    {
        LOGF("PacketsToStream: failed to create sensitive-mode timeout timer on worker %u", (unsigned int) wid);
        terminateProgram(1);
        return;
    }

    weventSetUserData(*timer_slot, t);
}

static void packetstostreamDisarmTimeoutTimer(tunnel_t *t, wid_t wid)
{
    packetstostream_tstate_t *ts = tunnelGetState(t);
    wtimer_t                **timer_slot = &ts->worker_timeout_timers[wid];

    if (*timer_slot == NULL)
    {
        return;
    }

    weventSetUserData(*timer_slot, NULL);
    wtimerDelete(*timer_slot);
    *timer_slot = NULL;
}

static bool packetstostreamSendSensitivePing(tunnel_t *t, line_t *packet_line, packetstostream_lstate_t *ls,
                                             line_t *stream_line)
{
    packetstostream_tstate_t *ts  = tunnelGetState(t);
    const uint64_t            now = wloopNowMS(getWorkerLoop(lineGetWID(packet_line)));
    sbuf_t *buf = packetstostreamCreateSensitiveFrame(packet_line, kSensitivePingByte);
    if (buf == NULL)
    {
        return true;
    }

    ls->awaiting_pong    = true;
    ls->ping_sent_at_ms  = now;
    ls->pong_deadline_ms = now + ts->tolerance_ms;
    packetstostreamArmTimeoutTimer(t, lineGetWID(packet_line));

    if (withLineLockedWithBuf(stream_line, tunnelNextUpStreamPayload, t, buf))
    {
        return true;
    }

    if (ls->line == stream_line)
    {
        packetstostreamResetOutputLineState(t, packet_line, ls);
        packetstostreamScheduleRecreateOutputLine(t, packet_line, ls);
    }

    return false;
}

bool packetstostreamFrameMatchesFillByte(const sbuf_t *packet, uint8_t fill_byte)
{
    if (sbufGetLength(packet) != kSensitivePayloadSize)
    {
        return false;
    }

    const uint8_t *data = sbufGetRawPtr(packet);

    for (uint32_t i = 0; i < kSensitivePayloadSize; ++i)
    {
        if (data[i] != fill_byte)
        {
            return false;
        }
    }

    return true;
}

bool packetstostreamReadStreamIsOverflowed(buffer_stream_t *read_stream)
{
    if (bufferstreamGetBufLen(read_stream) > kMaxBufferSize)
    {
        LOGW("PacketsToStream: read stream overflow, size: %zu, limit: %zu", bufferstreamGetBufLen(read_stream),
             (size_t) kMaxBufferSize);
        return true;
    }

    return false;
}

bool packetstostreamTryReadIPv4Packet(buffer_stream_t *stream, sbuf_t **packet_out)
{
    assert(packet_out != NULL);
    *packet_out = NULL;

    if (bufferstreamGetBufLen(stream) < kHeaderSize + 1)
    {
        return false;
    }

    uint8_t packet_first_bytes[kHeaderSize];
    bufferstreamViewBytesAt(stream, 0, packet_first_bytes, kHeaderSize);

    uint16_t total_packet_size_network;
    sbufByteCopy(&total_packet_size_network, packet_first_bytes, (uint32_t) sizeof(total_packet_size_network));
    uint16_t total_packet_size = ntohs(total_packet_size_network);
    
    if (total_packet_size < 1 ||  ((uint32_t) (total_packet_size  + kHeaderSize)) > (uint32_t) bufferstreamGetBufLen(stream))
    {
        return false;
    }

    // Read the complete packet (header + payload)
    *packet_out = bufferstreamReadExact(stream, kHeaderSize + total_packet_size);
    sbufShiftRight(*packet_out, kHeaderSize);

    return true;
}

void packetstostreamScheduleRecreateOutputLine(tunnel_t *t, line_t *packet_line, packetstostream_lstate_t *ls)
{
    if (ls->recreate_scheduled)
    {
        return;
    }

    ls->recreate_scheduled = true;
    lineScheduleTask(packet_line, packetstostreamRecreateOutputLineTask, t);
}

void packetstostreamResetOutputLineState(tunnel_t *t, line_t *packet_line, packetstostream_lstate_t *ls)
{
    ls->line             = NULL;
    ls->paused           = false;
    ls->awaiting_pong    = false;
    ls->ping_sent_at_ms  = 0;
    ls->pong_deadline_ms = 0;

    packetstostreamDisarmTimeoutTimer(t, lineGetWID(packet_line));

    if (ls->read_stream.pool != NULL)
    {
        bufferstreamEmpty(&ls->read_stream);
    }
}

void packetstostreamCloseOutputLineAndScheduleRecreate(tunnel_t *t, line_t *packet_line, packetstostream_lstate_t *ls)
{
    LOGW("PacketsToStream: closing output line and scheduling recreate, packet_line: %p, current stream_line: %p", packet_line, ls->line);
    line_t *stream_line = ls->line;

    packetstostreamResetOutputLineState(t, packet_line, ls);

    if (stream_line != NULL && lineIsAlive(stream_line))
    {
        lineLock(stream_line);
        tunnelNextUpStreamFinish(t, stream_line);
        if (lineIsAlive(stream_line))
        {
            lineDestroy(stream_line);
        }
        lineUnlock(stream_line);
    }

    packetstostreamScheduleRecreateOutputLine(t, packet_line, ls);
}

void packetstostreamRecreateOutputLineTask(tunnel_t *t, line_t *packet_line)
{
    packetstostream_lstate_t *ls = lineGetState(packet_line, t);

    if (! ls->recreate_scheduled)
    {
        return;
    }

    ls->recreate_scheduled = false;
    packetstostreamEnsureOutputLine(t, packet_line, ls);
}

line_t *packetstostreamEnsureOutputLine(tunnel_t *t, line_t *packet_line, packetstostream_lstate_t *ls)
{
    if (ls->read_stream.pool == NULL)
    {
        packetstostreamLinestateInitialize(ls, lineGetBufferPool(packet_line));
    }

    if (ls->line != NULL && lineIsAlive(ls->line))
    {
        return ls->line;
    }

    if (ls->recreate_scheduled)
    {
        return NULL;
    }

    ls->line   = NULL;
    ls->paused = false;
    bufferstreamEmpty(&ls->read_stream);

    line_t *new_line = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(packet_line));
    ls->line         = new_line;

    if (! withLineLocked(new_line, tunnelNextUpStreamInit, t))
    {
        if (ls->line == new_line)
        {
            ls->line = NULL;
        }
        return ls->line;
    }

    return ls->line;
}

void packetstostreamHeartbeatTimerCallback(wtimer_t *timer)
{
    tunnel_t *t = weventGetUserdata(timer);
    if (t == NULL)
    {
        return;
    }

    packetstostream_tstate_t *ts = tunnelGetState(t);
    if (! ts->sensitive_mode)
    {
        return;
    }

    line_t *packet_line = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), getWID());
    if (packet_line == NULL || ! lineIsAlive(packet_line))
    {
        return;
    }

    packetstostream_lstate_t *ls = lineGetState(packet_line, t);
    if (ls->read_stream.pool == NULL)
    {
        return;
    }

    if (ls->awaiting_pong)
    {
        return;
    }

    line_t *stream_line = packetstostreamEnsureOutputLine(t, packet_line, ls);
    if (stream_line == NULL)
    {
        return;
    }

    discard packetstostreamSendSensitivePing(t, packet_line, ls, stream_line);
}

void packetstostreamTimeoutTimerCallback(wtimer_t *timer)
{
    tunnel_t *t = weventGetUserdata(timer);
    if (t == NULL)
    {
        return;
    }

    packetstostream_tstate_t *ts = tunnelGetState(t);
    const wid_t               wid = getWID();

    line_t *packet_line = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), getWID());
    if (packet_line == NULL || ! lineIsAlive(packet_line))
    {
        ts->worker_timeout_timers[wid] = NULL;
        return;
    }

    packetstostream_lstate_t *ls = lineGetState(packet_line, t);
    if (! ls->awaiting_pong)
    {
        ts->worker_timeout_timers[wid] = NULL;
        return;
    }

    const uint64_t now = wloopNowMS(getWorkerLoop(lineGetWID(packet_line)));
    if (now < ls->pong_deadline_ms)
    {
        const uint64_t remaining_ms_u64 = ls->pong_deadline_ms - now;
        const uint32_t remaining_ms =
            (remaining_ms_u64 > UINT32_MAX) ? UINT32_MAX : (uint32_t) remaining_ms_u64;

        /*
         * The event loop can schedule timeout callbacks slightly before the
         * exact millisecond deadline because timer deadlines are tracked in
         * microseconds but some timeout values are rounded to coarser buckets.
         * Re-arm the same one-shot timer instead of clearing the slot, otherwise
         * awaiting_pong could remain stuck forever after a lost ping.
         */
        wtimerReset(timer, (remaining_ms == 0) ? 1U : remaining_ms);
        return;
    }

    ts->worker_timeout_timers[wid] = NULL;
    const uint64_t elapsed_ms = (ls->ping_sent_at_ms > 0 && now >= ls->ping_sent_at_ms) ?
                                    (now - ls->ping_sent_at_ms) :
                                    ts->tolerance_ms;

    LOGW("PacketsToStream: sensitive-mode ping timed out after %llums (limit=%u ms), resetting connection",
         (unsigned long long) elapsed_ms, (unsigned int) ts->tolerance_ms);
    packetstostreamCloseOutputLineAndScheduleRecreate(t, packet_line, ls);
}
