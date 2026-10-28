#include "structure.h"

#include "Ipv4StreamCodec/codec.h"

#include "loggers/network_logger.h"

// Builds a self-contained, fully valid IPv4 heartbeat packet. Because the on-wire format is
// now a raw concatenation of IPv4 packets (no length prefix), control frames must themselves be
// valid IPv4 packets so the size-based extractor on the peer keeps its framing. The heartbeat is
// tagged with a reserved experimentation protocol number and a constant payload fill byte.
static sbuf_t *packetstostreamCreateHeartbeatPacket(line_t *packet_line, uint8_t fill_byte)
{
    buffer_pool_t *pool = lineGetBufferPool(packet_line);
    sbuf_t        *buf  = bufferpoolGetBestFit(pool, kHeartbeatPacketSize, bufferpoolGetLargeBufferPadding(pool));

    sbufSetLength(buf, kHeartbeatPacketSize);

    uint8_t *raw = sbufGetMutablePtr(buf);
    memoryZero(raw, IP_HLEN);

    struct ip_hdr *iphdr = (struct ip_hdr *) raw;
    IPH_VHL_SET(iphdr, 4, IP_HLEN / 4);
    IPH_LEN_SET(iphdr, lwip_htons((uint16_t) kHeartbeatPacketSize));
    IPH_TTL_SET(iphdr, 64);
    IPH_PROTO_SET(iphdr, kHeartbeatProtocol);
    IPH_CHKSUM_SET(iphdr, 0);
    IPH_CHKSUM_SET(iphdr, inet_chksum(iphdr, IP_HLEN));

    memorySet(raw + IP_HLEN, fill_byte, kSensitivePayloadSize);

    return buf;
}

/*
 * Reports the failure instead of requesting shutdown itself: the caller still
 * owns the heartbeat buffer it built for this ping, and that buffer must be
 * recycled before any shutdown request.
 */
static bool packetstostreamArmTimeoutTimer(tunnel_t *t, wid_t wid)
{
    packetstostream_tstate_t *ts         = tunnelGetState(t);
    wtimer_t                **timer_slot = &ts->worker_timeout_timers[wid];

    if (*timer_slot != NULL)
    {
        wtimerReset(*timer_slot, ts->tolerance_ms);
        return true;
    }

    *timer_slot = wtimerAdd(getWorkerLoop(wid), packetstostreamTimeoutTimerCallback, ts->tolerance_ms, 1);
    if (*timer_slot == NULL)
    {
        LOGF("PacketsToStream: failed to create sensitive-mode timeout timer on worker %u", (unsigned int) wid);
        return false;
    }

    weventSetUserData(*timer_slot, t);
    return true;
}

static void packetstostreamDisarmTimeoutTimer(tunnel_t *t, wid_t wid)
{
    packetstostream_tstate_t *ts = tunnelGetState(t);

    if (ts->worker_timeout_timers == NULL)
    {
        return;
    }

    wtimer_t **timer_slot = &ts->worker_timeout_timers[wid];

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
    sbuf_t                   *buf = packetstostreamCreateHeartbeatPacket(packet_line, kSensitivePingByte);

    if (! packetstostreamArmTimeoutTimer(t, lineGetWID(packet_line)))
    {
        /*
         * Category B: an unsupervised ping would leave this worker waiting for a
         * pong forever. The heartbeat has not been forwarded yet, so this frame
         * still owns it: recycle it, leave the timer slot NULL and the pong
         * state untouched, then request an orderly shutdown and return.
         */
        lineReuseBuffer(packet_line, buf);
        if (! requestProgramShutdown(1))
        {
            abortProgramNow(1);
        }
        return false;
    }

    ls->awaiting_pong    = true;
    ls->ping_sent_at_ms  = now;
    ls->pong_deadline_ms = now + ts->tolerance_ms;

    if (lineCallWithRefWithBuf(stream_line, tunnelNextUpStreamPayload, t, buf))
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

// Detects a heartbeat packet produced by packetstostreamCreateHeartbeatPacket / the peer's
// equivalent: a minimal IPv4 packet tagged with kHeartbeatProtocol whose payload is filled with
// fill_byte. Real traffic is extremely unlikely to collide with this signature.
bool packetstostreamFrameMatchesFillByte(const sbuf_t *packet, uint8_t fill_byte)
{
    if (sbufGetLength(packet) != kHeartbeatPacketSize)
    {
        return false;
    }

    const uint8_t *data = sbufGetRawPtr(packet);

    if ((data[0] >> 4) != 4 || (data[0] & 0x0FU) != (IP_HLEN / 4) || data[9] != kHeartbeatProtocol)
    {
        return false;
    }

    const uint8_t *payload = data + IP_HLEN;
    for (uint32_t i = 0; i < kSensitivePayloadSize; ++i)
    {
        if (payload[i] != fill_byte)
        {
            return false;
        }
    }

    return true;
}

_Static_assert((int) kPacketsToStreamPacketValidationNone == (int) kIpv4StreamValidationNone &&
                   (int) kPacketsToStreamPacketValidationLoose == (int) kIpv4StreamValidationLoose &&
                   (int) kPacketsToStreamPacketValidationHard == (int) kIpv4StreamValidationHard,
               "Node validation levels must match the shared IPv4 codec");

bool packetstostreamValidatePacket(packetstostream_packet_validation_level_t level, sbuf_t *packet,
                                   const char *direction)
{
    const ipv4stream_validation_level_t shared_level = (ipv4stream_validation_level_t) level;
    const char                         *reason       = ipv4streamValidatePacket(shared_level, packet);
    if (reason != NULL)
    {
        LOGW("PacketsToStream: dropping packet during %s packet validation (%s): %s",
             direction,
             ipv4streamValidationLevelName(shared_level),
             reason);
        return false;
    }
    return true;
}

bool packetstostreamIsForwardableIpv4Packet(const sbuf_t *packet)
{
    return ipv4streamIsForwardablePacket(packet);
}

bool packetstostreamTryReadIPv4Packet(buffer_stream_t *stream, sbuf_t **packet_out)
{
    return ipv4streamTryReadPacket(stream, packet_out);
}

/* Decoding changes line identity, not worker ownership. The caller retains its
 * normal stream line across the packet callback and checks for reentrant close. */
void packetstostreamForwardDecodedPacket(tunnel_t *t, line_t *stream_line, sbuf_t *packet)
{
    assert(lineIsOnCurrentWorker(stream_line));
    line_t *packet_line = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), lineGetWID(stream_line));
    assert(packet_line != NULL);
    tunnelPrevDownStreamPayload(t, packet_line, packet);
}

void packetstostreamScheduleRecreateOutputLine(tunnel_t *t, line_t *packet_line, packetstostream_lstate_t *ls)
{
    if (ls->recreate_scheduled)
    {
        return;
    }

    ls->recreate_scheduled = true;
    const line_task_submit_result_e result =
        lineScheduleTask(packet_line, packetstostreamRecreateOutputLineTask, t, NULL);
    if (UNLIKELY(result == kLineTaskSubmitRejectedSettled))
    {
        /* Leave the packet worker retryable; the next packet/heartbeat may
         * schedule another attempt instead of permanently latching blackhole. */
        ls->recreate_scheduled = false;
    }
    else
    {
        assert(result == kLineTaskSubmitAcceptedAsync);
    }
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
        ipv4streamInputReset(&ls->read_input);
    }
}

void packetstostreamCloseOutputLineAndScheduleRecreate(tunnel_t *t, line_t *packet_line, packetstostream_lstate_t *ls)
{
    LOGW("PacketsToStream: closing output line and scheduling recreate, packet_line: %p, current stream_line: %p",
         packet_line,
         ls->line);
    line_t *stream_line = ls->line;

    packetstostreamResetOutputLineState(t, packet_line, ls);

    if (stream_line != NULL && lineIsAlive(stream_line))
    {
        lineRef(stream_line);
        tunnelNextUpStreamFinish(t, stream_line);
        if (lineIsAlive(stream_line))
        {
            lineDestroy(stream_line);
        }
        lineUnref(stream_line);
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
    bool    created;
    line_t *stream_line = packetstostreamEnsureOutputLine(t, packet_line, ls, &created);
    if (created)
    {
        packetstostreamResumePacketSource(t, packet_line, ls, stream_line);
    }
}

line_t *packetstostreamEnsureOutputLine(tunnel_t *t, line_t *packet_line, packetstostream_lstate_t *ls, bool *created)
{
    *created = false;

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
    ipv4streamInputReset(&ls->read_input);

    line_t *new_line = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(packet_line));
    ls->line         = new_line;

    if (! lineCallWithRef(new_line, tunnelNextUpStreamInit, t))
    {
        if (ls->line == new_line)
        {
            ls->line = NULL;
        }
        return ls->line;
    }

    *created = ls->line == new_line;
    return ls->line;
}

void packetstostreamResumePacketSource(tunnel_t *t, line_t *packet_line, packetstostream_lstate_t *ls,
                                       line_t *stream_line)
{
    if (stream_line != NULL && ls->line == stream_line && lineIsAlive(stream_line) && ! ls->paused)
    {
        // A former stream may have paused this persistent packet producer. Est
        // does not release that hold; repeatable Resume needs no extra latch.
        // Callers have already settled any packet/ping held across stream Init.
        tunnelPrevDownStreamResume(t, packet_line);
    }
}

void packetstostreamHeartbeatTimerCallback(wtimer_t *timer)
{
    tunnel_t *t = weventGetUserdata(timer);
    assert(t != NULL);

    packetstostream_tstate_t *ts = tunnelGetState(t);
    discard                   ts;
    assert(ts->sensitive_mode);

    // The heartbeat timer is armed per worker on that worker's own loop.
    const wid_t wid = getLoopWorkerWID(weventGetLoop(timer));
    assert(ts->worker_timers != NULL && ts->worker_timers[wid] == timer);

    line_t *packet_line = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), wid);
    assert(packet_line != NULL && lineIsAlive(packet_line));

    packetstostream_lstate_t *ls = lineGetState(packet_line, t);
    if (ls->read_stream.pool == NULL)
    {
        return;
    }

    if (ls->awaiting_pong)
    {
        return;
    }

    bool    created;
    line_t *stream_line = packetstostreamEnsureOutputLine(t, packet_line, ls, &created);
    if (stream_line == NULL)
    {
        return;
    }

    // A false result means the attempt was fully cleaned up by the callee, which
    // either scheduled output-line recreation or already requested shutdown.
    if (packetstostreamSendSensitivePing(t, packet_line, ls, stream_line) && created)
    {
        packetstostreamResumePacketSource(t, packet_line, ls, stream_line);
    }
}

void packetstostreamTimeoutTimerCallback(wtimer_t *timer)
{
    tunnel_t *t = weventGetUserdata(timer);
    assert(t != NULL);

    packetstostream_tstate_t *ts = tunnelGetState(t);
    // One checked identity for the packet line and the per-worker timer slot.
    const wid_t wid = getLoopWorkerWID(weventGetLoop(timer));
    assert(ts->worker_timeout_timers != NULL && ts->worker_timeout_timers[wid] == timer);

    line_t *packet_line = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), wid);
    assert(packet_line != NULL && lineIsAlive(packet_line));

    packetstostream_lstate_t *ls = lineGetState(packet_line, t);
    if (! ls->awaiting_pong)
    {
        ts->worker_timeout_timers[wid] = NULL;
        return;
    }

    assert(lineGetWID(packet_line) == wid);
    const uint64_t now = wloopNowMS(weventGetLoop(timer));
    if (now < ls->pong_deadline_ms)
    {
        const uint64_t remaining_ms_u64 = ls->pong_deadline_ms - now;
        const uint32_t remaining_ms     = (remaining_ms_u64 > UINT32_MAX) ? UINT32_MAX : (uint32_t) remaining_ms_u64;

        /*
         * The event loop can schedule timeout callbacks slightly before the
         * exact millisecond deadline because timer deadlines are tracked in
         * microseconds but some timeout values are rounded to coarser buckets.
         * Re-arm the same one-shot timer instead of clearing the slot, otherwise
         * awaiting_pong could remain stuck forever after a lost ping.
         */
        if (! wtimerReset(timer, remaining_ms))
        {
            ts->worker_timeout_timers[wid] = NULL;
            weventSetUserData(timer, NULL);
        }
        return;
    }

    ts->worker_timeout_timers[wid] = NULL;
    const uint64_t elapsed_ms =
        (ls->ping_sent_at_ms > 0 && now >= ls->ping_sent_at_ms) ? (now - ls->ping_sent_at_ms) : ts->tolerance_ms;

    LOGW("PacketsToStream: sensitive-mode ping timed out after %llums (limit=%u ms), resetting connection",
         (unsigned long long) elapsed_ms,
         (unsigned int) ts->tolerance_ms);
    packetstostreamCloseOutputLineAndScheduleRecreate(t, packet_line, ls);
}
