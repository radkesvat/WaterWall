#include "structure.h"

#include "loggers/network_logger.h"

static void speedtestclientWriteU16(uint8_t *ptr, uint16_t value)
{
    const uint16_t be = lwip_htons(value);
    memoryCopy(ptr, &be, sizeof(be));
}

static void speedtestclientWriteU32(uint8_t *ptr, uint32_t value)
{
    const uint32_t be = lwip_htonl(value);
    memoryCopy(ptr, &be, sizeof(be));
}

static void speedtestclientWriteU64(uint8_t *ptr, uint64_t value)
{
    const uint64_t be = htonll(value);
    memoryCopy(ptr, &be, sizeof(be));
}

static uint16_t speedtestclientReadU16(const uint8_t *ptr)
{
    uint16_t value;
    memoryCopy(&value, ptr, sizeof(value));
    return lwip_ntohs(value);
}

static uint32_t speedtestclientReadU32(const uint8_t *ptr)
{
    uint32_t value;
    memoryCopy(&value, ptr, sizeof(value));
    return lwip_ntohl(value);
}

static uint64_t speedtestclientReadU64(const uint8_t *ptr)
{
    uint64_t value;
    memoryCopy(&value, ptr, sizeof(value));
    return ntohll(value);
}

uint64_t speedtestclientNowMs(void)
{
    return getHRTimeUs() / 1000U;
}

uint64_t speedtestclientNowUs(void)
{
    return getHRTimeUs();
}

uint16_t speedtestclientBaseFlags(const speedtestclient_tstate_t *state)
{
    uint16_t flags = 0;

    if (state->upload)
    {
        flags |= kSpeedTestClientFlagUpload;
    }
    if (state->download)
    {
        flags |= kSpeedTestClientFlagDownload;
    }
    flags |= (state->mode == kSpeedTestClientModeUdp) ? kSpeedTestClientFlagUdp : kSpeedTestClientFlagTcp;
    if (state->json_summary)
    {
        flags |= kSpeedTestClientFlagJson;
    }
    return flags;
}

void speedtestclientFormatBytes(uint64_t bytes, char *out, size_t out_len)
{
    static const char *units[] = {"Bytes", "KBytes", "MBytes", "GBytes", "TBytes"};
    double value = (double) bytes;
    size_t unit = 0;

    while (value >= 1024.0 && unit + 1U < (sizeof(units) / sizeof(units[0])))
    {
        value /= 1024.0;
        unit += 1U;
    }

    stringNPrintf(out, out_len, "%.2f %s", value, units[unit]);
}

void speedtestclientFormatBitrate(double bits_per_sec, char *out, size_t out_len)
{
    static const char *units[] = {"bits/sec", "Kbits/sec", "Mbits/sec", "Gbits/sec", "Tbits/sec"};
    double value = bits_per_sec;
    size_t unit = 0;

    while (value >= 1000.0 && unit + 1U < (sizeof(units) / sizeof(units[0])))
    {
        value /= 1000.0;
        unit += 1U;
    }

    stringNPrintf(out, out_len, "%.2f %s", value, units[unit]);
}

void speedtestclientWriteHeader(uint8_t *ptr, uint8_t type, uint16_t flags, uint32_t stream_id, uint32_t payload_len,
                                uint64_t sequence, uint64_t timestamp_us, uint64_t aux1, uint64_t aux2)
{
    speedtestclientWriteU32(ptr + 0, kSpeedTestClientMagic);
    ptr[4] = kSpeedTestClientProtocolVersion;
    ptr[5] = type;
    speedtestclientWriteU16(ptr + 6, flags);
    speedtestclientWriteU32(ptr + 8, stream_id);
    speedtestclientWriteU32(ptr + 12, payload_len);
    speedtestclientWriteU64(ptr + 16, sequence);
    speedtestclientWriteU64(ptr + 24, timestamp_us);
    speedtestclientWriteU64(ptr + 32, aux1);
    speedtestclientWriteU64(ptr + 40, aux2);
}

bool speedtestclientReadHeader(const uint8_t *ptr, size_t len, speedtestclient_frame_t *frame)
{
    if (len < kSpeedTestClientFrameHeaderSize)
    {
        return false;
    }

    if (speedtestclientReadU32(ptr + 0) != kSpeedTestClientMagic)
    {
        return false;
    }

    frame->version      = ptr[4];
    frame->type         = ptr[5];
    frame->flags        = speedtestclientReadU16(ptr + 6);
    frame->stream_id    = speedtestclientReadU32(ptr + 8);
    frame->payload_len  = speedtestclientReadU32(ptr + 12);
    frame->sequence     = speedtestclientReadU64(ptr + 16);
    frame->timestamp_us = speedtestclientReadU64(ptr + 24);
    frame->aux1         = speedtestclientReadU64(ptr + 32);
    frame->aux2         = speedtestclientReadU64(ptr + 40);
    frame->payload      = ptr + kSpeedTestClientFrameHeaderSize;

    if (frame->version != kSpeedTestClientProtocolVersion)
    {
        return false;
    }

    if (frame->payload_len > UINT32_MAX - kSpeedTestClientFrameHeaderSize)
    {
        return false;
    }

    return true;
}

static bool speedtestclientFramePayloadLengthValid(tunnel_t *t, line_t *l, const speedtestclient_frame_t *frame)
{
    speedtestclient_tstate_t *state = tunnelGetState(t);

    discard l;

    switch (frame->type)
    {
    case kSpeedTestClientFrameAck:
        return frame->payload_len == 0;
    case kSpeedTestClientFrameData:
        return state->download && frame->payload_len > 0 && frame->payload_len <= state->payload_size &&
               (state->mode != kSpeedTestClientModeUdp || frame->payload_len <= kSpeedTestClientMaxUdpPayloadSize);
    case kSpeedTestClientFrameEnd:
        return state->download && frame->payload_len == 0;
    case kSpeedTestClientFrameReport:
        if (frame->payload_len != kSpeedTestClientReportSize)
        {
            return false;
        }
        const bool sender_report = (frame->flags & kSpeedTestClientFlagSender) != 0;
        const bool receiver_report = (frame->flags & kSpeedTestClientFlagReceiver) != 0;
        if (sender_report == receiver_report)
        {
            return false;
        }
        return sender_report ? state->download : state->upload;
    case kSpeedTestClientFrameError:
        return frame->payload_len == 0;
    default:
        return false;
    }
}

static sbuf_t *speedtestclientAllocBuffer(line_t *l, uint32_t len)
{
    buffer_pool_t *pool = lineGetBufferPool(l);
    sbuf_t        *buf;

    if (len <= bufferpoolGetSmallBufferSize(pool))
    {
        buf = bufferpoolGetSmallBuffer(pool);
    }
    else if (len <= bufferpoolGetLargeBufferSize(pool))
    {
        buf = bufferpoolGetLargeBuffer(pool);
    }
    else
    {
        buf = sbufCreateWithPadding(len, bufferpoolGetLargeBufferPadding(pool));
    }

    if (sbufGetMaximumWriteableSize(buf) < len)
    {
        buf = sbufReserveSpace(buf, len);
    }
    sbufSetLength(buf, len);
    return buf;
}

sbuf_t *speedtestclientCreateFrame(tunnel_t *t, line_t *l, uint8_t type, uint16_t flags, uint32_t stream_id,
                                   uint64_t sequence, uint32_t payload_len, uint64_t timestamp_us, uint64_t aux1,
                                   uint64_t aux2)
{
    discard t;

    if (payload_len > UINT32_MAX - kSpeedTestClientFrameHeaderSize)
    {
        LOGE("SpeedTestClient: frame payload is too large");
        return NULL;
    }

    sbuf_t *buf = speedtestclientAllocBuffer(l, kSpeedTestClientFrameHeaderSize + payload_len);
    speedtestclientWriteHeader(sbufGetMutablePtr(buf), type, flags, stream_id, payload_len, sequence, timestamp_us,
                               aux1, aux2);
    return buf;
}

void speedtestclientFillPattern(uint8_t *ptr, uint32_t len, uint32_t stream_id, uint64_t sequence, uint16_t flags)
{
    const uint32_t direction_salt = (flags & kSpeedTestClientFlagDownload) ? 0xA5A55A5AU : 0x5A5AA5A5U;
    uint32_t seed = (uint32_t) sequence ^ (uint32_t) (sequence >> 32U) ^ (stream_id * 0x45D9F3BU) ^ direction_salt;

    for (uint32_t i = 0; i < len; ++i)
    {
        uint32_t value = seed + i;
        value ^= value >> 13U;
        value *= 0x85EBCA6BU;
        value ^= value >> 16U;
        ptr[i] = (uint8_t) value;
    }
}

bool speedtestclientVerifyPattern(const uint8_t *ptr, uint32_t len, uint32_t stream_id, uint64_t sequence,
                                  uint16_t flags)
{
    const uint32_t direction_salt = (flags & kSpeedTestClientFlagDownload) ? 0xA5A55A5AU : 0x5A5AA5A5U;
    uint32_t seed = (uint32_t) sequence ^ (uint32_t) (sequence >> 32U) ^ (stream_id * 0x45D9F3BU) ^ direction_salt;

    for (uint32_t i = 0; i < len; ++i)
    {
        uint32_t value = seed + i;
        value ^= value >> 13U;
        value *= 0x85EBCA6BU;
        value ^= value >> 16U;
        if (ptr[i] != (uint8_t) value)
        {
            return false;
        }
    }
    return true;
}

static void speedtestclientWriteHelloPayload(speedtestclient_tstate_t *state, speedtestclient_lstate_t *ls, uint8_t *ptr)
{
    speedtestclientWriteU32(ptr + 0, state->duration_ms);
    speedtestclientWriteU32(ptr + 4, state->warmup_ms);
    speedtestclientWriteU32(ptr + 8, state->report_interval_ms);
    speedtestclientWriteU32(ptr + 12, state->payload_size);
    speedtestclientWriteU64(ptr + 16, state->target_bandwidth_bps);
    speedtestclientWriteU32(ptr + 24, state->connection_count);
    speedtestclientWriteU32(ptr + 28, ls->stream_id);
}

static bool speedtestclientSendFrame(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    if (buf == NULL)
    {
        speedtestclientFailLine(t, l, "failed to allocate protocol frame");
        return false;
    }

    return withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, buf);
}

static bool speedtestclientSendHello(tunnel_t *t, line_t *l, speedtestclient_lstate_t *ls)
{
    speedtestclient_tstate_t *state = tunnelGetState(t);
    const uint16_t flags = speedtestclientBaseFlags(state);
    sbuf_t *buf = speedtestclientCreateFrame(t, l, kSpeedTestClientFrameHello, flags, ls->stream_id,
                                             state->connection_count, kSpeedTestClientHelloSize,
                                             speedtestclientNowUs(), state->duration_ms, state->target_bandwidth_bps);
    if (buf == NULL)
    {
        speedtestclientFailLine(t, l, "failed to allocate hello frame");
        return false;
    }

    speedtestclientWriteHelloPayload(state, ls, sbufGetMutablePtr(buf) + kSpeedTestClientFrameHeaderSize);
    ls->hello_sent = true;
    return speedtestclientSendFrame(t, l, buf);
}

static uint32_t speedtestclientPayloadSizeForNextFrame(tunnel_t *t, line_t *l)
{
    speedtestclient_tstate_t *state = tunnelGetState(t);
    buffer_pool_t *pool = lineGetBufferPool(l);
    uint32_t payload_size = state->payload_size;
    uint32_t max_pooled = bufferpoolGetLargeBufferSize(pool);

    if (state->mode == kSpeedTestClientModeUdp && payload_size > kSpeedTestClientMaxUdpPayloadSize)
    {
        payload_size = kSpeedTestClientMaxUdpPayloadSize;
    }

    if (payload_size + kSpeedTestClientFrameHeaderSize <= max_pooled)
    {
        return payload_size;
    }

    if (state->mode == kSpeedTestClientModeTcp)
    {
        return payload_size;
    }

    if (max_pooled > kSpeedTestClientFrameHeaderSize)
    {
        return max_pooled - kSpeedTestClientFrameHeaderSize;
    }

    return payload_size;
}

static bool speedtestclientShouldWaitForPace(speedtestclient_tstate_t *state, speedtestclient_lstate_t *ls,
                                             uint64_t now_us, uint32_t *delay_ms_out)
{
    if (state->target_bandwidth_bps == 0)
    {
        return false;
    }

    const uint64_t start_us = ls->start_ms * 1000ULL;
    const uint64_t elapsed_us = (now_us > start_us) ? (now_us - start_us) : 0;
    const uint64_t expected_us = (ls->paced_bytes * 8000000ULL) / state->target_bandwidth_bps;

    if (expected_us <= elapsed_us)
    {
        return false;
    }

    uint64_t wait_us = expected_us - elapsed_us;
    uint64_t wait_ms = (wait_us + 999ULL) / 1000ULL;
    if (wait_ms == 0)
    {
        wait_ms = 1;
    }
    if (wait_ms > UINT32_MAX)
    {
        wait_ms = UINT32_MAX;
    }
    *delay_ms_out = (uint32_t) wait_ms;
    return true;
}

static void speedtestclientSendEnd(tunnel_t *t, line_t *l, speedtestclient_lstate_t *ls)
{
    speedtestclient_tstate_t *state = tunnelGetState(t);
    uint16_t flags = (uint16_t) ((speedtestclientBaseFlags(state) | kSpeedTestClientFlagUpload) &
                                 (uint16_t) ~kSpeedTestClientFlagDownload);
    const int repeats = (state->mode == kSpeedTestClientModeUdp) ? kSpeedTestClientUdpFinalRepeats : 1;

    if (ls->sender_finished)
    {
        return;
    }
    ls->sender_finished = true;

    for (int i = 0; i < repeats; ++i)
    {
        sbuf_t *buf = speedtestclientCreateFrame(t, l, kSpeedTestClientFrameEnd, flags, ls->stream_id,
                                                 ls->next_send_sequence, 0, speedtestclientNowUs(), ls->sender.bytes,
                                                 ls->sender.packets);
        if (! speedtestclientSendFrame(t, l, buf))
        {
            return;
        }
    }

    speedtestclientMaybeComplete(t, l);
}

void speedtestclientScheduleSend(tunnel_t *t, line_t *l, speedtestclient_lstate_t *ls)
{
    discard t;
    if (ls->send_scheduled || ls->sender_finished || ls->send_paused || ! ls->est_received)
    {
        return;
    }

    ls->send_scheduled = true;
    lineScheduleTask(l, speedtestclientSendTask, ls->tunnel);
}

void speedtestclientScheduleReport(tunnel_t *t, line_t *l, speedtestclient_lstate_t *ls)
{
    speedtestclient_tstate_t *state = tunnelGetState(t);

    if (ls->report_scheduled || ls->line_complete || state->report_interval_ms == 0)
    {
        return;
    }

    ls->report_scheduled = true;
    lineScheduleDelayedTask(l, speedtestclientReportTask, state->report_interval_ms, t);
}

void speedtestclientSendTask(tunnel_t *t, line_t *l)
{
    speedtestclient_tstate_t *state = tunnelGetState(t);
    speedtestclient_lstate_t *ls = lineGetState(l, t);
    int burst = 0;
    bool sent_hello_now = false;

    ls->send_scheduled = false;

    if (ls->line_complete || ls->failed || ls->send_paused)
    {
        return;
    }

    if (! ls->hello_sent)
    {
        if (! speedtestclientSendHello(t, l, ls))
        {
            return;
        }
        sent_hello_now = true;
    }

    if (state->mode == kSpeedTestClientModeUdp && ! ls->ack_received)
    {
        if (! sent_hello_now && ! speedtestclientSendHello(t, l, ls))
        {
            return;
        }

        if (! ls->ack_received && ! ls->send_paused)
        {
            uint32_t retry_ms = min(state->report_interval_ms, 250U);
            if (retry_ms == 0)
            {
                retry_ms = 1;
            }
            ls->send_scheduled = true;
            lineScheduleDelayedTask(l, speedtestclientSendTask, retry_ms, t);
        }
        return;
    }

    if (ls->sender_finished)
    {
        return;
    }

    while (! ls->send_paused && ! ls->sender_finished && burst < kSpeedTestClientMaxBurstFrames)
    {
        const uint64_t now_ms = speedtestclientNowMs();
        const uint64_t now_us = speedtestclientNowUs();
        const bool warmup = now_ms < ls->measure_start_ms;

        if (now_ms >= ls->measure_end_ms)
        {
            speedtestclientSendEnd(t, l, ls);
            return;
        }

        uint32_t delay_ms = 0;
        if (speedtestclientShouldWaitForPace(state, ls, now_us, &delay_ms))
        {
            ls->send_scheduled = true;
            lineScheduleDelayedTask(l, speedtestclientSendTask, delay_ms, t);
            return;
        }

        const uint32_t payload_size = speedtestclientPayloadSizeForNextFrame(t, l);
        uint16_t flags = (uint16_t) ((speedtestclientBaseFlags(state) | kSpeedTestClientFlagUpload) &
                                     (uint16_t) ~kSpeedTestClientFlagDownload);
        uint64_t sequence;

        if (warmup)
        {
            flags |= kSpeedTestClientFlagWarmup;
            sequence = ls->next_warmup_sequence++;
        }
        else
        {
            sequence = ls->next_send_sequence++;
        }

        sbuf_t *buf = speedtestclientCreateFrame(t, l, kSpeedTestClientFrameData, flags, ls->stream_id, sequence,
                                                 payload_size, now_us, 0, 0);
        if (buf == NULL)
        {
            speedtestclientFailLine(t, l, "failed to allocate data frame");
            return;
        }

        speedtestclientFillPattern(sbufGetMutablePtr(buf) + kSpeedTestClientFrameHeaderSize, payload_size,
                                   ls->stream_id, sequence, flags);

        if (! warmup)
        {
            ls->sender.bytes += payload_size;
            ls->sender.packets += 1U;
            ls->sender.valid_packets += 1U;
        }
        ls->paced_bytes += payload_size;
        burst += 1;

        if (! speedtestclientSendFrame(t, l, buf))
        {
            return;
        }
    }

    if (! ls->send_paused && ! ls->sender_finished)
    {
        speedtestclientScheduleSend(t, l, ls);
    }
}

static void speedtestclientLogInterval(tunnel_t *t, line_t *l, speedtestclient_lstate_t *ls, bool final)
{
    speedtestclient_tstate_t *state = tunnelGetState(t);
    const uint64_t now_ms = speedtestclientNowMs();
    uint64_t from_ms = ls->last_report_ms;
    uint64_t to_ms = now_ms;

    discard l;

    if (from_ms < ls->measure_start_ms)
    {
        from_ms = ls->measure_start_ms;
    }
    if (to_ms > ls->measure_end_ms)
    {
        to_ms = ls->measure_end_ms;
    }
    if (to_ms <= from_ms)
    {
        return;
    }

    const double interval_sec = (double) (to_ms - from_ms) / 1000.0;
    char bytes_buf[64];
    char rate_buf[64];

    if (state->upload)
    {
        uint64_t delta = ls->sender.bytes - ls->sender_last_report_bytes;
        speedtestclientFormatBytes(delta, bytes_buf, sizeof(bytes_buf));
        speedtestclientFormatBitrate((interval_sec > 0.0) ? ((double) delta * 8.0 / interval_sec) : 0.0,
                                     rate_buf, sizeof(rate_buf));
        LOGI("SpeedTestClient: stream %u sender %.2f-%.2f sec %s %s%s",
             (unsigned int) ls->stream_id, (double) (from_ms - ls->measure_start_ms) / 1000.0,
             (double) (to_ms - ls->measure_start_ms) / 1000.0, bytes_buf, rate_buf, final ? " final" : "");
        ls->sender_last_report_bytes = ls->sender.bytes;
    }

    if (state->download)
    {
        uint64_t delta = ls->receiver.bytes - ls->receiver_last_report_bytes;
        speedtestclientFormatBytes(delta, bytes_buf, sizeof(bytes_buf));
        speedtestclientFormatBitrate((interval_sec > 0.0) ? ((double) delta * 8.0 / interval_sec) : 0.0,
                                     rate_buf, sizeof(rate_buf));
        LOGI("SpeedTestClient: stream %u receiver %.2f-%.2f sec %s %s lost=%llu dup=%llu errors=%llu jitter=%.3f ms%s",
             (unsigned int) ls->stream_id, (double) (from_ms - ls->measure_start_ms) / 1000.0,
             (double) (to_ms - ls->measure_start_ms) / 1000.0, bytes_buf, rate_buf,
             (unsigned long long) ls->receiver.lost_packets,
             (unsigned long long) ls->receiver.duplicate_packets,
             (unsigned long long) ls->receiver.validation_errors, ls->receiver.jitter_us / 1000.0,
             final ? " final" : "");
        ls->receiver_last_report_bytes = ls->receiver.bytes;
    }

    ls->last_report_ms = to_ms;
}

void speedtestclientReportTask(tunnel_t *t, line_t *l)
{
    speedtestclient_lstate_t *ls = lineGetState(l, t);

    ls->report_scheduled = false;
    if (ls->line_complete || ls->failed)
    {
        return;
    }

    speedtestclientLogInterval(t, l, ls, false);
    speedtestclientScheduleReport(t, l, ls);
}

static void speedtestclientFinalizeReceiver(speedtestclient_lstate_t *ls, const speedtestclient_frame_t *frame)
{
    if (frame->sequence > ls->expected_recv_sequence)
    {
        ls->receiver.lost_packets += frame->sequence - ls->expected_recv_sequence;
        ls->expected_recv_sequence = frame->sequence;
    }
    ls->receiver_finished = true;
}

static void speedtestclientUpdateJitter(speedtestclient_stats_t *stats, speedtestclient_lstate_t *ls,
                                        const speedtestclient_frame_t *frame)
{
    if (frame->timestamp_us == 0)
    {
        return;
    }

    const uint64_t now_us = speedtestclientNowUs();
    const uint64_t transit = (now_us > frame->timestamp_us) ? (now_us - frame->timestamp_us) : 0;

    if (ls->last_transit_us != 0)
    {
        const uint64_t diff = (transit > ls->last_transit_us) ? (transit - ls->last_transit_us)
                                                              : (ls->last_transit_us - transit);
        stats->jitter_us += ((double) diff - stats->jitter_us) / 16.0;
    }
    ls->last_transit_us = transit;
}

static void speedtestclientHandleData(tunnel_t *t, line_t *l, const speedtestclient_frame_t *frame)
{
    discard t;
    speedtestclient_lstate_t *ls = lineGetState(l, t);

    if (frame->flags & kSpeedTestClientFlagWarmup)
    {
        discard speedtestclientVerifyPattern(frame->payload, frame->payload_len, frame->stream_id, frame->sequence,
                                             frame->flags);
        return;
    }

    if (frame->sequence == ls->expected_recv_sequence)
    {
        ls->expected_recv_sequence += 1U;
    }
    else if (frame->sequence > ls->expected_recv_sequence)
    {
        ls->receiver.lost_packets += frame->sequence - ls->expected_recv_sequence;
        ls->receiver.out_of_order_packets += 1U;
        ls->expected_recv_sequence = frame->sequence + 1U;
    }
    else
    {
        ls->receiver.duplicate_packets += 1U;
        ls->receiver.out_of_order_packets += 1U;
    }

    ls->receiver.bytes += frame->payload_len;
    ls->receiver.packets += 1U;
    if (speedtestclientVerifyPattern(frame->payload, frame->payload_len, frame->stream_id, frame->sequence,
                                     frame->flags))
    {
        ls->receiver.valid_packets += 1U;
    }
    else
    {
        ls->receiver.validation_errors += 1U;
    }

    speedtestclientUpdateJitter(&ls->receiver, ls, frame);
}

static void speedtestclientReadReportPayload(const speedtestclient_frame_t *frame, speedtestclient_stats_t *stats)
{
    if (frame->payload_len < kSpeedTestClientReportSize)
    {
        return;
    }

    stats->bytes = speedtestclientReadU64(frame->payload + 0);
    stats->packets = speedtestclientReadU64(frame->payload + 8);
    stats->valid_packets = speedtestclientReadU64(frame->payload + 16);
    stats->lost_packets = speedtestclientReadU64(frame->payload + 24);
    stats->duplicate_packets = speedtestclientReadU64(frame->payload + 32);
    stats->out_of_order_packets = speedtestclientReadU64(frame->payload + 40);
    stats->validation_errors = speedtestclientReadU64(frame->payload + 48);
    stats->jitter_us = (double) speedtestclientReadU64(frame->payload + 64);
}

static void speedtestclientHandleReport(tunnel_t *t, line_t *l, const speedtestclient_frame_t *frame)
{
    speedtestclient_lstate_t *ls = lineGetState(l, t);
    const bool sender_report = (frame->flags & kSpeedTestClientFlagSender) != 0;
    speedtestclient_stats_t  *target = sender_report ? &ls->remote_sender : &ls->remote_receiver;

    if (sender_report)
    {
        if (ls->remote_sender_report_received)
        {
            return;
        }
        ls->remote_sender_report_received = true;
    }
    else
    {
        if (ls->remote_receiver_report_received)
        {
            return;
        }
        ls->remote_receiver_report_received = true;
    }

    speedtestclientReadReportPayload(frame, target);

    ls->received_reports += 1U;

    char bytes_buf[64];
    char rate_buf[64];
    const uint64_t duration_us = frame->payload_len >= kSpeedTestClientReportSize
                                     ? speedtestclientReadU64(frame->payload + 56)
                                     : 0;
    const double seconds = duration_us > 0 ? (double) duration_us / 1000000.0 : 0.0;

    speedtestclientFormatBytes(target->bytes, bytes_buf, sizeof(bytes_buf));
    speedtestclientFormatBitrate(seconds > 0.0 ? (double) target->bytes * 8.0 / seconds : 0.0, rate_buf,
                                 sizeof(rate_buf));
    LOGI("SpeedTestClient: stream %u remote %s report %.2f sec %s %s packets=%llu lost=%llu dup=%llu errors=%llu jitter=%.3f ms",
         (unsigned int) ls->stream_id,
         sender_report ? "sender" : "receiver", seconds, bytes_buf, rate_buf,
         (unsigned long long) target->packets, (unsigned long long) target->lost_packets,
         (unsigned long long) target->duplicate_packets, (unsigned long long) target->validation_errors,
         target->jitter_us / 1000.0);
}

static void speedtestclientHandleFrame(tunnel_t *t, line_t *l, const speedtestclient_frame_t *frame)
{
    speedtestclient_lstate_t *ls = lineGetState(l, t);

    if (frame->stream_id != ls->stream_id)
    {
        speedtestclientFailLine(t, l, "received a frame for a different stream id");
        return;
    }

    switch (frame->type)
    {
    case kSpeedTestClientFrameAck:
        if (! ls->ack_received)
        {
            ls->ack_received = true;
            if (! ls->send_paused && ! ls->sender_finished)
            {
                ls->send_scheduled = true;
                lineScheduleTask(l, speedtestclientSendTask, t);
            }
        }
        return;
    case kSpeedTestClientFrameData:
        speedtestclientHandleData(t, l, frame);
        return;
    case kSpeedTestClientFrameEnd:
        speedtestclientFinalizeReceiver(ls, frame);
        speedtestclientLogInterval(t, l, ls, true);
        speedtestclientMaybeComplete(t, l);
        return;
    case kSpeedTestClientFrameReport:
        speedtestclientHandleReport(t, l, frame);
        speedtestclientMaybeComplete(t, l);
        return;
    case kSpeedTestClientFrameError:
        LOGE("SpeedTestClient: server reported an error on stream %u", (unsigned int) ls->stream_id);
        speedtestclientFailLine(t, l, "server error frame");
        return;
    default:
        speedtestclientFailLine(t, l, "received an unknown frame type");
        return;
    }
}

static bool speedtestclientProcessFrameBuffer(tunnel_t *t, line_t *l, sbuf_t *frame_buf)
{
    speedtestclient_frame_t frame;

    lineLock(l);

    if (! speedtestclientReadHeader(sbufGetRawPtr(frame_buf), sbufGetLength(frame_buf), &frame) ||
        ! speedtestclientFramePayloadLengthValid(t, l, &frame) ||
        sbufGetLength(frame_buf) < (size_t) kSpeedTestClientFrameHeaderSize + frame.payload_len)
    {
        lineReuseBuffer(l, frame_buf);
        speedtestclientFailLine(t, l, "received an invalid speed-test frame");
        bool alive = lineIsAlive(l);
        lineUnlock(l);
        return alive;
    }

    speedtestclientHandleFrame(t, l, &frame);
    lineReuseBuffer(l, frame_buf);
    bool alive = lineIsAlive(l);
    lineUnlock(l);
    return alive;
}

void speedtestclientProcessIncoming(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    speedtestclient_tstate_t *state = tunnelGetState(t);
    speedtestclient_lstate_t *ls = lineGetState(l, t);

    if (state->mode == kSpeedTestClientModeUdp)
    {
        discard speedtestclientProcessFrameBuffer(t, l, buf);
        return;
    }

    bufferstreamPush(&ls->recv_stream, buf);

    while (bufferstreamGetBufLen(&ls->recv_stream) >= kSpeedTestClientFrameHeaderSize)
    {
        uint8_t header[kSpeedTestClientFrameHeaderSize];
        speedtestclient_frame_t frame;
        bufferstreamViewBytesAt(&ls->recv_stream, 0, header, sizeof(header));

        if (! speedtestclientReadHeader(header, sizeof(header), &frame) ||
            ! speedtestclientFramePayloadLengthValid(t, l, &frame))
        {
            speedtestclientFailLine(t, l, "received an invalid stream frame header");
            return;
        }

        const size_t full_len = (size_t) kSpeedTestClientFrameHeaderSize + frame.payload_len;
        if (bufferstreamGetBufLen(&ls->recv_stream) < full_len)
        {
            return;
        }

        sbuf_t *frame_buf = bufferstreamReadExact(&ls->recv_stream, full_len);
        if (! speedtestclientProcessFrameBuffer(t, l, frame_buf))
        {
            return;
        }
    }
}

static void speedtestclientAddStats(speedtestclient_stats_t *dst, const speedtestclient_stats_t *src)
{
    dst->bytes += src->bytes;
    dst->packets += src->packets;
    dst->valid_packets += src->valid_packets;
    dst->lost_packets += src->lost_packets;
    dst->duplicate_packets += src->duplicate_packets;
    dst->out_of_order_packets += src->out_of_order_packets;
    dst->validation_errors += src->validation_errors;
    if (src->jitter_us > dst->jitter_us)
    {
        dst->jitter_us = src->jitter_us;
    }
}

static void speedtestclientLogAggregate(tunnel_t *t, bool success)
{
    speedtestclient_tstate_t *state = tunnelGetState(t);
    char bytes_buf[64];
    char rate_buf[64];
    const double seconds = (double) state->duration_ms / 1000.0;

    if (state->upload)
    {
        speedtestclientFormatBytes(state->aggregate_sender.bytes, bytes_buf, sizeof(bytes_buf));
        speedtestclientFormatBitrate(seconds > 0.0 ? (double) state->aggregate_sender.bytes * 8.0 / seconds : 0.0,
                                     rate_buf, sizeof(rate_buf));
        LOGI("SpeedTestClient: final sender summary %s %s streams=%u failed=%u",
             bytes_buf, rate_buf, (unsigned int) state->connection_count,
             (unsigned int) atomicLoadRelaxed(&state->failed_streams));
    }

    if (state->download)
    {
        speedtestclientFormatBytes(state->aggregate_receiver.bytes, bytes_buf, sizeof(bytes_buf));
        speedtestclientFormatBitrate(seconds > 0.0 ? (double) state->aggregate_receiver.bytes * 8.0 / seconds : 0.0,
                                     rate_buf, sizeof(rate_buf));
        LOGI("SpeedTestClient: final receiver summary %s %s packets=%llu lost=%llu dup=%llu errors=%llu jitter=%.3f ms streams=%u failed=%u",
             bytes_buf, rate_buf, (unsigned long long) state->aggregate_receiver.packets,
             (unsigned long long) state->aggregate_receiver.lost_packets,
             (unsigned long long) state->aggregate_receiver.duplicate_packets,
             (unsigned long long) state->aggregate_receiver.validation_errors,
             state->aggregate_receiver.jitter_us / 1000.0, (unsigned int) state->connection_count,
             (unsigned int) atomicLoadRelaxed(&state->failed_streams));
    }

    if (state->json_summary)
    {
        LOGI("SpeedTestClient: json-summary {\"success\":%s,\"streams\":%u,\"failed\":%u,\"sent_bytes\":%llu,\"received_bytes\":%llu,\"lost_packets\":%llu,\"validation_errors\":%llu}",
             success ? "true" : "false", (unsigned int) state->connection_count,
             (unsigned int) atomicLoadRelaxed(&state->failed_streams),
             (unsigned long long) state->aggregate_sender.bytes,
             (unsigned long long) state->aggregate_receiver.bytes,
             (unsigned long long) state->aggregate_receiver.lost_packets,
             (unsigned long long) state->aggregate_receiver.validation_errors);
    }
}

static void speedtestclientFinishLine(tunnel_t *t, line_t *l, bool success, bool send_upstream_finish)
{
    speedtestclient_tstate_t *state = tunnelGetState(t);
    speedtestclient_lstate_t *ls = lineGetState(l, t);

    if (ls->line_complete)
    {
        return;
    }

    ls->line_complete = true;

    if (! success)
    {
        ls->failed = true;
    }

    speedtestclientLogInterval(t, l, ls, true);

    mutexLock(&state->aggregate_mutex);
    speedtestclientAddStats(&state->aggregate_sender, &ls->sender);
    speedtestclientAddStats(&state->aggregate_receiver, &ls->receiver);
    speedtestclientAddStats(&state->aggregate_remote_sender, &ls->remote_sender);
    speedtestclientAddStats(&state->aggregate_remote_receiver, &ls->remote_receiver);
    mutexUnlock(&state->aggregate_mutex);

    if (! success)
    {
        atomicIncRelaxed(&state->failed_streams);
    }

    const unsigned int completed = atomicIncRelaxed(&state->completed_streams) + 1U;
    const bool all_done = completed == state->connection_count;
    const bool final_success = atomicLoadRelaxed(&state->failed_streams) == 0;

    lineLock(l);
    speedtestclientLinestateDestroy(ls);

    if (send_upstream_finish && lineIsAlive(l))
    {
        tunnelNextUpStreamFinish(t, l);
    }

    if (lineIsAlive(l))
    {
        lineDestroy(l);
    }
    lineUnlock(l);

    if (all_done)
    {
        speedtestclientLogAggregate(t, final_success);
        if (state->terminate_on_complete)
        {
            terminateProgram(final_success ? 0 : 1);
        }
    }
}

void speedtestclientMaybeComplete(tunnel_t *t, line_t *l)
{
    speedtestclient_lstate_t *ls = lineGetState(l, t);

    if (ls->line_complete || ls->failed)
    {
        return;
    }

    if (! ls->sender_finished || ! ls->receiver_finished)
    {
        return;
    }

    if (ls->received_reports < ls->expected_reports)
    {
        return;
    }

    speedtestclientFinishLine(t, l, true, true);
}

void speedtestclientFailLine(tunnel_t *t, line_t *l, const char *reason)
{
    speedtestclient_lstate_t *ls = lineGetState(l, t);

    if (ls->line_complete || ls->failed)
    {
        return;
    }

    LOGE("SpeedTestClient: stream %u failed: %s", (unsigned int) ls->stream_id, reason);
    speedtestclientFinishLine(t, l, false, true);
}

void speedtestclientFinishFromDownstreamFinish(tunnel_t *t, line_t *l, bool success, const char *reason)
{
    speedtestclient_lstate_t *ls = lineGetState(l, t);

    if (ls->line_complete || ls->failed)
    {
        return;
    }

    if (! success)
    {
        LOGE("SpeedTestClient: stream %u failed: %s", (unsigned int) ls->stream_id, reason);
    }

    speedtestclientFinishLine(t, l, success, false);
}

void speedtestclientWatchdogTask(tunnel_t *t, line_t *l)
{
    speedtestclient_lstate_t *ls = lineGetState(l, t);

    if (ls->line_complete || ls->failed)
    {
        return;
    }

    speedtestclientFailLine(t, l, "test timed out before completion");
}
