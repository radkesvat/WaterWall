#include "structure.h"

#include "loggers/network_logger.h"

static void speedtestserverWriteU16(uint8_t *ptr, uint16_t value)
{
    const uint16_t be = lwip_htons(value);
    memoryCopy(ptr, &be, sizeof(be));
}

static void speedtestserverWriteU32(uint8_t *ptr, uint32_t value)
{
    const uint32_t be = lwip_htonl(value);
    memoryCopy(ptr, &be, sizeof(be));
}

static void speedtestserverWriteU64(uint8_t *ptr, uint64_t value)
{
    const uint64_t be = htonll(value);
    memoryCopy(ptr, &be, sizeof(be));
}

static uint16_t speedtestserverReadU16(const uint8_t *ptr)
{
    uint16_t value;
    memoryCopy(&value, ptr, sizeof(value));
    return lwip_ntohs(value);
}

static uint32_t speedtestserverReadU32(const uint8_t *ptr)
{
    uint32_t value;
    memoryCopy(&value, ptr, sizeof(value));
    return lwip_ntohl(value);
}

static uint64_t speedtestserverReadU64(const uint8_t *ptr)
{
    uint64_t value;
    memoryCopy(&value, ptr, sizeof(value));
    return ntohll(value);
}

uint64_t speedtestserverNowMs(void)
{
    return getHRTimeUs() / 1000U;
}

uint64_t speedtestserverNowUs(void)
{
    return getHRTimeUs();
}

uint16_t speedtestserverBaseFlags(const speedtestserver_lstate_t *ls)
{
    uint16_t flags = 0;

    if (ls->upload)
    {
        flags |= kSpeedTestServerFlagUpload;
    }
    if (ls->download)
    {
        flags |= kSpeedTestServerFlagDownload;
    }
    flags |= (ls->mode == kSpeedTestServerModeUdp) ? kSpeedTestServerFlagUdp : kSpeedTestServerFlagTcp;
    if (ls->json_summary)
    {
        flags |= kSpeedTestServerFlagJson;
    }
    return flags;
}

void speedtestserverFormatBytes(uint64_t bytes, char *out, size_t out_len)
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

void speedtestserverFormatBitrate(double bits_per_sec, char *out, size_t out_len)
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

void speedtestserverWriteHeader(uint8_t *ptr, uint8_t type, uint16_t flags, uint32_t stream_id, uint32_t payload_len,
                                uint64_t sequence, uint64_t timestamp_us, uint64_t aux1, uint64_t aux2)
{
    speedtestserverWriteU32(ptr + 0, kSpeedTestServerMagic);
    ptr[4] = kSpeedTestServerProtocolVersion;
    ptr[5] = type;
    speedtestserverWriteU16(ptr + 6, flags);
    speedtestserverWriteU32(ptr + 8, stream_id);
    speedtestserverWriteU32(ptr + 12, payload_len);
    speedtestserverWriteU64(ptr + 16, sequence);
    speedtestserverWriteU64(ptr + 24, timestamp_us);
    speedtestserverWriteU64(ptr + 32, aux1);
    speedtestserverWriteU64(ptr + 40, aux2);
}

bool speedtestserverReadHeader(const uint8_t *ptr, size_t len, speedtestserver_frame_t *frame)
{
    if (len < kSpeedTestServerFrameHeaderSize || speedtestserverReadU32(ptr + 0) != kSpeedTestServerMagic)
    {
        return false;
    }

    frame->version      = ptr[4];
    frame->type         = ptr[5];
    frame->flags        = speedtestserverReadU16(ptr + 6);
    frame->stream_id    = speedtestserverReadU32(ptr + 8);
    frame->payload_len  = speedtestserverReadU32(ptr + 12);
    frame->sequence     = speedtestserverReadU64(ptr + 16);
    frame->timestamp_us = speedtestserverReadU64(ptr + 24);
    frame->aux1         = speedtestserverReadU64(ptr + 32);
    frame->aux2         = speedtestserverReadU64(ptr + 40);
    frame->payload      = ptr + kSpeedTestServerFrameHeaderSize;

    if (frame->version != kSpeedTestServerProtocolVersion)
    {
        return false;
    }

    if (frame->payload_len > UINT32_MAX - kSpeedTestServerFrameHeaderSize)
    {
        return false;
    }

    return true;
}

static bool speedtestserverFramePayloadLengthValid(tunnel_t *t, line_t *l, const speedtestserver_frame_t *frame)
{
    speedtestserver_lstate_t *ls = lineGetState(l, t);

    switch (frame->type)
    {
    case kSpeedTestServerFrameHello:
        return frame->payload_len == kSpeedTestServerHelloSize;
    case kSpeedTestServerFrameData:
        return ls->hello_received && ls->upload && frame->payload_len > 0 &&
               frame->payload_len <= ls->payload_size &&
               (ls->mode != kSpeedTestServerModeUdp || frame->payload_len <= kSpeedTestServerMaxUdpPayloadSize);
    case kSpeedTestServerFrameEnd:
        return ls->hello_received && ls->upload && frame->payload_len == 0;
    default:
        return false;
    }
}

static sbuf_t *speedtestserverAllocBuffer(line_t *l, uint32_t len)
{
    buffer_pool_t *pool = lineGetBufferPool(l);
    sbuf_t *buf;

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

sbuf_t *speedtestserverCreateFrame(tunnel_t *t, line_t *l, uint8_t type, uint16_t flags, uint32_t stream_id,
                                   uint64_t sequence, uint32_t payload_len, uint64_t timestamp_us, uint64_t aux1,
                                   uint64_t aux2)
{
    discard t;
    if (payload_len > UINT32_MAX - kSpeedTestServerFrameHeaderSize)
    {
        LOGE("SpeedTestServer: frame payload is too large");
        return NULL;
    }

    sbuf_t *buf = speedtestserverAllocBuffer(l, kSpeedTestServerFrameHeaderSize + payload_len);
    speedtestserverWriteHeader(sbufGetMutablePtr(buf), type, flags, stream_id, payload_len, sequence, timestamp_us,
                               aux1, aux2);
    return buf;
}

void speedtestserverFillPattern(uint8_t *ptr, uint32_t len, uint32_t stream_id, uint64_t sequence, uint16_t flags)
{
    const uint32_t direction_salt = (flags & kSpeedTestServerFlagDownload) ? 0xA5A55A5AU : 0x5A5AA5A5U;
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

bool speedtestserverVerifyPattern(const uint8_t *ptr, uint32_t len, uint32_t stream_id, uint64_t sequence,
                                  uint16_t flags)
{
    const uint32_t direction_salt = (flags & kSpeedTestServerFlagDownload) ? 0xA5A55A5AU : 0x5A5AA5A5U;
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

static bool speedtestserverSendFrame(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    if (buf == NULL)
    {
        speedtestserverFailLine(t, l, "failed to allocate protocol frame");
        return false;
    }

    return withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, buf);
}

static bool speedtestserverReadHelloPayload(speedtestserver_lstate_t *ls, const speedtestserver_frame_t *frame)
{
    if (frame->payload_len < kSpeedTestServerHelloSize)
    {
        return false;
    }

    ls->duration_ms = speedtestserverReadU32(frame->payload + 0);
    ls->warmup_ms = speedtestserverReadU32(frame->payload + 4);
    ls->report_interval_ms = speedtestserverReadU32(frame->payload + 8);
    ls->payload_size = speedtestserverReadU32(frame->payload + 12);
    ls->target_bandwidth_bps = speedtestserverReadU64(frame->payload + 16);
    ls->total_streams = speedtestserverReadU32(frame->payload + 24);
    ls->stream_id = speedtestserverReadU32(frame->payload + 28);

    return ls->duration_ms > 0 && ls->report_interval_ms > 0 && ls->payload_size > 0 &&
           ls->payload_size <= kSpeedTestServerMaxPayloadSize && ls->total_streams > 0;
}

static void speedtestserverWriteReportPayload(uint8_t *ptr, const speedtestserver_stats_t *stats, uint64_t duration_us)
{
    speedtestserverWriteU64(ptr + 0, stats->bytes);
    speedtestserverWriteU64(ptr + 8, stats->packets);
    speedtestserverWriteU64(ptr + 16, stats->valid_packets);
    speedtestserverWriteU64(ptr + 24, stats->lost_packets);
    speedtestserverWriteU64(ptr + 32, stats->duplicate_packets);
    speedtestserverWriteU64(ptr + 40, stats->out_of_order_packets);
    speedtestserverWriteU64(ptr + 48, stats->validation_errors);
    speedtestserverWriteU64(ptr + 56, duration_us);
    speedtestserverWriteU64(ptr + 64, (uint64_t) stats->jitter_us);
}

static bool speedtestserverSendReport(tunnel_t *t, line_t *l, speedtestserver_lstate_t *ls, bool sender_report)
{
    const speedtestserver_stats_t *stats = sender_report ? &ls->sender : &ls->receiver;
    uint16_t flags = speedtestserverBaseFlags(ls);

    flags |= sender_report ? kSpeedTestServerFlagSender : kSpeedTestServerFlagReceiver;
    flags |= sender_report ? kSpeedTestServerFlagDownload : kSpeedTestServerFlagUpload;
    flags &= sender_report ? (uint16_t) ~kSpeedTestServerFlagUpload : (uint16_t) ~kSpeedTestServerFlagDownload;

    const uint64_t duration_us = ((uint64_t) ls->duration_ms) * 1000ULL;
    const int repeats = (ls->mode == kSpeedTestServerModeUdp) ? kSpeedTestServerUdpFinalRepeats : 1;

    for (int i = 0; i < repeats; ++i)
    {
        sbuf_t *buf = speedtestserverCreateFrame(t, l, kSpeedTestServerFrameReport, flags, ls->stream_id,
                                                 stats->packets, kSpeedTestServerReportSize, speedtestserverNowUs(),
                                                 stats->bytes, stats->lost_packets);
        if (buf == NULL)
        {
            return false;
        }
        speedtestserverWriteReportPayload(sbufGetMutablePtr(buf) + kSpeedTestServerFrameHeaderSize, stats,
                                          duration_us);
        if (! speedtestserverSendFrame(t, l, buf))
        {
            return false;
        }
    }

    if (sender_report)
    {
        ls->download_report_sent = true;
    }
    else
    {
        ls->upload_report_sent = true;
    }

    return true;
}

static bool speedtestserverSendAck(tunnel_t *t, line_t *l, speedtestserver_lstate_t *ls)
{
    sbuf_t *buf = speedtestserverCreateFrame(t, l, kSpeedTestServerFrameAck, speedtestserverBaseFlags(ls),
                                             ls->stream_id, 0, 0, speedtestserverNowUs(), ls->duration_ms,
                                             ls->target_bandwidth_bps);
    return speedtestserverSendFrame(t, l, buf);
}

void speedtestserverScheduleSend(tunnel_t *t, line_t *l, speedtestserver_lstate_t *ls)
{
    discard t;
    if (ls->send_scheduled || ls->sender_finished || ls->send_paused || ! ls->hello_received)
    {
        return;
    }

    ls->send_scheduled = true;
    lineScheduleTask(l, speedtestserverSendTask, ls->tunnel);
}

void speedtestserverScheduleReport(tunnel_t *t, line_t *l, speedtestserver_lstate_t *ls)
{
    if (ls->report_scheduled || ls->closing || ls->report_interval_ms == 0)
    {
        return;
    }

    ls->report_scheduled = true;
    lineScheduleDelayedTask(l, speedtestserverReportTask, ls->report_interval_ms, t);
}

static bool speedtestserverShouldWaitForPace(speedtestserver_lstate_t *ls, uint64_t now_us, uint32_t *delay_ms_out)
{
    if (ls->target_bandwidth_bps == 0)
    {
        return false;
    }

    const uint64_t start_us = ls->start_ms * 1000ULL;
    const uint64_t elapsed_us = (now_us > start_us) ? (now_us - start_us) : 0;
    const uint64_t expected_us = (ls->paced_bytes * 8000000ULL) / ls->target_bandwidth_bps;

    if (expected_us <= elapsed_us)
    {
        return false;
    }

    uint64_t wait_ms = ((expected_us - elapsed_us) + 999ULL) / 1000ULL;
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

static void speedtestserverSendEnd(tunnel_t *t, line_t *l, speedtestserver_lstate_t *ls)
{
    uint16_t flags = (uint16_t) ((speedtestserverBaseFlags(ls) | kSpeedTestServerFlagDownload) &
                                 (uint16_t) ~kSpeedTestServerFlagUpload);
    const int repeats = (ls->mode == kSpeedTestServerModeUdp) ? kSpeedTestServerUdpFinalRepeats : 1;

    if (ls->sender_finished)
    {
        return;
    }
    ls->sender_finished = true;

    for (int i = 0; i < repeats; ++i)
    {
        sbuf_t *buf = speedtestserverCreateFrame(t, l, kSpeedTestServerFrameEnd, flags, ls->stream_id,
                                                 ls->next_send_sequence, 0, speedtestserverNowUs(), ls->sender.bytes,
                                                 ls->sender.packets);
        if (! speedtestserverSendFrame(t, l, buf))
        {
            return;
        }
    }

    if (! speedtestserverSendReport(t, l, ls, true))
    {
        return;
    }
    speedtestserverMaybeComplete(t, l);
}

void speedtestserverSendTask(tunnel_t *t, line_t *l)
{
    speedtestserver_lstate_t *ls = lineGetState(l, t);
    int burst = 0;

    ls->send_scheduled = false;

    if (ls->closing || ls->send_paused || ls->sender_finished || ! ls->hello_received)
    {
        return;
    }

    while (! ls->send_paused && ! ls->sender_finished && burst < kSpeedTestServerMaxBurstFrames)
    {
        const uint64_t now_ms = speedtestserverNowMs();
        const uint64_t now_us = speedtestserverNowUs();
        const bool warmup = now_ms < ls->measure_start_ms;

        if (now_ms >= ls->measure_end_ms)
        {
            speedtestserverSendEnd(t, l, ls);
            return;
        }

        uint32_t delay_ms = 0;
        if (speedtestserverShouldWaitForPace(ls, now_us, &delay_ms))
        {
            ls->send_scheduled = true;
            lineScheduleDelayedTask(l, speedtestserverSendTask, delay_ms, t);
            return;
        }

        uint16_t flags = (uint16_t) ((speedtestserverBaseFlags(ls) | kSpeedTestServerFlagDownload) &
                                     (uint16_t) ~kSpeedTestServerFlagUpload);
        uint64_t sequence;

        if (warmup)
        {
            flags |= kSpeedTestServerFlagWarmup;
            sequence = ls->next_warmup_sequence++;
        }
        else
        {
            sequence = ls->next_send_sequence++;
        }

        sbuf_t *buf = speedtestserverCreateFrame(t, l, kSpeedTestServerFrameData, flags, ls->stream_id, sequence,
                                                 ls->payload_size, now_us, 0, 0);
        if (buf == NULL)
        {
            speedtestserverFailLine(t, l, "failed to allocate data frame");
            return;
        }
        speedtestserverFillPattern(sbufGetMutablePtr(buf) + kSpeedTestServerFrameHeaderSize, ls->payload_size,
                                   ls->stream_id, sequence, flags);

        if (! warmup)
        {
            ls->sender.bytes += ls->payload_size;
            ls->sender.packets += 1U;
            ls->sender.valid_packets += 1U;
        }
        ls->paced_bytes += ls->payload_size;
        burst += 1;

        if (! speedtestserverSendFrame(t, l, buf))
        {
            return;
        }
    }

    if (! ls->send_paused && ! ls->sender_finished)
    {
        speedtestserverScheduleSend(t, l, ls);
    }
}

static void speedtestserverLogInterval(tunnel_t *t, line_t *l, speedtestserver_lstate_t *ls, bool final)
{
    discard t;
    discard l;
    const uint64_t now_ms = speedtestserverNowMs();
    uint64_t from_ms = ls->last_report_ms;
    uint64_t to_ms = now_ms;

    if (! ls->hello_received)
    {
        return;
    }

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

    if (ls->upload)
    {
        uint64_t delta = ls->receiver.bytes - ls->receiver_last_report_bytes;
        speedtestserverFormatBytes(delta, bytes_buf, sizeof(bytes_buf));
        speedtestserverFormatBitrate(interval_sec > 0.0 ? (double) delta * 8.0 / interval_sec : 0.0,
                                     rate_buf, sizeof(rate_buf));
        LOGI("SpeedTestServer: stream %u receiver %.2f-%.2f sec %s %s lost=%llu dup=%llu errors=%llu jitter=%.3f ms%s",
             (unsigned int) ls->stream_id, (double) (from_ms - ls->measure_start_ms) / 1000.0,
             (double) (to_ms - ls->measure_start_ms) / 1000.0, bytes_buf, rate_buf,
             (unsigned long long) ls->receiver.lost_packets,
             (unsigned long long) ls->receiver.duplicate_packets,
             (unsigned long long) ls->receiver.validation_errors, ls->receiver.jitter_us / 1000.0,
             final ? " final" : "");
        ls->receiver_last_report_bytes = ls->receiver.bytes;
    }

    if (ls->download)
    {
        uint64_t delta = ls->sender.bytes - ls->sender_last_report_bytes;
        speedtestserverFormatBytes(delta, bytes_buf, sizeof(bytes_buf));
        speedtestserverFormatBitrate(interval_sec > 0.0 ? (double) delta * 8.0 / interval_sec : 0.0,
                                     rate_buf, sizeof(rate_buf));
        LOGI("SpeedTestServer: stream %u sender %.2f-%.2f sec %s %s%s",
             (unsigned int) ls->stream_id, (double) (from_ms - ls->measure_start_ms) / 1000.0,
             (double) (to_ms - ls->measure_start_ms) / 1000.0, bytes_buf, rate_buf, final ? " final" : "");
        ls->sender_last_report_bytes = ls->sender.bytes;
    }

    ls->last_report_ms = to_ms;
}

void speedtestserverReportTask(tunnel_t *t, line_t *l)
{
    speedtestserver_lstate_t *ls = lineGetState(l, t);

    ls->report_scheduled = false;
    if (ls->closing)
    {
        return;
    }

    speedtestserverLogInterval(t, l, ls, false);
    speedtestserverScheduleReport(t, l, ls);
}

static void speedtestserverUpdateJitter(speedtestserver_stats_t *stats, speedtestserver_lstate_t *ls,
                                        const speedtestserver_frame_t *frame)
{
    if (frame->timestamp_us == 0)
    {
        return;
    }

    const uint64_t now_us = speedtestserverNowUs();
    const uint64_t transit = (now_us > frame->timestamp_us) ? (now_us - frame->timestamp_us) : 0;
    if (ls->last_transit_us != 0)
    {
        const uint64_t diff = (transit > ls->last_transit_us) ? (transit - ls->last_transit_us)
                                                              : (ls->last_transit_us - transit);
        stats->jitter_us += ((double) diff - stats->jitter_us) / 16.0;
    }
    ls->last_transit_us = transit;
}

static void speedtestserverHandleData(tunnel_t *t, line_t *l, const speedtestserver_frame_t *frame)
{
    speedtestserver_lstate_t *ls = lineGetState(l, t);

    if (! ls->hello_received)
    {
        speedtestserverFailLine(t, l, "received data before hello");
        return;
    }

    if (frame->flags & kSpeedTestServerFlagWarmup)
    {
        discard speedtestserverVerifyPattern(frame->payload, frame->payload_len, frame->stream_id, frame->sequence,
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
    if (speedtestserverVerifyPattern(frame->payload, frame->payload_len, frame->stream_id, frame->sequence,
                                     frame->flags))
    {
        ls->receiver.valid_packets += 1U;
    }
    else
    {
        ls->receiver.validation_errors += 1U;
    }
    speedtestserverUpdateJitter(&ls->receiver, ls, frame);
}

static void speedtestserverHandleEnd(tunnel_t *t, line_t *l, const speedtestserver_frame_t *frame)
{
    speedtestserver_lstate_t *ls = lineGetState(l, t);

    if (frame->sequence > ls->expected_recv_sequence)
    {
        ls->receiver.lost_packets += frame->sequence - ls->expected_recv_sequence;
        ls->expected_recv_sequence = frame->sequence;
    }

    ls->receiver_finished = true;
    speedtestserverLogInterval(t, l, ls, true);
    if (! speedtestserverSendReport(t, l, ls, false))
    {
        return;
    }
    speedtestserverMaybeComplete(t, l);
}

static void speedtestserverHandleHello(tunnel_t *t, line_t *l, const speedtestserver_frame_t *frame)
{
    speedtestserver_lstate_t *ls = lineGetState(l, t);

    if (ls->hello_received)
    {
        discard speedtestserverSendAck(t, l, ls);
        return;
    }

    if (! speedtestserverReadHelloPayload(ls, frame))
    {
        speedtestserverFailLine(t, l, "received invalid hello payload");
        return;
    }

    ls->mode = (frame->flags & kSpeedTestServerFlagUdp) ? kSpeedTestServerModeUdp : kSpeedTestServerModeTcp;
    ls->upload = (frame->flags & kSpeedTestServerFlagUpload) != 0;
    ls->download = (frame->flags & kSpeedTestServerFlagDownload) != 0;
    ls->json_summary = (frame->flags & kSpeedTestServerFlagJson) != 0;

    if (! ls->upload && ! ls->download)
    {
        speedtestserverFailLine(t, l, "hello requested neither upload nor download");
        return;
    }

    if (ls->mode == kSpeedTestServerModeUdp && ls->payload_size > kSpeedTestServerMaxUdpPayloadSize)
    {
        speedtestserverFailLine(t, l, "UDP payload size is too large");
        return;
    }

    const uint64_t now_ms = speedtestserverNowMs();
    ls->start_ms = now_ms;
    ls->measure_start_ms = now_ms + ls->warmup_ms;
    ls->measure_end_ms = now_ms + ls->warmup_ms + ls->duration_ms;
    ls->last_report_ms = ls->measure_start_ms;
    ls->sender_finished = ! ls->download;
    ls->receiver_finished = ! ls->upload;
    ls->hello_received = true;

    LOGI("SpeedTestServer: stream %u accepted (%s, %s%s%s, duration=%u ms, warmup=%u ms, payload=%u bytes)",
         (unsigned int) ls->stream_id, ls->mode == kSpeedTestServerModeUdp ? "udp" : "tcp",
         ls->upload ? "upload" : "", (ls->upload && ls->download) ? "+" : "", ls->download ? "download" : "",
         (unsigned int) ls->duration_ms, (unsigned int) ls->warmup_ms, (unsigned int) ls->payload_size);

    if (! speedtestserverSendAck(t, l, ls))
    {
        return;
    }

    if (ls->download)
    {
        speedtestserverScheduleSend(t, l, ls);
    }
    speedtestserverScheduleReport(t, l, ls);
}

static void speedtestserverHandleFrame(tunnel_t *t, line_t *l, const speedtestserver_frame_t *frame)
{
    speedtestserver_lstate_t *ls = lineGetState(l, t);

    if (ls->hello_received && frame->stream_id != ls->stream_id)
    {
        speedtestserverFailLine(t, l, "received a frame for a different stream id");
        return;
    }

    switch (frame->type)
    {
    case kSpeedTestServerFrameHello:
        speedtestserverHandleHello(t, l, frame);
        return;
    case kSpeedTestServerFrameData:
        speedtestserverHandleData(t, l, frame);
        return;
    case kSpeedTestServerFrameEnd:
        speedtestserverHandleEnd(t, l, frame);
        return;
    default:
        speedtestserverFailLine(t, l, "received an unexpected client frame");
        return;
    }
}

static bool speedtestserverProcessFrameBuffer(tunnel_t *t, line_t *l, sbuf_t *frame_buf)
{
    speedtestserver_frame_t frame;

    lineLock(l);

    if (! speedtestserverReadHeader(sbufGetRawPtr(frame_buf), sbufGetLength(frame_buf), &frame) ||
        ! speedtestserverFramePayloadLengthValid(t, l, &frame) ||
        sbufGetLength(frame_buf) < (size_t) kSpeedTestServerFrameHeaderSize + frame.payload_len)
    {
        lineReuseBuffer(l, frame_buf);
        speedtestserverFailLine(t, l, "received an invalid speed-test frame");
        bool alive = lineIsAlive(l);
        lineUnlock(l);
        return alive;
    }

    speedtestserverHandleFrame(t, l, &frame);
    lineReuseBuffer(l, frame_buf);
    bool alive = lineIsAlive(l);
    lineUnlock(l);
    return alive;
}

void speedtestserverProcessIncoming(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    speedtestserver_lstate_t *ls = lineGetState(l, t);

    if (ls->mode == kSpeedTestServerModeUdp)
    {
        discard speedtestserverProcessFrameBuffer(t, l, buf);
        return;
    }

    if (! ls->hello_received && sbufGetLength(buf) >= kSpeedTestServerFrameHeaderSize)
    {
        speedtestserver_frame_t probe;
        if (speedtestserverReadHeader(sbufGetRawPtr(buf), sbufGetLength(buf), &probe) &&
            ((probe.flags & kSpeedTestServerFlagUdp) != 0))
        {
            discard speedtestserverProcessFrameBuffer(t, l, buf);
            return;
        }
    }

    bufferstreamPush(&ls->recv_stream, buf);

    while (bufferstreamGetBufLen(&ls->recv_stream) >= kSpeedTestServerFrameHeaderSize)
    {
        uint8_t header[kSpeedTestServerFrameHeaderSize];
        speedtestserver_frame_t frame;

        bufferstreamViewBytesAt(&ls->recv_stream, 0, header, sizeof(header));
        if (! speedtestserverReadHeader(header, sizeof(header), &frame) ||
            ! speedtestserverFramePayloadLengthValid(t, l, &frame))
        {
            speedtestserverFailLine(t, l, "received an invalid stream frame header");
            return;
        }

        const size_t full_len = (size_t) kSpeedTestServerFrameHeaderSize + frame.payload_len;
        if (bufferstreamGetBufLen(&ls->recv_stream) < full_len)
        {
            return;
        }

        sbuf_t *frame_buf = bufferstreamReadExact(&ls->recv_stream, full_len);
        if (! speedtestserverProcessFrameBuffer(t, l, frame_buf))
        {
            return;
        }
    }
}

static void speedtestserverAddStats(speedtestserver_stats_t *dst, const speedtestserver_stats_t *src)
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

static void speedtestserverCloseLineInternal(tunnel_t *t, line_t *l, bool count_complete, bool already_closing)
{
    speedtestserver_tstate_t *state = tunnelGetState(t);
    speedtestserver_lstate_t *ls = lineGetState(l, t);

    if (! already_closing && ls->closing)
    {
        return;
    }
    ls->closing = true;

    mutexLock(&state->aggregate_mutex);
    speedtestserverAddStats(&state->aggregate_sender, &ls->sender);
    speedtestserverAddStats(&state->aggregate_receiver, &ls->receiver);
    mutexUnlock(&state->aggregate_mutex);

    if (count_complete)
    {
        atomicIncRelaxed(&state->completed_streams);
    }

    if (ls->json_summary)
    {
        LOGI("SpeedTestServer: json-summary {\"stream\":%u,\"sent_bytes\":%llu,\"received_bytes\":%llu,\"lost_packets\":%llu,\"validation_errors\":%llu}",
             (unsigned int) ls->stream_id, (unsigned long long) ls->sender.bytes,
             (unsigned long long) ls->receiver.bytes, (unsigned long long) ls->receiver.lost_packets,
             (unsigned long long) ls->receiver.validation_errors);
    }

    lineLock(l);
    speedtestserverLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
    lineUnlock(l);
}

static void speedtestserverCloseLine(tunnel_t *t, line_t *l, bool count_complete)
{
    speedtestserverCloseLineInternal(t, l, count_complete, false);
}

void speedtestserverMaybeComplete(tunnel_t *t, line_t *l)
{
    speedtestserver_lstate_t *ls = lineGetState(l, t);

    if (ls->closing || ! ls->hello_received || ! ls->sender_finished || ! ls->receiver_finished)
    {
        return;
    }

    if (ls->upload && ! ls->upload_report_sent)
    {
        return;
    }
    if (ls->download && ! ls->download_report_sent)
    {
        return;
    }

    speedtestserverCloseLine(t, l, true);
}

void speedtestserverFailLine(tunnel_t *t, line_t *l, const char *reason)
{
    speedtestserver_lstate_t *ls = lineGetState(l, t);

    if (ls->closing)
    {
        return;
    }

    LOGE("SpeedTestServer: stream %u failed: %s", (unsigned int) ls->stream_id, reason);
    ls->closing = true;

    sbuf_t *buf = speedtestserverCreateFrame(t, l, kSpeedTestServerFrameError, speedtestserverBaseFlags(ls),
                                             ls->stream_id, 0, 0, speedtestserverNowUs(), 0, 0);
    if (buf != NULL)
    {
        if (! speedtestserverSendFrame(t, l, buf))
        {
            return;
        }
    }

    speedtestserverCloseLineInternal(t, l, false, true);
}
