#include "TcpOverUdpCommon/session.h"
#include "buffer_budget.h"
#include "loggers/network_logger.h"

/* Library callbacks only stage output. User callbacks run with an engine reference
 * and a serialized driver; nested inputs become ordered, bounded work. */
typedef struct tou_work_s
{
    sbuf_t                     *buffer;
    bool                        wire;
    buffer_budget_reservation_t reservation;
} tou_work_t;
#define i_type tou_work_queue_t
#define i_key  tou_work_t
#include "stc/deque.h"

typedef struct tou_packet_s
{
    uint8_t *bytes;
    size_t   size;
} tou_packet_t;
#define i_type tou_packet_queue_t
#define i_key  tou_packet_t
#include "stc/deque.h"

struct tou_session_s
{
    tou_config_t              config;
    tou_callbacks_t           callbacks;
    void                     *user;
    size_t                    references;
    ikcpcb                   *kcp;
    tcpoverudp_fec_encoder_t *encoder;
    tcpoverudp_fec_decoder_t *decoder;
    wtimer_t                 *timer;
    tou_work_queue_t          work;
    tou_packet_queue_t        output;
    size_t                    output_bytes;
    size_t                    output_byte_limit;
    size_t                    output_packet_limit;
    buffer_budget_t           budget;
    tou_settings_t            settings;
    uint8_t                   client_nonce[kTouNonceSize];
    uint8_t                   server_nonce[kTouNonceSize];
    uint64_t                  last_recv;
    uint64_t                  handshake_deadline;
    uint64_t                  retry_at;
    uint64_t                  close_started;
    uint64_t                  send_deadline;
    uint64_t                  retention_deadline;
    uint64_t                  current_now;
    bool                      client : 1;
    bool                      started : 1;
    bool                      ready : 1;
    bool                      challenge_received : 1;
    bool                      driving : 1;
    bool                      dirty : 1;
    bool                      flush : 1;
    bool                      dead : 1;
    bool                      quiesced : 1;
    bool                      closing : 1;
    bool                      local_finish : 1;
    bool                      peer_closed : 1;
    bool                      close_enqueued : 1;
    bool                      send_settled : 1;
    bool                      confirmed : 1;
    bool                      send_completed : 1;
    bool                      pressure : 1;
    bool                      ping_sent : 1;
    bool                      output_failed : 1;
};

static uint64_t sessionNow(tou_session_t *s)
{
    return s->config.now != NULL    ? s->config.now(s->config.clock_user)
           : s->config.loop != NULL ? wloopNowMonotonicMS(s->config.loop)
                                    : s->current_now;
}

int touKcpMtu(const tou_config_t *c)
{
    return min((int) c->send_mtu - 20 - 8 - kTouEnvelopeSize - (c->fec_enabled ? kTcpOverUdpFecOuterHeaderSize : 0),
               kTouMaximumKcpPacketSize);
}

void touSessionRetain(tou_session_t *s)
{
    assert(s != NULL && s->references > 0);
    ++s->references;
}

void touSessionRelease(tou_session_t *s)
{
    assert(s != NULL && s->references > 0);
    if (--s->references != 0)
    {
        return;
    }
    assert(s->dead);
    if (s->timer != NULL)
    {
        weventSetUserData(s->timer, NULL);
        wtimerDelete(s->timer);
    }
    while (! tou_work_queue_t_is_empty(&s->work))
    {
        tou_work_t event = tou_work_queue_t_pull_front(&s->work);
        bufferbudgetReservationRelease(&event.reservation);
        bufferpoolReuseBuffer(s->config.pool, event.buffer);
    }
    tou_work_queue_t_drop(&s->work);
    while (! tou_packet_queue_t_is_empty(&s->output))
    {
        tou_packet_t packet = tou_packet_queue_t_pull_front(&s->output);
        memoryFree(packet.bytes);
    }
    tou_packet_queue_t_drop(&s->output);
    bufferbudgetAssertEmpty(&s->budget);
    tcpoverudpFecEncoderDestroy(&s->encoder);
    tcpoverudpFecDecoderDestroy(&s->decoder);
    ikcp_release(s->kcp);
    if (s->callbacks.destroy_user != NULL)
    {
        s->callbacks.destroy_user(s->user);
    }
    memoryFree(s);
}

void touSessionAbort(tou_session_t *s, tou_result_t result)
{
    touSessionRetain(s);
    if (! s->dead)
    {
        s->dead = true;
        if (s->timer != NULL)
        {
            weventSetUserData(s->timer, NULL);
            wtimerDelete(s->timer);
            s->timer = NULL;
        }
        if (s->callbacks.terminal != NULL)
        {
            s->callbacks.terminal(s->user, result);
        }
    }
    touSessionRelease(s);
}

static bool stagePacket(tou_session_t *s, uint8_t kind, const uint8_t *body, size_t length)
{
    if (length > UINT16_MAX)
    {
        s->output_failed = true;
        return false;
    }
    const size_t size = kTouEnvelopeSize + length;
    if (s->output_bytes > s->output_byte_limit || size > s->output_byte_limit - s->output_bytes ||
        (size_t) tou_packet_queue_t_size(&s->output) >= s->output_packet_limit)
    {
        s->output_failed = true;
        return false;
    }
    uint8_t   *bytes   = memoryAllocate(size);
    const bool encoded = touWireEncode(bytes, size, kind, s->client_nonce, s->server_nonce, body, length);
    assert(encoded);
    discard encoded;
    tou_packet_queue_t_push_back(&s->output, (tou_packet_t) {.bytes = bytes, .size = size});
    s->output_bytes += size;
    return true;
}

static bool stageOuter(void *user, const uint8_t *packet, size_t length)
{
    tou_session_t *s = user;
    return stagePacket(s, s->config.fec_enabled ? kTouFec : kTouKcp, packet, length);
}

static bool beginOutputBatch(tou_session_t *s)
{
    assert(tou_packet_queue_t_is_empty(&s->output) && s->output_bytes == 0);
    /* One driver batch performs update plus an optional explicit ACK flush.
     * Each call can emit at most the existing flight plus one send-window of
     * queued PUSHes, ackcount ACKs and two probes. Every datagram contains at
     * least one such segment. FEC completes at most ceil(packet_count/data)
     * parity blocks, including a previously partial block. This bounds exact
     * owned wire copies without capping KCP's configured window or queued data. */
    const uint64_t window    = min(s->kcp->snd_wnd, s->kcp->rmt_wnd);
    const uint64_t pushes    = (uint64_t) s->kcp->nsnd_buf + min((uint64_t) s->kcp->nsnd_que, window);
    const uint64_t records   = 2U * (pushes + s->kcp->ackcount + 2U);
    const uint64_t mtu       = (uint64_t) touKcpMtu(&s->config);
    const uint64_t raw_bytes = 2U * (pushes * mtu + (uint64_t) s->kcp->ackcount * 24U + 48U);
    const uint64_t parity =
        s->config.fec_enabled
            ? ((records + s->config.fec_data_shards - 1U) / s->config.fec_data_shards) * s->config.fec_parity_shards
            : 0;
    const uint64_t packets = records + parity;
    const uint64_t bytes   = raw_bytes +
                           records * (kTouEnvelopeSize + (s->config.fec_enabled ? kTcpOverUdpFecOuterHeaderSize : 0)) +
                           parity * (mtu + kTouEnvelopeSize + kTcpOverUdpFecOuterHeaderSize);
    if (packets > SIZE_MAX || bytes > SIZE_MAX)
    {
        return false;
    }
    s->output_packet_limit = (size_t) packets;
    s->output_byte_limit   = (size_t) bytes;
    return true;
}

static uint32_t readLE32(const uint8_t *p)
{
    return p[0] | ((uint32_t) p[1] << 8U) | ((uint32_t) p[2] << 16U) | ((uint32_t) p[3] << 24U);
}

static bool validKcp(const uint8_t *packet, size_t size)
{
    if (size < 24)
    {
        return false;
    }
    while (size != 0)
    {
        if (size < 24 || readLE32(packet) != 0 || packet[4] < 81 || packet[4] > 84)
        {
            return false;
        }
        const uint32_t length = readLE32(packet + 20);
        if (length > size - 24 || (packet[4] != 81 && length != 0))
        {
            return false;
        }
        packet += 24 + length;
        size -= 24 + length;
    }
    return true;
}

static bool inputKcp(void *user, const uint8_t *packet, size_t size)
{
    tou_session_t *s = user;
    return validKcp(packet, size) && ikcp_input(s->kcp, (const char *) packet, (long) size) >= 0;
}

static int outputKcp(const char *data, int length, ikcpcb *kcp, void *user)
{
    discard        kcp;
    tou_session_t *s      = user;
    const uint8_t *packet = (const uint8_t *) data;
    uint8_t        filtered[kTouMaximumKcpPacketSize];
    size_t         output_size = 0;
    if (s->send_settled)
    {
        /* A duplicate CLOSE can make flush combine ACK and expired PUSH. Preserve
         * KCP's ACK/probe segments, removing each PUSH before FEC sees the packet. */
        size_t remaining = (size_t) length;
        while (remaining >= 24)
        {
            const size_t segment = 24U + readLE32(packet + 20);
            assert(segment <= remaining);
            if (packet[4] != 81)
            {
                memoryCopyLarge(filtered + output_size, packet, segment);
                output_size += segment;
            }
            packet += segment;
            remaining -= segment;
        }
        assert(remaining == 0);
        if (output_size == 0)
        {
            return 0;
        }
        packet = filtered;
    }
    else
    {
        output_size = (size_t) length;
    }
    bool ok = s->encoder != NULL ? tcpoverudpFecEncodePacket(s->encoder, packet, output_size, stageOuter, s)
                                 : stageOuter(s, packet, output_size);
    return ok ? 0 : -1;
}

static void beginClose(tou_session_t *s, uint64_t now)
{
    if (! s->closing)
    {
        s->closing       = true;
        s->close_started = now;
        s->send_deadline = touDeadline(now, s->settings.close_ms);
    }
    s->dirty = true;
}

static void discardOutput(tou_session_t *s)
{
    while (! tou_packet_queue_t_is_empty(&s->output))
    {
        tou_packet_t packet = tou_packet_queue_t_pull_front(&s->output);
        memoryFree(packet.bytes);
    }
    s->output_bytes = 0;
}

static bool expire(tou_session_t *s, uint64_t now);

static void emitOutput(tou_session_t *s)
{
    if (s->dead || s->quiesced || tou_packet_queue_t_is_empty(&s->output) || expire(s, sessionNow(s)) ||
        tou_packet_queue_t_is_empty(&s->output))
    {
        return;
    }
    tou_packet_t packet = tou_packet_queue_t_pull_front(&s->output);
    s->output_bytes -= packet.size;
    sbuf_t *buffer = bufferpoolTryGetBestFit(s->config.pool, packet.size, 0);
    if (buffer == NULL)
    {
        memoryFree(packet.bytes);
        touSessionAbort(s, kTouCapacityFailure);
        return;
    }
    sbufSetLength(buffer, (uint32_t) packet.size);
    memoryCopyLarge(sbufGetMutablePtr(buffer), packet.bytes, packet.size);
    memoryFree(packet.bytes);
    s->callbacks.emit(s->user, buffer);
}

static bool expire(tou_session_t *s, uint64_t now)
{
    if (s->client && ! s->ready && now >= s->handshake_deadline)
    {
        touSessionAbort(s, kTouHandshakeTimeout);
        return true;
    }
    if (s->closing)
    {
        if (! s->send_settled && now >= s->send_deadline)
        {
            s->send_settled = true;
            tcpoverudpFecEncoderDiscardPending(s->encoder);
            discardOutput(s);
        }
        if (s->send_settled && (s->retention_deadline == 0 || now >= s->retention_deadline))
        {
            touSessionAbort(s, s->confirmed ? kTouConfirmed : s->send_completed ? kTouPeerDrained : kTouUnconfirmed);
            return true;
        }
    }
    else if (s->ready && now >= touDeadline(s->last_recv, s->config.no_recv_timeout_ms))
    {
        touSessionAbort(s, kTouIdleTimeout);
        return true;
    }
    return s->dead;
}

static void stageHandshake(tou_session_t *s)
{
    assert(tou_packet_queue_t_is_empty(&s->output));
    s->output_byte_limit   = kTouEnvelopeSize + kTouSettingsSize;
    s->output_packet_limit = 1;
    uint8_t body[kTouSettingsSize];
    touSettingsEncode(body, &s->settings);
    /* HELLO's server nonce is initially zero; once challenged this becomes CONFIRM. */
    stagePacket(s, s->challenge_received ? kTouConfirm : kTouHello, body, sizeof(body));
}

static bool matchingNonces(const tou_session_t *s, const tou_wire_t *wire)
{
    return memoryCompare(s->client_nonce, wire->client_nonce, kTouNonceSize) == 0 &&
           memoryCompare(s->server_nonce, wire->server_nonce, kTouNonceSize) == 0;
}

static void processWire(tou_session_t *s, sbuf_t *buffer, uint64_t now)
{
    tou_wire_t wire;
    if (! touWireDecode(sbufGetRawPtr(buffer), sbufGetLength(buffer), &wire))
    {
        return;
    }
    if (s->client && ! s->ready && wire.kind == kTouChallenge &&
        memoryCompare(s->client_nonce, wire.client_nonce, kTouNonceSize) == 0)
    {
        tou_settings_t accepted;
        if (! touSettingsDecode(wire.body, wire.body_len, &accepted) || accepted.close_ms > s->settings.close_ms ||
            accepted.data_shards != s->settings.data_shards || accepted.parity_shards != s->settings.parity_shards ||
            (s->challenge_received && ! matchingNonces(s, &wire)))
        {
            return;
        }
        memoryCopy(s->server_nonce, wire.server_nonce, kTouNonceSize);
        s->settings           = accepted;
        s->challenge_received = true;
        if (s->closing)
        {
            s->send_deadline = touDeadline(s->close_started, accepted.close_ms);
            if (now >= s->send_deadline)
            {
                return;
            }
        }
        stageHandshake(s);
        s->retry_at = touDeadline(now, kTouHandshakeRetryMs);
        return;
    }
    if (! matchingNonces(s, &wire))
    {
        return;
    }
    if (s->client && ! s->ready && s->challenge_received && wire.kind == kTouReady)
    {
        tou_settings_t accepted;
        if (touSettingsDecode(wire.body, wire.body_len, &accepted) && touSettingsEqual(&accepted, &s->settings))
        {
            s->ready     = true;
            s->last_recv = now;
            s->dirty     = true;
        }
        return;
    }
    if (! s->ready || wire.kind != (s->config.fec_enabled ? kTouFec : kTouKcp))
    {
        return;
    }
    /* Each peer chooses its own sending budget. Receive against the protocol
     * maximum, not this endpoint's potentially smaller outgoing packet size. */
    if (wire.body_len > (size_t) kTouMaximumKcpPacketSize + (s->config.fec_enabled ? kTcpOverUdpFecOuterHeaderSize : 0))
    {
        return;
    }
    if (s->config.fec_enabled)
    {
        if (wire.body_len < 24U + kTcpOverUdpFecOuterHeaderSize)
        {
            return;
        }
        const unsigned index = readLE32(wire.body) % ((unsigned) s->settings.data_shards + s->settings.parity_shards);
        const unsigned flag  = wire.body[4] | ((unsigned) wire.body[5] << 8U);
        if ((flag == 0xf1U && index >= s->settings.data_shards) || (flag == 0xf2U && index < s->settings.data_shards) ||
            (flag != 0xf1U && flag != 0xf2U))
        {
            return;
        }
        if (flag == 0xf1U && (size_t) (wire.body[6] | ((unsigned) wire.body[7] << 8U)) != wire.body_len - 6U)
        {
            return;
        }
    }
    const bool valid = s->decoder != NULL ? tcpoverudpFecDecodePacket(s->decoder, wire.body, wire.body_len, inputKcp, s)
                                          : inputKcp(s, wire.body, wire.body_len);
    if (valid)
    {
        s->last_recv = now;
        s->ping_sent = false;
        s->dirty     = true;
        s->flush     = true;
    }
}

static void sendRecord(tou_session_t *s, const char *record, int length)
{
    const int result = ikcp_send(s->kcp, record, length);
    if (result != length)
    {
        LOGF("TcpOverUdp: KCP refused a validated record (length %d, result %d)", length, result);
        abortProgramNow(1);
    }
}

static void processApplication(tou_session_t *s, sbuf_t *buffer)
{
    if (s->send_settled)
    {
        return;
    }
    const size_t   chunk_size = (size_t) touKcpMtu(&s->config) - 24U - 1U;
    const uint8_t *data       = sbufGetRawPtr(buffer);
    size_t         remaining  = sbufGetLength(buffer);
    uint8_t        frame[kTouMaximumKcpPacketSize];
    frame[0] = kTouFrameData;
    while (remaining > 0)
    {
        size_t chunk = min(remaining, chunk_size);
        memoryCopyLarge(frame + 1, data, chunk);
        sendRecord(s, (const char *) frame, (int) chunk + 1);
        remaining -= chunk;
        data += chunk;
    }
    s->dirty = true;
}

static void receiveRecords(tou_session_t *s, uint64_t now)
{
    while (! s->dead && ! s->quiesced)
    {
        now = sessionNow(s);
        if (expire(s, now))
        {
            return;
        }
        const int peek = ikcp_peeksize(s->kcp);
        if (peek < 0)
        {
            return;
        }
        if (peek == 0 || (size_t) peek > bufferpoolGetLargeBufferSize(s->config.pool))
        {
            touSessionAbort(s, kTouProtocolFailure);
            return;
        }
        /* Small records must not pin a large allocation in the next node's queue.
         * Preserve the former receive buffer's onward prepend headroom. */
        sbuf_t *buffer =
            bufferpoolGetBestFit(s->config.pool, (uint32_t) peek, bufferpoolGetLargeBufferPadding(s->config.pool));
        const int count =
            ikcp_recv(s->kcp, (char *) sbufGetMutablePtr(buffer), (int) sbufGetMaximumWriteableSize(buffer));
        if (count <= 0)
        {
            bufferpoolReuseBuffer(s->config.pool, buffer);
            touSessionAbort(s, kTouProtocolFailure);
            return;
        }
        sbufSetLength(buffer, (uint32_t) count);
        const uint8_t flag = ((const uint8_t *) sbufGetRawPtr(buffer))[0];
        sbufShiftRight(buffer, 1);
        if (flag == kTouFrameData)
        {
            if (! s->closing && sbufGetLength(buffer) != 0 && s->callbacks.payload != NULL)
            {
                s->callbacks.payload(s->user, buffer);
                continue;
            }
        }
        else if (flag == kTouFrameClose && count == 1)
        {
            if (! s->peer_closed)
            {
                /* Fix the peer's sending budget before publishing any ACK that
                 * acknowledges this CLOSE, including on direct-pair reentry. */
                beginClose(s, now);
                s->peer_closed = true;
                if (! s->confirmed)
                {
                    s->retention_deadline = touDeadline(now, s->settings.close_ms);
                }
                bufferpoolReuseBuffer(s->config.pool, buffer);
                if (s->callbacks.peer_close != NULL)
                {
                    s->callbacks.peer_close(s->user);
                }
                continue;
            }
        }
        else if (flag != kTouFramePing || count != 1)
        {
            bufferpoolReuseBuffer(s->config.pool, buffer);
            touSessionAbort(s, kTouProtocolFailure);
            return;
        }
        bufferpoolReuseBuffer(s->config.pool, buffer);
    }
}

static void closeProgress(tou_session_t *s, uint64_t now)
{
    if (! s->closing || s->send_settled || ! s->ready || ! tou_work_queue_t_is_empty(&s->work))
    {
        return;
    }
    if (ikcp_waitsnd(s->kcp) != 0)
    {
        return;
    }
    if (s->local_finish && ! s->close_enqueued)
    {
        const uint8_t close = kTouFrameClose;
        s->close_enqueued   = true;
        sendRecord(s, (const char *) &close, 1);
        s->dirty = true;
        s->flush = true;
    }
    else
    {
        s->send_settled   = true;
        s->send_completed = true;
        tcpoverudpFecEncoderDiscardPending(s->encoder);
        if (s->close_enqueued)
        {
            s->confirmed          = true;
            s->retention_deadline = touDeadline(now, s->settings.close_ms);
        }
    }
}

static void reconcilePressure(tou_session_t *s)
{
    if (s->closing || s->callbacks.pressure == NULL)
    {
        return;
    }
    const uint64_t inferred = (uint64_t) s->kcp->snd_wnd + s->kcp->rmt_wnd + 10U;
    const int      limit    = s->config.kcp_send_buffer_limit > 0 ? s->config.kcp_send_buffer_limit
                              : inferred > INT_MAX                ? INT_MAX
                                                                  : (int) inferred;
    const int      queued   = ikcp_waitsnd(s->kcp);
    if ((! s->pressure && queued > limit) || (s->pressure && queued < limit))
    {
        s->pressure = ! s->pressure;
        s->callbacks.pressure(s->user, s->pressure);
    }
}

static void armTimer(tou_session_t *s, uint64_t now)
{
    if (s->timer == NULL || s->dead || s->quiesced || ! s->started)
    {
        return;
    }
    uint64_t next;
    if (s->closing && s->send_settled)
    {
        next = s->retention_deadline;
    }
    else if (! s->ready)
    {
        next = min(s->retry_at, s->handshake_deadline);
    }
    else
    {
        const IINT32 delay = (IINT32) (ikcp_check(s->kcp, (IUINT32) now) - (IUINT32) now);
        next               = touDeadline(now, delay > 0 ? (uint32_t) delay : 1U);
    }
    if (s->closing && ! s->send_settled)
    {
        next = min(next, s->send_deadline);
    }
    uint64_t delay = next > now ? next - now : 1U;
    wtimerReset(s->timer, delay > UINT32_MAX ? UINT32_MAX : (uint32_t) delay);
}

static void drive(tou_session_t *s)
{
    if (s->driving || s->dead || s->quiesced)
    {
        return;
    }
    touSessionRetain(s);
    s->driving = true;
    for (;;)
    {
        uint64_t now = sessionNow(s);
        if (expire(s, now))
        {
            break;
        }
        while (! s->dead && ! s->quiesced && ! tou_work_queue_t_is_empty(&s->work))
        {
            now = sessionNow(s);
            if (expire(s, now))
                break;
            const tou_work_t *front = tou_work_queue_t_front(&s->work);
            if (front->wire && ! s->client && ! s->ready)
                break;
            tou_work_t event = tou_work_queue_t_pull_front(&s->work);
            if (event.wire)
                processWire(s, event.buffer, now);
            else
                processApplication(s, event.buffer);
            bufferpoolReuseBuffer(s->config.pool, event.buffer);
            bufferbudgetReservationRelease(&event.reservation);
            if (! s->dead && s->ready)
                receiveRecords(s, now);
            if (s->dead || s->quiesced || expire(s, sessionNow(s)) || ! tou_packet_queue_t_is_empty(&s->output))
                break;
        }
        if (s->dead || s->quiesced)
            break;
        if (s->ready)
        {
            receiveRecords(s, now);
            if (s->dead || s->quiesced)
                break;
            now = sessionNow(s);
            if (expire(s, now))
                break;
            closeProgress(s, now);
        }
        /* Nested ACK/input work is consumed between handoffs to release its
         * sbuf budget. The immutable older output batch retains FIFO priority;
         * no new update/flush may append another library batch before it drains. */
        if (! tou_packet_queue_t_is_empty(&s->output))
        {
            if (! s->started)
                break;
            emitOutput(s);
            continue;
        }
        if (s->started && s->client && ! s->ready && now >= s->retry_at)
        {
            stageHandshake(s);
            s->retry_at = touDeadline(now, kTouHandshakeRetryMs);
        }
        if (s->started && s->ready && s->dirty)
        {
            assert(tou_packet_queue_t_is_empty(&s->output));
            if (! beginOutputBatch(s))
            {
                touSessionAbort(s, kTouCapacityFailure);
                break;
            }
            s->dirty = false;
            ikcp_update(s->kcp, (IUINT32) now);
            if (s->flush)
            {
                s->flush = false;
                ikcp_flush(s->kcp);
            }
        }
        if (s->output_failed)
        {
            touSessionAbort(s, kTouCapacityFailure);
            break;
        }
        if (s->started)
            emitOutput(s);
        if (s->dead || s->quiesced)
            break;
        if (tou_work_queue_t_is_empty(&s->work) && tou_packet_queue_t_is_empty(&s->output))
            reconcilePressure(s);
        if (s->dead || s->quiesced || ! s->started || (! s->client && ! s->ready))
            break;
        if (tou_work_queue_t_is_empty(&s->work) && ! (s->ready && s->dirty) && tou_packet_queue_t_is_empty(&s->output))
            break;
    }
    s->driving = false;
    if (! s->dead)
        armTimer(s, sessionNow(s));
    touSessionRelease(s);
}

static void queueWork(tou_session_t *s, sbuf_t *buffer, bool wire)
{
    touSessionRetain(s);
    if (s->dead || s->quiesced || (! wire && s->closing))
    {
        bufferpoolReuseBuffer(s->config.pool, buffer);
    }
    else
    {
        tou_work_t event = {.buffer = buffer, .wire = wire};
        if (! bufferbudgetTryReserve(&s->budget, buffer, &event.reservation))
        {
            bufferpoolReuseBuffer(s->config.pool, buffer);
            touSessionAbort(s, kTouCapacityFailure);
        }
        else
        {
            tou_work_queue_t_push_back(&s->work, event);
            drive(s);
        }
    }
    touSessionRelease(s);
}

void touSessionSend(tou_session_t *s, sbuf_t *payload)
{
    /* An outer call can copy its entire accepted input directly into KCP before
     * any callback. Only nested work needs the retained-buffer admission budget. */
    if (! s->driving && ! s->dead && ! s->quiesced && ! s->closing && tou_work_queue_t_is_empty(&s->work))
    {
        touSessionRetain(s);
        processApplication(s, payload);
        bufferpoolReuseBuffer(s->config.pool, payload);
        drive(s);
        touSessionRelease(s);
        return;
    }
    queueWork(s, payload, false);
}

void touSessionInput(tou_session_t *s, sbuf_t *packet)
{
    queueWork(s, packet, true);
}

void touSessionAppFinish(tou_session_t *s)
{
    touSessionRetain(s);
    if (s->quiesced)
    {
        touSessionAbort(s, kTouAborted);
    }
    else if (! s->dead && ! s->local_finish)
    {
        s->local_finish = true;
        beginClose(s, sessionNow(s));
        drive(s);
    }
    touSessionRelease(s);
}

void touSessionStart(tou_session_t *s)
{
    touSessionRetain(s);
    if (! s->dead && ! s->quiesced)
    {
        s->started = true;
        s->dirty   = true;
        drive(s);
    }
    touSessionRelease(s);
}

void touSessionSetReady(tou_session_t *s)
{
    touSessionRetain(s);
    if (! s->dead && ! s->quiesced)
    {
        s->ready = true;
        s->dirty = true;
        drive(s);
    }
    touSessionRelease(s);
}

void touSessionTick(tou_session_t *s, uint64_t now)
{
    touSessionRetain(s);
    s->current_now = now;
    if (! s->dead && ! s->quiesced && s->started)
    {
        if (! s->closing && s->ready && now >= touDeadline(s->last_recv, s->config.ping_interval_ms) && ! s->ping_sent)
        {
            const uint8_t ping = kTouFramePing;
            sendRecord(s, (const char *) &ping, 1);
            s->ping_sent = true;
        }
        s->dirty = ! s->send_settled;
        drive(s);
    }
    touSessionRelease(s);
}

void touSessionQuiesce(tou_session_t *s)
{
    s->quiesced = true;
    if (s->timer != NULL)
    {
        weventSetUserData(s->timer, NULL);
        wtimerDelete(s->timer);
        s->timer = NULL;
    }
}

static void timerCallback(wtimer_t *timer)
{
    tou_session_t *s = weventGetUserdata(timer);
    assert(s != NULL && s->timer == timer);
    touSessionTick(s, sessionNow(s));
}

tou_session_t *touSessionCreate(const tou_config_t *config, const tou_callbacks_t *callbacks, void *user, bool client,
                                const uint8_t client_nonce[kTouNonceSize], const uint8_t server_nonce[kTouNonceSize],
                                const tou_settings_t *accepted)
{
    assert(config != NULL && callbacks != NULL && callbacks->emit != NULL && config->pool != NULL);
    assert(touKcpMtu(config) >= 50 && config->close_drain_timeout_ms > 0);
    tou_session_t *s = memoryAllocate(sizeof(*s));
    *s               = (tou_session_t) {.config     = *config,
                                        .callbacks  = *callbacks,
                                        .user       = user,
                                        .references = 1,
                                        .client     = client,
                                        .settings   = {.close_ms      = config->close_drain_timeout_ms,
                                                       .data_shards   = config->fec_enabled ? config->fec_data_shards : 0,
                                                       .parity_shards = config->fec_enabled ? config->fec_parity_shards : 0}};
    if (accepted != NULL)
    {
        s->settings = *accepted;
    }
    memoryCopy(s->client_nonce, client_nonce, kTouNonceSize);
    memoryCopy(s->server_nonce, server_nonce, kTouNonceSize);
    s->last_recv          = sessionNow(s);
    s->handshake_deadline = touDeadline(s->last_recv, config->no_recv_timeout_ms);
    s->retry_at           = s->last_recv;
    bufferbudgetInit(&s->budget, (buffer_budget_cost_t) {.bytes = 2U * 1024U * 1024U, .charge = 8U * 1024U * 1024U});
    s->kcp = ikcp_create(0, s);
    ikcp_setoutput(s->kcp, outputKcp);
    ikcp_nodelay(s->kcp,
                 config->kcp_nodelay ? 1 : 0,
                 config->kcp_interval_ms,
                 config->kcp_resend,
                 config->kcp_no_congestion_control ? 1 : 0);
    ikcp_wndsize(s->kcp, config->kcp_send_window, config->kcp_recv_window);
    const int mtu_result = ikcp_setmtu(s->kcp, touKcpMtu(config));
    if (mtu_result != 0)
    {
        LOGF("TcpOverUdp: KCP rejected validated packet geometry");
        abortProgramNow(1);
    }
    s->kcp->cwnd      = (IUINT32) config->kcp_initial_cwnd;
    s->kcp->rx_minrto = config->kcp_rx_minrto_ms;
    if (config->fec_enabled)
    {
        s->encoder = tcpoverudpFecEncoderCreate(config->fec_data_shards, config->fec_parity_shards);
        s->decoder = tcpoverudpFecDecoderCreate(config->fec_data_shards, config->fec_parity_shards);
    }
    if (config->loop != NULL)
    {
        s->timer = wtimerAdd(config->loop, timerCallback, (uint32_t) config->kcp_interval_ms, INFINITE);
    }
    if ((config->fec_enabled && (s->encoder == NULL || s->decoder == NULL)) ||
        (config->loop != NULL && s->timer == NULL))
    {
        s->callbacks.destroy_user = NULL;
        s->dead                   = true;
        touSessionRelease(s);
        return NULL;
    }
    if (s->timer != NULL)
    {
        weventSetUserData(s->timer, s);
    }
    return s;
}

bool touSessionIsAlive(const tou_session_t *s)
{
    return ! s->dead;
}
bool touSessionIsReady(const tou_session_t *s)
{
    return s->ready && ! s->dead;
}
const tou_settings_t *touSessionSettings(const tou_session_t *s)
{
    return &s->settings;
}
const uint8_t *touSessionClientNonce(const tou_session_t *s)
{
    return s->client_nonce;
}
const uint8_t *touSessionServerNonce(const tou_session_t *s)
{
    return s->server_nonce;
}
ikcpcb *touSessionKcp(tou_session_t *s)
{
    return s->kcp;
}
uint64_t touSessionSendDeadline(const tou_session_t *s)
{
    return s->send_deadline;
}
uint64_t touSessionRetentionDeadline(const tou_session_t *s)
{
    return s->retention_deadline;
}
bool touSessionCloseConfirmed(const tou_session_t *s)
{
    return s->confirmed;
}
