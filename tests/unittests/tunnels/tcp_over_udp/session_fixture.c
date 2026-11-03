/*
 * Actual TcpOverUdpClient/Server, real KCP/FEC and real worker timers. The fixture
 * owns application and shared UDP carrier lines; each node owns its split lines.
 * A controllable monotonic clock avoids wall-clock sleeps. Datagram capture,
 * selective loss, replay and pair reversal prove the requested wire event was
 * exercised. Every fixture ends with real node quiescence/worker Stop, releases
 * inspection references, and checks KCP/FEC/timer/line settlement.
 * CTest: waterwall.tcp_over_udp_session_unit and both line-failure unit entries.
 */
#include "session_fixture.h"
#include "TcpOverUdpClient/interface.h"
#include "TcpOverUdpCommon/session.h"
#include "TcpOverUdpServer/interface.h"
#include "settings_geometry_cases.h"
#include "test_assert.h"
#include "wevent.h"

#define require(c, m) TEST_REQUIRE(TEST_FAILURE_EXIT, c, m)

enum
{
    kMaxConnections = 80,
    kMaxPackets     = 8192,
    kMaxSessions    = 160,
    kReceiveSize    = 5 * 1024 * 1024
};

typedef struct endpoint_s
{
    line_t        *app, *transport, *service;
    tou_session_t *client_session, *server_session;
    uint8_t        nonce[kTouNonceSize];
    unsigned       app_finishes, service_finishes, establishments, pauses[2], resumes[2];
    size_t         received[2], sent[2];
    bool           app_closed;
} endpoint_t;
typedef struct packet_s
{
    sbuf_t     *buffer;
    endpoint_t *endpoint;
    unsigned    direction;
} packet_t;
typedef struct session_ref_s
{
    tou_session_t *session;
    bool           client;
} session_ref_t;
typedef struct fixture_s
{
    node_t          nodes[5];
    tunnel_t       *source, *client, *wire, *server, *service;
    tunnel_chain_t *chain;
    line_t         *carrier;
    endpoint_t      endpoints[kMaxConnections];
    unsigned        count, service_inits, carrier_finishes;
    packet_t        queue[kMaxPackets];
    size_t          count_packets;
    session_ref_t   sessions[kMaxSessions];
    unsigned        session_count;
    unsigned        drop_kind, drop_direction, drop_remaining, dropped;
    bool            drop_close, drop_close_ack, dropped_close, dropped_close_ack, saw_repeated_close;
    uint32_t        close_sequence;
    uint8_t         close_nonce[kTouNonceSize];
    unsigned        close_direction, close_transmissions;
    bool            reverse, reversed, direct, early_service_output, early_service_finish, close_on_pressure;
    unsigned        send_mtu[2], largest_packet[2];
    unsigned        service_pressure_action, service_pressure_closes;
    bool            nested_service_payload;
    bool            watch_expired, shutdown_on_emit, nested_shutdown;
    bool            abort_on_ready, ready_aborted, close_seen[2], close_ack_before_other;
    unsigned        saved_ack_direction;
    unsigned        wire_pauses[2], wire_resumes[2], emitted[2];
    bool            resume_during_init, require_dead_carrier;
    bool     nested_transport_from_app_finish, require_dead_app, nested_transport_finished, transport_admission_checked;
    unsigned expired_pushes, expired_acks;
    sbuf_t  *saved_close, *saved_hello, *saved_confirm, *saved_data, *saved_ack, *saved_parity;
} fixture_t;

static fixture_t *active;
static uint64_t   clock_us = 100000000ULL;
static int        live_kcp, live_encoders, live_decoders;
static unsigned   fail_timer, fail_encoder, fail_decoder;
static unsigned   decoder_inputs;

unsigned long long __wrap_getHRTimeUs(void);
unsigned long long __wrap_getHRTimeUs(void)
{
    return clock_us;
}
ikcpcb *__real_ikcp_create(IUINT32 conv, void *user);
ikcpcb *__wrap_ikcp_create(IUINT32 conv, void *user);
ikcpcb *__wrap_ikcp_create(IUINT32 conv, void *user)
{
    ikcpcb *result = __real_ikcp_create(conv, user);
    if (result)
        ++live_kcp;
    return result;
}
void __real_ikcp_release(ikcpcb *kcp);
void __wrap_ikcp_release(ikcpcb *kcp);
void __wrap_ikcp_release(ikcpcb *kcp)
{
    if (kcp)
        --live_kcp;
    __real_ikcp_release(kcp);
}
wtimer_t *__real_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t timeout, uint32_t repeat);
wtimer_t *__wrap_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t timeout, uint32_t repeat);
wtimer_t *__wrap_wtimerAdd(wloop_t *loop, wtimer_cb cb, uint32_t timeout, uint32_t repeat)
{
    if (fail_timer)
    {
        --fail_timer;
        return NULL;
    }
    return __real_wtimerAdd(loop, cb, timeout, repeat);
}
tcpoverudp_fec_encoder_t *__real_tcpoverudpFecEncoderCreate(uint8_t data, uint8_t parity);
tcpoverudp_fec_encoder_t *__wrap_tcpoverudpFecEncoderCreate(uint8_t data, uint8_t parity);
tcpoverudp_fec_encoder_t *__wrap_tcpoverudpFecEncoderCreate(uint8_t data, uint8_t parity)
{
    if (fail_encoder)
    {
        --fail_encoder;
        return NULL;
    }
    tcpoverudp_fec_encoder_t *result = __real_tcpoverudpFecEncoderCreate(data, parity);
    if (result)
        ++live_encoders;
    return result;
}
tcpoverudp_fec_decoder_t *__real_tcpoverudpFecDecoderCreate(uint8_t data, uint8_t parity);
tcpoverudp_fec_decoder_t *__wrap_tcpoverudpFecDecoderCreate(uint8_t data, uint8_t parity);
tcpoverudp_fec_decoder_t *__wrap_tcpoverudpFecDecoderCreate(uint8_t data, uint8_t parity)
{
    if (fail_decoder)
    {
        --fail_decoder;
        return NULL;
    }
    tcpoverudp_fec_decoder_t *result = __real_tcpoverudpFecDecoderCreate(data, parity);
    if (result)
        ++live_decoders;
    return result;
}
void __real_tcpoverudpFecEncoderDestroy(tcpoverudp_fec_encoder_t **encoder);
void __wrap_tcpoverudpFecEncoderDestroy(tcpoverudp_fec_encoder_t **encoder);
void __wrap_tcpoverudpFecEncoderDestroy(tcpoverudp_fec_encoder_t **encoder)
{
    if (encoder && *encoder)
        --live_encoders;
    __real_tcpoverudpFecEncoderDestroy(encoder);
}
void __real_tcpoverudpFecDecoderDestroy(tcpoverudp_fec_decoder_t **decoder);
void __wrap_tcpoverudpFecDecoderDestroy(tcpoverudp_fec_decoder_t **decoder);
void __wrap_tcpoverudpFecDecoderDestroy(tcpoverudp_fec_decoder_t **decoder)
{
    if (decoder && *decoder)
        --live_decoders;
    __real_tcpoverudpFecDecoderDestroy(decoder);
}
bool __real_tcpoverudpFecDecodePacket(tcpoverudp_fec_decoder_t *, const uint8_t *, size_t, tcpoverudp_fec_emit_fn,
                                      void *);
bool __wrap_tcpoverudpFecDecodePacket(tcpoverudp_fec_decoder_t *, const uint8_t *, size_t, tcpoverudp_fec_emit_fn,
                                      void *);
bool __wrap_tcpoverudpFecDecodePacket(tcpoverudp_fec_decoder_t *decoder, const uint8_t *packet, size_t size,
                                      tcpoverudp_fec_emit_fn emit, void *user)
{
    ++decoder_inputs;
    return __real_tcpoverudpFecDecodePacket(decoder, packet, size, emit, user);
}
tou_session_t *__real_touSessionCreate(const tou_config_t *, const tou_callbacks_t *, void *, bool, const uint8_t *,
                                       const uint8_t *, const tou_settings_t *);
tou_session_t *__wrap_touSessionCreate(const tou_config_t *, const tou_callbacks_t *, void *, bool, const uint8_t *,
                                       const uint8_t *, const tou_settings_t *);
tou_session_t *__wrap_touSessionCreate(const tou_config_t *config, const tou_callbacks_t *callbacks, void *user,
                                       bool client, const uint8_t *cn, const uint8_t *sn,
                                       const tou_settings_t *settings)
{
    tou_session_t *result = __real_touSessionCreate(config, callbacks, user, client, cn, sn, settings);
    if (result && active)
    {
        require(active->session_count < kMaxSessions, "inspection session list exceeded its bound");
        touSessionRetain(result);
        active->sessions[active->session_count++] = (session_ref_t) {result, client};
    }
    return result;
}

static sbuf_t *copyPacket(sbuf_t *packet)
{
    size_t  length = sbufGetLength(packet);
    sbuf_t *copy   = bufferpoolGetBestFit(getCurrentWorkerBufferPool(), length, 0);
    memcpy(sbufGetMutablePtr(copy), sbufGetRawPtr(packet), length);
    sbufSetLength(copy, length);
    return copy;
}
static endpoint_t *byApp(line_t *line)
{
    for (unsigned i = 0; i < active->count; ++i)
        if (active->endpoints[i].app == line)
            return &active->endpoints[i];
    require(false, "application callback used a foreign line");
    return NULL;
}
static endpoint_t *byTransport(line_t *line)
{
    for (unsigned i = 0; i < active->count; ++i)
        if (active->endpoints[i].transport == line)
            return &active->endpoints[i];
    require(false, "wire callback used a foreign transport");
    return NULL;
}
static endpoint_t *byService(line_t *line)
{
    for (unsigned i = 0; i < active->count; ++i)
        if (active->endpoints[i].service == line)
            return &active->endpoints[i];
    require(false, "service callback preceded its Init");
    return NULL;
}
static endpoint_t *byNonce(const uint8_t *nonce)
{
    for (unsigned i = 0; i < active->count; ++i)
        if (memcmp(active->endpoints[i].nonce, nonce, kTouNonceSize) == 0)
            return &active->endpoints[i];
    return NULL;
}
static void refreshSessions(void)
{
    for (unsigned i = 0; i < active->session_count; ++i)
    {
        session_ref_t *entry = &active->sessions[i];
        endpoint_t    *ep    = byNonce(touSessionClientNonce(entry->session));
        if (ep)
        {
            if (entry->client)
                ep->client_session = entry->session;
            else
                ep->server_session = entry->session;
        }
    }
}
static void closeApp(endpoint_t *ep)
{
    if (! lineIsAlive(ep->app))
        return;
    ep->app_closed = true;
    tunnelNextUpStreamFinish(active->source, ep->app);
    require(lineIsAlive(ep->app), "client destroyed its borrowed application line");
    lineDestroy(ep->app);
}
static void closeService(endpoint_t *ep)
{
    require(ep->service && lineIsAlive(ep->service), "service close has no owned live line");
    tunnelPrevDownStreamFinish(active->service, ep->service);
    require(! lineIsAlive(ep->service), "server receiving Finish kept its owned service logically alive");
}
static void appFinish(tunnel_t *t, line_t *line)
{
    require(t == active->source, "unexpected application owner");
    endpoint_t *ep = byApp(line);
    require(++ep->app_finishes == 1 && ! ep->app_closed, "application was finished more than once");
    if (active->nested_transport_from_app_finish)
    {
        active->nested_transport_from_app_finish = false;
        tunnelPrevDownStreamFinish(active->wire, ep->transport);
        require(! lineIsAlive(ep->transport),
                "reentrant transport Finish did not destroy exact owned transport before return");
        active->nested_transport_finished = true;
    }
    lineDestroy(line);
}
static void appEst(tunnel_t *t, line_t *line)
{
    require(t == active->source, "unexpected Est target");
    ++byApp(line)->establishments;
}
static void checkPayload(endpoint_t *ep, unsigned direction, line_t *line, sbuf_t *payload)
{
    const uint8_t *bytes = sbufGetRawPtr(payload);
    for (size_t i = 0; i < sbufGetLength(payload); ++i)
        require(bytes[i] == (uint8_t) ((ep->received[direction] + i) * 29U + 17U),
                "application payload changed or reordered");
    ep->received[direction] += sbufGetLength(payload);
    lineReuseBuffer(line, payload);
}
static void appPayload(tunnel_t *t, line_t *line, sbuf_t *payload)
{
    require(t == active->source, "unexpected reply target");
    checkPayload(byApp(line), 1, line, payload);
}
static void servicePayload(tunnel_t *t, line_t *line, sbuf_t *payload)
{
    require(t == active->service, "unexpected service target");
    checkPayload(byService(line), 0, line, payload);
}
static void serviceFinish(tunnel_t *t, line_t *line)
{
    require(t == active->service, "unexpected service Finish target");
    if (active->require_dead_carrier)
        require(! lineIsAlive(active->carrier), "service Finish ran before borrowed carrier owner closed admission");
    require(++byService(line)->service_finishes == 1, "service finished more than once");
}
static void appPause(tunnel_t *t, line_t *line)
{
    discard     t;
    endpoint_t *ep = byApp(line);
    ++ep->pauses[0];
    if (active->close_on_pressure)
        closeApp(ep);
}
static void appResume(tunnel_t *t, line_t *line)
{
    discard t;
    ++byApp(line)->resumes[0];
}
enum
{
    kServicePressureNone,
    kServicePressureNestedPayload,
    kServicePressureFinishOnPause,
    kServicePressureFinishOnResume
};
static void sendBytes(endpoint_t *ep, unsigned direction, size_t size);
static void servicePause(tunnel_t *t, line_t *line)
{
    require(t == active->service && lineIsAlive(line), "Pause reached a retired or foreign service");
    endpoint_t *ep = byService(line);
    ++ep->pauses[1];
    if (active->service_pressure_action == kServicePressureFinishOnPause)
    {
        ++active->service_pressure_closes;
        closeService(ep);
    }
    else if ((active->service_pressure_action == kServicePressureNestedPayload ||
              active->service_pressure_action == kServicePressureFinishOnResume) &&
             ! active->nested_service_payload)
    {
        active->nested_service_payload = true;
        sendBytes(ep, 1, 4097);
    }
}
static void serviceResume(tunnel_t *t, line_t *line)
{
    require(t == active->service && lineIsAlive(line), "Resume reached a retired or foreign service");
    endpoint_t *ep = byService(line);
    ++ep->resumes[1];
    if (active->service_pressure_action == kServicePressureFinishOnResume)
    {
        require(ikcp_waitsnd(touSessionKcp(ep->server_session)) < 2,
                "Resume preceded release of the server's local KCP pressure");
        ++active->service_pressure_closes;
        closeService(ep);
    }
}
static void sendBytes(endpoint_t *ep, unsigned direction, size_t size)
{
    line_t *line = direction ? ep->service : ep->app;
    require(line && lineIsAlive(line), "sending on a retired application/service");
    sbuf_t *payload = bufferpoolGetBestFit(lineGetBufferPool(line), size, 0);
    for (size_t i = 0; i < size; ++i)
        sbufGetMutablePtr(payload)[i] = (uint8_t) ((ep->sent[direction] + i) * 29U + 17U);
    sbufSetLength(payload, size);
    ep->sent[direction] += size;
    if (direction)
        tunnelPrevDownStreamPayload(active->service, line, payload);
    else
        tunnelNextUpStreamPayload(active->source, line, payload);
}
static void checkMetadata(line_t *copy, line_t *original, bool udp)
{
    require(copy != original && lineGetWID(copy) == lineGetWID(original) && copy->pools == original->pools,
            "split line changed worker or chain pool");
    address_context_t *dest        = lineGetDestinationAddressContext(copy);
    address_context_t *source_dest = lineGetDestinationAddressContext(original);
    require(addresscontextIsDomain(dest) && ! strcmp(dest->domain, "session.fixture") &&
                dest->domain != source_dest->domain && ! dest->domain_constant && dest->port == 12345,
            "split line lost routing domain ownership or destination port");
    require(addresscontextClassifyTransport(dest) == (udp ? kAddressContextTransportUdp : kAddressContextTransportTcp),
            "split line published incorrect transport protocol");
    require(copy->routing_context.local_listener_port == 34567 && copy->routing_context.peer_source_port == 45678,
            "split line lost listener/peer port context");
    require(lineGetUserAuthCount(copy) == 1 && lineHasAuthenticatedUsername(copy, "fixture-user"),
            "split line lost authenticated credentials");
    require(copy->prefer_ordinary_read_u && copy->prefer_ordinary_read_d && copy->fallback_mode &&
                copy->fallback_peer_write_closed,
            "split line lost routing/read policy fields");
}
static void serviceInit(tunnel_t *t, line_t *line)
{
    require(t == active->service && line != active->carrier, "server reused the borrowed carrier as its service line");
    refreshSessions();
    endpoint_t *ep = NULL;
    for (unsigned i = 0; i < active->count; ++i)
        if (! active->endpoints[i].service && active->endpoints[i].server_session)
        {
            ep = &active->endpoints[i];
            break;
        }
    require(ep != NULL, "service Init lacks a published matching session");
    ep->service = line;
    checkMetadata(line, active->carrier, false);
    lineRef(line);
    ++active->service_inits;
    if (active->resume_during_init)
        tunnelNextUpStreamResume(active->wire, active->carrier);
    require(lineGetWID(line) == 0, "service line moved workers");
    tunnelPrevDownStreamEst(t, line);
    if (active->early_service_output)
        sendBytes(ep, 1, 130001);
    if (active->early_service_finish)
        closeService(ep);
}
static uint32_t le32(const uint8_t *bytes)
{
    return (uint32_t) bytes[0] | (uint32_t) bytes[1] << 8 | (uint32_t) bytes[2] << 16 | (uint32_t) bytes[3] << 24;
}
static void deliver(packet_t packet)
{
    if (packet.direction == 0)
    {
        if (active->carrier && lineIsAlive(active->carrier))
            tunnelNextUpStreamPayload(active->wire, active->carrier, packet.buffer);
        else
            bufferpoolReuseBuffer(getCurrentWorkerBufferPool(), packet.buffer);
    }
    else if (packet.endpoint && packet.endpoint->transport && lineIsAlive(packet.endpoint->transport))
        tunnelPrevDownStreamPayload(active->wire, packet.endpoint->transport, packet.buffer);
    else
        bufferpoolReuseBuffer(getCurrentWorkerBufferPool(), packet.buffer);
}
static void queueWire(unsigned direction, endpoint_t *ep, sbuf_t *packet)
{
    tou_wire_t wire;
    ++active->emitted[direction];
    require(touWireDecode(sbufGetRawPtr(packet), sbufGetLength(packet), &wire), "node emitted an invalid envelope");
    const unsigned packet_size        = sbufGetLength(packet) + 28U;
    active->largest_packet[direction] = max(active->largest_packet[direction], packet_size);
    require(packet_size <= active->send_mtu[direction],
            "outer envelope/FEC exceeds the emitting node's configured send MTU");
    if (direction == 0)
    {
        memcpy(ep->nonce, wire.client_nonce, kTouNonceSize);
        if (wire.kind == kTouHello && ! active->saved_hello)
            active->saved_hello = copyPacket(packet);
        if (wire.kind == kTouConfirm && ! active->saved_confirm)
            active->saved_confirm = copyPacket(packet);
        if ((wire.kind == kTouKcp || wire.kind == kTouFec) && ! active->saved_data)
            active->saved_data = copyPacket(packet);
    }
    if (active->drop_remaining && wire.kind == active->drop_kind && direction == active->drop_direction)
    {
        --active->drop_remaining;
        ++active->dropped;
        lineReuseBuffer(active->carrier, packet);
        return;
    }
    if ((active->drop_close || active->drop_close_ack) && wire.kind == kTouFec && wire.body_len >= 6 &&
        wire.body[4] == 0xf2 && wire.body[5] == 0)
    {
        /* Drop repair shards too, so recovery proves KCP's retry/ACK path. */
        lineReuseBuffer(active->carrier, packet);
        return;
    }
    if (wire.kind == kTouFec && wire.body_len >= 6 && wire.body[4] == 0xf2 && ! active->saved_parity)
        active->saved_parity = copyPacket(packet);
    const uint8_t *inner  = wire.body;
    size_t         length = wire.body_len;
    /* FEC data shards contain the original KCP packet after their 8-byte header. */
    if (wire.kind == kTouFec && length >= 8 && inner[4] == 0xf1 && inner[5] == 0x00)
    {
        inner += 8;
        length -= 8;
    }
    else if (wire.kind != kTouKcp)
        length = 0;
    bool is_close = false, acknowledges_close = false;
    for (size_t at = 0; at + 24 <= length;)
    {
        uint32_t body = le32(inner + at + 20);
        if (active->watch_expired && direction == 0)
        {
            if (inner[at + 4] == 81)
                ++active->expired_pushes;
            if (inner[at + 4] == 82)
                ++active->expired_acks;
        }
        if (body > length - at - 24)
            break;
        if (inner[at + 4] == 81 && body == 1 && inner[at + 24] == kTouFrameClose)
        {
            is_close                      = true;
            active->close_seen[direction] = true;
            if (! active->close_transmissions)
            {
                active->close_sequence = le32(inner + at + 12);
                memcpy(active->close_nonce, wire.client_nonce, kTouNonceSize);
                active->close_direction = direction;
            }
            if (active->close_direction == direction)
            {
                ++active->close_transmissions;
                active->saw_repeated_close = active->close_transmissions > 1;
            }
            if (! active->saved_close)
                active->saved_close = copyPacket(packet);
        }
        if (inner[at + 4] == 82 && active->close_transmissions && direction != active->close_direction &&
            ! memcmp(active->close_nonce, wire.client_nonce, kTouNonceSize) &&
            (le32(inner + at + 12) == active->close_sequence || le32(inner + at + 16) > active->close_sequence))
            acknowledges_close = true;
        at += 24U + body;
    }
    for (size_t at = 0; at + 24 <= length;)
    {
        uint32_t body = le32(inner + at + 20);
        if (body > length - at - 24)
            break;
        if (inner[at + 4] == 82 && ! active->saved_ack)
        {
            active->saved_ack           = copyPacket(packet);
            active->saved_ack_direction = direction;
        }
        at += 24U + body;
    }
    if (acknowledges_close && ep)
    {
        tou_session_t *receiver = direction ? ep->server_session : ep->client_session;
        line_t        *app      = direction ? ep->service : ep->app;
        require(receiver && touSessionSendDeadline(receiver) != 0 && app && ! lineIsAlive(app),
                "CLOSE ACK was published before closing deadline/application detachment");
        if (! active->close_seen[direction])
            active->close_ack_before_other = true;
    }
    if (active->abort_on_ready && direction == 1 && wire.kind == kTouReady)
    {
        active->abort_on_ready = false;
        active->ready_aborted  = true;
        lineReuseBuffer(active->carrier, packet);
        tunnelNextUpStreamFinish(active->wire, active->carrier);
        require(lineIsAlive(active->carrier), "server destroyed borrowed carrier during READY abort");
        lineDestroy(active->carrier);
        tunnelPrevDownStreamFinish(active->wire, ep->transport);
        return;
    }
    if (is_close && active->drop_close && ! active->dropped_close)
    {
        active->dropped_close = true;
        lineReuseBuffer(active->carrier, packet);
        return;
    }
    if (acknowledges_close && active->drop_close_ack && ! active->dropped_close_ack)
    {
        active->dropped_close_ack = true;
        lineReuseBuffer(active->carrier, packet);
        return;
    }
    packet_t queued = {packet, ep, direction};
    if (active->direct)
        deliver(queued);
    else
    {
        require(active->count_packets < kMaxPackets, "fixture datagram queue exceeded its bound");
        active->queue[active->count_packets++] = queued;
        if (active->shutdown_on_emit)
        {
            active->shutdown_on_emit              = false;
            active->nested_shutdown               = true;
            const ww_lifecycle_context_t *context = wwLifecycleStartupRollback();
            active->client->onQuiesceRequest(active->client, context);
            active->server->onQuiesceRequest(active->server, context);
            active->client->onWorkerStop(active->client, 0, context);
            active->server->onWorkerStop(active->server, 0, context);
        }
    }
}
static void wireUp(tunnel_t *t, line_t *line, sbuf_t *packet)
{
    require(t == active->wire, "unexpected wire target");
    queueWire(0, byTransport(line), packet);
}
static void wireDown(tunnel_t *t, line_t *line, sbuf_t *packet)
{
    require(t == active->wire && line == active->carrier, "server sent on a foreign carrier");
    tou_wire_t wire;
    require(touWireDecode(sbufGetRawPtr(packet), sbufGetLength(packet), &wire), "server envelope invalid");
    queueWire(1, byNonce(wire.client_nonce), packet);
}
static void carrierFinish(tunnel_t *t, line_t *line)
{
    require(t == active->wire && line == active->carrier, "carrier Finish mapped to a foreign line");
    ++active->carrier_finishes;
    lineDestroy(line);
}
static void transportFinish(tunnel_t *t, line_t *line)
{
    discard     t;
    endpoint_t *ep = byTransport(line);
    if (active->require_dead_app)
    {
        require(! lineIsAlive(ep->app),
                "transport Finish allowed reentrant input before application owner closed admission");
        active->transport_admission_checked = true;
    }
}
static void wireInit(tunnel_t *t, line_t *line)
{
    require(t == active->wire, "unexpected transport Init");
    endpoint_t *ep = &active->endpoints[active->count - 1];
    require(ep->transport == NULL && line != ep->app,
            "client did not split its borrowed application and owned carrier");
    ep->transport = line;
    checkMetadata(line, ep->app, true);
    lineRef(line);
    require(lineGetWID(line) == lineGetWID(ep->app), "client transport moved workers");
    if (! active->carrier || ! lineIsAlive(active->carrier))
    {
        if (active->carrier)
            lineUnref(active->carrier);
        active->carrier = lineCreate(active->chain->line_pools, 0);
        lineRef(active->carrier);
        addresscontextCopy(lineGetSourceAddressContext(active->carrier), lineGetSourceAddressContext(line));
        addresscontextCopy(lineGetDestinationAddressContext(active->carrier), lineGetDestinationAddressContext(line));
        active->carrier->routing_context.local_listener_port = 34567;
        active->carrier->routing_context.peer_source_port    = 45678;
        lineCopyUsers(active->carrier, line);
        active->carrier->prefer_ordinary_read_u = active->carrier->prefer_ordinary_read_d = true;
        active->carrier->fallback_mode = active->carrier->fallback_peer_write_closed = true;
        tunnelNextUpStreamInit(t, active->carrier);
        require(active->service_inits == 0 || active->count > 1, "carrier Init eagerly initialized a service");
    }
    tunnelPrevDownStreamEst(t, line);
}
static void wireIgnoreEst(tunnel_t *t, line_t *line)
{
    discard t;
    discard line;
}
static void wirePause(tunnel_t *t, line_t *line)
{
    discard t;
    ++active->wire_pauses[line == active->carrier ? 1 : 0];
}
static void wireResume(tunnel_t *t, line_t *line)
{
    discard t;
    ++active->wire_resumes[line == active->carrier ? 1 : 0];
}
static void flushWire(void)
{
    const size_t count = active->count_packets;
    packet_t    *batch = memoryAllocate(count * sizeof(*batch) + 1);
    memcpy(batch, active->queue, count * sizeof(*batch));
    active->count_packets = 0;
    for (size_t i = 0; i < count; i += 2)
    {
        if (active->reverse && i + 1 < count)
        {
            active->reversed = true;
            deliver(batch[i + 1]);
            deliver(batch[i]);
        }
        else
        {
            deliver(batch[i]);
            if (i + 1 < count)
                deliver(batch[i + 1]);
        }
    }
    memoryFree(batch);
    refreshSessions();
}
static void advance(unsigned ms)
{
    clock_us += (uint64_t) ms * 1000;
    wloopUpdateTime(getWorkerLoop(0));
    discard wloopProcessEvents(getWorkerLoop(0), 0);
    flushWire();
}
static void pump(unsigned ms)
{
    for (unsigned elapsed = 0; elapsed < ms; elapsed += 10)
        advance(min(10U, ms - elapsed));
}
static void setupWithMtus(fixture_t *fixture, bool fec, unsigned client_close, unsigned server_close,
                          unsigned client_mtu, unsigned server_mtu)
{
    memoryZero(fixture, sizeof(*fixture));
    active               = fixture;
    fixture->send_mtu[0] = client_mtu;
    fixture->send_mtu[1] = server_mtu;
    fixture->nodes[0]    = (node_t) {.type = stringDuplicate("FixtureSource"), .flags = kNodeFlagChainHead};
    fixture->nodes[1]    = nodeTcpOverUdpClientGet();
    fixture->nodes[2]    = (node_t) {.type = stringDuplicate("FixtureWire")};
    fixture->nodes[3]    = nodeTcpOverUdpServerGet();
    fixture->nodes[4]    = (node_t) {.type = stringDuplicate("FixtureService"), .flags = kNodeFlagChainEnd};
    for (unsigned i = 1; i <= 3; i += 2)
    {
        char settings[512];
        snprintf(
            settings,
            sizeof(settings),
            "{\"send-mtu\":%u,\"fec\":%s,\"fec-data-shards\":2,\"fec-parity-shards\":1,\"close-drain-timeout-ms\":%u,"
            "\"ping-interval-ms\":100,\"no-recv-timeout-ms\":2000,\"kcp-send-buffer-limit\":2}",
            i == 1 ? client_mtu : server_mtu,
            fec ? "true" : "false",
            i == 1 ? client_close : server_close);
        fixture->nodes[i].node_settings_json = cJSON_Parse(settings);
    }
    fixture->source  = tunnelCreate(&fixture->nodes[0], 0, 0);
    fixture->client  = fixture->nodes[1].createHandle(&fixture->nodes[1]);
    fixture->wire    = tunnelCreate(&fixture->nodes[2], 0, 0);
    fixture->server  = fixture->nodes[3].createHandle(&fixture->nodes[3]);
    fixture->service = tunnelCreate(&fixture->nodes[4], 0, 0);
    require(fixture->source && fixture->client && fixture->wire && fixture->server && fixture->service,
            "paired tunnel construction failed");
    fixture->source->fnFinD     = appFinish;
    fixture->source->fnEstD     = appEst;
    fixture->source->fnPayloadD = appPayload;
    fixture->source->fnPauseD   = appPause;
    fixture->source->fnResumeD  = appResume;
    fixture->wire->fnInitU      = wireInit;
    fixture->wire->fnFinU       = transportFinish;
    fixture->wire->fnEstD       = wireIgnoreEst;
    fixture->wire->fnFinD       = carrierFinish;
    fixture->wire->fnPayloadU   = wireUp;
    fixture->wire->fnPayloadD   = wireDown;
    fixture->wire->fnPauseU = fixture->wire->fnPauseD = wirePause;
    fixture->wire->fnResumeU = fixture->wire->fnResumeD = wireResume;
    fixture->service->fnInitU                           = serviceInit;
    fixture->service->fnPayloadU                        = servicePayload;
    fixture->service->fnFinU                            = serviceFinish;
    fixture->service->fnPauseU                          = servicePause;
    fixture->service->fnResumeU                         = serviceResume;
    tunnel_t *tunnels[] = {fixture->source, fixture->client, fixture->wire, fixture->server, fixture->service};
    fixture->chain      = tunnelchainCreate(1);
    uint32_t offset     = 0;
    for (unsigned i = 0; i < ARRAY_SIZE(tunnels); ++i)
    {
        if (i)
            tunnelBind(tunnels[i - 1], tunnels[i]);
        tunnelchainInsert(fixture->chain, tunnels[i]);
        tunnels[i]->onIndex(tunnels[i], (uint16_t) i, &offset);
    }
    tunnelchainFinalize(fixture->chain);
}
static void setup(fixture_t *fixture, bool fec, unsigned client_close, unsigned server_close, unsigned mtu)
{
    setupWithMtus(fixture, fec, client_close, server_close, mtu, mtu);
}
static endpoint_t *openApp(void)
{
    require(active->count < kMaxConnections, "connection fixture exceeded its bound");
    endpoint_t *ep = &active->endpoints[active->count++];
    ep->app        = lineCreate(active->chain->line_pools, 0);
    lineRef(ep->app);
    require(
        addresscontextSetIpAddressPortProtocol(lineGetSourceAddressContext(ep->app), "127.0.0.2", 45678, IP_PROTO_TCP),
        "fixture source address setup failed");
    addresscontextDomainSetByString(lineGetDestinationAddressContext(ep->app), "session.fixture");
    addresscontextSetPort(lineGetDestinationAddressContext(ep->app), 12345);
    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(ep->app), IP_PROTO_TCP);
    ep->app->routing_context.local_listener_port = 34567;
    ep->app->routing_context.peer_source_port    = 45678;
    lineAddAuthenticatedCredentials(ep->app, "fixture-user", "fixture-password");
    ep->app->prefer_ordinary_read_u = ep->app->prefer_ordinary_read_d = true;
    ep->app->fallback_mode = ep->app->fallback_peer_write_closed = true;
    tunnelNextUpStreamInit(active->source, ep->app);
    refreshSessions();
    return ep;
}
static void established(endpoint_t *ep)
{
    for (unsigned time = 0;
         time < 2500 && (! ep->service || ! ep->client_session || ! touSessionIsReady(ep->client_session));
         time += 10)
        advance(10);
    require(ep->service && lineIsAlive(ep->service), "handshake failed to initialize service");
    refreshSessions();
    require(touSessionIsReady(ep->client_session), "client readiness did not follow the matching READY");
}
static void requireStateZero(line_t *line, tunnel_t *tunnel)
{
    const uint8_t *state = lineGetState(line, tunnel);
    for (size_t i = 0; i < tunnel->lstate_size; ++i)
        require(state[i] == 0, "retired line kept nonzero node state");
}
static void teardown(void)
{
    fail_timer = fail_encoder = fail_decoder = 0;
    const ww_lifecycle_context_t *context    = wwLifecycleStartupRollback();
    active->client->onQuiesceRequest(active->client, context);
    active->server->onQuiesceRequest(active->server, context);
    active->client->onWorkerQuiesce(active->client, 0, context);
    active->server->onWorkerQuiesce(active->server, 0, context);
    for (unsigned i = 0; i < active->count; ++i)
        closeApp(&active->endpoints[i]);
    if (active->carrier && lineIsAlive(active->carrier))
    {
        tunnelNextUpStreamFinish(active->wire, active->carrier);
        require(lineIsAlive(active->carrier), "server destroyed the borrowed UDP carrier");
        lineDestroy(active->carrier);
    }
    active->client->onWorkerStop(active->client, 0, context);
    active->server->onWorkerStop(active->server, 0, context);
    for (size_t i = 0; i < active->count_packets; ++i)
        bufferpoolReuseBuffer(getCurrentWorkerBufferPool(), active->queue[i].buffer);
    active->count_packets = 0;
    sbuf_t *saved[]       = {active->saved_close,
                             active->saved_hello,
                             active->saved_confirm,
                             active->saved_data,
                             active->saved_ack,
                             active->saved_parity};
    for (unsigned i = 0; i < ARRAY_SIZE(saved); ++i)
        if (saved[i])
            bufferpoolReuseBuffer(getCurrentWorkerBufferPool(), saved[i]);
    for (unsigned i = 0; i < active->session_count; ++i)
    {
        require(! touSessionIsAlive(active->sessions[i].session), "session survived worker Stop");
        touSessionRelease(active->sessions[i].session);
    }
    for (unsigned i = 0; i < active->count; ++i)
    {
        endpoint_t *ep = &active->endpoints[i];
        require(! lineIsAlive(ep->app), "fixture application survived owner cleanup");
        requireStateZero(ep->app, active->client);
        lineUnref(ep->app);
        if (ep->transport)
        {
            require(! lineIsAlive(ep->transport), "owned client transport survived cleanup");
            requireStateZero(ep->transport, active->client);
            lineUnref(ep->transport);
        }
        if (ep->service)
        {
            require(! lineIsAlive(ep->service), "owned server service survived cleanup");
            requireStateZero(ep->service, active->server);
            lineUnref(ep->service);
        }
    }
    if (active->carrier)
    {
        requireStateZero(active->carrier, active->server);
        lineUnref(active->carrier);
    }
    require(live_kcp == 0 && live_encoders == 0 && live_decoders == 0, "KCP/FEC resources survived terminal cleanup");
    tunnel_t *tunnels[] = {active->source, active->client, active->wire, active->server, active->service};
    for (unsigned i = 0; i < ARRAY_SIZE(tunnels); ++i)
        tunnels[i]->onDestroy(tunnels[i], context);
    tunnelchainDestroy(active->chain);
    for (unsigned i = 0; i < ARRAY_SIZE(active->nodes); ++i)
    {
        cJSON_Delete(active->nodes[i].node_settings_json);
        memoryFree(active->nodes[i].type);
    }
    active = NULL;
}

static void caseTransferClose(bool fec, unsigned direction, unsigned loss)
{
    testCaseSet(loss == 1 ? "lost CLOSE" : loss == 2 ? "lost CLOSE ACK" : direction ? "service close" : "upload close");
    fixture_t fixture;
    setup(&fixture, fec, 3000, 4000, 1500);
    fixture.drop_close     = loss == 1;
    fixture.drop_close_ack = loss == 2;
    endpoint_t *ep         = openApp();
    established(ep);
    require(ep->establishments == 1, "transport Est was fabricated or withheld until service Est");
    require(touSessionSettings(ep->client_session)->close_ms == 3000 &&
                touSessionSettings(ep->server_session)->close_ms == 3000,
            "asymmetric close settings did not negotiate minimum");
    sendBytes(ep, direction, 512 * 1024);

    if (direction)
        closeService(ep);
    else
        closeApp(ep);
    require(ep->transport && lineIsAlive(ep->transport), "application Finish prematurely destroyed its transport");
    pump(1800);
    require(ep->received[direction] == 512 * 1024, "close lost accepted application bytes");
    require((direction ? ep->app_finishes : ep->service_finishes) == 1,
            "peer did not finish exactly once after payload");
    tou_session_t *sender = direction ? ep->server_session : ep->client_session;
    require(touSessionCloseConfirmed(sender), "CLOSE was not confirmed by KCP acknowledgement");
    require(touSessionIsAlive(sender), "confirmed sender did not retain an ACK-capable session");
    if (loss == 1)
        require(fixture.dropped_close && fixture.saw_repeated_close,
                "selected CLOSE was not actually dropped and retransmitted");
    if (loss == 2)
        require(fixture.dropped_close_ack && fixture.saw_repeated_close,
                "selected CLOSE ACK loss did not cause a repeated CLOSE");
    uint64_t retention = touSessionRetentionDeadline(sender);
    if (fixture.saved_close)
    {
        deliver((packet_t) {copyPacket(fixture.saved_close), ep, direction});
        pump(10);
        require((direction ? ep->app_finishes : ep->service_finishes) == 1, "duplicate CLOSE emitted another Finish");
        require(touSessionRetentionDeadline(sender) == retention, "duplicate CLOSE extended fixed retention");
    }
    pump(5000);
    require(! touSessionIsAlive(ep->client_session) && ! touSessionIsAlive(ep->server_session),
            "graceful close exceeded its bounded retention");
    teardown();
}
static void caseAsymmetricMtu(bool fec, unsigned direction, bool larger_client)
{
    testCaseSet(direction ? "download with independent send MTUs" : "upload with independent send MTUs");
    fixture_t fixture;
    setupWithMtus(&fixture, fec, 3000, 3000, larger_client ? 1500 : 1200, larger_client ? 1200 : 1500);
    endpoint_t *ep = openApp();
    established(ep);
    sendBytes(ep, direction, 512 * 1024);
    if (direction)
        closeService(ep);
    else
        closeApp(ep);
    pump(1800);
    require(ep->received[direction] == 512 * 1024,
            "receiver dropped valid peer packets because its own send MTU was smaller");
    require((direction ? ep->app_finishes : ep->service_finishes) == 1,
            "asymmetric MTUs did not finish the peer exactly once after all data");
    tou_session_t *sender = direction ? ep->server_session : ep->client_session;
    require(touSessionCloseConfirmed(sender), "asymmetric MTUs prevented confirmed close");
    if (fixture.send_mtu[direction] > fixture.send_mtu[1 - direction])
        require(fixture.largest_packet[direction] > fixture.send_mtu[1 - direction],
                "asymmetric fixture never sent a packet larger than the receiver's send MTU");
    teardown();
}
static void caseLargeFlight(bool fec, bool direct)
{
    testCaseSet(direct ? "direct 3 MiB flight serializes nested ACKs within input admission"
                       : "accepted 3 MiB payload survives immediate owner Finish");
    fixture_t fixture;
    setup(&fixture, fec, 3000, 3000, 1500);
    fixture.direct = direct;
    endpoint_t *ep = openApp();
    established(ep);
    sendBytes(ep, 0, 3 * 1024 * 1024);
    closeApp(ep);
    require(lineIsAlive(ep->transport), "normal KCP flight expansion imposed a second application admission cap");
    pump(1800);
    require(ep->received[0] == 3 * 1024 * 1024 && ep->service_finishes == 1 &&
                touSessionCloseConfirmed(ep->client_session),
            "large accepted flight lost data or reliable close");
    teardown();
}
static void caseZeroWindowReopen(bool fec)
{
    testCaseSet("accumulated zero-window input drains after reopening with application attached");
    fixture_t fixture;
    setup(&fixture, fec, 1000, 1000, 1500);
    endpoint_t *ep = openApp();
    established(ep);
    touSessionKcp(ep->client_session)->rmt_wnd = 0;
    for (unsigned i = 0; i < 64; ++i)
        sendBytes(ep, 0, 65536);
    require(lineIsAlive(ep->app) && ep->received[0] == 0 && ikcp_waitsnd(touSessionKcp(ep->client_session)) >= 64,
            "zero-window input was dropped or admitted out of order");
    clock_us += 10000;
    wloopUpdateTime(getWorkerLoop(0));
    touSessionTick(ep->client_session, clock_us / 1000);
    require(ep->received[0] == 0, "zero-window KCP generated application output");
    touSessionKcp(ep->client_session)->rmt_wnd = 8192;
    pump(500);
    require(lineIsAlive(ep->app) && ep->received[0] == 4 * 1024 * 1024 && ep->resumes[0] == 1,
            "reopened window did not drain every accepted callback and release pressure");
    closeApp(ep);
    pump(100);
    require(touSessionCloseConfirmed(ep->client_session) && ep->service_finishes == 1,
            "reopened-window transfer did not complete reliable CLOSE");
    teardown();
}
static void caseHandshakeLoss(bool fec, unsigned kind, bool direct)
{
    testCaseSet("handshake packet loss and duplicate confirmation");
    fixture_t fixture;
    setup(&fixture, fec, 1000, 1000, 1500);
    fixture.drop_kind      = kind;
    fixture.drop_direction = kind == kTouHello || kind == kTouConfirm ? 0 : 1;
    fixture.drop_remaining = 1;
    fixture.direct         = direct;
    fixture.reverse        = ! direct;
    endpoint_t *ep         = openApp();
    sendBytes(ep, 0, 65001);
    established(ep);
    pump(400);
    require(fixture.dropped == 1 && fixture.service_inits == 1,
            "handshake retry did not initialize exactly one service");
    require(ep->received[0] == 65001, "pre-handshake accepted payload did not drain");
    require(fixture.saved_confirm != NULL, "fixture failed to capture CONFIRM");
    deliver((packet_t) {copyPacket(fixture.saved_confirm), ep, 0});
    pump(20);
    require(fixture.service_inits == 1, "duplicate CONFIRM recreated a service");
    teardown();
}
static void caseFinishBeforeReady(bool fec)
{
    testCaseSet("Finish before READY uses original deadline");
    fixture_t fixture;
    setup(&fixture, fec, 600, 300, 1500);
    fixture.drop_kind      = kTouReady;
    fixture.drop_direction = 1;
    fixture.drop_remaining = 1;
    endpoint_t *ep         = openApp();
    sendBytes(ep, 0, 65001);
    closeApp(ep);
    uint64_t deadline = touSessionSendDeadline(ep->client_session);
    pump(260);
    require(touSessionSendDeadline(ep->client_session) <= deadline, "negotiation restarted close deadline");
    pump(1200);
    require(ep->app_finishes == 0, "finished application was resurrected");
    require(! touSessionIsAlive(ep->client_session), "pre-READY Finish exceeded fixed close/retention budget");
    teardown();
}
static void caseEarlyOutput(bool fec)
{
    testCaseSet("direct READY and service Init reentry");
    fixture_t fixture;
    setup(&fixture, fec, 1000, 1000, 1500);
    fixture.direct               = true;
    fixture.early_service_output = true;
    fixture.early_service_finish = true;
    endpoint_t *ep               = openApp();
    pump(2000);
    require(fixture.service_inits == 1, "early Init output created a duplicate service");
    require(ep->received[1] == 130001 && ep->app_finishes == 1,
            "Init output/Finish lost bytes or reached an uninitialized application");
    teardown();
}
static void caseReadyAbort(bool fec)
{
    testCaseSet("READY output abort does not Finish a service before Init");
    fixture_t fixture;
    setup(&fixture, fec, 1000, 1000, 1500);
    fixture.abort_on_ready = true;
    endpoint_t *ep         = openApp();
    pump(100);
    require(fixture.ready_aborted && fixture.service_inits == 0 && ep->service == NULL,
            "READY abort initialized or notified a never-entered service");
    require(! lineIsAlive(ep->transport) && ep->app_finishes == 1,
            "READY abort did not settle its client owned transport/application");
    teardown();
}
static void flushDirection(unsigned direction);
static void flushAckOnly(unsigned direction);
static void caseSimultaneous(bool fec, bool peer_first)
{
    testCaseSet(peer_first ? "peer close drains accepted local output"
                           : "simultaneous close preserves both send obligations");
    fixture_t fixture;
    setup(&fixture, fec, 2000, 2000, 1500);
    endpoint_t *ep = openApp();
    established(ep);
    sendBytes(ep, 0, 180001);
    sendBytes(ep, 1, 260001);
    closeApp(ep);
    if (! peer_first)
        closeService(ep);
    if (! peer_first)
    {
        clock_us += 10000;
        wloopUpdateTime(getWorkerLoop(0));
        touSessionTick(ep->client_session, clock_us / 1000);
        touSessionTick(ep->server_session, clock_us / 1000);
        flushDirection(0);
        flushAckOnly(1);
        flushDirection(0);

        for (unsigned round = 0; round < 3 && ! fixture.close_ack_before_other; ++round)
        {
            clock_us += 10000;
            wloopUpdateTime(getWorkerLoop(0));
            touSessionTick(ep->client_session, clock_us / 1000);
            flushDirection(0);
            flushAckOnly(1);
            flushDirection(0);
        }
        require(fixture.close_ack_before_other && ikcp_waitsnd(touSessionKcp(ep->server_session)) > 0,
                "simultaneous fixture did not ACK one CLOSE before the other could be emitted");
    }
    pump(1500);
    require(ep->received[0] == (peer_first ? 180001U : 0U) && ep->received[1] == 0,
            "concurrent close delivered into a retired application or abandoned live-service input");
    require(touSessionCloseConfirmed(ep->client_session), "client CLOSE not confirmed during concurrent drain");
    if (! peer_first)
        require(touSessionCloseConfirmed(ep->server_session), "server CLOSE not confirmed during concurrent drain");
    require(ep->service_finishes == (peer_first ? 1U : 0U),
            "service retirement count changed during simultaneous close");
    teardown();
}
static void caseDeadline(bool fec)
{
    testCaseSet("absolute equality deadline and late ACK");
    fixture_t fixture;
    setup(&fixture, fec, 300, 300, 1500);
    endpoint_t *ep = openApp();
    established(ep);
    sendBytes(ep, 0, 70001);
    closeApp(ep);
    const uint64_t deadline = touSessionSendDeadline(ep->client_session);
    /* Do not deliver queued traffic: receive progress cannot manufacture confirmation. */
    clock_us = deadline * 1000;
    wloopUpdateTime(getWorkerLoop(0));
    touSessionTick(ep->client_session, deadline);
    require(! touSessionCloseConfirmed(ep->client_session), "equality deadline falsely confirmed a close");
    require(! touSessionIsAlive(ep->client_session), "send-only obligation survived exact deadline");
    flushWire();
    pump(400);
    require(! touSessionCloseConfirmed(ep->client_session), "late ACK rewrote terminal unconfirmed outcome");
    teardown();
}
static void caseReconnect(bool fec)
{
    testCaseSet("same carrier reconnect, retired replay and fresh confirmation");
    fixture_t fixture;
    setup(&fixture, fec, 600, 600, 1500);
    endpoint_t *old = openApp();
    established(old);
    sendBytes(old, 0, 70001);
    closeApp(old);
    pump(300);
    require(touSessionIsAlive(old->server_session), "old responder disappeared before its promised retention");
    line_t     *carrier = fixture.carrier;
    endpoint_t *fresh   = openApp();
    established(fresh);
    require(fixture.carrier == carrier && fresh->service != old->service,
            "reconnect failed to retain carrier and distinct services");
    sendBytes(fresh, 0, 70001);
    pump(100);
    require(fresh->received[0] == 70001, "fresh session stalled while old responder lingered");
    sbuf_t *replays[] = {fixture.saved_close, fixture.saved_data, fixture.saved_hello, fixture.saved_confirm};
    for (unsigned pass = 0; pass < 2; ++pass)
    {
        for (unsigned i = 0; i < ARRAY_SIZE(replays); ++i)
            if (replays[i])
                deliver((packet_t) {copyPacket(replays[i]), old, 0});
        if (fixture.saved_ack)
            deliver((packet_t) {copyPacket(fixture.saved_ack), fresh, fixture.saved_ack_direction});
        if (fixture.saved_parity)
        {
            unsigned before = decoder_inputs;
            deliver((packet_t) {copyPacket(fixture.saved_parity), old, 0});
            if (pass)
                require(decoder_inputs == before, "retired parity reached an unrelated live FEC decoder");
        }
        pump(pass ? 20 : 800);
        require(fixture.service_inits == 2 && lineIsAlive(fresh->service),
                "old wire traffic recreated or closed a new service");
        require(fresh->received[0] == 70001, "old payload contaminated the fresh session");
    }
    teardown();
}
static void caseOuterRejection(bool fec)
{
    testCaseSet("outer identity and malformed geometry are rejected before KCP/FEC");
    fixture_t fixture;
    setup(&fixture, fec, 1000, 1000, 1500);
    endpoint_t *ep = openApp();
    established(ep);
    sendBytes(ep, 0, 4097);
    pump(100);
    require(fixture.saved_data != NULL, "outer rejection fixture captured no real inner wire");
    size_t         bytes        = ep->received[0];
    unsigned       decoded      = decoder_inputs;
    const unsigned corrupt_at[] = {0, 4, 5, 6, 8, 24};
    for (unsigned i = 0; i < ARRAY_SIZE(corrupt_at); ++i)
    {
        sbuf_t *bad = copyPacket(fixture.saved_data);
        sbufGetMutablePtr(bad)[corrupt_at[i]] ^= corrupt_at[i] == 4 ? 0x80 : 1;
        deliver((packet_t) {bad, ep, 0});
    }
    sbuf_t *short_packet = copyPacket(fixture.saved_data);
    sbufSetLength(short_packet, 39);
    deliver((packet_t) {short_packet, ep, 0});
    require(decoder_inputs == decoded && ep->received[0] == bytes && fixture.service_inits == 1 &&
                lineIsAlive(ep->service),
            "invalid outer wire touched the decoder/application or session admission");
    teardown();
}
static void caseCapacity(void)
{
    testCaseSet("64-session admission and pending challenge bound");
    fixture_t fixture;
    setup(&fixture, false, 2000, 2000, 1500);
    for (unsigned i = 0; i < kTouMaximumSessions; ++i)
    {
        endpoint_t *ep = openApp();
        established(ep);
    }
    endpoint_t *refused = openApp();
    pump(500);
    require(fixture.service_inits == kTouMaximumSessions && refused->service == NULL,
            "carrier session cap did not refuse admission");
    require(lineIsAlive(fixture.endpoints[0].service), "capacity refusal evicted an admitted session");
    closeApp(&fixture.endpoints[0]);
    pump(2300);
    endpoint_t *after = openApp();
    established(after);
    require(fixture.service_inits >= kTouMaximumSessions + 1, "expired capacity did not permit fresh admission");
    teardown();
}
static void caseFailure(unsigned failure, bool server)
{
    testCaseSet(server ? "server establishment resource refusal" : "client initialization resource refusal");
    fixture_t fixture;
    setup(&fixture, failure != 0, 1000, 1000, 1500);
    if (! server)
    {
        if (failure == 0)
            fail_timer = 1;
        else if (failure == 1)
            fail_encoder = 1;
        else
            fail_decoder = 1;
    }
    endpoint_t *ep = openApp();
    if (server)
    {
        flushWire();
        flushWire(); /* HELLO then CHALLENGE; CONFIRM remains queued. */
        if (failure == 0)
            fail_timer = 1;
        else if (failure == 1)
            fail_encoder = 1;
        else
            fail_decoder = 1;
        flushWire();
    }
    pump(50);
    if (! server)
        require(ep->app_finishes == 1, "client initialization refusal did not settle borrowed app exactly once");
    else
        require(fixture.service_inits == 0, "server failure initialized service before resources were admitted");
    teardown();
}
static void casePressure(bool server, bool close_on_pause)
{
    testCaseSet("complete input admission precedes pressure and reentrant Finish");
    fixture_t fixture;
    setup(&fixture, false, 1000, 1000, 1500);
    endpoint_t *ep = openApp();
    established(ep);
    fixture.close_on_pressure = close_on_pause;
    sendBytes(ep, server ? 1 : 0, 70001);
    require(ep->pauses[server ? 1 : 0] == 1, "KCP queue did not publish its independent pressure hold");
    tou_session_t *session = server ? ep->server_session : ep->client_session;
    require(ikcp_waitsnd(touSessionKcp(session)) >= 40, "pressure preceded admission of the entire input");
    pump(500);
    require(ep->received[server ? 1 : 0] == 70001, "pressure or reentrant close dropped admitted input");
    if (! close_on_pause)
        require(ep->resumes[server ? 1 : 0] == 1, "ACK-only progress did not release local pressure");
    teardown();
}

static void caseServerPressureReentry(bool fec, unsigned action)
{
    testCaseSet(action == kServicePressureFinishOnPause    ? "server Pause synchronously closes owned service"
                : action == kServicePressureFinishOnResume ? "server Resume synchronously closes owned service"
                                                           : "server Pause nested Payload preserves FIFO");
    fixture_t fixture;
    setup(&fixture, fec, 1000, 1000, 1500);
    endpoint_t *ep = openApp();
    established(ep);
    fixture.service_pressure_action = action;
    const uint32_t initial_refs     = atomicLoadU32Relaxed(&ep->service->refc);
    sendBytes(ep, 1, 70001);
    require(ep->pauses[1] == 1, "server did not publish one local pressure Pause after admission");
    const bool finish_on_pause = action == kServicePressureFinishOnPause;
    require(fixture.nested_service_payload == ! finish_on_pause,
            "server Pause did not exercise the requested nested Payload or Finish");
    if (finish_on_pause)
    {
        require(! lineIsAlive(ep->service) && fixture.service_pressure_closes == 1,
                "Pause-triggered Finish returned before exact owned service destruction");
        requireStateZero(ep->service, fixture.server);
    }
    pump(500);
    require(ep->received[1] == 70001U + (finish_on_pause ? 0U : 4097U),
            "server pressure callback lost accepted bytes or reordered nested Payload");
    require(ep->pauses[1] == 1 && ep->resumes[1] == (finish_on_pause ? 0U : 1U),
            "server pressure was duplicated or ACK progress did not release it");
    if (action == kServicePressureNestedPayload)
    {
        require(lineIsAlive(ep->service) && atomicLoadU32Relaxed(&ep->service->refc) == initial_refs,
                "nested pressure Payload retired the service or leaked a line reference");
        closeService(ep);
    }
    else
        require(fixture.service_pressure_closes == 1, "pressure callback did not close exactly once");
    require(! lineIsAlive(ep->service), "pressure Finish kept the exact owned service alive");
    requireStateZero(ep->service, fixture.server);
    require(atomicLoadU32Relaxed(&ep->service->refc) == 1,
            "retired service retained a reference beyond the fixture inspection reference");
    pump(100);
    require(ep->service_finishes == 0 && ep->app_finishes == 1 && touSessionCloseConfirmed(ep->server_session),
            "pressure close reflected Finish or failed to deliver confirmed close to the peer");
    teardown();
}

static void flushDirection(unsigned direction)
{
    size_t    count = active->count_packets;
    packet_t *batch = memoryAllocate(count * sizeof(*batch) + 1);
    memcpy(batch, active->queue, count * sizeof(*batch));
    active->count_packets = 0;
    for (size_t i = 0; i < count; ++i)
    {
        if (batch[i].direction == direction)
            deliver(batch[i]);
        else
            active->queue[active->count_packets++] = batch[i];
    }
    memoryFree(batch);
}
static bool packetHasAck(sbuf_t *packet)
{
    tou_wire_t wire;
    require(touWireDecode(sbufGetRawPtr(packet), sbufGetLength(packet), &wire), "ACK selector got invalid envelope");
    const uint8_t *inner  = wire.body;
    size_t         length = wire.body_len;
    if (wire.kind == kTouFec)
    {
        if (length < 8 || inner[4] != 0xf1)
            return false;
        inner += 8;
        length -= 8;
    }
    else if (wire.kind != kTouKcp)
        return false;
    while (length >= 24)
    {
        uint32_t size = 24U + le32(inner + 20);
        if (size > length)
            return false;
        if (inner[4] == 82)
            return true;
        inner += size;
        length -= size;
    }
    return false;
}
static void flushAckOnly(unsigned direction)
{
    size_t    count = active->count_packets;
    packet_t *batch = memoryAllocate(count * sizeof(*batch) + 1);
    memcpy(batch, active->queue, count * sizeof(*batch));
    active->count_packets = 0;
    for (size_t i = 0; i < count; ++i)
    {
        if (batch[i].direction == direction && packetHasAck(batch[i].buffer))
            deliver(batch[i]);
        else
            active->queue[active->count_packets++] = batch[i];
    }
    memoryFree(batch);
}
static void caseReceiveOnlyExpiry(bool fec)
{
    testCaseSet("receive-only expiry suppresses mixed PUSH while retaining duplicate CLOSE ACK");
    fixture_t fixture;
    setup(&fixture, fec, 1000, 1000, 1500);
    endpoint_t *ep = openApp();
    established(ep);
    sendBytes(ep, 0, 70001);
    closeApp(ep);
    clock_us += 10000;
    wloopUpdateTime(getWorkerLoop(0));
    touSessionTick(ep->client_session, clock_us / 1000);
    require(touSessionKcp(ep->client_session)->nsnd_buf > 0, "expiry fixture did not transmit outstanding data");
    clock_us += 90000;
    wloopUpdateTime(getWorkerLoop(0));
    closeService(ep);
    touSessionTick(ep->server_session, clock_us / 1000);
    flushDirection(1);
    require(fixture.saved_close && fixture.close_direction == 1, "expiry fixture did not receive server CLOSE");
    uint64_t deadline  = touSessionSendDeadline(ep->client_session);
    uint64_t retention = touSessionRetentionDeadline(ep->client_session);
    require(retention > deadline, "peer CLOSE did not establish a later independent responder obligation");
    clock_us = deadline * 1000;
    wloopUpdateTime(getWorkerLoop(0));
    touSessionTick(ep->client_session, deadline);
    require(touSessionIsAlive(ep->client_session) && ! touSessionCloseConfirmed(ep->client_session),
            "expired sender canceled peer ACK obligation or falsely confirmed");
    /* Pending unacknowledged PUSH segments are now due for retransmission.
     * Duplicate CLOSE creates an ACK in the same flush; filtering must keep it. */
    struct IKCPSEG *segment = iqueue_entry(touSessionKcp(ep->client_session)->snd_buf.next, struct IKCPSEG, node);
    /* Expiry Tick itself may have advanced retry bookkeeping while filtering its
     * output. Make the still-pending segment due for the following ACK flush. */
    segment->resendts     = (uint32_t) deadline;
    fixture.watch_expired = true;
    deliver((packet_t) {copyPacket(fixture.saved_close), ep, 1});
    require(fixture.expired_acks > 0 && fixture.expired_pushes == 0,
            "receive-only duplicate flush lost ACK or emitted expired PUSH");
    require(touSessionSendDeadline(ep->client_session) == deadline &&
                touSessionRetentionDeadline(ep->client_session) == retention,
            "duplicate input moved fixed close deadlines");
    clock_us = retention * 1000;
    wloopUpdateTime(getWorkerLoop(0));
    touSessionTick(ep->client_session, retention);
    require(! touSessionIsAlive(ep->client_session), "receive-only responder survived exact retention deadline");
    teardown();
}
static void caseZeroWindow(bool fec)
{
    testCaseSet("zero remote window keeps unsent CLOSE unconfirmed and bounded");
    fixture_t fixture;
    setup(&fixture, fec, 300, 300, 1500);
    endpoint_t *ep = openApp();
    established(ep);
    touSessionKcp(ep->client_session)->rmt_wnd = 0;
    closeApp(ep);
    uint64_t deadline = touSessionSendDeadline(ep->client_session);
    clock_us += 10000;
    wloopUpdateTime(getWorkerLoop(0));
    touSessionTick(ep->client_session, clock_us / 1000);
    require(! fixture.saved_close && ikcp_waitsnd(touSessionKcp(ep->client_session)) > 0 &&
                ! touSessionCloseConfirmed(ep->client_session),
            "zero-window flush counted as acknowledged CLOSE");
    clock_us = deadline * 1000;
    wloopUpdateTime(getWorkerLoop(0));
    touSessionTick(ep->client_session, deadline);
    require(! touSessionIsAlive(ep->client_session) && ! touSessionCloseConfirmed(ep->client_session),
            "zero-window CLOSE exceeded its finite unconfirmed deadline");
    teardown();
}
static void caseShutdownPhases(bool fec)
{
    for (unsigned phase = 0; phase < 5; ++phase)
    {
        testCaseSet("shutdown aborts pending handshake, drain, CLOSE wait, retention and nested callback");
        fixture_t fixture;
        setup(&fixture, fec, 1000, 1000, 1500);
        endpoint_t *ep = openApp();
        if (phase != 0)
        {
            established(ep);
            if (phase == 1)
                sendBytes(ep, 0, 70001);
            if (phase == 4)
                fixture.shutdown_on_emit = true;
            closeApp(ep);
            if (phase == 2 || phase == 4)
            {
                clock_us += 10000;
                wloopUpdateTime(getWorkerLoop(0));
                touSessionTick(ep->client_session, clock_us / 1000);
            }
            if (phase == 3)
            {
                pump(100);
                require(touSessionCloseConfirmed(ep->client_session),
                        "shutdown retention fixture never acknowledged CLOSE");
            }
            if (phase == 4)
                require(fixture.nested_shutdown, "shutdown did not run inside an output callback");
        }
        teardown();
    }
}
static void caseClientTerminalReentry(void)
{
    for (unsigned nested_finish = 0; nested_finish < 2; ++nested_finish)
    {
        testCaseSet("client local abort closes application admission and settles nested transport Finish");
        fixture_t fixture;
        setup(&fixture, false, 1000, 1000, 1500);
        endpoint_t *ep = openApp();
        established(ep);
        fixture.nested_transport_from_app_finish = nested_finish != 0;
        fixture.require_dead_app                 = nested_finish == 0;
        touSessionAbort(ep->client_session, kTouProtocolFailure);
        require(! lineIsAlive(ep->app) && ! lineIsAlive(ep->transport) && ep->app_finishes == 1,
                "client local terminal failed exact application/transport settlement");
        require(nested_finish ? fixture.nested_transport_finished : fixture.transport_admission_checked,
                "client terminal fixture did not exercise requested cross-line reentry");
        teardown();
    }
}
static void caseCarrierStopReentry(void)
{
    testCaseSet("local carrier retirement closes owner admission before service Finish reentry");
    fixture_t fixture;
    setup(&fixture, false, 1000, 1000, 1500);
    endpoint_t *ep = openApp();
    established(ep);
    fixture.require_dead_carrier = true;
    fixture.server->onWorkerStop(fixture.server, 0, wwLifecycleStartupRollback());
    require(! lineIsAlive(fixture.carrier) && ! lineIsAlive(ep->service) && ep->service_finishes == 1,
            "local carrier Stop did not settle exact owned service after source admission closure");
    teardown();
}
static void caseAdvisorySignals(void)
{
    testCaseSet("repeat advisory signals map split lines without gating due KCP output");
    fixture_t fixture;
    setup(&fixture, false, 1000, 1000, 1500);
    endpoint_t *ep = openApp();
    established(ep);
    for (unsigned i = 0; i < 2; ++i)
    {
        tunnelNextUpStreamPause(fixture.source, ep->app);
        tunnelPrevDownStreamPause(fixture.wire, ep->transport);
        tunnelNextUpStreamPause(fixture.wire, fixture.carrier);
        tunnelPrevDownStreamPause(fixture.service, ep->service);
    }
    require(ep->pauses[0] == 2 && ep->pauses[1] == 2 && fixture.wire_pauses[0] == 2 && fixture.wire_pauses[1] == 2,
            "repeated Pause was suppressed or mapped to wrong line");
    unsigned emitted = fixture.emitted[0] + fixture.emitted[1];
    sendBytes(ep, 0, 10001);
    pump(150);
    require(ep->received[0] == 10001 && fixture.emitted[0] + fixture.emitted[1] > emitted && ep->resumes[0] == 1,
            "advisory Pause gated due KCP output or ACK-only local Resume");
    for (unsigned i = 0; i < 2; ++i)
    {
        tunnelNextUpStreamResume(fixture.source, ep->app);
        tunnelPrevDownStreamResume(fixture.wire, ep->transport);
        tunnelNextUpStreamResume(fixture.wire, fixture.carrier);
        tunnelPrevDownStreamResume(fixture.service, ep->service);
    }
    require(ep->resumes[0] == 3 && ep->resumes[1] == 2 && fixture.wire_resumes[0] == 2 && fixture.wire_resumes[1] == 2,
            "repeated Resume was suppressed or mapped to wrong line");
    teardown();
}
static void caseDeferredPressure(bool fec)
{
    for (unsigned nested_resume = 0; nested_resume < 2; ++nested_resume)
    {
        testCaseSet("carrier pressure during handshake replays after service Init with nested Resume reconciliation");
        fixture_t fixture;
        setup(&fixture, fec, 1000, 1000, 1500);
        fixture.resume_during_init = nested_resume != 0;
        endpoint_t *ep             = openApp();
        tunnelNextUpStreamPause(fixture.wire, fixture.carrier);
        tunnelNextUpStreamPause(fixture.wire, fixture.carrier);
        established(ep);
        require(ep->pauses[1] == (nested_resume ? 0U : 1U) && ep->resumes[1] == (nested_resume ? 1U : 0U),
                "deferred Pause was lost/duplicated or replayed after nested Resume");
        teardown();
    }
}
#include "receive_cases.h"
#include "session_extra_cases.h"

static void caseWirePrimitives(void)
{
    testCaseSet("golden envelope/settings and checked deadline fixtures");
    uint8_t cn[16], sn[16];
    for (unsigned i = 0; i < 16; ++i)
    {
        cn[i] = (uint8_t) (i + 1);
        sn[i] = (uint8_t) (i + 17);
    }
    tou_settings_t       settings = {.close_ms = 30000, .data_shards = 2, .parity_shards = 1};
    sbuf_t              *packet   = touControlCreate(getCurrentWorkerBufferPool(), kTouChallenge, cn, sn, &settings);
    static const uint8_t prefix[] = {0x57, 0x57, 0x4b, 0x43, 2, 0, 0, 8};
    static const uint8_t body[]   = {0, 0, 0x75, 0x30, 2, 1, 0, 0};
    require(packet && sbufGetLength(packet) == 48, "golden control size changed");
    const uint8_t *bytes = sbufGetRawPtr(packet);
    require(! memcmp(bytes, prefix, 8) && ! memcmp(bytes + 8, cn, 16) && ! memcmp(bytes + 24, sn, 16) &&
                ! memcmp(bytes + 40, body, 8),
            "golden network-order fixture changed");
    tou_wire_t     wire;
    tou_settings_t decoded;
    require(touWireDecode(bytes, 48, &wire) && touSettingsDecode(wire.body, wire.body_len, &decoded) &&
                touSettingsEqual(&settings, &decoded),
            "golden settings did not roundtrip");
    require(! touWireDecode(bytes, 47, &wire) && ! touWireDecode(bytes, 39, &wire), "truncated envelope accepted");
    for (unsigned at = 0; at < 8; ++at)
    {
        sbuf_t *bad = copyPacket(packet);
        sbufGetMutablePtr(bad)[at] ^= at == 4 ? 0x80 : 1;
        require(! touWireDecode(sbufGetRawPtr(bad), sbufGetLength(bad), &wire), "malformed header accepted");
        bufferpoolReuseBuffer(getCurrentWorkerBufferPool(), bad);
    }
    const uint8_t invalid_settings[][8] = {{0, 0, 0, 0, 0, 0, 0, 0},
                                           {0x80, 0, 0, 0, 0, 0, 0, 0},
                                           {0, 0, 0, 1, 1, 0, 0, 0},
                                           {0, 0, 0, 1, 0, 1, 0, 0},
                                           {0, 0, 0, 1, 255, 1, 0, 0},
                                           {0, 0, 0, 1, 0, 0, 1, 0},
                                           {0, 0, 0, 1, 0, 0, 0, 1}};
    for (unsigned i = 0; i < ARRAY_SIZE(invalid_settings); ++i)
        require(! touSettingsDecode(invalid_settings[i], 8, &decoded), "invalid handshake settings accepted");
    require(! touSettingsDecode(body, 7, &decoded) && ! touSettingsDecode(body, 9, &decoded),
            "incorrect settings body length accepted");
    require(touDeadline(UINT64_MAX - 1, 1000) == UINT64_MAX, "deadline arithmetic overflowed");
    require(touDeadline(100, 30000) == 30100, "deadline changed its original origin");
    bufferpoolReuseBuffer(getCurrentWorkerBufferPool(), packet);
}
int tcpOverUdpSessionCases(const char *selection)
{
    static char            log_off[]    = "OFF";
    ww_construction_data_t init         = {.workers_count = 1, .ram_profile = 4, .mtu_size = 1500};
    init.internal_logger_data.log_level = log_off;
    init.core_logger_data.log_level     = log_off;
    init.network_logger_data.log_level  = log_off;
    init.dns_logger_data.log_level      = log_off;
    require(wwStartupSucceeded(createGlobalState(init)), "worker runtime construction failed");
    atomicStoreExplicit(&getWorkerLoop(0)->status, WLOOP_STATUS_RUNNING, memory_order_release);
    atomicStoreExplicit(&GSTATE.workers_run_flag, true, memory_order_release);
    unsigned timers_at_start = wloopNTimers(getWorkerLoop(0));
    if (! strcmp(selection, "session"))
    {

        for (unsigned fec = 0; fec < 2; ++fec)
        {
            for (unsigned direction = 0; direction < 2; ++direction)
                for (unsigned loss = 0; loss < 3; ++loss)
                    caseTransferClose(fec != 0, direction, loss);
            for (unsigned direction = 0; direction < 2; ++direction)
                for (unsigned larger_client = 0; larger_client < 2; ++larger_client)
                    caseAsymmetricMtu(fec != 0, direction, larger_client != 0);
            for (unsigned kind = kTouHello; kind <= kTouReady; ++kind)
                caseHandshakeLoss(fec != 0, kind, kind % 2 == 0);
            caseDeferredPressure(fec != 0);
            caseLargeFlight(fec != 0, false);
            caseLargeFlight(fec != 0, true);
            caseZeroWindowReopen(fec != 0);
            caseFinishBeforeReady(fec != 0);
            caseEarlyOutput(fec != 0);
            caseReadyAbort(fec != 0);
            caseSimultaneous(fec != 0, false);
            caseSimultaneous(fec != 0, true);
            caseReceiveOnlyExpiry(fec != 0);
            caseZeroWindow(fec != 0);
            caseShutdownPhases(fec != 0);
            caseDeadline(fec != 0);
            caseReconnect(fec != 0);
            caseOuterRejection(fec != 0);
        }
        caseClientTerminalReentry();
        caseCarrierStopReentry();
        caseAdvisorySignals();
        caseCapacity();
        tcpOverUdpExtraCases();
        tcpOverUdpClientSettingsGeometryCases();
        tcpOverUdpServerSettingsGeometryCases();
        caseWirePrimitives();
    }
    else
    {
        bool server = ! strcmp(selection, "server");
        for (unsigned failure = 0; failure < 3; ++failure)
            caseFailure(failure, server);
        casePressure(server, false);
        if (! server)
            casePressure(server, true);
        else
            for (unsigned fec = 0; fec < 2; ++fec)
                for (unsigned action = kServicePressureNestedPayload; action <= kServicePressureFinishOnResume;
                     ++action)
                    caseServerPressureReentry(fec != 0, action);
        caseReceiveMessages(server);
    }
    require(wloopNTimers(getWorkerLoop(0)) == timers_at_start, "node timer root survived focused fixtures");
    const ww_lifecycle_context_t *context = wwLifecycleStartupRollback();
    require(workerInstallApplicationQuiesceRequest(getWorker(0), context) != kWorkerQuiesceRequestUnavailable,
            "worker quiescence failed");
    workerPerformQuiesce(getWorker(0), context);
    require(workerRequestDrain(getWorker(0)), "worker drain refused");
    workerPerformDrain(getWorker(0), context);
    require(workerRequestTeardown(getWorker(0)), "worker teardown refused");
    workerPerformTeardown(getWorker(0));
    destroyGlobalState();
    printf("tcp_over_udp_%s: all cases passed\n", selection);
    return 0;
}
