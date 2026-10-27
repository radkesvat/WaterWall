/*
 * Covers: bounded owner-engine TCP ACK coalescing before packet construction.
 * Setup: the existing small raw-engine runtime fixture, real IPv4/TCP handshakes and packets,
 * and a recording netif; no host sockets or timers are needed for successful batches.
 * Checks: exact cumulative ACK/window values and packet counts, scaled and unscaled credit/zero-window updates,
 * complete wide credit returns with batching and output-failure retry,
 * recovery/control traffic, piggybacking, queued PCB retirement, failed output retry, and two owners.
 * Limits: this proves protocol behavior and ACK suppression, not application throughput.
 * CTest: waterwall.lwip_ack_batch_unit (Debug and Release).
 */
#include "fixtures/lwip/lwip_engine_test_runtime.h"
#include "lwip/ip.h"
#include "lwip/netif.h"
#include "lwip/priv/tcp_priv.h"

enum
{
    payload_limit = 1460
};

typedef struct
{
    ww_lwip_engine_t *engine, *previous;
    struct netif      netif;
    struct tcp_pcb   *pcb;
    uint32_t          peer_next, last_ack, initial_peer_sequence;
    uint16_t          last_window, last_payload;
    uint8_t           last_flags, offered_scale;
    unsigned          outputs, received, fins, recursive_refusals, allocation_refusals;
    bool return_credit, fail_output, try_recursive_input, scaled_handshake, fail_allocation, clobber_output;
} fixture_t;

static fixture_t         fixtures[2];
static pthread_barrier_t rendezvous;

struct pbuf *__real_pbuf_alloc(pbuf_layer layer, u16_t length, pbuf_type type);

struct pbuf *__wrap_pbuf_alloc(pbuf_layer layer, u16_t length, pbuf_type type)
{
    if (owner < 2 && fixtures[owner].fail_allocation)
    {
        ++fixtures[owner].allocation_refusals;
        return NULL;
    }
    return __real_pbuf_alloc(layer, length, type);
}

static void put16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t) (value >> 8);
    p[1] = (uint8_t) value;
}

static void put32(uint8_t *p, uint32_t value)
{
    put16(p, (uint16_t) (value >> 16));
    put16(p + 2, (uint16_t) value);
}

static uint16_t get16(const uint8_t *p)
{
    return (uint16_t) (((unsigned) p[0] << 8) | p[1]);
}

static uint32_t get32(const uint8_t *p)
{
    return ((uint32_t) get16(p) << 16) | get16(p + 2);
}

static err_t output(struct netif *netif, struct pbuf *packet, const ip4_addr_t *destination)
{
    (void) destination;
    fixture_t *f = netif->state;
    uint8_t    bytes[60];
    CHECK(f == &fixtures[owner] && wwLwipEngineCurrent() == f->engine);
    const uint16_t copied = (uint16_t) LWIP_MIN(packet->tot_len, sizeof(bytes));
    CHECK(copied >= 40 && pbuf_copy_partial(packet, bytes, copied, 0) == copied);
    CHECK(bytes[0] == 0x45 && bytes[9] == 6);
    ++f->outputs;
    f->last_ack     = get32(bytes + 28);
    f->last_flags   = bytes[33];
    f->last_window  = get16(bytes + 34);
    f->last_payload = (uint16_t) (get16(bytes + 2) - 20 - (bytes[32] >> 4) * 4);
    if (f->last_flags & TCP_SYN)
    {
        const unsigned header_length = 20U + (bytes[32] >> 4) * 4U;
        CHECK(header_length <= copied && f->last_window == UINT16_MAX);
        for (unsigned i = 40; i < header_length && bytes[i] != 0;)
        {
            if (bytes[i] == 1)
            {
                ++i;
                continue;
            }
            CHECK(i + 1 < header_length && bytes[i + 1] >= 2 && i + bytes[i + 1] <= header_length);
            if (bytes[i] == 3)
            {
                CHECK(bytes[i + 1] == 3);
                f->offered_scale = bytes[i + 2];
            }
            i += bytes[i + 1];
        }
    }
    if (f->try_recursive_input)
    {
        f->try_recursive_input = false;
        struct pbuf *nested    = pbuf_alloc(PBUF_RAW, 20, PBUF_RAM);
        CHECK(nested != NULL);
        CHECK(wwLwipEngineInput(f->engine, nested, netif) == ERR_ARG);
        pbuf_free(nested);
        ++f->recursive_refusals;
    }
    if (f->clobber_output)
    {
        CHECK(packet->len >= 40);
        put32((uint8_t *) packet->payload + 28, UINT32_C(0x11223344));
        put16((uint8_t *) packet->payload + 34, UINT16_MAX);
    }
    return f->fail_output ? ERR_IF : ERR_OK;
}

static err_t initNetif(struct netif *netif)
{
    netif->name[0] = 'a';
    netif->name[1] = 'b';
    netif->mtu     = 1500;
    netif->output  = output;
    return ERR_OK;
}

static void lost(void *argument, err_t error)
{
    fixture_t *f = argument;
    CHECK(error == ERR_ABRT || error == ERR_RST);
    f->pcb = NULL;
}

static err_t receive(void *argument, struct tcp_pcb *pcb, struct pbuf *packet, err_t error)
{
    fixture_t *f = argument;
    CHECK(pcb == f->pcb && error == ERR_OK);
    if (packet == NULL)
    {
        ++f->fins;
        return ERR_OK;
    }
    f->received += packet->tot_len;
    if (f->return_credit)
        tcp_recved(pcb, packet->tot_len);
    pbuf_free(packet);
    return ERR_OK;
}

static void inject(fixture_t *f, uint32_t sequence, uint8_t flags, uint16_t payload)
{
    CHECK(payload <= payload_limit && f->pcb != NULL);
    const uint16_t options                    = f->scaled_handshake && (flags & TCP_SYN) != 0 ? 8 : 0;
    const uint16_t length                     = (uint16_t) (40 + options + payload);
    uint8_t        bytes[48 + payload_limit]  = {0x45};
    uint8_t        pseudo[40 + payload_limit] = {0};
    put16(bytes + 2, length);
    bytes[8]  = 64;
    bytes[9]  = 6;
    bytes[12] = 10;
    bytes[15] = 2;
    bytes[16] = 10;
    bytes[19] = 1;
    put16(bytes + 20, 80);
    put16(bytes + 22, f->pcb->local_port);
    put32(bytes + 24, sequence);
    put32(bytes + 28, (flags & TCP_ACK) != 0 ? f->pcb->snd_nxt : 0);
    bytes[32] = (uint8_t) ((5 + options / 4) << 4);
    bytes[33] = flags;
    put16(bytes + 34, 65535);
    if (options != 0)
    {
        const uint8_t opts[] = {2, 4, TCP_MSS >> 8, TCP_MSS & 255, 3, 3, 7, 0};
        memcpy(bytes + 40, opts, sizeof(opts));
    }
    memset(bytes + 40 + options, 0x5a, payload);
    memcpy(pseudo, bytes + 12, 8);
    pseudo[9] = 6;
    put16(pseudo + 10, (uint16_t) (length - 20));
    memcpy(pseudo + 12, bytes + 20, length - 20);
    uint16_t sum = (uint16_t) ~wwLwipChecksum(pseudo, length - 8);
    memcpy(bytes + 36, &sum, sizeof(sum));
    sum = (uint16_t) ~wwLwipChecksum(bytes, 20);
    memcpy(bytes + 10, &sum, sizeof(sum));
    struct pbuf *packet = pbuf_alloc(PBUF_RAW, length, PBUF_RAM);
    CHECK(packet != NULL && pbuf_take(packet, bytes, length) == ERR_OK);
    CHECK(wwLwipEngineInput(f->engine, packet, &f->netif) == ERR_OK);
}

static void data(fixture_t *f, uint16_t length)
{
    inject(f, f->peer_next, TCP_ACK, length);
    f->peer_next += length;
}

static void expectAck(fixture_t *f, unsigned count, uint32_t ack, uint16_t window)
{
    CHECK(f->outputs == count && f->last_ack == ack && f->last_window == window);
    CHECK(f->last_flags == TCP_ACK && f->last_payload == 0);
}

static void expectAdvertisement(fixture_t *f)
{
    CHECK((f->last_flags & (TCP_ACK | TCP_RST)) == TCP_ACK);
    const unsigned scale =
        (f->last_flags & TCP_SYN) == 0 && (f->pcb->flags & TF_WND_SCALE) != 0 ? f->pcb->rcv_scale : 0;
    CHECK(f->pcb->ww_rcv_advertised_valid);
    CHECK(f->pcb->ww_rcv_advertised_edge == f->last_ack + ((uint32_t) f->last_window << scale));
}

static void begin(fixture_t *f)
{
    wwLwipEngineLeave(f->engine, f->previous);
    wwLwipEngineBeginAckBatch(f->engine);
    CHECK(wwLwipEngineCurrent() == NULL);
    CHECK(wwLwipEngineEnter(f->engine, &f->previous));
}

static void end(fixture_t *f)
{
    wwLwipEngineLeave(f->engine, f->previous);
    wwLwipEngineEndAckBatch(f->engine);
    CHECK(wwLwipEngineCurrent() == NULL);
    CHECK(wwLwipEngineEnter(f->engine, &f->previous));
}

static void connectPeer(fixture_t *f, uint16_t port)
{
    f->pcb = tcp_new();
    CHECK(f->pcb != NULL && tcp_bind_netif(f->pcb, &f->netif) == ERR_OK);
    CHECK(! f->pcb->ww_rcv_advertised_valid);
    CHECK(tcp_bind(f->pcb, IP_ADDR_ANY, port) == ERR_OK);
    tcp_arg(f->pcb, f);
    tcp_err(f->pcb, lost);
    tcp_recv(f->pcb, receive);
    ip_addr_t peer;
    IP_ADDR4(&peer, 10, 0, 0, 2);
    begin(f);
    CHECK(tcp_connect(f->pcb, &peer, 80, NULL) == ERR_OK);
    CHECK(f->outputs == 1 && f->last_flags == TCP_SYN);
    CHECK(f->offered_scale == 7);
    CHECK(! f->pcb->ww_rcv_advertised_valid);
    inject(f, f->initial_peer_sequence, TCP_SYN | TCP_ACK, 0);
    f->peer_next = f->initial_peer_sequence + 1U;
    CHECK(f->pcb->state == ESTABLISHED);
    expectAck(f, 2, f->peer_next, f->scaled_handshake ? 32768 : UINT16_MAX);
    CHECK(f->pcb->rcv_wnd == (f->scaled_handshake ? 4U * 1024U * 1024U : UINT16_MAX));
    if (f->scaled_handshake)
        CHECK(f->pcb->rcv_scale == 7 && f->pcb->snd_scale == 7);
    expectAdvertisement(f);
    end(f);
    CHECK(f->outputs == 2);
    f->outputs = 0;
}

static fixture_t *startAt(bool return_credit, bool scale, uint32_t initial_peer_sequence)
{
    fixture_t *f = &fixtures[owner];
    memset(f, 0, sizeof(*f));
    owner_loop               = (struct wloop_s *) &f->netif;
    f->return_credit         = return_credit;
    f->scaled_handshake      = scale;
    f->offered_scale         = UINT8_MAX;
    f->initial_peer_sequence = initial_peer_sequence;
    f->engine                = wwLwipEngineCreate((uint8_t) owner, (struct wloop_s *) owner_loop);
    CHECK(f->engine != NULL && wwLwipEngineEnter(f->engine, &f->previous));
    ip4_addr_t address, mask, gateway;
    IP4_ADDR(&address, 10, 0, 0, 1);
    IP4_ADDR(&mask, 255, 255, 255, 0);
    ip4_addr_set_zero(&gateway);
    CHECK(netif_add(&f->netif, &address, &mask, &gateway, f, initNetif, ip_input) != NULL);
    netif_set_up(&f->netif);
    netif_set_link_up(&f->netif);
    connectPeer(f, 1234);
    return f;
}

static fixture_t *startWithScale(bool return_credit, bool scale)
{
    return startAt(return_credit, scale, 100);
}

static fixture_t *start(bool return_credit)
{
    return startWithScale(return_credit, false);
}

static void stop(fixture_t *f)
{
    if (f->pcb != NULL)
        tcp_abort(f->pcb);
    wwLwipEngineLeave(f->engine, f->previous);
    wwLwipEngineDestroy(f->engine);
    CHECK(wwLwipEngineCurrent() == NULL);
}

static void batchAndCredit(void)
{
    fixture_t *f = start(true);
    for (unsigned i = 0; i < 8; ++i)
        data(f, payload_limit);
    expectAck(f, 4, f->peer_next, 65535);
    stop(f);

    f = start(true);
    begin(f);
    for (unsigned i = 0; i < 8; ++i)
        data(f, payload_limit);
    CHECK(f->outputs == 0 && f->received == 8 * payload_limit);
    f->try_recursive_input = true;
    end(f);
    expectAck(f, 1, f->peer_next, 65535);
    CHECK(f->recursive_refusals == 1);
    for (unsigned i = 0; i < 2; ++i)
    {
        begin(f);
        data(f, 1);
        CHECK(f->outputs == i + 1);
        end(f);
        expectAck(f, i + 2, f->peer_next, (uint16_t) (65535 - i - 1));
    }
    stop(f);

    f = start(false);
    begin(f);
    for (unsigned i = 0; i < 8; ++i)
        data(f, payload_limit);
    end(f);
    expectAck(f, 1, f->peer_next, 65535 - 8 * payload_limit);
    begin(f);
    tcp_recved(f->pcb, 4 * payload_limit);
    tcp_recved(f->pcb, 4 * payload_limit);
    CHECK(f->outputs == 1);
    end(f);
    expectAck(f, 2, f->peer_next, 65535);
    stop(f);
}

static void zeroWindow(void)
{
    fixture_t *f = start(false);
    begin(f);
    for (unsigned remaining = 65535; remaining != 0;)
    {
        uint16_t length = (uint16_t) LWIP_MIN(remaining, payload_limit);
        data(f, length);
        remaining -= length;
    }
    end(f);
    expectAck(f, 1, f->peer_next, 0);
    begin(f);
    CHECK(TCP_WND_UPDATE_THRESHOLD == 5840);
    tcp_recved(f->pcb, 1460);
    CHECK(f->outputs == 1);
    tcp_recved(f->pcb, 4380);
    expectAck(f, 2, f->peer_next, TCP_WND_UPDATE_THRESHOLD);
    end(f);
    CHECK(f->outputs == 2);
    stop(f);
}

static void scaledWindowBatches(void)
{
    fixture_t     *f        = startWithScale(false, true);
    const uint32_t capacity = 4U * 1024U * 1024U;
    unsigned       batches  = 0;

    /* Each receive quantum stays below device packet/byte limits. The complete
     * scaled window drains across many independent batches, never one burst. */
    while (f->received < capacity)
    {
        begin(f);
        for (unsigned packets = 0; packets < 64 && f->received < capacity; ++packets)
            data(f, (uint16_t) LWIP_MIN(capacity - f->received, payload_limit));
        if (f->received != capacity)
            CHECK(f->outputs == batches);
        end(f);
        expectAck(f, ++batches, f->peer_next, (uint16_t) ((capacity - f->received) >> 7));
        CHECK(f->pcb->rcv_wnd == capacity - f->received);
    }
    CHECK(batches > 1 && f->last_window == 0 && f->pcb->rcv_wnd == 0);

    begin(f);
    tcp_recved(f->pcb, TCP_WND_UPDATE_THRESHOLD);
    expectAck(f, batches + 1, f->peer_next, TCP_WND_UPDATE_THRESHOLD >> 7);
    CHECK(f->pcb->rcv_wnd == TCP_WND_UPDATE_THRESHOLD);
    end(f);
    CHECK(f->outputs == batches + 1);
    tcp_fasttmr();
    CHECK(f->outputs == batches + 1);

    begin(f);
    tcp_recved(f->pcb, TCP_WND_UPDATE_THRESHOLD);
    tcp_recved(f->pcb, TCP_WND_UPDATE_THRESHOLD);
    CHECK(f->outputs == batches + 1);
    end(f);
    expectAck(f, batches + 2, f->peer_next, (3U * TCP_WND_UPDATE_THRESHOLD) >> 7);
    stop(f);
}

static void drainReceiveWindow(fixture_t *f)
{
    while (f->pcb->rcv_wnd != 0)
    {
        const unsigned expected_outputs = f->outputs + 1;
        begin(f);
        for (unsigned packets = 0; packets < 64 && f->pcb->rcv_wnd != 0; ++packets)
            data(f, (uint16_t) LWIP_MIN(f->pcb->rcv_wnd, payload_limit));
        end(f);
        expectAck(f, expected_outputs, f->peer_next, (uint16_t) (f->pcb->rcv_wnd >> (f->scaled_handshake ? 7 : 0)));
        expectAdvertisement(f);
    }
    CHECK(f->pcb->ww_rcv_advertised_edge == f->peer_next);
}

static void wideReceiveCredit(void)
{
    fixture_t *f = startWithScale(false, true);
    begin(f);
    for (unsigned i = 0; i < 90; ++i)
        data(f, payload_limit);
    end(f);
    unsigned before = f->outputs;
    begin(f);
    wwLwipTcpRecved(f->pcb, f->received);
    CHECK(f->outputs == before && f->pcb->rcv_wnd == TCP_WND);
    end(f);
    expectAck(f, ++before, f->peer_next, TCP_WND >> 7);
    expectAdvertisement(f);
    stop(f);

    f = startWithScale(false, true);
    drainReceiveWindow(f);
    const uint32_t closed_edge = f->pcb->ww_rcv_advertised_edge;
    before                     = f->outputs;
    begin(f);
    f->fail_output = true;
    wwLwipTcpRecved(f->pcb, TCP_WND);
    /* Reopening a closed wire window still bypasses an active batch. The
     * complete update retains the ordinary output-failure retry obligation. */
    expectAck(f, ++before, f->peer_next, TCP_WND >> 7);
    CHECK(f->pcb->ww_rcv_advertised_edge == closed_edge && (f->pcb->flags & TF_ACK_NOW) != 0);
    f->fail_output = false;
    tcp_fasttmr();
    expectAck(f, ++before, f->peer_next, TCP_WND >> 7);
    expectAdvertisement(f);
    end(f);
    CHECK(f->outputs == before);
    stop(f);
}

static void leaveQuantizedZero(fixture_t *f, uint16_t remaining)
{
    drainReceiveWindow(f);
    const unsigned before = f->outputs;
    tcp_recved(f->pcb, 6144);
    expectAck(f, before + 1, f->peer_next, 48);
    begin(f);
    while (f->pcb->rcv_wnd > remaining)
        data(f, (uint16_t) LWIP_MIN(f->pcb->rcv_wnd - remaining, payload_limit));
    end(f);
    expectAck(f, before + 2, f->peer_next, 0);
    CHECK(f->pcb->rcv_wnd == remaining && f->pcb->rcv_ann_wnd == remaining);
    expectAdvertisement(f);
}

static void quantizedZeroAndWrap(void)
{
    const uint16_t small_credit[] = {1, 64, 127};
    for (unsigned i = 0; i < sizeof(small_credit) / sizeof(small_credit[0]); ++i)
    {
        fixture_t *f = startAt(false, true, i == 2 ? UINT32_MAX - 31U : 100U);
        if (i == 2)
            CHECK(f->pcb->ww_rcv_advertised_edge < f->peer_next &&
                  TCP_SEQ_GT(f->pcb->ww_rcv_advertised_edge, f->peer_next));
        leaveQuantizedZero(f, small_credit[i]);
        const unsigned before = f->outputs;
        begin(f);
        CHECK(tcp_keepalive(f->pcb) == ERR_OK);
        expectAck(f, before + 1, f->peer_next, 0);
        expectAdvertisement(f);
        CHECK(f->pcb->ww_rcv_advertised_edge == f->peer_next);
        tcp_recved(f->pcb, 1460);
        CHECK(f->outputs == before + 1);
        tcp_recved(f->pcb, 4380);
        expectAck(f, before + 2, f->peer_next, (TCP_WND_UPDATE_THRESHOLD + small_credit[i]) >> 7);
        expectAdvertisement(f);
        end(f);
        CHECK(f->outputs == before + 2);
        stop(f);
    }
}

static void failedAdvertisementAndRetry(void)
{
    for (unsigned scaled = 0; scaled != 2; ++scaled)
    {
        fixture_t *f = startWithScale(false, scaled != 0);
        drainReceiveWindow(f);
        const uint32_t closed_edge = f->pcb->ww_rcv_advertised_edge;
        unsigned       before      = f->outputs;
        begin(f);
        tcp_recved(f->pcb, 1460);
        f->fail_output = true;
        tcp_recved(f->pcb, 4380);
        expectAck(f, ++before, f->peer_next, (uint16_t) (5840U >> (scaled ? 7 : 0)));
        CHECK(f->pcb->ww_rcv_advertised_edge == closed_edge && (f->pcb->flags & TF_ACK_NOW) != 0);
        f->fail_output = false;
        tcp_fasttmr();
        expectAck(f, ++before, f->peer_next, (uint16_t) (5840U >> (scaled ? 7 : 0)));
        expectAdvertisement(f);
        end(f);
        CHECK(f->outputs == before);
        stop(f);

        f = startWithScale(false, scaled != 0);
        drainReceiveWindow(f);
        const uint32_t piggyback_closed_edge = f->pcb->ww_rcv_advertised_edge;
        before                               = f->outputs;
        begin(f);
        tcp_recved(f->pcb, 1460);
        CHECK(tcp_write(f->pcb, "reply", 5, TCP_WRITE_FLAG_COPY) == ERR_OK);
        f->fail_output = true;
        CHECK(tcp_output(f->pcb) == ERR_IF);
        CHECK(f->outputs == ++before && f->last_payload == 5);
        CHECK(f->pcb->ww_rcv_advertised_edge == piggyback_closed_edge);
        f->fail_output = false;
        /* Upstream intended-edge accounting already advanced for the failed
         * segment. Reach its unchanged update threshold with fresh credit. */
        tcp_recved(f->pcb, TCP_WND_UPDATE_THRESHOLD);
        CHECK(f->outputs == ++before && f->last_payload == 5 && f->last_ack == f->peer_next);
        CHECK(f->last_window == (7300U >> (scaled ? 7 : 0)));
        expectAdvertisement(f);
        end(f);
        CHECK(f->outputs == before);
        stop(f);
    }
}

static void outputPathAdvertisements(void)
{
    fixture_t *f = startWithScale(false, true);
    leaveQuantizedZero(f, 127);
    uint32_t edge   = f->pcb->ww_rcv_advertised_edge;
    unsigned before = f->outputs;
    CHECK(f->outputs == before && f->pcb->rcv_ann_wnd == 127);

    CHECK(tcp_output(f->pcb) == ERR_OK && tcp_zero_window_probe(f->pcb) == ERR_OK);
    CHECK(f->outputs == before && f->pcb->ww_rcv_advertised_edge == edge);
    f->fail_allocation = true;
    CHECK(tcp_send_empty_ack(f->pcb) == ERR_BUF && f->allocation_refusals == 1);
    f->fail_allocation = false;
    CHECK(f->outputs == before && f->pcb->ww_rcv_advertised_edge == edge);
    netif_set_down(&f->netif);
    CHECK(tcp_bind_netif(f->pcb, NULL) == ERR_OK);
    CHECK(tcp_keepalive(f->pcb) == ERR_RTE);
    CHECK(f->outputs == before && f->pcb->ww_rcv_advertised_edge == edge);
    netif_set_up(&f->netif);
    CHECK(tcp_bind_netif(f->pcb, &f->netif) == ERR_OK);

    f->clobber_output = true;
    CHECK(tcp_send_empty_ack(f->pcb) == ERR_OK);
    f->clobber_output = false;
    expectAck(f, ++before, f->peer_next, 0);
    expectAdvertisement(f);
    CHECK(f->pcb->ww_rcv_advertised_edge == edge);

    tcp_rst(f->pcb,
            f->pcb->snd_nxt,
            f->peer_next + 17U,
            &f->pcb->local_ip,
            &f->pcb->remote_ip,
            f->pcb->local_port,
            f->pcb->remote_port);
    CHECK(f->outputs == ++before && (f->last_flags & TCP_RST) != 0);
    CHECK(f->pcb->ww_rcv_advertised_edge == edge);
    tcp_recved(f->pcb, TCP_WND_UPDATE_THRESHOLD);
    expectAck(f, ++before, f->peer_next, (TCP_WND_UPDATE_THRESHOLD + 127U) >> 7);
    expectAdvertisement(f);
    edge = f->pcb->ww_rcv_advertised_edge;

    begin(f);
    tcp_recved(f->pcb, TCP_WND_UPDATE_THRESHOLD);
    CHECK(f->outputs == before);
    f->fail_output = true;
    CHECK(tcp_keepalive(f->pcb) == ERR_IF && f->outputs == ++before);
    CHECK(f->pcb->ww_rcv_advertised_edge == edge);
    f->fail_output = false;
    CHECK(tcp_keepalive(f->pcb) == ERR_OK);
    expectAck(f, ++before, f->peer_next, (2U * TCP_WND_UPDATE_THRESHOLD + 127U) >> 7);
    expectAdvertisement(f);
    end(f);
    CHECK(f->outputs == before);

    CHECK(tcp_write(f->pcb, "probe", 5, TCP_WRITE_FLAG_COPY) == ERR_OK);
    edge = f->pcb->ww_rcv_advertised_edge;
    tcp_recved(f->pcb, 127);
    f->fail_output = true;
    CHECK(tcp_zero_window_probe(f->pcb) == ERR_IF && f->outputs == ++before);
    CHECK(f->pcb->ww_rcv_advertised_edge == edge);
    f->fail_output = false;
    CHECK(tcp_zero_window_probe(f->pcb) == ERR_OK && f->outputs == ++before && f->last_payload == 1);
    expectAdvertisement(f);
    stop(f);
}

static void synWindowAdvertisement(void)
{
    fixture_t *f = startWithScale(false, true);
    tcp_abort(f->pcb);
    CHECK(f->pcb == NULL);
    struct tcp_pcb *listener = tcp_new();
    CHECK(listener != NULL && tcp_bind_netif(listener, &f->netif) == ERR_OK);
    CHECK(tcp_bind(listener, IP_ADDR_ANY, 1235) == ERR_OK);
    listener = tcp_listen(listener);
    CHECK(listener != NULL);
    f->pcb     = listener;
    f->outputs = 0;
    inject(f, 100, TCP_SYN, 0);
    f->peer_next = 101;
    f->pcb       = tcp_active_pcbs;
    CHECK(f->pcb != NULL && f->pcb->state == SYN_RCVD && f->pcb->local_port == 1235);
    CHECK(f->outputs == 1 && f->last_flags == (TCP_SYN | TCP_ACK) && f->last_window == UINT16_MAX);
    expectAdvertisement(f);
    CHECK(f->pcb->ww_rcv_advertised_edge == 101U + UINT16_MAX);
    CHECK(tcp_close(listener) == ERR_OK);
    stop(f);
}

static void recoveryAndControl(void)
{
    fixture_t *f = start(true);
    begin(f);
    data(f, 512);
    inject(f, f->peer_next - 512, TCP_ACK, 512);
    expectAck(f, 1, f->peer_next, 65535 - 512);
    end(f);
    CHECK(f->outputs == 1);
    begin(f);
    inject(f, f->peer_next + 512, TCP_ACK, 512);
    expectAck(f, 2, f->peer_next, 65535 - 512);
    inject(f, f->peer_next, TCP_ACK, 512);
    f->peer_next += 1024;
    CHECK(f->outputs == 3 && f->received == 1536 && f->last_ack == f->peer_next);
    end(f);
    CHECK(f->outputs == 3);
    tcp_fasttmr();
    CHECK(f->outputs == 3 && f->last_ack == f->peer_next);
    begin(f);
    inject(f, f->peer_next - 256, TCP_ACK, 512);
    f->peer_next += 256;
    CHECK(f->outputs == 3 && f->received == 1792);
    end(f);
    CHECK(f->outputs == 3);
    tcp_fasttmr();
    CHECK(f->outputs == 4 && f->last_ack == f->peer_next);
    begin(f);
    data(f, 512);
    unsigned before = f->outputs;
    inject(f, f->peer_next, TCP_FIN | TCP_ACK, 0);
    ++f->peer_next;
    CHECK(f->outputs == before + 1 && f->last_ack == f->peer_next && f->fins == 1);
    CHECK(f->pcb->state == CLOSE_WAIT);
    end(f);
    CHECK(f->outputs == before + 1);
    stop(f);
}

static void gapRecovery(void)
{
    for (unsigned batching = 0; batching != 2; ++batching)
    {
        for (unsigned queued = 0; queued != 2; ++queued)
        {
            for (unsigned overlap = 0; overlap != 2; ++overlap)
            {
                fixture_t *f = start(true);
                if (batching)
                    begin(f);
                if (queued)
                    data(f, 256);
                inject(f, f->peer_next + 512, TCP_ACK, 256);
                CHECK(f->pcb->ooseq != NULL);
                CHECK((f->pcb->flags & (TF_ACK_DELAY | TF_ACK_NOW)) == 0);
                CHECK((f->pcb->ww_ack_previous != NULL) == (batching && queued));
                unsigned outputs = f->outputs;
                /* Both partial gap progress and complete gap closure ACK
                 * immediately, including a trimmed duplicate prefix. */
                inject(f, f->peer_next - overlap * 64, TCP_ACK, (uint16_t) (256 + overlap * 64));
                f->peer_next += 256;
                CHECK(f->outputs == ++outputs && f->last_ack == f->peer_next);
                CHECK(f->pcb->ooseq != NULL);
                data(f, 256);
                f->peer_next += 256;
                CHECK(f->outputs == ++outputs && f->last_ack == f->peer_next);
                CHECK(f->pcb->ooseq == NULL);
                if (batching)
                    end(f);
                tcp_fasttmr();
                CHECK(f->outputs == outputs);
                stop(f);
            }
        }
    }
}

static void piggybackAndRetirement(void)
{
    fixture_t *f = start(true);
    begin(f);
    data(f, 512);
    CHECK(f->outputs == 0);
    CHECK(tcp_write(f->pcb, "reply", 5, TCP_WRITE_FLAG_COPY) == ERR_OK);
    CHECK(tcp_output(f->pcb) == ERR_OK);
    CHECK(f->outputs == 1 && f->last_ack == f->peer_next && f->last_payload == 5);
    end(f);
    CHECK(f->outputs == 1);
    stop(f);

    f = start(true);
    begin(f);
    data(f, 512);
    inject(f, f->peer_next, TCP_RST | TCP_ACK, 0);
    CHECK(f->pcb == NULL && f->outputs == 0);
    end(f);
    CHECK(f->outputs == 0);
    stop(f);

    f = start(true);
    begin(f);
    data(f, 512);
    tcp_abort(f->pcb);
    /* tcp_pcb_remove sends its pending ACK before tcp_abandon emits the RST. */
    CHECK(f->pcb == NULL && f->outputs == 2 && (f->last_flags & TCP_RST));
    end(f);
    CHECK(f->outputs == 2);
    stop(f);
}

static void retireQueuedConnections(void)
{
    fixture_t      *f              = start(true);
    struct tcp_pcb *connections[3] = {f->pcb};
    for (unsigned i = 1; i < 3; ++i)
    {
        connectPeer(f, (uint16_t) (1234 + i));
        connections[i] = f->pcb;
    }
    begin(f);
    for (unsigned i = 0; i < 3; ++i)
    {
        f->pcb       = connections[i];
        f->peer_next = 101;
        data(f, 512);
    }
    CHECK(f->outputs == 0);
    /* Remove the middle, then the head, leaving the old tail to flush. */
    f->pcb = connections[1];
    tcp_abort(f->pcb);
    CHECK(f->pcb == NULL && f->outputs == 2);
    f->pcb = connections[2];
    tcp_abort(f->pcb);
    CHECK(f->pcb == NULL && f->outputs == 4);
    f->pcb = connections[0];
    end(f);
    expectAck(f, 5, f->peer_next, 65535 - 512);
    stop(f);
}

static void failedOutput(void)
{
    fixture_t *f = start(true);
    begin(f);
    data(f, 512);
    f->fail_output = true;
    end(f);
    expectAck(f, 1, f->peer_next, 65535 - 512);
    f->fail_output = false;
    tcp_fasttmr();
    expectAck(f, 2, f->peer_next, 65535 - 512);
    tcp_fasttmr();
    CHECK(f->outputs == 2);
    stop(f);
}

static void meet(void)
{
    int result = pthread_barrier_wait(&rendezvous);
    CHECK(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD);
}

static void *isolatedBatch(void *argument)
{
    owner        = (unsigned) (uintptr_t) argument;
    fixture_t *f = start(true);
    begin(f);
    data(f, (uint16_t) (512 + owner));
    CHECK(f->outputs == 0);
    meet();
    if (owner == 0)
        end(f);
    meet();
    CHECK(f->outputs == (owner == 0 ? 1U : 0U));
    if (owner == 1)
        end(f);
    expectAck(f, 1, f->peer_next, (uint16_t) (65535 - 512 - owner));
    meet();
    stop(f);
    return NULL;
}

int main(void)
{
    wwLwipEngineSharedInit();
    owner = 0;
    testCaseSet("batch and receive credit");
    batchAndCredit();
    testCaseSet("zero-window reopening");
    zeroWindow();
    testCaseSet("scaled window ACK batches and immediate zero-window reopening");
    scaledWindowBatches();
    testCaseSet("wide receive credit preserves batching, zero-window reopening and output retry");
    wideReceiveCredit();
    testCaseSet("scaled quantized-zero windows and sequence wrap");
    quantizedZeroAndWrap();
    testCaseSet("failed reopening and piggyback advertisements retry");
    failedAdvertisementAndRetry();
    testCaseSet("ACK/control output acceptance and failure accounting");
    outputPathAdvertisements();
    testCaseSet("SYN ACK window advertisements remain unscaled");
    synWindowAdvertisement();
    testCaseSet("recovery and connection control");
    recoveryAndControl();
    testCaseSet("gap recovery ACKs with and without batching");
    gapRecovery();
    testCaseSet("piggyback and queued PCB retirement");
    piggybackAndRetirement();
    testCaseSet("retire queued middle and head connections");
    retireQueuedConnections();
    testCaseSet("failed ACK output retry");
    failedOutput();
    testCaseSet("concurrent engine isolation");
    CHECK(pthread_barrier_init(&rendezvous, NULL, 2) == 0);
    pthread_t threads[2];
    for (uintptr_t i = 0; i < 2; ++i)
        CHECK(pthread_create(&threads[i], NULL, isolatedBatch, (void *) i) == 0);
    for (unsigned i = 0; i < 2; ++i)
        CHECK(pthread_join(threads[i], NULL) == 0);
    CHECK(pthread_barrier_destroy(&rendezvous) == 0);
    wwLwipEngineSharedCleanup();
    puts("bounded TCP ACK batches preserve cumulative progress, windows, recovery and owner isolation");
    return 0;
}
