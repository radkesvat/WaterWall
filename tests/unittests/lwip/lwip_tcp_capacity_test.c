/*
 * Covers: the production TCP send cap, scaled receive window and credit accounting.
 * Setup: the existing isolated owner-engine runtime, production lwIP pools, real IPv4/TCP
 * handshakes, and a recording netif. No sockets, worker loops or wall-clock timers are used.
 * Checks: 2 MiB COPY queue across 16-bit writes, refusal at capacity, byte-exact output,
 * cumulative ACK credit across 16-bit callbacks, 4 MiB receive exhaustion/reopening, and
 * the unscaled peer's 65535-byte fallback. Resource accounting is empty after each case.
 * Limits: this proves stack capacity and protocol behavior, not application throughput.
 * CTest: waterwall.lwip_tcp_capacity_unit (Debug and Release).
 */
#include "fixtures/lwip/lwip_engine_test_runtime.h"
#include "lwip/ip.h"
#include "lwip/netif.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/stats.h"
#include "shared_pools.h"

typedef struct
{
    ww_lwip_engine_t *engine, *previous;
    struct netif      netif;
    struct tcp_pcb   *pcb;
    uint32_t          peer_next, output_next, sent, acknowledged, received, last_ack;
    uint16_t          last_window;
    uint8_t           offered_scale;
    unsigned          sent_callbacks;
} fixture_t;

static uint8_t valueAt(uint32_t offset)
{
    return (uint8_t) ((offset * 19U) ^ (offset >> 8U));
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
    uint8_t    bytes[1500];
    CHECK(wwLwipEngineCurrent() == f->engine && packet->tot_len <= sizeof(bytes));
    CHECK(pbuf_copy_partial(packet, bytes, packet->tot_len, 0) == packet->tot_len);
    CHECK(bytes[0] == 0x45 && bytes[9] == 6 && get16(bytes + 2) == packet->tot_len);
    const uint16_t header = (uint16_t) (20 + (bytes[32] >> 4) * 4);
    CHECK(header >= 40 && header <= packet->tot_len);
    f->last_ack    = get32(bytes + 28);
    f->last_window = get16(bytes + 34);
    if (bytes[33] & TCP_SYN)
    {
        CHECK(f->last_window == UINT16_MAX);
        for (unsigned i = 40; i < header && bytes[i] != 0;)
        {
            if (bytes[i] == 1)
            {
                ++i;
                continue;
            }
            CHECK(i + 1 < header && bytes[i + 1] >= 2 && i + bytes[i + 1] <= header);
            if (bytes[i] == 3)
            {
                CHECK(bytes[i + 1] == 3);
                f->offered_scale = bytes[i + 2];
            }
            i += bytes[i + 1];
        }
        f->output_next = get32(bytes + 24) + 1;
    }
    const uint16_t payload = (uint16_t) (packet->tot_len - header);
    if (payload != 0)
    {
        CHECK(payload <= TCP_MSS && get32(bytes + 24) == f->output_next);
        for (unsigned i = 0; i < payload; ++i)
            CHECK(bytes[header + i] == valueAt(f->sent + i));
        f->output_next += payload;
        f->sent += payload;
    }
    return ERR_OK;
}

static err_t initNetif(struct netif *netif)
{
    netif->name[0] = 'c';
    netif->name[1] = 'p';
    netif->mtu     = 1500;
    netif->output  = output;
    return ERR_OK;
}

static err_t receive(void *argument, struct tcp_pcb *pcb, struct pbuf *packet, err_t error)
{
    fixture_t *f = argument;
    CHECK(pcb == f->pcb && error == ERR_OK && packet != NULL);
    uint8_t bytes[TCP_MSS];
    CHECK(packet->tot_len <= sizeof(bytes));
    CHECK(pbuf_copy_partial(packet, bytes, packet->tot_len, 0) == packet->tot_len);
    for (unsigned i = 0; i < packet->tot_len; ++i)
        CHECK(bytes[i] == valueAt(f->received + i));
    f->received += packet->tot_len;
    pbuf_free(packet);
    return ERR_OK;
}

static err_t sent(void *argument, struct tcp_pcb *pcb, u16_t length)
{
    fixture_t *f = argument;
    CHECK(pcb == f->pcb && length != 0);
    f->acknowledged += length;
    ++f->sent_callbacks;
    return ERR_OK;
}

static void inject(fixture_t *f, uint8_t flags, uint16_t payload, bool scale)
{
    CHECK(payload <= TCP_MSS && (! scale || flags == (TCP_SYN | TCP_ACK)));
    const uint16_t options             = scale ? 8 : 0;
    const uint16_t length              = (uint16_t) (40 + options + payload);
    uint8_t        bytes[48 + TCP_MSS] = {0x45}, pseudo[40 + TCP_MSS] = {0};
    put16(bytes + 2, length);
    bytes[8]  = 64;
    bytes[9]  = 6;
    bytes[12] = 10;
    bytes[15] = 2;
    bytes[16] = 10;
    bytes[19] = 1;
    put16(bytes + 20, 80);
    put16(bytes + 22, f->pcb->local_port);
    put32(bytes + 24, f->peer_next);
    put32(bytes + 28, f->pcb->snd_nxt);
    bytes[32] = (uint8_t) ((5 + options / 4) << 4);
    bytes[33] = flags;
    put16(bytes + 34, UINT16_MAX);
    if (scale)
    {
        const uint8_t opts[] = {2, 4, TCP_MSS >> 8, TCP_MSS & 255, 3, 3, 7, 0};
        memcpy(bytes + 40, opts, sizeof(opts));
    }
    for (unsigned i = 0; i < payload; ++i)
        bytes[40 + options + i] = valueAt(f->received + i);
    memcpy(pseudo, bytes + 12, 8);
    pseudo[9] = 6;
    put16(pseudo + 10, (uint16_t) (length - 20));
    memcpy(pseudo + 12, bytes + 20, length - 20);
    uint16_t checksum = (uint16_t) ~wwLwipChecksum(pseudo, length - 8);
    memcpy(bytes + 36, &checksum, sizeof(checksum));
    checksum = (uint16_t) ~wwLwipChecksum(bytes, 20);
    memcpy(bytes + 10, &checksum, sizeof(checksum));
    struct pbuf *packet = pbuf_alloc(PBUF_RAW, length, PBUF_RAM);
    CHECK(packet != NULL && pbuf_take(packet, bytes, length) == ERR_OK);
    CHECK(wwLwipEngineInput(f->engine, packet, &f->netif) == ERR_OK);
}

static void start(fixture_t *f, bool scale)
{
    memset(f, 0, sizeof(*f));
    owner            = 0;
    owner_loop       = (struct wloop_s *) &f->netif;
    f->offered_scale = UINT8_MAX;
    f->engine        = wwLwipEngineCreate(0, (struct wloop_s *) owner_loop);
    CHECK(f->engine != NULL && wwLwipEngineEnter(f->engine, &f->previous));
    ip4_addr_t address, mask, gateway;
    IP4_ADDR(&address, 10, 0, 0, 1);
    IP4_ADDR(&mask, 255, 255, 255, 0);
    ip4_addr_set_zero(&gateway);
    CHECK(netif_add(&f->netif, &address, &mask, &gateway, f, initNetif, ip_input) != NULL);
    netif_set_up(&f->netif);
    netif_set_link_up(&f->netif);
    f->pcb = tcp_new();
    CHECK(f->pcb != NULL && tcp_bind_netif(f->pcb, &f->netif) == ERR_OK);
    CHECK(tcp_bind(f->pcb, IP_ADDR_ANY, 1234) == ERR_OK);
    tcp_arg(f->pcb, f);
    tcp_recv(f->pcb, receive);
    tcp_sent(f->pcb, sent);
    ip_addr_t peer;
    IP_ADDR4(&peer, 10, 0, 0, 2);
    CHECK(tcp_connect(f->pcb, &peer, 80, NULL) == ERR_OK);
    CHECK(f->offered_scale == 7);
    f->peer_next = 100;
    inject(f, TCP_SYN | TCP_ACK, 0, scale);
    ++f->peer_next;
    CHECK(f->pcb->state == ESTABLISHED && f->last_ack == f->peer_next);
    CHECK(f->pcb->rcv_wnd == (scale ? 4U * 1024U * 1024U : UINT16_MAX));
    CHECK(f->last_window == (scale ? 32768 : UINT16_MAX));
}

static void stop(fixture_t *f)
{
    tcp_abort(f->pcb);
    wwLwipEngineLeave(f->engine, f->previous);
    wwLwipEngineDestroy(f->engine);
    CHECK(wwLwipEngineCurrent() == NULL);
    CHECK(wwLwipSharedStats()->memp[MEMP_TCP_SEG]->used == 0 && wwLwipSharedStats()->mem.used == 0);
}

static void sendCapacity(void)
{
    testCaseSet("production send capacity and ACK credit");
    fixture_t f;
    start(&f, true);
    const uint32_t capacity = 2U * 1024U * 1024U;
    CHECK(f.pcb->snd_buf == capacity && tcp_sndbuf(f.pcb) == UINT16_MAX);
    uint8_t bytes[UINT16_MAX];
    for (uint32_t offset = 0; offset < capacity;)
    {
        const uint16_t length = (uint16_t) LWIP_MIN(capacity - offset, UINT16_MAX);
        for (unsigned i = 0; i < length; ++i)
            bytes[i] = valueAt(offset + i);
        CHECK(tcp_write(f.pcb, bytes, length, TCP_WRITE_FLAG_COPY) == ERR_OK);
        offset += length;
        CHECK(f.pcb->snd_buf == capacity - offset);
    }
    CHECK(tcp_write(f.pcb, bytes, 1, TCP_WRITE_FLAG_COPY) == ERR_MEM);
    CHECK(tcp_output(f.pcb) == ERR_OK && f.sent != 0);
    bool wide_ack = false;
    while (f.acknowledged < capacity)
    {
        const uint32_t outstanding = f.sent - f.acknowledged;
        const unsigned callbacks   = f.sent_callbacks;
        CHECK(outstanding != 0);
        wide_ack |= outstanding > UINT16_MAX;
        inject(&f, TCP_ACK, 0, false);
        CHECK(f.sent_callbacks - callbacks == (outstanding + UINT16_MAX - 1) / UINT16_MAX);
        CHECK(f.pcb->snd_buf == f.acknowledged);
    }
    CHECK(wide_ack && f.sent == capacity && f.acknowledged == capacity);
    CHECK(f.pcb->unsent == NULL && f.pcb->unacked == NULL && f.pcb->snd_queuelen == 0);
    bytes[0] = valueAt(capacity);
    CHECK(tcp_write(f.pcb, bytes, 1, TCP_WRITE_FLAG_COPY) == ERR_OK && tcp_output(f.pcb) == ERR_OK);
    inject(&f, TCP_ACK, 0, false);
    CHECK(f.sent == capacity + 1 && f.acknowledged == capacity + 1 && f.pcb->snd_buf == capacity);
    stop(&f);
}

static void receiveCapacity(bool scale)
{
    testCaseSet(scale ? "scaled receive capacity and credit" : "unscaled receive fallback");
    fixture_t f;
    start(&f, scale);
    const uint32_t capacity = scale ? 4U * 1024U * 1024U : UINT16_MAX;
    while (f.received < capacity)
    {
        const uint16_t length = (uint16_t) LWIP_MIN(capacity - f.received, TCP_MSS);
        inject(&f, TCP_ACK, length, false);
        f.peer_next += length;
    }
    tcp_fasttmr();
    CHECK(f.received == capacity && f.pcb->rcv_wnd == 0);
    CHECK(f.last_ack == f.peer_next && f.last_window == 0);
    inject(&f, TCP_ACK, 1, false);
    CHECK(f.received == capacity && f.last_ack == f.peer_next && f.last_window == 0);
    for (uint32_t credited = 0; credited < capacity;)
    {
        const uint16_t length = (uint16_t) LWIP_MIN(capacity - credited, 32768);
        tcp_recved(f.pcb, length);
        credited += length;
        CHECK(f.pcb->rcv_wnd == credited && f.last_window != 0);
    }
    /* The final 32 KiB credit is coalesced while the scaled peer still has
     * ample advertised space. Internal capacity is already fully restored. */
    CHECK(f.pcb->rcv_wnd == capacity);
    CHECK(f.last_window == (scale ? (capacity - 32768U) >> 7 : UINT16_MAX));
    inject(&f, TCP_ACK, TCP_MSS, false);
    f.peer_next += TCP_MSS;
    CHECK(f.received == capacity + TCP_MSS && f.pcb->rcv_wnd == capacity - TCP_MSS);
    tcp_fasttmr();
    CHECK(f.last_ack == f.peer_next && f.last_window == (uint16_t) ((capacity - TCP_MSS) >> (scale ? 7 : 0)));
    stop(&f);
}

int main(void)
{
    wwLwipEngineSharedInit();
    sendCapacity();
    receiveCapacity(true);
    receiveCapacity(false);
    wwLwipEngineSharedCleanup();
    puts("production TCP send/receive capacity, scaling and ACK credit passed");
    return 0;
}
