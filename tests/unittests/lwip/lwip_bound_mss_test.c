/*
 * Covers: the send MSS of a TCP connection whose PCB is bound to a netif.
 * Setup: a private raw engine and a recording netif that owns one /32 address and has no route to the
 * peer, as ConnectionToPackets' virtual netif has; its MTU is 1420 and the peer offers an MSS of 1460.
 * Checks: active and passive opens, including a passive open that retransmits its SYN-ACK, use an MSS
 * of 1380 and send a 3000-byte write as three whole datagrams within the MTU.
 * Limits: IPv4 only; this checks the segment sizes, not what a path does with fragments.
 * CTest: waterwall.lwip_bound_mss_unit (Debug and Release).
 */
#include "fixtures/lwip/lwip_engine_test_runtime.h"
#include "lwip/ip.h"
#include "lwip/netif.h"
#include "lwip/priv/tcp_priv.h"

enum
{
    netif_mtu  = 1420,
    netif_mss  = netif_mtu - 40,
    peer_mss   = 1460,
    peer_port  = 80,
    local_port = 1234,
    write_size = 3000
};

typedef struct
{
    ww_lwip_engine_t *engine, *previous;
    struct netif      netif;
    struct tcp_pcb   *pcb;
    uint32_t          last_sequence, payload;
    uint16_t          syn_mss, largest;
    uint8_t           last_flags;
    unsigned          outputs, fragments;
} fixture_t;

static fixture_t fixture;

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
    return (uint16_t) (((uint16_t) p[0] << 8) | p[1]);
}

static uint32_t get32(const uint8_t *p)
{
    return ((uint32_t) get16(p) << 16) | get16(p + 2);
}

static err_t output(struct netif *netif, struct pbuf *packet, const ip4_addr_t *destination)
{
    (void) destination;
    fixture_t *f = netif->state;
    uint8_t    bytes[80];
    CHECK(f == &fixture && wwLwipEngineCurrent() == f->engine && packet->tot_len >= 20);
    const uint16_t copied = (uint16_t) LWIP_MIN(packet->tot_len, sizeof(bytes));
    CHECK(pbuf_copy_partial(packet, bytes, copied, 0) == copied);
    ++f->outputs;
    f->largest = LWIP_MAX(f->largest, packet->tot_len);
    /* The more-fragments flag or a fragment offset: the datagram did not fit the netif. */
    if ((get16(bytes + 6) & 0x3fffU) != 0)
    {
        ++f->fragments;
        return ERR_OK;
    }
    CHECK(packet->tot_len >= 40);
    const unsigned header_length = 20U + (bytes[32] >> 4) * 4U;
    CHECK(header_length <= packet->tot_len && header_length <= sizeof(bytes));
    f->last_sequence = get32(bytes + 24);
    f->last_flags    = bytes[33];
    f->payload += packet->tot_len - header_length;
    if ((f->last_flags & TCP_SYN) == 0)
    {
        return ERR_OK;
    }
    for (unsigned i = 40; i < header_length && bytes[i] != 0;)
    {
        if (bytes[i] == 1)
        {
            ++i;
            continue;
        }
        CHECK(i + 1 < header_length && bytes[i + 1] >= 2 && i + bytes[i + 1] <= header_length);
        if (bytes[i] == 2)
        {
            CHECK(bytes[i + 1] == 4);
            f->syn_mss = get16(bytes + i + 2);
        }
        i += bytes[i + 1];
    }
    return ERR_OK;
}

static err_t initNetif(struct netif *netif)
{
    netif->name[0] = 'b';
    netif->name[1] = 'm';
    netif->mtu     = netif_mtu;
    netif->output  = output;
    return ERR_OK;
}

/* A segment from the peer without payload; an mss of 0 sends no option. */
static void inject(fixture_t *f, uint16_t port, uint32_t sequence, uint32_t acknowledgement, uint8_t flags,
                   uint16_t mss)
{
    const uint16_t options    = mss == 0 ? 0 : 4;
    const uint16_t length     = (uint16_t) (40 + options);
    uint8_t        bytes[44]  = {0x45};
    uint8_t        pseudo[36] = {0};
    put16(bytes + 2, length);
    bytes[8]  = 64;
    bytes[9]  = 6;
    bytes[12] = 203;
    bytes[14] = 113;
    bytes[15] = 9;
    bytes[16] = 10;
    bytes[19] = 1;
    put16(bytes + 20, peer_port);
    put16(bytes + 22, port);
    put32(bytes + 24, sequence);
    put32(bytes + 28, acknowledgement);
    bytes[32] = (uint8_t) ((5 + options / 4) << 4);
    bytes[33] = flags;
    put16(bytes + 34, UINT16_MAX);
    if (options != 0)
    {
        bytes[40] = 2;
        bytes[41] = 4;
        put16(bytes + 42, mss);
    }
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

/* One address, no subnet and no default route: ip_route() finds no netif for the peer. */
static fixture_t *start(void)
{
    fixture_t *f = &fixture;
    memset(f, 0, sizeof(*f));
    owner      = 0;
    owner_loop = (struct wloop_s *) &f->netif;
    f->engine  = wwLwipEngineCreate((uint8_t) owner, (struct wloop_s *) owner_loop);
    CHECK(f->engine != NULL && wwLwipEngineEnter(f->engine, &f->previous));
    ip4_addr_t address, mask, gateway;
    IP4_ADDR(&address, 10, 0, 0, 1);
    IP4_ADDR(&mask, 255, 255, 255, 255);
    ip4_addr_set_zero(&gateway);
    CHECK(netif_add(&f->netif, &address, &mask, &gateway, f, initNetif, ip_input) != NULL);
    netif_set_up(&f->netif);
    netif_set_link_up(&f->netif);
    return f;
}

static void stop(fixture_t *f)
{
    tcp_abort(f->pcb);
    f->pcb = NULL;
    wwLwipEngineLeave(f->engine, f->previous);
    wwLwipEngineDestroy(f->engine);
    CHECK(wwLwipEngineCurrent() == NULL);
}

static void writeFitsTheNetif(fixture_t *f)
{
    static const uint8_t data[write_size];
    CHECK(f->pcb->state == ESTABLISHED);
    CHECK(f->pcb->mss == netif_mss);
    tcp_nagle_disable(f->pcb);
    f->outputs = f->fragments = 0;
    f->payload = f->largest = 0;
    CHECK(tcp_write(f->pcb, data, write_size, TCP_WRITE_FLAG_COPY) == ERR_OK);
    CHECK(tcp_output(f->pcb) == ERR_OK);
    CHECK(f->fragments == 0 && f->largest == netif_mtu && f->payload == write_size && f->outputs == 3);
}

static err_t connected(void *argument, struct tcp_pcb *pcb, err_t error)
{
    fixture_t *f = argument;
    CHECK(pcb == f->pcb && error == ERR_OK);
    return ERR_OK;
}

static void activeOpen(void)
{
    fixture_t *f = start();
    ip_addr_t  local, peer;
    IP_ADDR4(&local, 10, 0, 0, 1);
    IP_ADDR4(&peer, 203, 0, 113, 9);
    f->pcb = tcp_new();
    CHECK(f->pcb != NULL && tcp_bind_netif(f->pcb, &f->netif) == ERR_OK);
    CHECK(tcp_bind(f->pcb, &local, local_port) == ERR_OK);
    tcp_arg(f->pcb, f);
    CHECK(tcp_connect(f->pcb, &peer, peer_port, connected) == ERR_OK);
    /* The SYN already offers the netif's MSS; what follows is about the MSS this side sends with. */
    CHECK(f->outputs == 1 && f->last_flags == TCP_SYN && f->syn_mss == netif_mss);
    inject(f, local_port, 7000, f->last_sequence + 1U, TCP_SYN | TCP_ACK, peer_mss);
    writeFitsTheNetif(f);
    stop(f);
}

static err_t accepted(void *argument, struct tcp_pcb *pcb, err_t error)
{
    fixture_t *f = argument;
    CHECK(pcb == f->pcb && error == ERR_OK);
    return ERR_OK;
}

static void passiveOpen(bool lose_first_syn_ack)
{
    fixture_t *f = start();
    f->pcb       = tcp_new();
    CHECK(f->pcb != NULL && tcp_bind_netif(f->pcb, &f->netif) == ERR_OK);
    CHECK(tcp_bind(f->pcb, IP_ADDR_ANY, local_port) == ERR_OK);
    tcp_arg(f->pcb, f);
    struct tcp_pcb *listener = tcp_listen(f->pcb);
    CHECK(listener != NULL);
    tcp_accept(listener, accepted);
    inject(f, local_port, 7000, 0, TCP_SYN, peer_mss);
    f->pcb = tcp_active_pcbs;
    CHECK(f->pcb != NULL && f->pcb->state == SYN_RCVD);
    CHECK(f->outputs == 1 && f->last_flags == (TCP_SYN | TCP_ACK) && f->syn_mss == netif_mss);
    if (lose_first_syn_ack)
    {
        const uint32_t first_sequence = f->last_sequence;
        inject(f, local_port, 7000, 0, TCP_SYN, peer_mss);
        CHECK(f->outputs == 2 && f->last_flags == (TCP_SYN | TCP_ACK) && f->last_sequence == first_sequence);
    }
    inject(f, local_port, 7001, f->last_sequence + 1U, TCP_ACK, 0);
    CHECK(tcp_close(listener) == ERR_OK);
    writeFitsTheNetif(f);
    stop(f);
}

int main(void)
{
    wwLwipEngineSharedInit();
    testCaseSet("an active open sends within the bound netif's MTU");
    activeOpen();
    testCaseSet("a passive open sends within the bound netif's MTU");
    passiveOpen(false);
    testCaseSet("a passive open preserves the send MSS after the peer retries its SYN");
    passiveOpen(true);
    wwLwipEngineSharedCleanup();
    puts("a connection bound to a netif sends segments that fit its MTU");
    return 0;
}
