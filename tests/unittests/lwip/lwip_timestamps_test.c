/*
 * Covers: negotiated TCP timestamps, and the echo a retransmission gets.
 * Setup: a private raw engine, real IPv4/TCP handshakes and a recording MTU-1500 netif.
 * Checks: no timestamps without the peer's option; the SYN-ACK echoes the SYN's value; the ACK that
 * fills a gap echoes the retransmitted segment's own value, which tells a sender such as iOS that
 * this ACK answers its retransmission and the retransmission was needed.
 * Limits: this checks the wire protocol, not how a sender recovers.
 * CTest: waterwall.lwip_timestamps_unit (Debug and Release).
 */
#include "fixtures/lwip/lwip_engine_test_runtime.h"
#include "lwip/ip.h"
#include "lwip/netif.h"
#include "lwip/priv/tcp_priv.h"

enum
{
    payload_limit = 128,
    no_timestamp  = 0
};

typedef struct
{
    ww_lwip_engine_t *engine, *previous;
    struct netif      netif;
    struct tcp_pcb   *pcb;
    uint32_t          peer_next, last_ack, last_echo;
    uint8_t           last_flags;
    unsigned          outputs;
    bool              last_had_timestamp;
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
    CHECK(f == &fixture && wwLwipEngineCurrent() == f->engine);
    CHECK(packet->tot_len >= 40 && packet->tot_len <= sizeof(bytes));
    CHECK(pbuf_copy_partial(packet, bytes, packet->tot_len, 0) == packet->tot_len);
    const unsigned header_length = 20U + (bytes[32] >> 4) * 4U;
    CHECK(header_length == packet->tot_len);
    ++f->outputs;
    f->last_ack           = get32(bytes + 28);
    f->last_flags         = bytes[33];
    f->last_had_timestamp = false;
    for (unsigned i = 40; i < header_length && bytes[i] != 0;)
    {
        if (bytes[i] == 1)
        {
            ++i;
            continue;
        }
        CHECK(i + 1 < header_length && bytes[i + 1] >= 2 && i + bytes[i + 1] <= header_length);
        if (bytes[i] == 8)
        {
            CHECK(bytes[i + 1] == 10);
            f->last_had_timestamp = true;
            f->last_echo          = get32(bytes + i + 6);
        }
        i += bytes[i + 1];
    }
    return ERR_OK;
}

static err_t initNetif(struct netif *netif)
{
    netif->name[0] = 't';
    netif->name[1] = 's';
    netif->mtu     = 1500;
    netif->output  = output;
    return ERR_OK;
}

static err_t receive(void *argument, struct tcp_pcb *pcb, struct pbuf *packet, err_t error)
{
    fixture_t *f = argument;
    CHECK(pcb == f->pcb && packet != NULL && error == ERR_OK);
    tcp_recved(pcb, packet->tot_len);
    pbuf_free(packet);
    return ERR_OK;
}

static err_t accepted(void *argument, struct tcp_pcb *pcb, err_t error)
{
    fixture_t *f = argument;
    CHECK(pcb == f->pcb && error == ERR_OK);
    tcp_recv(pcb, receive);
    return ERR_OK;
}

/* A timestamp of no_timestamp sends no option. */
static void inject(fixture_t *f, uint32_t sequence, uint8_t flags, uint16_t payload, uint32_t timestamp)
{
    CHECK(payload <= payload_limit && f->pcb != NULL);
    const uint16_t options                    = timestamp == no_timestamp ? 0 : 12;
    const uint16_t length                     = (uint16_t) (40 + options + payload);
    uint8_t        bytes[52 + payload_limit]  = {0x45};
    uint8_t        pseudo[44 + payload_limit] = {0};
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
    put16(bytes + 34, UINT16_MAX);
    if (options != 0)
    {
        bytes[40] = 1;
        bytes[41] = 1;
        bytes[42] = 8;
        bytes[43] = 10;
        put32(bytes + 44, timestamp);
        put32(bytes + 48, f->last_had_timestamp ? 1U : 0U);
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

static fixture_t *start(uint32_t initial_sequence, uint32_t timestamp)
{
    fixture_t *f = &fixture;
    memset(f, 0, sizeof(*f));
    owner      = 0;
    owner_loop = (struct wloop_s *) &f->netif;
    f->engine  = wwLwipEngineCreate((uint8_t) owner, (struct wloop_s *) owner_loop);
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
    struct tcp_pcb *listener = tcp_listen(f->pcb);
    CHECK(listener != NULL);
    tcp_accept(listener, accepted);
    f->pcb = listener;
    inject(f, initial_sequence, TCP_SYN, 0, timestamp);
    f->pcb = tcp_active_pcbs;
    CHECK(f->pcb != NULL && f->pcb->state == SYN_RCVD);
    CHECK(f->outputs == 1 && f->last_flags == (TCP_SYN | TCP_ACK));
    CHECK(f->last_had_timestamp == (timestamp != no_timestamp));
    CHECK(timestamp == no_timestamp || f->last_echo == timestamp);
    f->peer_next = initial_sequence + 1U;
    inject(f, f->peer_next, TCP_ACK, 0, timestamp);
    CHECK(f->pcb->state == ESTABLISHED);
    CHECK(tcp_close(listener) == ERR_OK);
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

static void withoutThePeersOption(void)
{
    fixture_t *f = start(100, no_timestamp);
    CHECK(! f->last_had_timestamp);
    inject(f, f->peer_next + 64, TCP_ACK, 64, no_timestamp);
    CHECK(f->last_ack == f->peer_next && ! f->last_had_timestamp);
    stop(f);
}

static void handshakeEchoesTheSyn(void)
{
    fixture_t *f = start(100, 500);
    /* start() checked the SYN-ACK; this ACK shows the value kept for later segments. */
    inject(f, f->peer_next + 64, TCP_ACK, 64, 600);
    CHECK(f->last_ack == f->peer_next && f->last_had_timestamp && f->last_echo == 500);
    stop(f);
}

/* Without this echo a sender cannot tell this ACK from one for its original, lost segment. */
static void gapFillEchoesTheRetransmission(uint32_t initial_sequence)
{
    fixture_t     *f       = start(initial_sequence, 500);
    const uint32_t missing = f->peer_next;
    inject(f, missing + 64, TCP_ACK, 64, 600);
    CHECK(f->last_ack == missing && f->last_had_timestamp && f->last_echo == 500);
    f->outputs = 0;
    inject(f, missing, TCP_ACK, 64, 700);
    tcp_ack_now(f->pcb);
    CHECK(tcp_output(f->pcb) == ERR_OK);
    CHECK(f->outputs >= 1 && f->last_ack == missing + 128);
    CHECK(f->last_had_timestamp && f->last_echo == 700);
    stop(f);
}

int main(void)
{
    CHECK(LWIP_TCP_TIMESTAMPS == 1);
    wwLwipEngineSharedInit();
    testCaseSet("no timestamps without the peer's option");
    withoutThePeersOption();
    testCaseSet("the handshake's value is echoed");
    handshakeEchoesTheSyn();
    testCaseSet("the ACK that fills a gap echoes the retransmission");
    gapFillEchoesTheRetransmission(100);
    testCaseSet("the same across sequence wrap");
    gapFillEchoesTheRetransmission(UINT32_MAX - 32U);
    wwLwipEngineSharedCleanup();
    puts("negotiated timestamps echo the retransmission that fills a gap");
    return 0;
}
