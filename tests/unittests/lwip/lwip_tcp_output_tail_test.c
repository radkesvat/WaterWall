/*
 * Covers: the owner-local unacknowledged-segment tail used by TCP output.
 * Setup: isolated owner-engine runtime, two real TCP handshakes, a recording netif,
 * and deterministic raw ACK packets. No host sockets or wall-clock timers.
 * Checks: exact list-tail identity, sorted sequence order and payload bytes across
 * append, partial/full ACKs, SYN ACK, fast/RTO retransmission, failed output,
 * queue purge, sequence wrap and two independent PCBs.
 * Limits: protocol/bookkeeping coverage; throughput is measured separately.
 * CTest: waterwall.lwip_tcp_output_tail_unit (Debug and Release).
 */
#include "fixtures/lwip/lwip_engine_test_runtime.h"
#include "lwip/ip.h"
#include "lwip/netif.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/stats.h"

typedef struct output_s
{
    uint32_t sequence;
    uint16_t length;
    uint8_t  flags;
} output_t;

typedef struct flow_s
{
    struct tcp_pcb *pcb;
    output_t        output[128];
    unsigned        outputs;
    bool            fail_output;
} flow_t;

typedef struct fixture_s
{
    ww_lwip_engine_t *engine, *previous;
    struct netif      netif;
    flow_t            flow[2];
} fixture_t;

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

static uint8_t valueAt(uint32_t sequence)
{
    return (uint8_t) ((sequence * 19U) ^ (sequence >> 8U));
}

static unsigned requireTail(flow_t *flow)
{
    struct tcp_seg *tail  = NULL;
    unsigned        count = 0;
    for (struct tcp_seg *seg = flow->pcb->unacked; seg != NULL; seg = seg->next)
    {
        CHECK(++count < 128);
        if (tail != NULL)
            CHECK(TCP_SEQ_LT(lwip_ntohl(tail->tcphdr->seqno), lwip_ntohl(seg->tcphdr->seqno)));
        tail = seg;
    }
    CHECK(flow->pcb->ww_unacked_tail == tail);
    return count;
}

static err_t output(struct netif *netif, struct pbuf *packet, const ip4_addr_t *destination)
{
    (void) destination;
    fixture_t *f = netif->state;
    uint8_t    bytes[1500];
    CHECK(wwLwipEngineCurrent() == f->engine && packet->tot_len <= sizeof(bytes));
    CHECK(pbuf_copy_partial(packet, bytes, packet->tot_len, 0) == packet->tot_len);
    CHECK(bytes[0] == 0x45 && bytes[9] == 6);
    const uint16_t port = get16(bytes + 20);
    CHECK(port >= 1234 && port < 1236);
    flow_t *flow = &f->flow[port - 1234];
    CHECK(flow->outputs < sizeof(flow->output) / sizeof(flow->output[0]));
    const uint16_t header = (uint16_t) (20 + (bytes[32] >> 4) * 4);
    CHECK(header >= 40 && header <= packet->tot_len);
    const output_t event = {
        .sequence = get32(bytes + 24), .length = (uint16_t) (packet->tot_len - header), .flags = bytes[33]};
    for (unsigned i = 0; i < event.length; ++i)
        CHECK(bytes[header + i] == valueAt(event.sequence + i));
    flow->output[flow->outputs++] = event;
    return flow->fail_output ? ERR_IF : ERR_OK;
}

static err_t initNetif(struct netif *netif)
{
    netif->name[0] = 'u';
    netif->name[1] = 't';
    netif->mtu     = 1500;
    netif->output  = output;
    return ERR_OK;
}

static void lost(void *argument, err_t error)
{
    flow_t *flow = argument;
    CHECK(error == ERR_ABRT || error == ERR_RST);
    flow->pcb = NULL;
}

static void inject(fixture_t *f, unsigned index, uint8_t flags, uint32_t acknowledgement)
{
    flow_t        *flow      = &f->flow[index];
    const uint16_t length    = (flags & TCP_SYN) != 0 ? 44 : 40;
    uint8_t        bytes[44] = {0x45}, pseudo[36] = {0};
    put16(bytes + 2, length);
    bytes[8]  = 64;
    bytes[9]  = 6;
    bytes[12] = 10;
    bytes[15] = 2;
    bytes[16] = 10;
    bytes[19] = 1;
    put16(bytes + 20, 80);
    put16(bytes + 22, (uint16_t) (1234 + index));
    put32(bytes + 24, (flags & TCP_SYN) != 0 ? 100 : 101);
    put32(bytes + 28, acknowledgement);
    bytes[32] = (uint8_t) ((length - 20) << 2);
    bytes[33] = flags;
    put16(bytes + 34, UINT16_MAX);
    if (length == 44)
    {
        bytes[40] = 2;
        bytes[41] = 4;
        put16(bytes + 42, TCP_MSS);
    }
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
    CHECK(flow->pcb != NULL);
    requireTail(flow);
}

static void start(fixture_t *f)
{
    memset(f, 0, sizeof(*f));
    owner      = 0;
    owner_loop = (struct wloop_s *) &f->netif;
    f->engine  = wwLwipEngineCreate(0, (struct wloop_s *) owner_loop);
    CHECK(f->engine != NULL && wwLwipEngineEnter(f->engine, &f->previous));
    ip4_addr_t address, mask, gateway;
    IP4_ADDR(&address, 10, 0, 0, 1);
    IP4_ADDR(&mask, 255, 255, 255, 0);
    ip4_addr_set_zero(&gateway);
    CHECK(netif_add(&f->netif, &address, &mask, &gateway, f, initNetif, ip_input) != NULL);
    netif_set_up(&f->netif);
    netif_set_link_up(&f->netif);
    for (unsigned i = 0; i < 2; ++i)
    {
        flow_t *flow = &f->flow[i];
        flow->pcb    = tcp_new();
        CHECK(flow->pcb != NULL && tcp_bind_netif(flow->pcb, &f->netif) == ERR_OK);
        CHECK(tcp_bind(flow->pcb, IP_ADDR_ANY, (uint16_t) (1234 + i)) == ERR_OK);
        tcp_arg(flow->pcb, flow);
        tcp_err(flow->pcb, lost);
        ip_addr_t peer;
        IP_ADDR4(&peer, 10, 0, 0, 2);
        CHECK(tcp_connect(flow->pcb, &peer, 80, NULL) == ERR_OK);
        CHECK(flow->pcb->state == SYN_SENT && requireTail(flow) == 1);
        CHECK(flow->output[0].flags == TCP_SYN && flow->output[0].length == 0);
        inject(f, i, TCP_SYN | TCP_ACK, flow->pcb->snd_nxt);
        CHECK(flow->pcb->state == ESTABLISHED && requireTail(flow) == 0);
        tcp_nagle_disable(flow->pcb);
        flow->pcb->cwnd = UINT16_MAX;
        flow->outputs   = 0;
    }
}

static void stop(fixture_t *f)
{
    for (unsigned i = 0; i < 2; ++i)
    {
        requireTail(&f->flow[i]);
        tcp_abort(f->flow[i].pcb);
        CHECK(f->flow[i].pcb == NULL);
    }
    wwLwipEngineLeave(f->engine, f->previous);
    wwLwipEngineDestroy(f->engine);
    CHECK(wwLwipSharedStats()->memp[MEMP_TCP_SEG]->used == 0 && wwLwipSharedStats()->mem.used == 0);
}

static uint32_t writeSegments(flow_t *flow, unsigned segments)
{
    const uint32_t first = flow->pcb->snd_lbb;
    uint8_t        bytes[TCP_MSS];
    for (unsigned segment = 0; segment < segments; ++segment)
    {
        for (unsigned i = 0; i < sizeof(bytes); ++i)
            bytes[i] = valueAt(flow->pcb->snd_lbb + i);
        CHECK(tcp_write(flow->pcb, bytes, sizeof(bytes), TCP_WRITE_FLAG_COPY) == ERR_OK);
    }
    return first;
}

static void expectOutput(flow_t *flow, unsigned event, uint32_t sequence, uint16_t length)
{
    CHECK(event < flow->outputs);
    CHECK(flow->output[event].sequence == sequence && flow->output[event].length == length);
    CHECK((flow->output[event].flags & (TCP_ACK | TCP_RST)) == TCP_ACK);
}

static void appendAndAcknowledge(bool wrap)
{
    fixture_t f;
    start(&f);
    flow_t *flow = &f.flow[0], *other = &f.flow[1];
    if (wrap)
    {
        flow->pcb->snd_nxt = flow->pcb->snd_lbb = flow->pcb->lastack = UINT32_MAX - TCP_MSS - 31U;
        flow->pcb->snd_wl2                                           = flow->pcb->lastack;
    }
    const uint32_t first = writeSegments(flow, 3);
    CHECK(tcp_output(flow->pcb) == ERR_OK && requireTail(flow) == 3);
    for (unsigned i = 0; i < 3; ++i)
        expectOutput(flow, i, first + i * TCP_MSS, TCP_MSS);
    struct tcp_seg *tail = flow->pcb->ww_unacked_tail;
    inject(&f, 0, TCP_ACK, first + TCP_MSS / 2);
    CHECK(requireTail(flow) == 3 && flow->pcb->ww_unacked_tail == tail);
    inject(&f, 0, TCP_ACK, first + TCP_MSS);
    CHECK(requireTail(flow) == 2 && flow->pcb->ww_unacked_tail == tail);
    const uint32_t separate = writeSegments(other, 2);
    CHECK(tcp_output(other->pcb) == ERR_OK && requireTail(other) == 2);
    CHECK(flow->pcb->ww_unacked_tail == tail && tail != other->pcb->ww_unacked_tail);
    writeSegments(flow, 1);
    CHECK(tcp_output(flow->pcb) == ERR_OK && requireTail(flow) == 3);
    expectOutput(flow, 3, first + 3U * TCP_MSS, TCP_MSS);
    inject(&f, 0, TCP_ACK, flow->pcb->snd_nxt);
    CHECK(requireTail(flow) == 0 && requireTail(other) == 2);
    expectOutput(other, 0, separate, TCP_MSS);
    expectOutput(other, 1, separate + TCP_MSS, TCP_MSS);
    inject(&f, 1, TCP_ACK, other->pcb->snd_nxt);
    CHECK(requireTail(other) == 0);
    const uint32_t restarted = writeSegments(flow, 1);
    CHECK(tcp_output(flow->pcb) == ERR_OK && requireTail(flow) == 1);
    expectOutput(flow, 4, restarted, TCP_MSS);
    stop(&f);
}

static void retransmitAndFailure(void)
{
    fixture_t f;
    start(&f);
    flow_t        *flow  = &f.flow[0];
    const uint32_t first = writeSegments(flow, 4);
    CHECK(tcp_output(flow->pcb) == ERR_OK && requireTail(flow) == 4);
    struct tcp_seg *tail = flow->pcb->ww_unacked_tail;
    CHECK(tcp_rexmit(flow->pcb) == ERR_OK && requireTail(flow) == 3);
    CHECK(flow->pcb->ww_unacked_tail == tail);
    flow->fail_output = true;
    CHECK(tcp_output(flow->pcb) == ERR_IF && requireTail(flow) == 3);
    CHECK(flow->pcb->ww_unacked_tail == tail && flow->pcb->unsent != NULL);
    flow->fail_output = false;
    CHECK(tcp_output(flow->pcb) == ERR_OK && requireTail(flow) == 4);
    CHECK(flow->pcb->ww_unacked_tail == tail);
    expectOutput(flow, 4, first, TCP_MSS);
    expectOutput(flow, 5, first, TCP_MSS);
    pbuf_ref(flow->pcb->unacked->p);
    CHECK(tcp_rexmit_rto_prepare(flow->pcb) == ERR_VAL && requireTail(flow) == 4);
    CHECK(flow->pcb->ww_unacked_tail == tail);
    pbuf_free(flow->pcb->unacked->p);
    writeSegments(flow, 2);
    CHECK(tcp_rexmit_rto_prepare(flow->pcb) == ERR_OK && requireTail(flow) == 0);
    CHECK(flow->pcb->unsent != NULL);
    CHECK(tcp_output(flow->pcb) == ERR_OK && requireTail(flow) == 6);
    for (unsigned i = 0; i < 6; ++i)
        expectOutput(flow, 6 + i, first + i * TCP_MSS, TCP_MSS);
    inject(&f, 0, TCP_ACK, flow->pcb->snd_nxt);
    writeSegments(flow, 1);
    flow->fail_output = true;
    CHECK(tcp_output(flow->pcb) == ERR_IF && requireTail(flow) == 0);
    flow->fail_output = false;
    CHECK(tcp_output(flow->pcb) == ERR_OK && requireTail(flow) == 1);
    CHECK(tcp_rexmit(flow->pcb) == ERR_OK && requireTail(flow) == 0);
    CHECK(tcp_output(flow->pcb) == ERR_OK && requireTail(flow) == 1);
    tcp_pcb_purge(flow->pcb);
    CHECK(flow->pcb->unsent == NULL && requireTail(flow) == 0);
    stop(&f);
}

int main(void)
{
    wwLwipEngineSharedInit();
    testCaseSet("TCP cached tail survives append, prefix ACKs and independent PCBs");
    appendAndAcknowledge(false);
    testCaseSet("TCP cached tail preserves output order across sequence wrap");
    appendAndAcknowledge(true);
    testCaseSet("TCP cached tail survives failed output, fast/RTO retransmit and purge");
    retransmitAndFailure();
    wwLwipEngineSharedCleanup();
    puts("TCP unacknowledged tail preserves sequence order, retransmission and ownership");
    return 0;
}
