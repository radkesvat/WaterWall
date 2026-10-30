/*
 * Covers: negotiated receive-side SACK with the production out-of-order retention bound.
 * Setup: a private raw engine, real IPv4/TCP handshakes and a recording MTU-1500 netif.
 * Checks: handshake permission, malformed/no permission, exact gap ranges during ACK batches,
 * sequence wrap, gap closure, queue-cap eviction, queue cleanup and segment-pool refusal.
 * Limits: this checks wire protocol and bounded retention, not sender SACK recovery or throughput.
 * CTest: waterwall.lwip_sack_unit (Debug and Release).
 */
#include "fixtures/lwip/lwip_engine_test_runtime.h"
#include "lwip/ip.h"
#include "lwip/netif.h"
#include "lwip/priv/tcp_priv.h"

enum
{
    payload_limit = 128,
    sack_limit    = 4
};

typedef enum
{
    permission_none,
    permission_valid,
    permission_bad_length
} permission_t;

typedef struct
{
    uint32_t left, right;
} range_t;

typedef struct
{
    ww_lwip_engine_t *engine, *previous;
    struct netif      netif;
    struct tcp_pcb   *pcb;
    uint32_t          peer_next, last_ack;
    uint8_t           last_flags;
    unsigned          outputs, received, sack_count, refusals;
    range_t           sacks[sack_limit];
    bool              sack_permitted, refuse_segment;
} fixture_t;

static fixture_t fixture;

struct tcp_seg *__real_tcp_seg_copy(struct tcp_seg *segment);

struct tcp_seg *__wrap_tcp_seg_copy(struct tcp_seg *segment)
{
    if (fixture.refuse_segment)
    {
        fixture.refuse_segment = false;
        ++fixture.refusals;
        return NULL;
    }
    return __real_tcp_seg_copy(segment);
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
    uint8_t    bytes[80];
    CHECK(f == &fixture && wwLwipEngineCurrent() == f->engine);
    CHECK(packet->tot_len >= 40 && packet->tot_len <= sizeof(bytes));
    CHECK(pbuf_copy_partial(packet, bytes, packet->tot_len, 0) == packet->tot_len);
    CHECK(bytes[0] == 0x45 && bytes[9] == 6 && get16(bytes + 2) == packet->tot_len);
    CHECK(wwLwipChecksum(bytes, 20) == 0xffff);
    const unsigned header_length = 20U + (bytes[32] >> 4) * 4U;
    CHECK(header_length == packet->tot_len && header_length <= 80);
    ++f->outputs;
    f->last_ack       = get32(bytes + 28);
    f->last_flags     = bytes[33];
    f->sack_count     = 0;
    f->sack_permitted = false;
    for (unsigned i = 40; i < header_length && bytes[i] != 0;)
    {
        if (bytes[i] == 1)
        {
            ++i;
            continue;
        }
        CHECK(i + 1 < header_length && bytes[i + 1] >= 2 && i + bytes[i + 1] <= header_length);
        if (bytes[i] == 4)
        {
            CHECK(bytes[i + 1] == 2);
            f->sack_permitted = true;
        }
        else if (bytes[i] == 5)
        {
            CHECK(bytes[i + 1] >= 10 && (bytes[i + 1] - 2) % 8 == 0);
            CHECK(f->sack_count == 0);
            f->sack_count = (bytes[i + 1] - 2) / 8;
            CHECK(f->sack_count <= sack_limit);
            for (unsigned range = 0; range < f->sack_count; ++range)
            {
                f->sacks[range].left  = get32(bytes + i + 2 + range * 8);
                f->sacks[range].right = get32(bytes + i + 6 + range * 8);
            }
        }
        i += bytes[i + 1];
    }
    return ERR_OK;
}

static err_t initNetif(struct netif *netif)
{
    netif->name[0] = 's';
    netif->name[1] = 'a';
    netif->mtu     = 1500;
    netif->output  = output;
    return ERR_OK;
}

static err_t receive(void *argument, struct tcp_pcb *pcb, struct pbuf *packet, err_t error)
{
    fixture_t *f = argument;
    CHECK(pcb == f->pcb && packet != NULL && error == ERR_OK);
    f->received += packet->tot_len;
    pbuf_free(packet);
    return ERR_OK;
}

static void inject(fixture_t *f, uint32_t sequence, uint8_t flags, uint16_t payload, permission_t permission)
{
    CHECK(payload <= payload_limit && f->pcb != NULL);
    const uint16_t options                    = permission == permission_none ? 0 : 4;
    const uint16_t length                     = (uint16_t) (40 + options + payload);
    uint8_t        bytes[44 + payload_limit]  = {0x45};
    uint8_t        pseudo[36 + payload_limit] = {0};
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
        bytes[40] = 4;
        bytes[41] = permission == permission_valid ? 2 : 3;
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

static bool sackEnabled(const struct tcp_pcb *pcb)
{
#if LWIP_TCP_SACK_OUT
    return (pcb->flags & TF_SACK) != 0;
#else
    (void) pcb;
    return false;
#endif
}

static fixture_t *start(uint32_t initial_sequence, permission_t permission, bool passive)
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
    tcp_recv(f->pcb, receive);
    if (passive)
    {
        struct tcp_pcb *listener = tcp_listen(f->pcb);
        CHECK(listener != NULL);
        f->pcb = listener;
        inject(f, initial_sequence, TCP_SYN, 0, permission);
        f->pcb = tcp_active_pcbs;
        CHECK(f->pcb != NULL && f->pcb->state == SYN_RCVD);
        CHECK(f->outputs == 1 && f->last_flags == (TCP_SYN | TCP_ACK));
        CHECK(f->sack_permitted == (permission == permission_valid));
        CHECK(sackEnabled(f->pcb) == (permission == permission_valid));
        CHECK(tcp_close(listener) == ERR_OK);
    }
    else
    {
        ip_addr_t peer;
        IP_ADDR4(&peer, 10, 0, 0, 2);
        CHECK(tcp_connect(f->pcb, &peer, 80, NULL) == ERR_OK);
        CHECK(f->outputs == 1 && f->last_flags == TCP_SYN && f->sack_permitted);
        inject(f, initial_sequence, TCP_SYN | TCP_ACK, 0, permission);
        CHECK(f->pcb->state == ESTABLISHED && f->outputs == 2);
        CHECK(sackEnabled(f->pcb) == (permission == permission_valid));
    }
    f->peer_next = initial_sequence + 1U;
    f->outputs   = 0;
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

static void begin(fixture_t *f)
{
    wwLwipEngineLeave(f->engine, f->previous);
    wwLwipEngineBeginAckBatch(f->engine);
    CHECK(wwLwipEngineEnter(f->engine, &f->previous));
}

static void end(fixture_t *f)
{
    wwLwipEngineLeave(f->engine, f->previous);
    wwLwipEngineEndAckBatch(f->engine);
    CHECK(wwLwipEngineEnter(f->engine, &f->previous));
}

static void expectAck(fixture_t *f, unsigned outputs, uint32_t ack, unsigned ranges)
{
    CHECK(f->outputs == outputs && f->last_flags == TCP_ACK && f->last_ack == ack);
    CHECK(f->sack_count == ranges && ! f->sack_permitted);
}

static void expectRange(fixture_t *f, unsigned index, uint32_t left, uint32_t right)
{
    CHECK(index < f->sack_count && f->sacks[index].left == left && f->sacks[index].right == right);
}

static void negotiation(void)
{
    for (unsigned passive = 0; passive != 2; ++passive)
    {
        for (permission_t permission = permission_none; permission <= permission_bad_length; ++permission)
        {
            fixture_t *f = start(100, permission, passive != 0);
            if (! passive)
            {
                /* A late SACK-permitted option cannot enable an unnegotiated connection. */
                inject(f, f->peer_next + 64, TCP_ACK, 64, permission_valid);
                expectAck(f, 1, f->peer_next, permission == permission_valid ? 1 : 0);
                CHECK(sackEnabled(f->pcb) == (permission == permission_valid));
            }
            stop(f);
        }
    }
}

static void gapRanges(uint32_t initial_sequence)
{
    fixture_t     *f    = start(initial_sequence, permission_valid, false);
    const uint32_t base = f->peer_next;
    begin(f);
    inject(f, base + 128U, TCP_ACK, 64, permission_none);
    expectAck(f, 1, base, 1);
    expectRange(f, 0, base + 128U, base + 192U);
    inject(f, base + 256U, TCP_ACK, 64, permission_none);
    expectAck(f, 2, base, 2);
    expectRange(f, 0, base + 256U, base + 320U);
    expectRange(f, 1, base + 128U, base + 192U);
    inject(f, base + 192U, TCP_ACK, 64, permission_none);
    expectAck(f, 3, base, 1);
    expectRange(f, 0, base + 128U, base + 320U);
    inject(f, base, TCP_ACK, 128, permission_none);
    expectAck(f, 4, base + 320U, 0);
    CHECK(f->received == 320 && f->pcb->ooseq == NULL);
    end(f);
    tcp_fasttmr();
    CHECK(f->outputs == 4);
    stop(f);
}

static void boundedRetention(void)
{
    fixture_t     *f    = start(100, permission_valid, false);
    const uint32_t base = f->peer_next;
    CHECK(TCP_OOSEQ_MAX_PBUFS == 32);
    begin(f);
    for (unsigned i = 0; i <= TCP_OOSEQ_MAX_PBUFS; ++i)
    {
        inject(f, base + (i + 1U) * 64U, TCP_ACK, 64, permission_none);
        expectAck(f, i + 1, base, 1);
        const unsigned retained = LWIP_MIN(i + 1, TCP_OOSEQ_MAX_PBUFS);
        expectRange(f, 0, base + 64U, base + (retained + 1U) * 64U);
        unsigned pbufs = 0;
        for (const struct tcp_seg *segment = f->pcb->ooseq; segment != NULL; segment = segment->next)
            pbufs += pbuf_clen(segment->p);
        CHECK(pbufs == retained);
    }
    inject(f, base, TCP_ACK, 64, permission_none);
    expectAck(f, 34, base + 33U * 64U, 0);
    CHECK(f->received == 33U * 64U && f->pcb->ooseq == NULL);
    end(f);
    CHECK(f->outputs == 34);
    /* The dropped tail was never reported as retained and still needs delivery. */
    inject(f, base + 33U * 64U, TCP_ACK, 64, permission_none);
    tcp_fasttmr();
    expectAck(f, 35, base + 34U * 64U, 0);
    CHECK(f->received == 34U * 64U);
    stop(f);
}

static void rangeCapacity(void)
{
    fixture_t     *f    = start(100, permission_valid, false);
    const uint32_t base = f->peer_next;
    for (unsigned i = 0; i <= sack_limit; ++i)
    {
        inject(f, base + (i + 1U) * 128U, TCP_ACK, 64, permission_none);
        const unsigned ranges = LWIP_MIN(i + 1, sack_limit);
        expectAck(f, i + 1, base, ranges);
        for (unsigned range = 0; range < ranges; ++range)
        {
            const uint32_t left = base + (i + 1U - range) * 128U;
            expectRange(f, range, left, left + 64U);
        }
    }
    stop(f);
}

static void queueCleanupAndRefusal(void)
{
    fixture_t     *f    = start(100, permission_valid, false);
    const uint32_t base = f->peer_next;
    f->refuse_segment   = true;
    inject(f, base + 64U, TCP_ACK, 64, permission_none);
    CHECK(f->refusals == 1 && f->pcb->ooseq == NULL);
    expectAck(f, 1, base, 0);
    inject(f, base + 64U, TCP_ACK, 64, permission_none);
    expectAck(f, 2, base, 1);
    expectRange(f, 0, base + 64U, base + 128U);
    tcp_free_ooseq(f->pcb);
    CHECK(f->pcb->ooseq == NULL);
    CHECK(tcp_send_empty_ack(f->pcb) == ERR_OK);
    expectAck(f, 3, base, 0);
    inject(f, base, TCP_ACK, 64, permission_none);
    tcp_fasttmr();
    expectAck(f, 4, base + 64U, 0);
    CHECK(f->received == 64);
    stop(f);
}

static void nonemptyQueueRefusals(void)
{
    /* Exercise prepend, replacement, middle insertion and append copy refusal. */
    const uint16_t offsets[] = {64, 128, 192, 384};
    const uint16_t lengths[] = {64, 128, 64, 64};
    for (unsigned path = 0; path < sizeof(offsets) / sizeof(offsets[0]); ++path)
    {
        fixture_t     *f    = start(100, permission_valid, false);
        const uint32_t base = f->peer_next;
        begin(f);
        inject(f, base + 128U, TCP_ACK, 64, permission_none);
        inject(f, base + 256U, TCP_ACK, 64, permission_none);
        f->refuse_segment = true;
        inject(f, base + offsets[path], TCP_ACK, lengths[path], permission_none);
        CHECK(f->refusals == 1);
        expectAck(f, 3, base, 2);
        const unsigned first  = path < 2 ? 128U : 256U;
        const unsigned second = path < 2 ? 256U : 128U;
        expectRange(f, 0, base + first, base + first + 64U);
        expectRange(f, 1, base + second, base + second + 64U);
        const struct tcp_seg *head = f->pcb->ooseq;
        CHECK(head != NULL && head->tcphdr->seqno == base + 128U && head->len == 64);
        CHECK(head->next != NULL && head->next->tcphdr->seqno == base + 256U && head->next->len == 64);
        CHECK(head->next->next == NULL && f->received == 0);
        if (path == 0)
        {
            /* A successful retry can now advertise the previously refused prefix. */
            inject(f, base + 64U, TCP_ACK, 64, permission_none);
            expectAck(f, 4, base, 2);
            expectRange(f, 0, base + 64U, base + 192U);
            expectRange(f, 1, base + 256U, base + 320U);
        }
        const unsigned outputs = f->outputs;
        end(f);
        CHECK(f->outputs == outputs);
        stop(f);
    }
}

int main(void)
{
    CHECK(LWIP_TCP_SACK_OUT == 1 && LWIP_TCP_MAX_SACK_NUM == sack_limit);
    wwLwipEngineSharedInit();
    testCaseSet("SACK permission negotiation and refusal");
    negotiation();
    testCaseSet("immediate selective gap ACKs during a receive batch");
    gapRanges(100);
    testCaseSet("selective gap ranges across sequence wrap");
    gapRanges(UINT32_MAX - 192U);
    testCaseSet("bounded out-of-order eviction and cumulative recovery");
    boundedRetention();
    testCaseSet("four wire SACK ranges retain the most recent gaps");
    rangeCapacity();
    testCaseSet("segment-pool refusal and queue cleanup");
    queueCleanupAndRefusal();
    testCaseSet("nonempty out-of-order queue copy refusals retain exact SACK ranges");
    nonemptyQueueRefusals();
    wwLwipEngineSharedCleanup();
    puts("negotiated SACK reports only bounded retained receive ranges");
    return 0;
}
