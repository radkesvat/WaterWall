/*
 * Covers: sender-side RACK loss detection for SACK peers (ww/lwip/tcp_rack.c).
 * Setup: a private raw engine, a real passive IPv4/TCP handshake negotiating SACK and timestamps,
 *        a recording MTU-1500 netif and the shared test clock.
 * Checks: reordering inside the reordering window is not retransmitted even after three SACKed
 *         segments; two holes get one cwnd reduction; the timer retransmits a hole once its window
 *         expired; a spurious recovery is undone by the timestamp echo; reneging resends the head;
 *         a tail loss probe follows two smoothed RTTs of silence; malformed and out-of-range SACK
 *         blocks are ignored; peers without SACK keep three-duplicate-ACK fast retransmit.
 * Limits: single connection, no throughput or pacing claims.
 * CTest: waterwall.lwip_rack_unit (Debug and Release).
 */
#include "fixtures/lwip/lwip_engine_test_runtime.h"
#include "lwip/ip.h"
#include "lwip/netif.h"
#include "lwip/priv/tcp_priv.h"
#include "tcp_rack.h"

enum
{
    record_limit = 256,
    segments     = 12,
    rtt_ms       = 100
};

typedef struct
{
    uint32_t seq, tsval;
    uint16_t len;
    uint8_t  flags;
} record_t;

typedef struct
{
    ww_lwip_engine_t *engine, *previous;
    struct netif      netif;
    struct tcp_pcb   *pcb;
    uint32_t          peer_next, peer_ts, seglen;
    record_t          sent[record_limit];
    unsigned          outputs;
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
    return (uint16_t) (((unsigned) p[0] << 8) | p[1]);
}

static uint32_t get32(const uint8_t *p)
{
    return ((uint32_t) get16(p) << 16) | get16(p + 2);
}

static void setClock(uint32_t now)
{
    atomic_store(&clock_ms, now);
}

static err_t output(struct netif *netif, struct pbuf *packet, const ip4_addr_t *destination)
{
    (void) destination;
    fixture_t *f = netif->state;
    uint8_t    bytes[1600];
    CHECK(f == &fixture && packet->tot_len >= 40 && packet->tot_len <= sizeof(bytes));
    CHECK(pbuf_copy_partial(packet, bytes, packet->tot_len, 0) == packet->tot_len);
    CHECK(bytes[0] == 0x45 && bytes[9] == 6);
    const unsigned header = 20U + (bytes[32] >> 4) * 4U;
    CHECK(f->outputs < record_limit);
    record_t *r = &f->sent[f->outputs++];
    r->seq      = get32(bytes + 24);
    r->flags    = bytes[33];
    r->len      = (uint16_t) (packet->tot_len - header);
    r->tsval    = 0;
    for (unsigned i = 40; i < header && bytes[i] != 0;)
    {
        if (bytes[i] == 1)
        {
            ++i;
            continue;
        }
        CHECK(i + 1 < header && bytes[i + 1] >= 2);
        if (bytes[i] == 8)
        {
            r->tsval = get32(bytes + i + 2);
        }
        i += bytes[i + 1];
    }
    return ERR_OK;
}

static err_t initNetif(struct netif *netif)
{
    netif->name[0] = 'r';
    netif->name[1] = 'k';
    netif->mtu     = 1500;
    netif->output  = output;
    return ERR_OK;
}

static err_t accepted(void *argument, struct tcp_pcb *pcb, err_t error)
{
    (void) argument;
    (void) pcb;
    (void) error;
    return ERR_OK;
}

/* One segment from the peer. sack: pairs of absolute (left, right); count <= 3. A non-zero
   bad_sack_length writes a malformed SACK option of that length instead. */
static void injectFull(fixture_t *f, uint8_t flags, uint32_t ack, uint32_t tsecr, const uint32_t *sack, unsigned count,
                       bool permit_sack, bool timestamps, uint8_t bad_sack_length)
{
    CHECK(count <= 3);
    uint8_t  options[40] = {0};
    unsigned o           = 0;
    if (timestamps)
    {
        options[o++] = 1;
        options[o++] = 1;
        options[o++] = 8;
        options[o++] = 10;
        put32(options + o, ++f->peer_ts);
        put32(options + o + 4, tsecr);
        o += 8;
    }
    if (permit_sack)
    {
        options[o++] = 1;
        options[o++] = 1;
        options[o++] = 4;
        options[o++] = 2;
    }
    if (bad_sack_length != 0)
    {
        options[o++] = 1;
        options[o++] = 1;
        options[o++] = 5;
        options[o++] = bad_sack_length;
        o += 8; /* bytes the bad option would claim to cover */
    }
    else if (count != 0)
    {
        options[o++] = 1;
        options[o++] = 1;
        options[o++] = 5;
        options[o++] = (uint8_t) (2 + 8 * count);
        for (unsigned i = 0; i < count; ++i)
        {
            put32(options + o, sack[2 * i]);
            put32(options + o + 4, sack[2 * i + 1]);
            o += 8;
        }
    }
    CHECK(o % 4 == 0 && o <= 40);
    const uint16_t length     = (uint16_t) (40 + o);
    uint8_t        bytes[80]  = {0x45};
    uint8_t        pseudo[72] = {0};
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
    put32(bytes + 28, ack);
    bytes[32] = (uint8_t) ((5 + o / 4) << 4);
    bytes[33] = flags;
    put16(bytes + 34, UINT16_MAX);
    memcpy(bytes + 40, options, o);
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

static void ack(fixture_t *f, uint32_t ackno, uint32_t tsecr, const uint32_t *sack, unsigned count)
{
    injectFull(f, TCP_ACK, ackno, tsecr, sack, count, false, true, 0);
}

static fixture_t *start(bool sack)
{
    fixture_t *f = &fixture;
    memset(f, 0, sizeof(*f));
    owner      = 0;
    owner_loop = (struct wloop_s *) &f->netif;
    /* The handshake takes one path RTT and ends at 1000, where data starts. */
    setClock(1000 - rtt_ms);
    f->engine = wwLwipEngineCreate((uint8_t) owner, (struct wloop_s *) owner_loop);
    CHECK(f->engine != NULL && wwLwipEngineEnter(f->engine, &f->previous));
    ip4_addr_t address, mask, gateway;
    IP4_ADDR(&address, 10, 0, 0, 1);
    IP4_ADDR(&mask, 255, 255, 255, 0);
    ip4_addr_set_zero(&gateway);
    CHECK(netif_add(&f->netif, &address, &mask, &gateway, f, initNetif, ip_input) != NULL);
    netif_set_up(&f->netif);
    netif_set_link_up(&f->netif);
    struct tcp_pcb *pcb = tcp_new();
    CHECK(pcb != NULL && tcp_bind_netif(pcb, &f->netif) == ERR_OK);
    CHECK(tcp_bind(pcb, IP_ADDR_ANY, 1234) == ERR_OK);
    struct tcp_pcb *listener = tcp_listen(pcb);
    CHECK(listener != NULL);
    tcp_accept(listener, accepted);
    f->pcb       = listener;
    f->peer_next = 5000;
    injectFull(f, TCP_SYN, 0, 0, NULL, 0, sack, true, 0);
    f->pcb = tcp_active_pcbs;
    CHECK(f->pcb != NULL && f->pcb->state == SYN_RCVD);
    f->peer_next += 1;
    setClock(1000);
    injectFull(f, TCP_ACK, f->pcb->snd_nxt, f->sent[f->outputs - 1].tsval, NULL, 0, false, true, 0);
    CHECK(f->pcb->state == ESTABLISHED);
    CHECK(((f->pcb->flags & TF_SACK) != 0) == sack && wwTcpRackActive(f->pcb) == (int) sack);
    CHECK(tcp_close(listener) == ERR_OK);
    /* Segments are mss minus the timestamp option; Nagle would hold the last one. */
    tcp_nagle_disable(f->pcb);
    f->outputs = 0;
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

/* Sends `segments` full segments at the current clock; returns the first sequence. */
static uint32_t sendBurst(fixture_t *f)
{
    static uint8_t data[segments * TCP_MSS];
    /* Timestamps occupy option space in every data segment. */
    f->seglen          = f->pcb->mss - ((f->pcb->flags & TF_TIMESTAMP) ? 12U : 0U);
    f->pcb->cwnd       = (tcpwnd_size_t) (64U * f->pcb->mss);
    const uint32_t seq = f->pcb->snd_nxt;
    CHECK(tcp_write(f->pcb, data, (u16_t) (segments * f->seglen), TCP_WRITE_FLAG_COPY) == ERR_OK);
    f->outputs = 0;
    CHECK(tcp_output(f->pcb) == ERR_OK);
    CHECK(f->outputs == segments);
    for (unsigned i = 0; i < segments; ++i)
    {
        CHECK(f->sent[i].len == f->seglen && f->sent[i].seq == seq + i * f->seglen);
    }
    f->outputs = 0;
    return seq;
}

static uint32_t segStart(const fixture_t *f, uint32_t base, unsigned index)
{
    return base + index * f->seglen;
}

static unsigned dataRetransmissions(const fixture_t *f, uint32_t seq)
{
    unsigned n = 0;
    for (unsigned i = 0; i < f->outputs; ++i)
    {
        n += f->sent[i].len != 0 && f->sent[i].seq == seq;
    }
    return n;
}

/* First ACK: one RTT sample establishes min_rtt and srtt. */
static void firstSample(fixture_t *f, uint32_t base, uint32_t tsval)
{
    setClock(1000 + rtt_ms);
    ack(f, segStart(f, base, 1), tsval, NULL, 0);
    CHECK(f->pcb->ww_rack_min_rtt_ms == rtt_ms && f->pcb->ww_rack_srtt_ms == rtt_ms);
}

static void sackRange(fixture_t *f, uint32_t base, unsigned hole, unsigned from, unsigned to, uint32_t tsval)
{
    const uint32_t block[2] = {segStart(f, base, from), segStart(f, base, to)};
    ack(f, segStart(f, base, hole), tsval, block, 1);
}

/* Reordering is learned, after which a later hole with three SACKed segments above it waits for
   the reordering window instead of being fast retransmitted. */
static void reorderingIsNotLoss(void)
{
    fixture_t     *f     = start(true);
    const uint32_t base  = sendBurst(f);
    const uint32_t tsval = 0;
    firstSample(f, base, tsval);
    /* Segment 1 is late: 2 is SACKed, then 1 arrives and both are cumulatively ACKed. */
    setClock(1000 + rtt_ms + 1);
    sackRange(f, base, 1, 2, 3, tsval);
    setClock(1000 + rtt_ms + 3);
    ack(f, segStart(f, base, 3), tsval, NULL, 0);
    CHECK((f->pcb->ww_rack_state & WW_TCP_RACK_REORDERED) != 0);
    CHECK(f->outputs == 0 || dataRetransmissions(f, segStart(f, base, 1)) == 0);
    const tcpwnd_size_t cwnd = f->pcb->cwnd;
    /* Segment 3 is late; 4..6 are SACKed. Classic lwIP retransmits on the third duplicate. */
    f->outputs = 0;
    for (unsigned top = 5; top <= 7; ++top)
    {
        setClock(1000 + rtt_ms + top);
        sackRange(f, base, 3, 4, top, tsval);
    }
    CHECK(f->pcb->ww_rack_sacked_out == 3 && dataRetransmissions(f, segStart(f, base, 3)) == 0);
    CHECK((f->pcb->ww_rack_state & WW_TCP_RACK_RECOVERY) == 0 && f->pcb->cwnd >= cwnd);
    /* The late segment arrives inside the window: no retransmission, no reduction. */
    setClock(1000 + rtt_ms + 10);
    ack(f, segStart(f, base, 7), tsval, NULL, 0);
    CHECK(dataRetransmissions(f, segStart(f, base, 3)) == 0 && f->pcb->ww_rack_sacked_out == 0);
    stop(f);
}

/* Without reordering evidence and with three or more SACKed segments the reordering window is
   zero (RFC 8985 6.2): both holes are lost on the ACK that SACKs past them, and the episode
   keeps a single reduction through the partial ACK that repairs the first hole. */
static void twoHolesOneReduction(void)
{
    fixture_t     *f    = start(true);
    const uint32_t base = sendBurst(f);
    firstSample(f, base, 0);
    const tcpwnd_size_t before = f->pcb->cwnd;
    const uint32_t blocks[4] = {segStart(f, base, 2), segStart(f, base, 5), segStart(f, base, 6), segStart(f, base, 9)};
    setClock(1000 + rtt_ms + 2);
    f->outputs = 0;
    ack(f, segStart(f, base, 1), 0, blocks, 2);
    CHECK(f->pcb->ww_rack_sacked_out == 6);
    CHECK(dataRetransmissions(f, segStart(f, base, 1)) == 1 && dataRetransmissions(f, segStart(f, base, 5)) == 1);
    CHECK(dataRetransmissions(f, segStart(f, base, 9)) == 0 && (f->pcb->ww_rack_state & WW_TCP_RACK_RECOVERY));
    const tcpwnd_size_t ssthresh = f->pcb->ssthresh;
    CHECK(ssthresh == LWIP_MAX(LWIP_MIN(before, f->pcb->snd_wnd) / 2, 2U * f->pcb->mss));
    const uint32_t retransmitted_ts = f->sent[0].tsval;
    setClock(1000 + 2 * rtt_ms + 3);
    ack(f, segStart(f, base, 5), retransmitted_ts, blocks + 2, 1);
    CHECK(f->pcb->ssthresh == ssthresh && (f->pcb->ww_rack_state & WW_TCP_RACK_RECOVERY) != 0);
    setClock(1000 + 2 * rtt_ms + 4);
    ack(f, segStart(f, base, segments), retransmitted_ts, NULL, 0);
    CHECK((f->pcb->ww_rack_state & WW_TCP_RACK_RECOVERY) == 0 && f->pcb->ssthresh == ssthresh);
    stop(f);
}

/* One SACKed segment keeps a reordering window of min_rtt / 4: the ACK path waits and the
   timer marks the hole once that window has expired. */
static void timerMarksExpiredHole(void)
{
    fixture_t     *f    = start(true);
    const uint32_t base = sendBurst(f);
    firstSample(f, base, 0);
    setClock(1000 + rtt_ms + 1);
    f->outputs = 0;
    sackRange(f, base, 1, 2, 3, 0);
    CHECK(f->outputs == 0 || dataRetransmissions(f, segStart(f, base, 1)) == 0);
    /* Deadline: transmit 1000 + RACK RTT 101 + window 25. */
    setClock(1000 + rtt_ms + 1 + rtt_ms / 4 - 1);
    f->outputs = 0;
    tcp_fasttmr();
    CHECK(dataRetransmissions(f, segStart(f, base, 1)) == 0);
    setClock(1000 + rtt_ms + 1 + rtt_ms / 4);
    tcp_fasttmr();
    CHECK(dataRetransmissions(f, segStart(f, base, 1)) == 1 && (f->pcb->ww_rack_state & WW_TCP_RACK_RECOVERY));
    stop(f);
}

/* The original of a retransmitted segment arrives: the echo predates the retransmission. */
static void spuriousRecoveryIsUndone(void)
{
    fixture_t     *f    = start(true);
    const uint32_t base = sendBurst(f);
    firstSample(f, base, 0);
    const tcpwnd_size_t cwnd     = f->pcb->cwnd;
    const tcpwnd_size_t ssthresh = f->pcb->ssthresh;
    setClock(1000 + rtt_ms + 1);
    f->outputs = 0;
    sackRange(f, base, 1, 2, 5, 0);
    CHECK(dataRetransmissions(f, segStart(f, base, 1)) == 1 && (f->pcb->ww_rack_state & WW_TCP_RACK_RECOVERY));
    const uint32_t retransmitted_ts = f->sent[0].tsval;
    CHECK(retransmitted_ts == 1000 + rtt_ms + 1);
    /* The late original fills the hole; the receiver echoes the original's older value. */
    setClock(1000 + rtt_ms + 2);
    ack(f, segStart(f, base, 5), retransmitted_ts - 1, NULL, 0);
    CHECK((f->pcb->ww_rack_state & (WW_TCP_RACK_RECOVERY | WW_TCP_RACK_REORDERED)) == WW_TCP_RACK_REORDERED);
    CHECK(f->pcb->cwnd >= cwnd && f->pcb->ssthresh == ssthresh && f->pcb->ww_rack_reo_steps == 1);
    stop(f);
}

/* A SACK for the segment at snd_una without a cumulative ACK means the receiver dropped data it
   reported: resend the head instead of waiting for the retransmission timeout. */
static void renegingResendsTheHead(void)
{
    fixture_t     *f    = start(true);
    const uint32_t base = sendBurst(f);
    firstSample(f, base, 0);
    setClock(1000 + rtt_ms + 1);
    f->outputs = 0;
    sackRange(f, base, 1, 1, 4, 0);
    CHECK(dataRetransmissions(f, segStart(f, base, 1)) == 1);
    CHECK(f->pcb->ww_rack_sacked_out == 0 && f->pcb->ww_rack_sacked_bytes == 0);
    stop(f);
}

/* No ACK at all for two smoothed RTTs: one probe of the highest segment, once. */
static void tailLossProbe(void)
{
    fixture_t     *f    = start(true);
    const uint32_t base = sendBurst(f);
    firstSample(f, base, 0);
    setClock(1000 + rtt_ms + 2 * rtt_ms - 10);
    f->outputs = 0;
    tcp_fasttmr();
    CHECK(f->outputs == 0);
    setClock(1000 + rtt_ms + 2 * rtt_ms + 1);
    tcp_fasttmr();
    CHECK(dataRetransmissions(f, segStart(f, base, segments - 1)) == 1 && f->outputs == 1);
    setClock(1000 + rtt_ms + 4 * rtt_ms + 2);
    tcp_fasttmr();
    CHECK(f->outputs == 1);
    stop(f);
}

/* Malformed options stop parsing; ranges above snd_nxt or below the cumulative ACK mark nothing. */
static void invalidSackIsIgnored(void)
{
    fixture_t     *f    = start(true);
    const uint32_t base = sendBurst(f);
    firstSample(f, base, 0);
    setClock(1000 + rtt_ms + 1);
    injectFull(f, TCP_ACK, segStart(f, base, 1), 0, NULL, 0, false, true, 9);
    injectFull(f, TCP_ACK, segStart(f, base, 1), 0, NULL, 0, false, true, 11);
    CHECK(f->pcb->ww_rack_sacked_out == 0);
    const uint32_t beyond[2] = {f->pcb->snd_nxt, f->pcb->snd_nxt + 4U * f->pcb->mss};
    ack(f, segStart(f, base, 1), 0, beyond, 1);
    const uint32_t below[2] = {base, segStart(f, base, 1)};
    ack(f, segStart(f, base, 1), 0, below, 1);
    CHECK(f->pcb->ww_rack_sacked_out == 0 && f->pcb->ww_rack_sacked_bytes == 0);
    stop(f);
}

/* Without SACK the classic third duplicate ACK still retransmits the head. */
static void withoutSackKeepsFastRetransmit(void)
{
    fixture_t     *f    = start(false);
    const uint32_t base = sendBurst(f);
    setClock(1000 + rtt_ms);
    ack(f, segStart(f, base, 1), 0, NULL, 0);
    f->outputs = 0;
    for (unsigned i = 0; i < 3; ++i)
    {
        setClock(1000 + rtt_ms + 1 + i);
        ack(f, segStart(f, base, 1), 0, NULL, 0);
    }
    tcp_output(f->pcb);
    CHECK(dataRetransmissions(f, segStart(f, base, 1)) == 1);
    stop(f);
}

int main(void)
{
    CHECK(WW_LWIP_TCP_RACK == 1);
    wwLwipEngineSharedInit();
    testCaseSet("learned reordering is not loss after three SACKed segments");
    reorderingIsNotLoss();
    testCaseSet("two holes, one window reduction per recovery episode");
    twoHolesOneReduction();
    testCaseSet("the timer marks a hole once the reordering window expired");
    timerMarksExpiredHole();
    testCaseSet("a spurious recovery is undone by the timestamp echo");
    spuriousRecoveryIsUndone();
    testCaseSet("reneging resends the head");
    renegingResendsTheHead();
    testCaseSet("a tail loss probe after two smoothed RTTs, once");
    tailLossProbe();
    testCaseSet("malformed and out-of-range SACK blocks are ignored");
    invalidSackIsIgnored();
    testCaseSet("peers without SACK keep three-duplicate-ACK fast retransmit");
    withoutSackKeepsFastRetransmit();
    wwLwipEngineSharedCleanup();
    puts("RACK replaces duplicate-ACK loss detection for SACK peers");
    return 0;
}
