/*
 * Covers: owner-engine adaptive advertised TCP receive-window targets.
 * Setup: isolated raw engines, scaled/unscaled TCP handshakes and recording netifs.
 * Checks: independent engine shares, old grants, held/refused credit, wrap, failed
 * advertisements, prompt redistribution, batched retirement/reopening, clean
 * close, quiescence and opt-out.
 * Limits: the aggregate is a fair-share target, not an allocation or flight bound;
 * correctness here does not establish WAN latency or throughput improvements.
 * CTest: waterwall.lwip_receive_budget_unit (Debug and Release).
 */
#include "fixtures/lwip/lwip_engine_test_runtime.h"
#include "lwip/ip.h"
#include "lwip/netif.h"
#include "lwip/priv/tcp_priv.h"

enum
{
    flow_limit     = 8,
    aggregate_size = 16 * 1024 * 1024,
    minimum_share  = 64 * 1024,
    local_port     = 1234
};

typedef struct flow_s
{
    struct tcp_pcb *pcb;
    uint32_t        peer_next, last_ack, last_window, last_edge;
    unsigned        outputs, ack_outputs, resets, fins, received, refusals;
    uint8_t         last_flags;
    bool            scaled, fail_output, refuse_next;
} flow_t;

typedef struct fixture_s
{
    ww_lwip_engine_t *engine, *previous;
    struct netif      netif;
    struct tcp_pcb   *listener;
    unsigned          wid;
    flow_t            flow[flow_limit];
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

static void enter(fixture_t *f)
{
    owner      = f->wid;
    owner_loop = (struct wloop_s *) &f->netif;
    CHECK(wwLwipEngineEnter(f->engine, &f->previous));
}

static void leave(fixture_t *f)
{
    wwLwipEngineLeave(f->engine, f->previous);
}

static err_t output(struct netif *netif, struct pbuf *packet, const ip4_addr_t *destination)
{
    (void) destination;
    fixture_t *f = netif->state;
    uint8_t    bytes[1500];
    CHECK(wwLwipEngineCurrent() == f->engine && packet->tot_len <= sizeof(bytes));
    CHECK(pbuf_copy_partial(packet, bytes, packet->tot_len, 0) == packet->tot_len);
    CHECK(bytes[0] == 0x45 && bytes[9] == 6 && get16(bytes + 2) == packet->tot_len);
    CHECK(wwLwipChecksum(bytes, 20) == 0xffff);
    const unsigned port = get16(bytes + 20);
    CHECK(port >= local_port && port < local_port + flow_limit);
    flow_t *flow = &f->flow[port - local_port];
    ++flow->outputs;
    flow->last_flags = bytes[33];
    flow->resets += (flow->last_flags & TCP_RST) != 0;
    flow->fins += (flow->last_flags & TCP_FIN) != 0;
    if ((flow->last_flags & (TCP_ACK | TCP_RST)) == TCP_ACK)
    {
        ++flow->ack_outputs;
        flow->last_ack    = get32(bytes + 28);
        flow->last_window = get16(bytes + 34);
        if (flow->scaled && (flow->last_flags & TCP_SYN) == 0)
            flow->last_window <<= TCP_RCV_SCALE;
        flow->last_edge = flow->last_ack + flow->last_window;
    }
    return flow->fail_output ? ERR_IF : ERR_OK;
}

static err_t initNetif(struct netif *netif)
{
    netif->name[0] = 'r';
    netif->name[1] = 'b';
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

static err_t receive(void *argument, struct tcp_pcb *pcb, struct pbuf *packet, err_t error)
{
    flow_t *flow = argument;
    CHECK(flow->pcb == pcb && error == ERR_OK);
    if (packet == NULL)
        return ERR_OK;
    if (flow->refuse_next)
    {
        flow->refuse_next = false;
        ++flow->refusals;
        return ERR_MEM;
    }
    flow->received += packet->tot_len;
    pbuf_free(packet);
    return ERR_OK;
}

static err_t accepted(void *argument, struct tcp_pcb *pcb, err_t error)
{
    flow_t *flow = argument;
    CHECK(error == ERR_OK && flow->pcb == pcb);
    tcp_arg(pcb, flow);
    tcp_recv(pcb, receive);
    tcp_err(pcb, lost);
    return ERR_OK;
}

/* The caller holds this owner engine. Input itself enters a nested stack scope. */
static void inject(fixture_t *f, unsigned index, uint8_t flags, uint16_t payload)
{
    flow_t        *flow                = &f->flow[index];
    const unsigned options             = (flags & TCP_SYN) != 0 ? (flow->scaled ? 8U : 4U) : 0;
    const uint16_t length              = (uint16_t) (40 + options + payload);
    uint8_t        bytes[48 + TCP_MSS] = {0x45}, pseudo[40 + TCP_MSS] = {0};
    CHECK(payload <= TCP_MSS && flow->pcb != NULL);
    put16(bytes + 2, length);
    bytes[8]  = 64;
    bytes[9]  = 6;
    bytes[12] = bytes[16] = 10;
    bytes[15]             = 2;
    bytes[19]             = 1;
    put16(bytes + 20, 80);
    put16(bytes + 22, (uint16_t) (local_port + index));
    put32(bytes + 24, flow->peer_next);
    put32(bytes + 28, (flags & TCP_ACK) != 0 ? flow->pcb->snd_nxt : 0);
    bytes[32] = (uint8_t) ((5 + options / 4) << 4);
    bytes[33] = flags;
    put16(bytes + 34, UINT16_MAX);
    if (options != 0)
    {
        bytes[40] = 2;
        bytes[41] = 4;
        put16(bytes + 42, TCP_MSS);
        if (flow->scaled)
        {
            bytes[44] = 1;
            bytes[45] = 3;
            bytes[46] = 3;
            bytes[47] = TCP_RCV_SCALE;
        }
    }
    memset(bytes + 40 + options, 0x5a, payload);
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

static void start(fixture_t *f, unsigned wid)
{
    memset(f, 0, sizeof(*f));
    f->wid     = wid;
    owner      = wid;
    owner_loop = (struct wloop_s *) &f->netif;
    f->engine  = wwLwipEngineCreate((uint8_t) wid, (struct wloop_s *) owner_loop);
    CHECK(f->engine != NULL);
    enter(f);
    ip4_addr_t address, mask, gateway;
    IP4_ADDR(&address, 10, 0, 0, 1);
    IP4_ADDR(&mask, 255, 255, 255, 0);
    ip4_addr_set_zero(&gateway);
    CHECK(netif_add(&f->netif, &address, &mask, &gateway, f, initNetif, ip_input) != NULL);
    netif_set_up(&f->netif);
    netif_set_link_up(&f->netif);
    leave(f);
}

static flow_t *openFlow(fixture_t *f, unsigned index, bool scaled, uint32_t initial)
{
    CHECK(index < flow_limit && f->flow[index].pcb == NULL);
    enter(f);
    flow_t *flow    = &f->flow[index];
    flow->scaled    = scaled;
    flow->peer_next = initial;
    flow->pcb       = tcp_new();
    CHECK(flow->pcb != NULL && flow->pcb->ww_receive_previous == NULL);
    CHECK(tcp_bind_netif(flow->pcb, &f->netif) == ERR_OK);
    CHECK(tcp_bind(flow->pcb, IP_ADDR_ANY, (uint16_t) (local_port + index)) == ERR_OK);
    tcp_arg(flow->pcb, flow);
    tcp_recv(flow->pcb, receive);
    tcp_err(flow->pcb, lost);
    ip_addr_t peer;
    IP_ADDR4(&peer, 10, 0, 0, 2);
    CHECK(tcp_connect(flow->pcb, &peer, 80, NULL) == ERR_OK);
    CHECK(flow->pcb->state == SYN_SENT && flow->last_flags == TCP_SYN);
    inject(f, index, TCP_SYN | TCP_ACK, 0);
    ++flow->peer_next;
    CHECK(flow->pcb->state == ESTABLISHED);
    CHECK(((flow->pcb->flags & TF_WND_SCALE) != 0) == scaled);
    CHECK(flow->last_flags == TCP_ACK);
    leave(f);
    return flow;
}

static void sendAck(fixture_t *f, unsigned index)
{
    enter(f);
    tcp_ack_now(f->flow[index].pcb);
    (void) tcp_output(f->flow[index].pcb);
    leave(f);
}

static void expectWindow(const flow_t *flow, uint32_t expected)
{
    const uint32_t quantum = flow->scaled ? 1U << TCP_RCV_SCALE : 1U;
    CHECK(flow->last_window <= expected && flow->last_window + quantum > expected);
}

static void stop(fixture_t *f)
{
    enter(f);
    if (f->listener != NULL)
    {
        CHECK(tcp_close(f->listener) == ERR_OK);
        f->listener = NULL;
    }
    for (unsigned i = 0; i < flow_limit; ++i)
    {
        if (f->flow[i].pcb != NULL)
        {
            tcp_abort(f->flow[i].pcb);
            CHECK(f->flow[i].pcb == NULL);
        }
    }
    leave(f);
    wwLwipEngineDestroy(f->engine);
    CHECK(wwLwipEngineCurrent() == NULL);
}

static void initBudget(uint32_t amount)
{
    wwLwipEngineSetDefaultReceiveBudget(amount);
    wwLwipEngineSharedInit();
}

static void joinFlows(fixture_t *f, unsigned first, unsigned end)
{
    for (unsigned i = first; i < end; ++i)
        openFlow(f, i, true, 100 + i * 65536U);
}

static void engineIsolation(bool use_default)
{
    fixture_t      a, b;
    const uint32_t budget       = use_default ? WW_LWIP_DEFAULT_RECEIVE_BUDGET : aggregate_size;
    const uint32_t joined_share = budget == 0 ? TCP_WND : LWIP_MIN(TCP_WND, LWIP_MAX(minimum_share, budget / 6U));
    /* Exercise untouched startup defaults as well as explicitly enabled shares. */
    if (use_default)
        wwLwipEngineSharedInit();
    else
        initBudget(aggregate_size);
    start(&a, 0);
    flow_t *first = openFlow(&a, 0, true, 100);
    expectWindow(first, TCP_WND);
    enter(&a);
    struct tcp_pcb *unused = tcp_new();
    CHECK(unused != NULL && unused->ww_receive_previous == NULL);
    CHECK(tcp_bind(unused, IP_ADDR_ANY, 9000) == ERR_OK);
    a.listener = tcp_listen(unused);
    CHECK(a.listener != NULL);
    leave(&a);
    joinFlows(&a, 1, 6);
    expectWindow(&a.flow[5], joined_share);
    /* An old advertised grant survives joins instead of being withdrawn. */
    sendAck(&a, 0);
    expectWindow(first, TCP_WND);
    start(&b, 1);
    expectWindow(openFlow(&b, 0, true, 100), TCP_WND);
    sendAck(&a, 5);
    expectWindow(&a.flow[5], joined_share);
    stop(&b);
    stop(&a);
    wwLwipEngineSharedCleanup();
}

static void heldCreditAndReopen(uint32_t initial)
{
    fixture_t f;
    initBudget(aggregate_size);
    start(&f, 0);
    flow_t        *flow     = openFlow(&f, 0, true, initial);
    const uint32_t old_edge = flow->last_edge;
    joinFlows(&f, 1, 6);
    enter(&f);
    const unsigned drain_acks = flow->ack_outputs;
    /* Receive the entire old grant, even though the new share is smaller. */
    for (uint32_t remaining = TCP_WND; remaining != 0;)
    {
        const uint16_t amount = (uint16_t) (remaining < TCP_MSS ? remaining : TCP_MSS);
        inject(&f, 0, TCP_ACK, amount);
        flow->peer_next += amount;
        remaining -= amount;
        /* Keep one committed logical edge while scaled wire windows round
         * down. Reusing each rounded wire edge would compound that loss. */
        CHECK(flow->pcb->rcv_ann_right_edge == old_edge);
        CHECK((uint32_t) (old_edge - flow->last_edge) < (1U << TCP_RCV_SCALE));
    }
    CHECK(flow->ack_outputs - drain_acks > 128);
    CHECK(flow->received == TCP_WND && flow->pcb->rcv_wnd == 0);
    CHECK(flow->pcb->rcv_nxt == old_edge);
    tcp_ack_now(flow->pcb);
    CHECK(tcp_output(flow->pcb) == ERR_OK);
    CHECK(flow->last_window == 0);
    /* Some delivered credit is available, but held debt still exceeds share. */
    wwLwipTcpRecved(flow->pcb, 1024U * 1024U);
    CHECK(flow->pcb->rcv_wnd == 1024U * 1024U && flow->last_window == 0);
    leave(&f);
    const unsigned before = flow->ack_outputs;
    enter(&f);
    for (unsigned i = 1; i < 6; ++i)
        tcp_abort(f.flow[i].pcb);
    leave(&f);
    CHECK(flow->ack_outputs > before);
    expectWindow(flow, 1024U * 1024U);
    enter(&f);
    wwLwipTcpRecved(flow->pcb, 3U * 1024U * 1024U);
    CHECK(flow->pcb->rcv_wnd == TCP_WND);
    leave(&f);
    sendAck(&f, 0);
    expectWindow(flow, TCP_WND);
    enter(&f);
    const unsigned resets = flow->resets;
    CHECK(tcp_close(flow->pcb) == ERR_OK);
    CHECK(flow->resets == resets && (flow->last_flags & TCP_FIN) != 0);
    leave(&f);
    stop(&f);
    wwLwipEngineSharedCleanup();
}

static void failedGrant(void)
{
    fixture_t f;
    initBudget(aggregate_size);
    start(&f, 0);
    joinFlows(&f, 0, 6);
    flow_t        *flow      = &f.flow[5];
    const uint32_t committed = flow->pcb->ww_rcv_advertised_edge;
    const uint32_t logical   = flow->pcb->rcv_ann_right_edge;
    expectWindow(flow, aggregate_size / 6);
    flow->fail_output = true;
    enter(&f);
    for (unsigned i = 0; i < 5; ++i)
        tcp_abort(f.flow[i].pcb);
    leave(&f);
    /* A larger grant may have been attempted, but was not accepted by output. */
    sendAck(&f, 5);
    CHECK(flow->pcb->ww_rcv_advertised_edge == committed);
    CHECK(flow->pcb->rcv_ann_right_edge == logical);
    joinFlows(&f, 0, 5);
    flow->fail_output = false;
    sendAck(&f, 5);
    expectWindow(flow, aggregate_size / 6);
    CHECK(flow->pcb->ww_rcv_advertised_edge == flow->last_edge);
    stop(&f);
    wwLwipEngineSharedCleanup();
}

static void refusedCreditAndFloor(void)
{
    fixture_t f;
    initBudget(minimum_share);
    start(&f, 0);
    flow_t *flow = openFlow(&f, 0, true, 100);
    openFlow(&f, 1, true, 100);
    expectWindow(flow, minimum_share);
    expectWindow(&f.flow[1], minimum_share);
    /* Two minimum grants exceed this target: it is deliberately not a hard cap. */
    enter(&f);
    flow->refuse_next = true;
    inject(&f, 0, TCP_ACK, 1460);
    flow->peer_next += 1460;
    CHECK(flow->refusals == 1 && flow->received == 0 && flow->pcb->refused_data != NULL);
    CHECK(flow->pcb->rcv_wnd == TCP_WND - 1460);
    CHECK(tcp_process_refused_data(flow->pcb) == ERR_OK);
    CHECK(flow->received == 1460 && flow->pcb->refused_data == NULL);
    /* Replay consumed the pbuf once; it did not return application credit. */
    CHECK(flow->pcb->rcv_wnd == TCP_WND - 1460);
    wwLwipTcpRecved(flow->pcb, 1460);
    CHECK(flow->pcb->rcv_wnd == TCP_WND);
    leave(&f);
    sendAck(&f, 0);
    expectWindow(flow, minimum_share);
    stop(&f);
    wwLwipEngineSharedCleanup();
}

static void batchRetirementAndReopen(void)
{
    fixture_t f;
    initBudget(4U * minimum_share);
    start(&f, 0);
    joinFlows(&f, 0, 6);
    flow_t *flow = &f.flow[5];
    expectWindow(flow, minimum_share);
    enter(&f);
    for (uint32_t remaining = minimum_share; remaining != 0;)
    {
        const uint16_t amount = (uint16_t) LWIP_MIN(remaining, TCP_MSS);
        inject(&f, 5, TCP_ACK, amount);
        flow->peer_next += amount;
        remaining -= amount;
    }
    tcp_ack_now(flow->pcb);
    CHECK(tcp_output(flow->pcb) == ERR_OK);
    CHECK(flow->last_window == 0 && flow->pcb->rcv_wnd == TCP_WND - minimum_share);
    leave(&f);
    const unsigned before = flow->ack_outputs;

    wwLwipEngineBeginAckBatch(f.engine);
    enter(&f);
    /* Keep one ordinary ACK queued while another queued member is retired. */
    for (unsigned i = 0; i < 2; ++i)
    {
        inject(&f, i, TCP_ACK, 512);
        f.flow[i].peer_next += 512;
        CHECK(f.flow[i].pcb->ww_ack_previous != NULL);
    }
    const unsigned pending_acks  = f.flow[0].ack_outputs;
    const unsigned survivor_acks = f.flow[1].ack_outputs;
    tcp_abort(f.flow[0].pcb);
    /* tcp_pcb_remove settles its delayed ACK before the reset. The batch must
     * not retain that freed PCB or emit another ACK for it afterward. */
    CHECK(f.flow[0].pcb == NULL && f.flow[0].ack_outputs == pending_acks + 1);
    CHECK(f.flow[0].resets == 1 && f.flow[0].last_flags == (TCP_RST | TCP_ACK));
    const unsigned retired_acks = f.flow[0].ack_outputs;
    tcp_abort(f.flow[2].pcb);
    /* Six through four members all use the floor. No credit was returned. */
    leave(&f);
    CHECK(flow->ack_outputs == before && flow->last_window == 0);
    enter(&f);
    tcp_abort(f.flow[3].pcb);
    tcp_abort(f.flow[4].pcb);
    leave(&f);
    CHECK(flow->ack_outputs == before && f.flow[1].ack_outputs == survivor_acks);
    wwLwipEngineEndAckBatch(f.engine);

    CHECK(f.flow[0].pcb == NULL && f.flow[0].ack_outputs == retired_acks);
    CHECK(f.flow[1].ack_outputs == survivor_acks + 1 && f.flow[1].pcb->ww_ack_previous == NULL);
    CHECK(flow->ack_outputs == before + 1 && flow->pcb->ww_ack_previous == NULL);
    expectWindow(flow, minimum_share);
    CHECK(flow->pcb->rcv_wnd == TCP_WND - minimum_share);
    enter(&f);
    wwLwipTcpRecved(flow->pcb, minimum_share);
    leave(&f);
    expectWindow(flow, 2U * minimum_share);
    stop(&f);
    wwLwipEngineSharedCleanup();
}

static void passiveAndUnscaled(void)
{
    fixture_t f;
    initBudget(minimum_share);
    start(&f, 0);
    enter(&f);
    flow_t *flow        = &f.flow[0];
    flow->scaled        = true;
    flow->peer_next     = UINT32_MAX - 1024U;
    struct tcp_pcb *pcb = tcp_new();
    CHECK(pcb != NULL && tcp_bind_netif(pcb, &f.netif) == ERR_OK);
    CHECK(tcp_bind(pcb, IP_ADDR_ANY, local_port) == ERR_OK);
    tcp_arg(pcb, flow);
    f.listener = tcp_listen(pcb);
    CHECK(f.listener != NULL);
    tcp_accept(f.listener, accepted);
    flow->pcb = f.listener;
    inject(&f, 0, TCP_SYN, 0);
    flow->pcb = tcp_active_pcbs;
    CHECK(flow->pcb != NULL && flow->pcb->state == SYN_RCVD);
    CHECK(flow->last_flags == (TCP_SYN | TCP_ACK) && flow->last_window <= UINT16_MAX);
    ++flow->peer_next;
    inject(&f, 0, TCP_ACK, 0);
    CHECK(flow->pcb->state == ESTABLISHED);
    leave(&f);
    sendAck(&f, 0);
    /* The unscaled SYN granted 65,535 bytes. A one-byte increase to the
     * 64-KiB target stays below lwIP's normal MSS advertisement threshold. */
    expectWindow(flow, UINT16_MAX);
    flow_t *unscaled = openFlow(&f, 1, false, 100);
    expectWindow(unscaled, UINT16_MAX);
    enter(&f);
    /* An actual unread byte still makes close reset, just as without budgeting. */
    inject(&f, 1, TCP_ACK, 1);
    ++unscaled->peer_next;
    pcb                   = unscaled->pcb;
    unscaled->pcb         = NULL;
    const unsigned resets = unscaled->resets;
    CHECK(tcp_close(pcb) == ERR_OK && unscaled->resets > resets);
    leave(&f);
    stop(&f);
    wwLwipEngineSharedCleanup();
}

static void purgeAndQuiesce(void)
{
    fixture_t f;
    initBudget(aggregate_size);
    start(&f, 0);
    joinFlows(&f, 0, 6);
    enter(&f);
    struct tcp_pcb *pcb = f.flow[0].pcb;
    CHECK(pcb->ww_receive_previous != NULL);
    tcp_pcb_purge(pcb);
    CHECK(pcb->ww_receive_previous == NULL);
    tcp_pcb_purge(pcb);
    leave(&f);
    /* A repeated purge and eventual free must not decrement another flow's share. */
    enter(&f);
    tcp_abort(pcb);
    leave(&f);
    sendAck(&f, 5);
    expectWindow(&f.flow[5], aggregate_size / 5);
    const unsigned before = f.flow[5].ack_outputs;
    owner                 = f.wid;
    owner_loop            = (struct wloop_s *) &f.netif;
    wwLwipEngineQuiesce(f.engine);
    enter(&f);
    for (unsigned i = 1; i < 5; ++i)
        tcp_abort(f.flow[i].pcb);
    leave(&f);
    CHECK(f.flow[5].ack_outputs == before);
    stop(&f);
    wwLwipEngineSharedCleanup();
}

static void disabled(void)
{
    fixture_t f;
    initBudget(0);
    start(&f, 0);
    joinFlows(&f, 0, 6);
    for (unsigned i = 0; i < 6; ++i)
    {
        sendAck(&f, i);
        expectWindow(&f.flow[i], TCP_WND);
    }
    stop(&f);
    wwLwipEngineSharedCleanup();
}

int main(void)
{
    CHECK(TCP_WND == 4U * 1024U * 1024U && TCP_RCV_SCALE == 7);
    testCaseSet("default receive policy preserves independent engine windows");
    engineIsolation(true);
    testCaseSet("enabled receive shares are independent per engine and exclude listeners");
    engineIsolation(false);
    testCaseSet("old receive grants and held credit survive joins and promptly reopen");
    heldCreditAndReopen(100);
    testCaseSet("old receive grants survive TCP sequence wrap");
    heldCreditAndReopen(UINT32_MAX - 2U * 1024U * 1024U);
    testCaseSet("failed output never commits a larger receive grant");
    failedGrant();
    testCaseSet("receive refusal retains credit and minimum shares remain usable");
    refusedCreditAndFloor();
    testCaseSet("batch retirement crosses the receive-share floor and reopens without stale ACKs");
    batchRetirementAndReopen();
    testCaseSet("passive and unscaled handshakes preserve close semantics");
    passiveAndUnscaled();
    testCaseSet("purge is idempotent and quiescence emits no redistribution updates");
    purgeAndQuiesce();
    testCaseSet("disabled budgeting retains legacy full windows");
    disabled();
    puts("adaptive TCP receive targets preserve credit, advertisements and owner lifetime");
    return 0;
}
