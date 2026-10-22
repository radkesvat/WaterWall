/*
 * Covers: bounded owner-engine TCP ACK coalescing before packet construction.
 * Setup: the existing small raw-engine runtime fixture, real IPv4/TCP handshakes and packets,
 * and a recording netif; no host sockets or timers are needed for successful batches.
 * Checks: exact cumulative ACK/window values and packet counts, credit and zero-window updates,
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
    uint32_t          peer_next, last_ack;
    uint16_t          last_window, last_payload;
    uint8_t           last_flags;
    unsigned          outputs, received, fins, recursive_refusals;
    bool              return_credit, fail_output, try_recursive_input;
} fixture_t;

static fixture_t         fixtures[2];
static pthread_barrier_t rendezvous;

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
    uint8_t    bytes[40];
    CHECK(f == &fixtures[owner] && wwLwipEngineCurrent() == f->engine);
    CHECK(pbuf_copy_partial(packet, bytes, sizeof(bytes), 0) == sizeof(bytes));
    CHECK(bytes[0] == 0x45 && bytes[9] == 6);
    ++f->outputs;
    f->last_ack     = get32(bytes + 28);
    f->last_flags   = bytes[33];
    f->last_window  = get16(bytes + 34);
    f->last_payload = (uint16_t) (get16(bytes + 2) - 20 - (bytes[32] >> 4) * 4);
    if (f->try_recursive_input)
    {
        f->try_recursive_input = false;
        struct pbuf *nested    = pbuf_alloc(PBUF_RAW, 20, PBUF_RAM);
        CHECK(nested != NULL);
        CHECK(wwLwipEngineInput(f->engine, nested, netif) == ERR_ARG);
        pbuf_free(nested);
        ++f->recursive_refusals;
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
    uint8_t bytes[40 + payload_limit]  = {0x45};
    uint8_t pseudo[32 + payload_limit] = {0};
    put16(bytes + 2, (uint16_t) (40 + payload));
    bytes[8]  = 64;
    bytes[9]  = 6;
    bytes[12] = 10;
    bytes[15] = 2;
    bytes[16] = 10;
    bytes[19] = 1;
    put16(bytes + 20, 80);
    put16(bytes + 22, f->pcb->local_port);
    put32(bytes + 24, sequence);
    put32(bytes + 28, f->pcb->snd_nxt);
    bytes[32] = 0x50;
    bytes[33] = flags;
    put16(bytes + 34, 65535);
    memset(bytes + 40, 0x5a, payload);
    memcpy(pseudo, bytes + 12, 8);
    pseudo[9] = 6;
    put16(pseudo + 10, (uint16_t) (20 + payload));
    memcpy(pseudo + 12, bytes + 20, 20 + payload);
    uint16_t sum = (uint16_t) ~wwLwipChecksum(pseudo, 32 + payload);
    memcpy(bytes + 36, &sum, sizeof(sum));
    sum = (uint16_t) ~wwLwipChecksum(bytes, 20);
    memcpy(bytes + 10, &sum, sizeof(sum));
    struct pbuf *packet = pbuf_alloc(PBUF_RAW, (u16_t) (40 + payload), PBUF_RAM);
    CHECK(packet != NULL && pbuf_take(packet, bytes, (u16_t) (40 + payload)) == ERR_OK);
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
    CHECK(tcp_bind(f->pcb, IP_ADDR_ANY, port) == ERR_OK);
    tcp_arg(f->pcb, f);
    tcp_err(f->pcb, lost);
    tcp_recv(f->pcb, receive);
    ip_addr_t peer;
    IP_ADDR4(&peer, 10, 0, 0, 2);
    begin(f);
    CHECK(tcp_connect(f->pcb, &peer, 80, NULL) == ERR_OK);
    CHECK(f->outputs == 1 && f->last_flags == TCP_SYN);
    inject(f, 100, TCP_SYN | TCP_ACK, 0);
    f->peer_next = 101;
    CHECK(f->pcb->state == ESTABLISHED);
    expectAck(f, 2, f->peer_next, 65535);
    end(f);
    CHECK(f->outputs == 2);
    f->outputs = 0;
}

static fixture_t *start(bool return_credit)
{
    fixture_t *f = &fixtures[owner];
    memset(f, 0, sizeof(*f));
    owner_loop       = (struct wloop_s *) &f->netif;
    f->return_credit = return_credit;
    f->engine        = wwLwipEngineCreate((uint8_t) owner, (struct wloop_s *) owner_loop);
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
    tcp_recved(f->pcb, TCP_WND_UPDATE_THRESHOLD);
    expectAck(f, 2, f->peer_next, TCP_WND_UPDATE_THRESHOLD);
    end(f);
    CHECK(f->outputs == 2);
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
