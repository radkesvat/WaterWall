#include "lwip/ip.h"
#include "lwip/memp.h"
#include "lwip/netif.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/udp.h"
#include "lwip_engine_test_runtime.h"
#include "port_registry.h"

static pthread_barrier_t             rendezvous;
static struct netif                  interfaces[2];
static uint16_t                      automatic_tcp[2], automatic_udp[2];
static _Thread_local uint32_t        last_tcp_sequence;
static _Thread_local struct udp_pcb *pretend_child;
static _Thread_local bool            refuse_child;
static _Thread_local unsigned        received;
static _Thread_local unsigned        refused_count;

static void meet(void)
{
    int result = pthread_barrier_wait(&rendezvous);
    CHECK(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD);
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
static uint32_t get32(const uint8_t *p)
{
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) | ((uint32_t) p[2] << 8) | p[3];
}
static err_t output(struct netif *netif, struct pbuf *p, const ip4_addr_t *destination)
{
    (void) netif;
    (void) destination;
    uint8_t  bytes[40];
    unsigned count = pbuf_copy_partial(p, bytes, sizeof(bytes), 0);
    if (count >= 40 && bytes[9] == 6)
        last_tcp_sequence = get32(bytes + 24);
    return ERR_OK;
}
static err_t init_netif(struct netif *netif)
{
    netif->name[0] = 'p';
    netif->name[1] = 't';
    netif->mtu     = 1500;
    netif->output  = output;
    return ERR_OK;
}
static void inject(ww_lwip_engine_t *engine, uint16_t destination, uint8_t flags, uint32_t sequence, uint32_t ack,
                   bool udp)
{
    uint8_t        bytes[40] = {0x45};
    const unsigned length    = udp ? 29 : 40;
    put16(bytes + 2, (uint16_t) length);
    bytes[8]  = 64;
    bytes[9]  = udp ? 17 : 6;
    bytes[12] = 10;
    bytes[15] = 2;
    bytes[16] = 10;
    bytes[19] = udp ? 9 : 1;
    put16(bytes + 20, 80);
    put16(bytes + 22, destination);
    if (udp)
    {
        put16(bytes + 24, 9);
        bytes[28] = 42;
    }
    else
    {
        put32(bytes + 24, sequence);
        put32(bytes + 28, ack);
        bytes[32] = 0x50;
        bytes[33] = flags;
        put16(bytes + 34, 16384);
        uint8_t pseudo[32] = {0};
        memcpy(pseudo, bytes + 12, 8);
        pseudo[9]  = 6;
        pseudo[11] = 20;
        memcpy(pseudo + 12, bytes + 20, 20);
        uint16_t sum = (uint16_t) ~wwLwipChecksum(pseudo, sizeof(pseudo));
        memcpy(bytes + 36, &sum, 2);
    }
    uint16_t sum = (uint16_t) ~wwLwipChecksum(bytes, 20);
    memcpy(bytes + 10, &sum, 2);
    struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t) length, PBUF_POOL);
    CHECK(p != NULL);
    CHECK(pbuf_take(p, bytes, (u16_t) length) == ERR_OK);
    CHECK(wwLwipEngineInput(engine, p, &interfaces[owner]) == ERR_OK);
}
static void registryExhaustion(ww_lwip_transport_t transport)
{
    uint16_t holds[8] = {0};
    for (unsigned i = 0; i < 8; ++i)
    {
        uint16_t port = wwLwipPortAllocate(transport, 49152, 49159);
        CHECK(port != 0);
        wwLwipPortCommit(transport, &holds[i], port, true);
    }
    CHECK(wwLwipPortAllocate(transport, 49152, 49159) == 0);
    uint16_t duplicate = 0, freed = holds[0];
    wwLwipPortCommit(transport, &duplicate, freed, false);
    CHECK(wwLwipTestPortOccupancy(transport, freed) == 2);
    wwLwipPortRelease(transport, &holds[0]);
    CHECK(wwLwipPortAllocate(transport, 49152, 49159) == 0);
    wwLwipPortRelease(transport, &duplicate);
    uint16_t reused = wwLwipPortAllocate(transport, 49152, 49159);
    CHECK(reused == freed);
    wwLwipPortCommit(transport, &holds[0], reused, true);
    for (unsigned i = 0; i < 8; ++i)
        wwLwipPortRelease(transport, &holds[i]);
}
static struct tcp_pcb *makeTimeWait(ww_lwip_engine_t *engine)
{
    ip_addr_t peer;
    IP_ADDR4(&peer, 10, 0, 0, 2);
    struct tcp_pcb *pcb = tcp_new();
    CHECK(pcb != NULL);
    CHECK(tcp_bind_netif(pcb, &interfaces[owner]) == ERR_OK);
    CHECK(tcp_connect(pcb, &peer, 80, NULL) == ERR_OK);
    uint32_t iss  = last_tcp_sequence;
    uint16_t port = pcb->local_port;
    CHECK(wwLwipTestPortOccupancy(kWwLwipTcp, port) == 1);
    inject(engine, port, TCP_SYN | TCP_ACK, 9000, iss + 1, false);
    CHECK(pcb->state == ESTABLISHED);
    CHECK(tcp_close(pcb) == ERR_OK);
    CHECK(pcb->state == FIN_WAIT_1);
    inject(engine, port, TCP_FIN | TCP_ACK, 9001, iss + 2, false);
    CHECK(pcb->state == TIME_WAIT && tcp_tw_pcbs == pcb);
    CHECK(wwLwipTestPortOccupancy(kWwLwipTcp, port) == 1);
    return pcb;
}
static void receiveChild(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *source, u16_t port)
{
    (void) arg;
    (void) source;
    (void) port;
    CHECK(pcb == pretend_child && p->tot_len == 1);
    ++received;
    pbuf_free(p);
}
static void acceptChild(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *source, u16_t port)
{
    (void) arg;
    (void) p;
    (void) source;
    (void) port;
    CHECK(wwLwipTestPortOccupancy(kWwLwipUdp, pcb->local_port) == 1);
    if (refuse_child)
    {
        CHECK(++refused_count == 1);
        udp_remove(pcb);
        return;
    }
    pretend_child = pcb;
    udp_recv(pcb, receiveChild, NULL);
}
static void detailedChecks(ww_lwip_engine_t *engine)
{
    registryExhaustion(kWwLwipTcp);
    registryExhaustion(kWwLwipUdp);
    struct tcp_pcb *tcp = tcp_new();
    CHECK(tcp != NULL);
    CHECK(tcp_bind(tcp, IP_ADDR_ANY, 49152) == ERR_OK);
    struct tcp_pcb *listener = tcp_listen(tcp);
    CHECK(listener != NULL);
    CHECK(wwLwipTestPortOccupancy(kWwLwipTcp, 49152) == 1);
    inject(engine, 49152, TCP_SYN, 100, 0, false);
    CHECK(tcp_active_pcbs != NULL && tcp_active_pcbs->state == SYN_RCVD);
    CHECK(wwLwipTestPortOccupancy(kWwLwipTcp, 49152) == 2);
    CHECK(tcp_close(listener) == ERR_OK);
    CHECK(wwLwipTestPortOccupancy(kWwLwipTcp, 49152) == 1);
    tcp_abort(tcp_active_pcbs);
    CHECK(wwLwipTestPortOccupancy(kWwLwipTcp, 49152) == 0);

    struct tcp_pcb *tw   = makeTimeWait(engine);
    uint16_t        port = tw->local_port;
    tcp                  = tcp_new();
    CHECK(tcp != NULL);
    CHECK(tcp_bind(tcp, IP_ADDR_ANY, 0) == ERR_OK);
    CHECK(tcp->local_port != port);
    CHECK(tcp_close(tcp) == ERR_OK);
    for (unsigned i = 0; i <= 2 * TCP_MSL / TCP_SLOW_INTERVAL + 1; ++i)
        tcp_slowtmr();
    CHECK(tcp_tw_pcbs == NULL && wwLwipTestPortOccupancy(kWwLwipTcp, port) == 0);
    tw   = makeTimeWait(engine);
    port = tw->local_port;
    struct tcp_pcb *held[MEMP_NUM_TCP_PCB - 1];
    for (unsigned i = 0; i < MEMP_NUM_TCP_PCB - 1; ++i)
    {
        held[i] = tcp_new();
        CHECK(held[i] != NULL);
    }
    tcp = tcp_new();
    CHECK(tcp != NULL); /* pressure reclaims the local TIME_WAIT holder */
    CHECK(tcp_tw_pcbs == NULL && wwLwipTestPortOccupancy(kWwLwipTcp, port) == 0);
    tcp_abort(tcp);
    for (unsigned i = 0; i < MEMP_NUM_TCP_PCB - 1; ++i)
        tcp_abort(held[i]);

    void *segments[MEMP_NUM_TCP_SEG];
    for (unsigned i = 0; i < MEMP_NUM_TCP_SEG; ++i)
    {
        segments[i] = memp_malloc(MEMP_TCP_SEG);
        CHECK(segments[i] != NULL);
    }
    ip_addr_t peer;
    IP_ADDR4(&peer, 10, 0, 0, 2);
    tcp = tcp_new();
    CHECK(tcp != NULL);
    CHECK(tcp_bind_netif(tcp, &interfaces[owner]) == ERR_OK);
    CHECK(tcp_connect(tcp, &peer, 80, NULL) == ERR_MEM);
    CHECK(tcp->local_port == 0 && tcp->ww_tracked_port == 0);
    tcp_abort(tcp);
    for (unsigned i = 0; i < MEMP_NUM_TCP_SEG; ++i)
        memp_free(MEMP_TCP_SEG, segments[i]);
    registryExhaustion(kWwLwipTcp);

    struct udp_pcb *a = udp_new(), *b = udp_new();
    CHECK(a != NULL && b != NULL);
    CHECK(udp_bind(a, IP_ADDR_ANY, 49152) == ERR_OK);
    CHECK(udp_bind(b, IP_ADDR_ANY, 49153) == ERR_OK);
    CHECK(udp_bind(a, IP_ADDR_ANY, 49153) == ERR_USE);
    CHECK(a->local_port == 49152 && a->ww_tracked_port == 49152);
    CHECK(wwLwipTestPortOccupancy(kWwLwipUdp, 49152) == 1);
    CHECK(udp_bind(a, IP_ADDR_ANY, 49154) == ERR_OK);
    CHECK(wwLwipTestPortOccupancy(kWwLwipUdp, 49152) == 0);
    CHECK(udp_connect(a, &peer, 80) == ERR_OK);
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, 1, PBUF_POOL);
    CHECK(p != NULL);
    ip_addr_t local;
    IP_ADDR4(&local, 10, 0, 0, 1);
    CHECK(udp_sendfrom(a, p, &local, 49155) == ERR_OK);
    CHECK(a->local_port == 49154 && a->ww_tracked_port == 49154);
    CHECK(wwLwipTestPortOccupancy(kWwLwipUdp, 49155) == 0);
    CHECK(udp_sendfrom(a, p, &local, 0) == ERR_OK);
    CHECK(a->local_port == 49154 && a->ww_tracked_port == 49154);
    pbuf_free(p);
    udp_remove(a);
    udp_remove(b);
    registryExhaustion(kWwLwipUdp);

    netif_set_flags(&interfaces[owner], NETIF_FLAG_PRETEND);
    a = udp_new();
    CHECK(a != NULL);
    CHECK(udp_bind_netif(a, &interfaces[owner]) == ERR_OK);
    CHECK(udp_bind(a, NULL, 0) == ERR_OK);
    udp_recv(a, acceptChild, NULL);
    inject(engine, 49152, 0, 0, 0, true);
    CHECK(pretend_child != NULL && received == 1);
    CHECK(wwLwipTestPortOccupancy(kWwLwipUdp, 49152) == 1);
    udp_remove(pretend_child);
    pretend_child = NULL;
    refuse_child  = true;
    inject(engine, 49152, 0, 0, 0, true);
    CHECK(wwLwipTestPortOccupancy(kWwLwipUdp, 49152) == 0);
    CHECK(refused_count == 1);
    udp_remove(a);
}
static void *run(void *argument)
{
    owner                    = (unsigned) (uintptr_t) argument;
    owner_loop               = (struct wloop_s *) &interfaces[owner];
    ww_lwip_engine_t *engine = wwLwipEngineCreate((uint8_t) owner, (struct wloop_s *) owner_loop);
    CHECK(engine != NULL);
    ww_lwip_engine_t *previous;
    CHECK(wwLwipEngineEnter(engine, &previous));
    ip4_addr_t address, mask, gateway;
    IP4_ADDR(&address, 10, 0, 0, 1);
    IP4_ADDR(&mask, 255, 255, 255, 0);
    ip4_addr_set_zero(&gateway);
    CHECK(netif_add(&interfaces[owner], &address, &mask, &gateway, NULL, init_netif, ip_input) != NULL);
    netif_set_up(&interfaces[owner]);
    netif_set_link_up(&interfaces[owner]);
    struct tcp_pcb *tcp = tcp_new();
    struct udp_pcb *udp = udp_new();
    CHECK(tcp != NULL && udp != NULL);
    meet();
    CHECK(tcp_bind(tcp, IP_ADDR_ANY, 0) == ERR_OK);
    CHECK(udp_bind(udp, IP_ADDR_ANY, 0) == ERR_OK);
    automatic_tcp[owner] = tcp->local_port;
    automatic_udp[owner] = udp->local_port;
    meet();
    CHECK(automatic_tcp[0] != automatic_tcp[1]);
    CHECK(automatic_udp[0] != automatic_udp[1]);
    CHECK(tcp_close(tcp) == ERR_OK);
    udp_remove(udp);
    meet();
    if (owner == 0)
        detailedChecks(engine);
    meet();
    wwLwipEngineLeave(engine, previous);
    wwLwipEngineDestroy(engine);
    return NULL;
}
int main(void)
{
    wwLwipEngineSharedInit();
    CHECK(pthread_barrier_init(&rendezvous, NULL, 2) == 0);
    pthread_t threads[2];
    for (uintptr_t i = 0; i < 2; ++i)
        CHECK(pthread_create(&threads[i], NULL, run, (void *) i) == 0);
    for (unsigned i = 0; i < 2; ++i)
        CHECK(pthread_join(threads[i], NULL) == 0);
    CHECK(pthread_barrier_destroy(&rendezvous) == 0);
    wwLwipEngineSharedCleanup();
    puts("concurrent automatic ports, PCB-lifetime holds, TIME_WAIT, rebind and failure settlement passed");
    return 0;
}
