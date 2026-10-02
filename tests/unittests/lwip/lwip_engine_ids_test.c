/*
 * Covers: lwip engine ids; the explicit inputs, callbacks and expected results below define this suite.
 * Setup: The included implementation/API and the deterministic inputs shown below; no integration
 * topology is implied.
 * Checks: Exact return/byte/order and resource-count oracles in the explicit case bodies.
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.lwip_engine_ids_unit
 */
#include "fixtures/lwip/lwip_engine_test_runtime.h"
#include "lwip/ip.h"
#include "lwip/netif.h"
#include "lwip/udp.h"

struct capture
{
    uint8_t  bytes[8][1600];
    uint16_t lengths[8];
    unsigned count;
    uint32_t identification;
};
static struct capture     captures[2];
static struct netif       senders[2], receivers[2];
static pthread_barrier_t  rendezvous;
static unsigned           delivered[2];
static _Thread_local bool ipv6;

static void meet(void)
{
    int result = pthread_barrier_wait(&rendezvous);
    CHECK(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD);
}
static uint32_t get32(const uint8_t *p)
{
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) | ((uint32_t) p[2] << 8) | p[3];
}
static err_t capture(struct pbuf *p)
{
    struct capture *c = &captures[owner];
    CHECK(c->count < 8 && p->tot_len <= sizeof(c->bytes[0]));
    uint8_t *bytes       = c->bytes[c->count];
    c->lengths[c->count] = p->tot_len;
    CHECK(pbuf_copy_partial(p, bytes, p->tot_len, 0) == p->tot_len);
    CHECK((bytes[0] >> 4) == (ipv6 ? 6 : 4));
    uint32_t id;
    if (ipv6)
    {
        CHECK(bytes[6] == 44);
        id = get32(bytes + 44);
    }
    else
    {
        CHECK(wwLwipChecksum(bytes, 20) == 0xffff);
        id = ((unsigned) bytes[4] << 8) | bytes[5];
    }
    if (c->count == 0)
    {
        c->identification = id;
        meet();
    }
    CHECK(id == c->identification);
    ++c->count;
    return ERR_OK;
}
static err_t output4(struct netif *netif, struct pbuf *p, const ip4_addr_t *dest)
{
    (void) dest;
    CHECK(netif == &senders[owner]);
    return capture(p);
}
static err_t output6(struct netif *netif, struct pbuf *p, const ip6_addr_t *dest)
{
    (void) dest;
    CHECK(netif == &senders[owner]);
    return capture(p);
}
static err_t init_netif(struct netif *netif)
{
    netif->name[0]    = 'i';
    netif->name[1]    = 'd';
    netif->mtu        = 576;
    netif->output     = output4;
    netif->output_ip6 = output6;
    return ERR_OK;
}
static void received(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *source, u16_t port)
{
    (void) arg;
    (void) pcb;
    (void) source;
    (void) port;
    CHECK(p->tot_len == 1800);
    uint8_t bytes[1800];
    CHECK(pbuf_copy_partial(p, bytes, sizeof(bytes), 0) == sizeof(bytes));
    for (unsigned i = 0; i < sizeof(bytes); ++i)
        CHECK(bytes[i] == (uint8_t) (i + owner));
    ++delivered[owner];
    pbuf_free(p);
}
static void add_interface(struct netif *netif, bool receiver)
{
    ip4_addr_t ip, mask, gw;
    IP4_ADDR(&ip, 10, 0, 0, receiver ? 2 : 1);
    IP4_ADDR(&mask, 255, 255, 255, 0);
    ip4_addr_set_zero(&gw);
    CHECK(netif_add(netif, &ip, &mask, &gw, NULL, init_netif, ip_input) != NULL);
    ip6_addr_t address6;
    CHECK(ip6addr_aton(receiver ? "fd00::2" : "fd00::1", &address6));
    netif_ip6_addr_set(netif, 0, &address6);
    netif_ip6_addr_set_state(netif, 0, IP6_ADDR_VALID);
    netif_set_up(netif);
    netif_set_link_up(netif);
}
static void *run(void *argument)
{
    owner                    = (unsigned) (uintptr_t) argument;
    owner_loop               = (struct wloop_s *) &senders[owner];
    ww_lwip_engine_t *engine = wwLwipEngineCreate((uint8_t) owner, (struct wloop_s *) owner_loop);
    CHECK(engine != NULL);
    ww_lwip_engine_t *previous;
    CHECK(wwLwipEngineEnter(engine, &previous));
    add_interface(&senders[owner], false);
    add_interface(&receivers[owner], true);
    struct udp_pcb *sender = udp_new_ip_type(IPADDR_TYPE_ANY), *receiver = udp_new_ip_type(IPADDR_TYPE_ANY);
    CHECK(sender != NULL && receiver != NULL);
    CHECK(udp_bind(sender, IP_ANY_TYPE, 0) == ERR_OK);
    CHECK(udp_bind(receiver, IP_ANY_TYPE, 6000) == ERR_OK);
    CHECK(udp_bind_netif(sender, &senders[owner]) == ERR_OK);
    CHECK(udp_bind_netif(receiver, &receivers[owner]) == ERR_OK);
    udp_recv(receiver, received, NULL);
    for (unsigned family = 0; family < 2; ++family)
    {
        ipv6               = family != 0;
        senders[owner].mtu = receivers[owner].mtu = ipv6 ? 1280 : 576;
        memset(&captures[owner], 0, sizeof(captures[owner]));
        ip_addr_t destination;
        CHECK(ipaddr_aton(ipv6 ? "fd00::2" : "10.0.0.2", &destination));
        struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, 1800, PBUF_POOL);
        CHECK(p != NULL);
        uint8_t bytes[1800];
        for (unsigned i = 0; i < sizeof(bytes); ++i)
            bytes[i] = (uint8_t) (i + owner);
        CHECK(pbuf_take(p, bytes, sizeof(bytes)) == ERR_OK);
        CHECK(udp_sendto_if(sender, p, &destination, 6000, &senders[owner]) == ERR_OK);
        pbuf_free(p);
        CHECK(captures[owner].count > 1);
        meet();
        CHECK(captures[0].identification != captures[1].identification);
        /* Detached wire copies enter the peer netif, never a foreign engine pbuf. */
        for (unsigned i = captures[owner].count; i > 0; --i)
        {
            uint16_t length = captures[owner].lengths[i - 1];
            p               = pbuf_alloc(PBUF_RAW, length, PBUF_POOL);
            CHECK(p != NULL);
            CHECK(pbuf_take(p, captures[owner].bytes[i - 1], length) == ERR_OK);
            CHECK(wwLwipEngineInput(engine, p, &receivers[owner]) == ERR_OK);
        }
        CHECK(delivered[owner] == family + 1);
        meet();
    }
    /* Header-included output retains the caller's IPv4 identification. */
    ipv6 = false;
    memset(&captures[owner], 0, sizeof(captures[owner]));
    uint8_t supplied[28] = {0x45};
    supplied[3]          = sizeof(supplied);
    supplied[4]          = 0xbe;
    supplied[5]          = 0xef;
    supplied[8]          = 64;
    supplied[9]          = 253;
    supplied[12]         = 10;
    supplied[15]         = 1;
    supplied[16]         = 10;
    supplied[19]         = 2;
    uint16_t checksum    = (uint16_t) ~wwLwipChecksum(supplied, 20);
    memcpy(supplied + 10, &checksum, sizeof(checksum));
    struct pbuf *included = pbuf_alloc(PBUF_RAW, sizeof(supplied), PBUF_POOL);
    CHECK(included != NULL);
    CHECK(pbuf_take(included, supplied, sizeof(supplied)) == ERR_OK);
    CHECK(ip4_output_if(included, NULL, LWIP_IP_HDRINCL, 64, 0, 253, &senders[owner]) == ERR_OK);
    pbuf_free(included);
    CHECK(captures[owner].count == 1 && captures[owner].identification == 0xbeef);
    meet();
    udp_remove(sender);
    udp_remove(receiver);
    wwLwipEngineLeave(engine, previous);
    wwLwipEngineDestroy(engine);
    return NULL;
}
int main(void)
{
    testCaseSet("lwip_engine_ids_test");
    wwLwipEngineSharedInit();
    CHECK(pthread_barrier_init(&rendezvous, NULL, 2) == 0);
    pthread_t threads[2];
    for (uintptr_t i = 0; i < 2; ++i)
        CHECK(pthread_create(&threads[i], NULL, run, (void *) i) == 0);
    for (unsigned i = 0; i < 2; ++i)
        CHECK(pthread_join(threads[i], NULL) == 0);
    CHECK(pthread_barrier_destroy(&rendezvous) == 0);
    wwLwipEngineSharedCleanup();
    puts("concurrent IPv4/IPv6 fragment IDs and reverse-order peer reassembly passed");
    return 0;
}
