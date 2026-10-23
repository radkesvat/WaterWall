/*
 * Covers: feature-enabled UDP broadcast reuse without discarded clone allocations.
 * Setup: a private raw stack and this fixture both enable SO_REUSE/SO_REUSE_RXTOALL;
 * production defaults remain disabled. Real owner-engine input and receive callbacks
 * exercise ordinary recipients and a connected child accepted by a pretend listener.
 * Checks: recipient counts/bytes, excluded-path allocation, clone transfer/free,
 * allocation refusal, malformed-length rejection, empty/prefix trimming and cleanup.
 * Limits: no host networking or throughput claims.
 * CTest: waterwall.lwip_udp_reuse_unit (Debug and Release).
 */
#include "fixtures/lwip/lwip_engine_test_runtime.h"
#include "lwip/ip.h"
#include "lwip/netif.h"
#include "lwip/udp.h"
#include "shared_pools.h"

#if ! SO_REUSE || ! SO_REUSE_RXTOALL
#error "The private stack and UDP reuse fixture must both enable reuse fan-out"
#endif

typedef struct
{
    ww_lwip_engine_t *engine, *previous;
    struct netif      netif;
    struct udp_pcb   *listener, *primary, *secondary;
    struct pbuf      *input, *clone;
    unsigned          accepts, primary_received, secondary_received;
    unsigned          clone_attempts, clone_allocated, clone_delivered, clone_freed, input_freed;
    uint16_t          expected_length;
    bool              refuse_clone;
} fixture_t;

static fixture_t    *active;
static const uint8_t payload[] = "udp-trail";

struct pbuf *__real_pbuf_clone(pbuf_layer layer, pbuf_type type, struct pbuf *p);
u8_t         __real_pbuf_free(struct pbuf *p);

struct pbuf *__wrap_pbuf_clone(pbuf_layer layer, pbuf_type type, struct pbuf *p)
{
    CHECK(active != NULL && active->clone == NULL);
    ++active->clone_attempts;
    if (active->refuse_clone)
        return NULL;
    struct pbuf *clone = __real_pbuf_clone(layer, type, p);
    CHECK(clone != NULL);
    active->clone = clone;
    ++active->clone_allocated;
    return clone;
}

u8_t __wrap_pbuf_free(struct pbuf *p)
{
    if (active != NULL)
    {
        if (p == active->input)
            ++active->input_freed;
        if (p == active->clone)
            ++active->clone_freed;
    }
    return __real_pbuf_free(p);
}

static void receive(void *argument, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *address, u16_t port)
{
    fixture_t *f = argument;
    CHECK(wwLwipEngineCurrent() == f->engine && p != NULL && address != NULL && port == 40000);
    CHECK(ip4_addr4(ip_2_ip4(address)) == 2 && p->tot_len == f->expected_length);
    uint8_t bytes[sizeof(payload)];
    CHECK(pbuf_copy_partial(p, bytes, p->tot_len, 0) == p->tot_len);
    CHECK(memcmp(bytes, payload, p->tot_len) == 0);
    if (pcb == f->primary)
        ++f->primary_received;
    else
    {
        CHECK(pcb == f->secondary && p == f->clone);
        ++f->secondary_received;
        ++f->clone_delivered;
    }
    pbuf_free(p);
}

static void acceptChild(void *argument, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *address, u16_t port)
{
    fixture_t *f = argument;
    CHECK(pcb != f->listener && f->primary == NULL && p != NULL && address != NULL && port == 5353);
    CHECK((pcb->flags & UDP_FLAGS_CONNECTED) != 0 && pcb->pretend_netif_idx != NETIF_NO_INDEX);
    f->primary = pcb;
    ++f->accepts;
    ip_set_option(pcb, SOF_REUSEADDR);
    udp_recv(pcb, receive, f);
}

static err_t initNetif(struct netif *netif)
{
    netif->name[0] = 'r';
    netif->name[1] = 'u';
    netif->mtu     = 1500;
    netif->flags   = NETIF_FLAG_BROADCAST;
    return ERR_OK;
}

static void put16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t) (value >> 8);
    bytes[1] = (uint8_t) value;
}

static void inject(fixture_t *f, uint16_t udp_length)
{
    uint8_t bytes[20 + UDP_HLEN + sizeof(payload) - 1] = {0x45};
    put16(bytes + 2, sizeof(bytes));
    bytes[8]  = 64;
    bytes[9]  = IP_PROTO_UDP;
    bytes[12] = bytes[16] = 10;
    bytes[15]             = 2;
    bytes[19]             = 255;
    put16(bytes + 20, 40000);
    put16(bytes + 22, 5353);
    put16(bytes + 24, udp_length);
    memcpy(bytes + 20 + UDP_HLEN, payload, sizeof(payload) - 1);
    const uint16_t checksum = (uint16_t) ~wwLwipChecksum(bytes, 20);
    memcpy(bytes + 10, &checksum, sizeof(checksum));
    f->input = pbuf_alloc(PBUF_RAW, sizeof(bytes), PBUF_RAM);
    CHECK(f->input != NULL && pbuf_take(f->input, bytes, sizeof(bytes)) == ERR_OK);
    f->input_freed = 0;
    CHECK(wwLwipEngineInput(f->engine, f->input, &f->netif) == ERR_OK);
    CHECK(f->input_freed == 1);
    f->input = NULL;
}

static struct udp_pcb *ordinaryRecipient(fixture_t *f)
{
    struct udp_pcb *pcb = udp_new();
    CHECK(pcb != NULL);
    ip_set_option(pcb, SOF_REUSEADDR);
    CHECK(udp_bind_netif(pcb, &f->netif) == ERR_OK && udp_bind(pcb, IP_ADDR_ANY, 5353) == ERR_OK);
    CHECK(pcb->pretend_netif_idx == NETIF_NO_INDEX);
    udp_recv(pcb, receive, f);
    return pcb;
}

static void start(fixture_t *f, bool pretend)
{
    memset(f, 0, sizeof(*f));
    active             = f;
    owner              = 0;
    owner_loop         = (struct wloop_s *) &f->netif;
    f->expected_length = sizeof(payload) - 1;
    f->engine          = wwLwipEngineCreate(0, (struct wloop_s *) owner_loop);
    CHECK(f->engine != NULL && wwLwipEngineEnter(f->engine, &f->previous));
    ip4_addr_t local, mask, gateway;
    IP4_ADDR(&local, 10, 0, 0, 1);
    IP4_ADDR(&mask, 255, 255, 255, 0);
    ip4_addr_set_zero(&gateway);
    CHECK(netif_add(&f->netif, &local, &mask, &gateway, f, initNetif, ip_input) != NULL);
    netif_set_up(&f->netif);
    netif_set_link_up(&f->netif);
    if (pretend)
    {
        netif_set_flags(&f->netif, NETIF_FLAG_PRETEND_UDP);
        f->listener = udp_new();
        CHECK(f->listener != NULL && udp_bind_netif(f->listener, &f->netif) == ERR_OK);
        CHECK(udp_bind(f->listener, NULL, 0) == ERR_OK);
        udp_recv(f->listener, acceptChild, f);
        inject(f, UDP_HLEN + sizeof(payload) - 1);
        CHECK(f->accepts == 1 && f->primary_received == 1 && f->clone_attempts == 0);
        f->primary_received = 0;
    }
    else
    {
        f->primary = ordinaryRecipient(f);
        ip_addr_t peer;
        IP_ADDR4(&peer, 10, 0, 0, 2);
        CHECK(udp_connect(f->primary, &peer, 40000) == ERR_OK);
    }
    f->secondary = ordinaryRecipient(f);
}

static void stop(fixture_t *f)
{
    CHECK(f->clone_allocated == f->clone_delivered && f->clone_allocated == f->clone_freed);
    udp_remove(f->primary);
    udp_remove(f->secondary);
    if (f->listener != NULL)
        udp_remove(f->listener);
    CHECK(udp_pcbs == NULL);
    netif_remove(&f->netif);
    wwLwipEngineLeave(f->engine, f->previous);
    wwLwipEngineDestroy(f->engine);
    active = NULL;
    CHECK(wwLwipSharedStats()->memp[MEMP_PBUF_POOL]->used == 0 && wwLwipSharedStats()->mem.used == 0);
}

static void deliveryCase(bool pretend, bool refuse, uint16_t udp_length)
{
    fixture_t f;
    start(&f, pretend);
    f.refuse_clone    = refuse;
    f.expected_length = (uint16_t) (udp_length - UDP_HLEN);
    inject(&f, udp_length);
    CHECK(f.primary_received == 1 && f.secondary_received == (! pretend && ! refuse ? 1U : 0U));
    CHECK(f.clone_attempts == (pretend ? 0U : 1U));
    CHECK(f.clone_allocated == (! pretend && ! refuse ? 1U : 0U));
    stop(&f);
}

static void invalidLengths(void)
{
    const uint16_t invalid[] = {0, 7, UDP_HLEN + sizeof(payload)};
    for (unsigned pretend = 0; pretend != 2; ++pretend)
    {
        for (unsigned i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
        {
            fixture_t f;
            start(&f, pretend != 0);
            inject(&f, invalid[i]);
            CHECK(f.primary_received == 0 && f.secondary_received == 0 && f.clone_attempts == 0);
            CHECK(f.accepts == pretend);
            stop(&f);
        }
    }
}

int main(void)
{
    wwLwipEngineSharedInit();
    testCaseSet("pretend primary excludes reuse cloning");
    deliveryCase(true, false, UDP_HLEN + sizeof(payload) - 1);
    testCaseSet("ordinary primary delivers and frees reuse clone");
    deliveryCase(false, false, UDP_HLEN + sizeof(payload) - 1);
    testCaseSet("clone allocation refusal preserves primary delivery");
    deliveryCase(false, true, UDP_HLEN + sizeof(payload) - 1);
    testCaseSet("reuse variant preserves empty and prefix trimming");
    deliveryCase(false, false, UDP_HLEN);
    deliveryCase(false, false, UDP_HLEN + 3);
    testCaseSet("reuse variant rejects malformed UDP lengths before delivery or cloning");
    invalidLengths();
    wwLwipEngineSharedCleanup();
    puts("UDP reuse eligibility, clone ownership, refusal and length boundaries passed");
    return 0;
}
