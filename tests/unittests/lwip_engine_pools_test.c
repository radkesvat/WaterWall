#include "engine_internal.h"
#include "lwip_engine_test_runtime.h"
#include "pool_cache.h"
#include "shared_pools.h"

#include "lwip/autoip.h"
#include "lwip/dhcp.h"
#include "lwip/ip.h"
#include "lwip/ip4_frag.h"
#include "lwip/ip6_frag.h"
#include "lwip/mem.h"
#include "lwip/memp.h"
#include "lwip/netif.h"
#include "lwip/priv/memp_priv.h"
#include "lwip/stats.h"
#include "lwip/sys.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"

static pthread_barrier_t  rendezvous;
static struct netif       interfaces[2];
static _Thread_local bool fail_engine_allocation;
static unsigned           custom_frees[2];

static void                  *heap_handoff[2];
static _Thread_local unsigned protection_calls;
static void                   meet(void);

LWIP_MEMPOOL_DECLARE(CACHE_RX_TEST, 33, 64, "RX cache fixture")

sys_prot_t __real_sys_arch_protect(void);
sys_prot_t __wrap_sys_arch_protect(void);
sys_prot_t __wrap_sys_arch_protect(void)
{
    ++protection_calls;
    return __real_sys_arch_protect();
}

static void cacheHotPath(void)
{
    if (owner == 0)
    {
        for (unsigned i = 0; i < (unsigned) (MEMP_POOL_LAST - MEMP_POOL_FIRST + 3); ++i)
        {
            const struct memp_desc *pool = i == 0   ? memp_pools[MEMP_TCP_SEG]
                                           : i == 1 ? &memp_CACHE_RX_TEST
                                                    : memp_pools[MEMP_POOL_FIRST + i - 2];
            void                   *item = memp_malloc_pool(pool);
            CHECK(item != NULL);
            memp_free_pool(pool, item);
            protection_calls = 0;
            for (unsigned j = 0; j < 100; ++j)
            {
                item = memp_malloc_pool(pool);
                CHECK(item != NULL);
                memset(item, 0x5a, pool->size);
                memp_free_pool(pool, item);
            }
#if WW_LWIP_POOL_CACHE_ENABLED
            CHECK(protection_calls == 0);
#else
            CHECK(protection_calls > 0);
#endif
        }
    }
    meet();
}

static void concurrentCachePressure(void)
{
    /* Two owners compete for 33 slots while each can hold 24. Filling all
     * payload bytes catches a duplicated allocation or a stolen live object. */
    for (unsigned round = 0; round < 1000; ++round)
    {
        void               *held[24];
        unsigned            count  = 0;
        const unsigned char marker = (unsigned char) (round * 2 + owner);
        while (count < 24)
        {
            void *item = LWIP_MEMPOOL_ALLOC(CACHE_RX_TEST);
            if (item == NULL)
                break;
            memset(item, marker, 64);
            held[count++] = item;
        }
        meet();
        for (unsigned i = 0; i < count; ++i)
        {
            for (unsigned j = 0; j < 64; ++j)
                CHECK(((unsigned char *) held[i])[j] == marker);
            LWIP_MEMPOOL_FREE(CACHE_RX_TEST, held[i]);
        }
        meet();
    }
}

void *__real_calloc(size_t count, size_t size);
void *__wrap_calloc(size_t count, size_t size)
{
    if (fail_engine_allocation && count == 1 && size == wwLwipEngineControlSize())
        return NULL;
    return __real_calloc(count, size);
}

static void meet(void)
{
    int result = pthread_barrier_wait(&rendezvous);
    CHECK(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD);
}

static err_t output(struct netif *netif, struct pbuf *p, const ip4_addr_t *dest)
{
    (void) netif;
    (void) p;
    (void) dest;
    return ERR_OK;
}

static err_t init_netif(struct netif *netif)
{
    netif->name[0] = 'q';
    netif->name[1] = 't';
    netif->output  = output;
    netif->mtu     = 1500;
    return ERR_OK;
}

static void poolCapacity(const struct memp_desc *pool)
{
    const unsigned capacity = pool->num;
    void         **held     = calloc(capacity, sizeof(*held));
    CHECK(held != NULL && capacity > 0);
    if (owner == 0)
    {
        for (unsigned i = 0; i < capacity; ++i)
        {
            held[i] = memp_malloc_pool(pool);
            CHECK(held[i] != NULL);
        }
        CHECK(memp_malloc_pool(pool) == NULL);
    }
    meet();
    if (owner == 1)
        CHECK(memp_malloc_pool(pool) == NULL);
    meet();
    if (owner == 0)
    {
        memp_free_pool(pool, held[0]);
        held[0] = NULL;
    }
    meet();
    if (owner == 1)
    {
        void *item = memp_malloc_pool(pool);
        CHECK(item != NULL);
        CHECK(memp_malloc_pool(pool) == NULL);
        memp_free_pool(pool, item);
    }
    meet();
    if (owner == 0)
        for (unsigned i = 1; i < capacity; ++i)
            memp_free_pool(pool, held[i]);
    free(held);
    meet();
    for (unsigned i = 0; i < 100; ++i)
    {
        void *item = memp_malloc_pool(pool);
        /* Some small heap classes have one entry: simultaneous checkout may
         * legitimately refuse one worker until the other returns its item. */
        if (item != NULL)
            memp_free_pool(pool, item);
    }
    meet();
}

static void customFree(struct pbuf *p)
{
    (void) p;
    ++custom_frees[owner];
    /* This rendezvous cannot complete if either destructor holds the allocator lock. */
    meet();
}

static void fragment4(unsigned ident, unsigned offset)
{
    struct pbuf *p = pbuf_alloc(PBUF_RAW, 28, PBUF_POOL);
    CHECK(p != NULL);
    memset(p->payload, 0, 28);
    struct ip_hdr *ip = p->payload;
    IPH_VHL_SET(ip, 4, 5);
    IPH_LEN_SET(ip, lwip_htons(28));
    IPH_ID_SET(ip, lwip_htons((u16_t) ident));
    IPH_OFFSET_SET(ip, lwip_htons((u16_t) (IP_MF | offset)));
    IPH_PROTO_SET(ip, 17);
    IPH_TTL_SET(ip, 64);
    ip4_addr_t source, destination;
    IP4_ADDR(&source, 10, 0, 0, 2);
    IP4_ADDR(&destination, 10, 0, 0, 1);
    ip4_addr_copy(ip->src, source);
    ip4_addr_copy(ip->dest, destination);
    CHECK(ip4_reass(p, &interfaces[owner]) == NULL);
}

static void fragment6(ww_lwip_engine_t *engine, unsigned ident, unsigned offset)
{
    struct pbuf *p = pbuf_alloc(PBUF_RAW, 56, PBUF_POOL);
    CHECK(p != NULL);
    uint8_t *bytes = p->payload;
    memset(bytes, 0, 56);
    bytes[0]                      = 0x60;
    bytes[5]                      = 16;
    bytes[6]                      = 44;
    bytes[7]                      = 64;
    bytes[8]                      = 0xfd;
    bytes[23]                     = 2;
    bytes[24]                     = 0xfd;
    bytes[39]                     = 1;
    struct ip6_frag_hdr *fragment = (struct ip6_frag_hdr *) (bytes + 40);
    fragment->_nexth              = 17;
    fragment->_fragment_offset    = lwip_htons((u16_t) (offset * 8 | IP6_FRAG_MORE_FLAG));
    fragment->_identification     = lwip_htonl(ident);
    CHECK(wwLwipEngineInput(engine, p, &interfaces[owner]) == ERR_OK);
}

static void *run(void *argument)
{
    owner                  = (unsigned) (uintptr_t) argument;
    owner_loop             = (struct wloop_s *) &interfaces[owner];
    fail_engine_allocation = true;
    CHECK(wwLwipEngineCreate((uint8_t) owner, (struct wloop_s *) owner_loop) == NULL);
    CHECK(wwLwipEngineCurrent() == NULL);
    fail_engine_allocation   = false;
    ww_lwip_engine_t *engine = wwLwipEngineCreate((uint8_t) owner, (struct wloop_s *) owner_loop);
    CHECK(engine != NULL);
    ww_lwip_engine_t *previous;
    CHECK(wwLwipEngineEnter(engine, &previous));
    ip4_addr_t address, mask, gateway;
    IP4_ADDR(&address, 10, 0, 0, 1);
    IP4_ADDR(&mask, 255, 255, 255, 0);
    ip4_addr_set_zero(&gateway);
    CHECK(netif_add(&interfaces[owner], &address, &mask, &gateway, NULL, init_netif, ip_input) != NULL);
    ip6_addr_t address6;
    CHECK(ip6addr_aton("fd00::1", &address6));
    netif_ip6_addr_set(&interfaces[owner], 0, &address6);
    netif_ip6_addr_set_state(&interfaces[owner], 0, IP6_ADDR_VALID);
    netif_set_up(&interfaces[owner]);
    meet();
    /* Mandatory timers leave bounded private capacity, independent of the other engine. */
    void    *timeouts[MEMP_NUM_SYS_TIMEOUT];
    unsigned timeout_count = 0;
    void    *timeout;
    while ((timeout = wwLwipTimeoutAlloc()) != NULL)
    {
        CHECK(timeout_count < MEMP_NUM_SYS_TIMEOUT);
        timeouts[timeout_count++] = timeout;
    }
    CHECK(timeout_count > 0 && timeout_count < MEMP_NUM_SYS_TIMEOUT);
    meet();
    CHECK(wwLwipTimeoutAlloc() == NULL);
    for (unsigned i = 0; i < timeout_count; ++i)
        wwLwipTimeoutFree(timeouts[i]);
    meet();
    cacheHotPath();
    concurrentCachePressure();
    const memp_t tested[] = {MEMP_TCP_PCB,
                             MEMP_TCP_PCB_LISTEN,
                             MEMP_TCP_SEG,
                             MEMP_UDP_PCB,
                             MEMP_PBUF,
                             MEMP_PBUF_POOL,
                             MEMP_REASSDATA,
                             MEMP_IP6_REASSDATA};
    for (unsigned i = 0; i < sizeof(tested) / sizeof(tested[0]); ++i)
        poolCapacity(memp_pools[tested[i]]);
    for (memp_t i = MEMP_POOL_FIRST; i <= MEMP_POOL_LAST; i = (memp_t) (i + 1))
        poolCapacity(memp_pools[i]);
    poolCapacity(&memp_CACHE_RX_TEST);

    struct tcp_pcb *tcp_held[MEMP_NUM_TCP_PCB];
    if (owner == 0)
    {
        for (unsigned i = 0; i < MEMP_NUM_TCP_PCB; ++i)
        {
            tcp_held[i] = tcp_new();
            CHECK(tcp_held[i] != NULL);
        }
    }
    meet();
    if (owner == 1)
        CHECK(tcp_new() == NULL); /* no foreign victims under pressure */
    meet();
    if (owner == 0)
        for (unsigned i = 0; i < MEMP_NUM_TCP_PCB; ++i)
            tcp_abort(tcp_held[i]);
    meet();
    /* Full-MSS heap accounting follows the shared allocation through a foreign free. */
    heap_handoff[owner] = mem_malloc(1460);
    CHECK(heap_handoff[owner] != NULL);
    memset(heap_handoff[owner], (int) owner, 1460);
    meet();
    CHECK(*(unsigned char *) heap_handoff[1 - owner] == 1 - owner);
    mem_free(heap_handoff[1 - owner]);
    meet();
    for (unsigned i = 0; i < 1000; ++i)
    {
        void *allocation = mem_malloc(1460);
        CHECK(allocation != NULL);
        mem_free(allocation);
    }
    meet();
    CHECK(wwLwipSharedStats()->mem.used == 0);
    struct pbuf_custom custom = {0};
    unsigned char      storage[64];
    custom.custom_free_function = customFree;
    struct pbuf *p = pbuf_alloced_custom(PBUF_RAW, sizeof(storage), PBUF_REF, &custom, storage, sizeof(storage));
    CHECK(p != NULL);
    CHECK(pbuf_free(p) == 1);
    CHECK(custom_frees[owner] == 1);

    /* Separate IPv4/IPv6 counters, with no per-worker partition. */
    if (owner == 0)
    {
        CHECK(wwLwipReassemblyReserve(4, IP_REASS_MAX_PBUFS));
        CHECK(wwLwipReassemblyReserve(6, IP_REASS_MAX_PBUFS));
    }
    meet();
    CHECK(! wwLwipReassemblyReserve(4, 1));
    CHECK(! wwLwipReassemblyReserve(6, 1));
    meet();
    if (owner == 0)
    {
        wwLwipReassemblyRelease(4, IP_REASS_MAX_PBUFS);
        wwLwipReassemblyRelease(6, IP_REASS_MAX_PBUFS);
    }
    meet();
    CHECK(IP_REASS_MAX_PBUFS == 2 * IP_REASS_MAX_PBUFS_PER_DATAGRAM);
    for (unsigned i = 1; i <= IP_REASS_MAX_PBUFS_PER_DATAGRAM; ++i)
        fragment4(7, i);
    meet();
    CHECK(wwLwipReassemblyUsage(4) == IP_REASS_MAX_PBUFS);
    CHECK(wwLwipReassemblyUsage(6) == 0);
    meet();
    if (owner == 0)
        fragment4(8, 1); /* may reclaim only worker 0's datagram */
    meet();
    CHECK(wwLwipReassemblyUsage(4) == IP_REASS_MAX_PBUFS_PER_DATAGRAM + 1);
    meet();
    ip4_addr_t source, destination;
    IP4_ADDR(&source, 10, 0, 0, 2);
    IP4_ADDR(&destination, 10, 0, 0, 1);
    const u16_t purged = ip4_reass_purge(&interfaces[owner], &source, &destination, 17, (owner == 0 ? 8 : 7));
    CHECK(purged == (owner == 0 ? 1 : IP_REASS_MAX_PBUFS_PER_DATAGRAM));
    meet();
    CHECK(wwLwipReassemblyUsage(4) == 0);
    /* A worker with no local victim refuses a packet at another worker's quota.
     * The newly created empty IPv6 reassembly record must also expire safely. */
    if (owner == 0)
        for (unsigned i = 1; i <= IP_REASS_MAX_PBUFS; ++i)
            fragment6(engine, 9, i);
    meet();
    if (owner == 1)
        fragment6(engine, 9, 1);
    meet();
    CHECK(wwLwipReassemblyUsage(6) == IP_REASS_MAX_PBUFS);
    meet();
    for (unsigned i = 0; i <= IPV6_REASS_MAXAGE; ++i)
        ip6_reass_tmr();
    meet();
    CHECK(wwLwipReassemblyUsage(6) == 0);
    meet();
    for (unsigned i = 1; i <= IP_REASS_MAX_PBUFS_PER_DATAGRAM; ++i)
        fragment6(engine, 7, i);
    meet();
    CHECK(wwLwipReassemblyUsage(6) == IP_REASS_MAX_PBUFS);
    CHECK(wwLwipReassemblyUsage(4) == 0);
    meet();
    if (owner == 0)
        fragment6(engine, 8, 1);
    meet();
    CHECK(wwLwipReassemblyUsage(6) == IP_REASS_MAX_PBUFS_PER_DATAGRAM + 1);
    meet();
    for (unsigned i = 0; i <= IPV6_REASS_MAXAGE; ++i)
        ip6_reass_tmr();
    meet();
    CHECK(wwLwipReassemblyUsage(6) == 0);
    meet();
    /* Leave retained packets for engine teardown, including IPv6 fragment zero. */
    fragment4(10, 1);
    fragment6(engine, 10, 0);
    struct dhcp   external_dhcp;
    struct autoip external_autoip;
    dhcp_set_struct(&interfaces[owner], &external_dhcp);
    autoip_set_struct(&interfaces[owner], &external_autoip);
    CHECK(dhcp_start(&interfaces[owner]) == ERR_OK);
    CHECK(autoip_start(&interfaces[owner]) == ERR_OK);
    CHECK((external_dhcp.flags & DHCP_FLAG_EXTERNAL_MEM) != 0);
    struct netif allocated_clients = {0};
    CHECK(netif_add(&allocated_clients, &address, &mask, &gateway, NULL, init_netif, ip_input) != NULL);
    netif_set_up(&allocated_clients);
    CHECK(dhcp_start(&allocated_clients) == ERR_OK);
    CHECK(autoip_start(&allocated_clients) == ERR_OK);
    void *detached = mem_malloc(1460);
    CHECK(detached != NULL);
    wwLwipEngineLeave(engine, previous);
    wwLwipEngineDestroy(engine);
    /* Shared backing outlives the engine; an unscoped final free must not
     * dereference its former owner's now-destroyed cache. */
    mem_free(detached);
    CHECK(netif_dhcp_data(&allocated_clients) == NULL && netif_autoip_data(&allocated_clients) == NULL);
    CHECK(netif_dhcp_data(&interfaces[owner]) == NULL && netif_autoip_data(&interfaces[owner]) == NULL);
    return NULL;
}

int main(void)
{
    wwLwipEngineSharedInit();
    LWIP_MEMPOOL_INIT(CACHE_RX_TEST);
    wwLwipPoolCacheRegisterRxPool(&memp_CACHE_RX_TEST);
    CHECK(pthread_barrier_init(&rendezvous, NULL, 2) == 0);
    pthread_t threads[2];
    for (uintptr_t i = 0; i < 2; ++i)
        CHECK(pthread_create(&threads[i], NULL, run, (void *) i) == 0);
    for (unsigned i = 0; i < 2; ++i)
        CHECK(pthread_join(threads[i], NULL) == 0);
    CHECK(pthread_barrier_destroy(&rendezvous) == 0);
    CHECK(memp_CACHE_RX_TEST.stats->used == 0);
    wwLwipEngineSharedCleanup();
    puts("shared capacities, concurrent allocation, custom free, initialization refusal and IPv4 quotas passed");
    return 0;
}
