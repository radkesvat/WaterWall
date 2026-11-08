/* OPTIONAL: Pools to replace heap allocation
 * Optional: Pools can be used instead of the heap for mem_malloc. If
 * so, these should be defined here, in increasing order according to
 * the pool element size.
 *
 * LWIP_MALLOC_MEMPOOL(number_elements, element_size)
 */

/*
 * MEM_USE_POOLS is on, so this list - not MEM_SIZE - defines lwIP's size classes. Every
 * PBUF_RAM allocation lands here, including the copies tcp_write(...,
 * TCP_WRITE_FLAG_COPY) makes for outbound data and the per-fragment buffers
 * ip4_frag() builds. Production allocates backing slabs on demand within the
 * configured byte budget, independently of the flow-count defaults.
 *
 * MEM_USE_POOLS_TRY_BIGGER_POOL is on, so a request that finds its own class
 * empty falls forward into the next one instead of failing immediately.
 * Exhaustion must still stay survivable: callers close or shed the affected flow.
 *
 * Both flow targets feed static-fixture sizing because UDP also consumes these
 * classes. Production class counts are descriptor seeds, not fixed inventory;
 * ordinary and recovery backing remain isolated under the shared byte ceiling.
 * Production grows these classes on demand within the shared byte budget; their
 * declared counts apply only to the bounded static allocator fixture.
 *
 * WW_LWIP_FULL_MSS_BLOCK is the hot class, and its size is computed rather than
 * guessed. A full-MSS tcp_write(..., COPY) asks pbuf_alloc() for
 * PBUF_TRANSPORT headroom plus TCP_MSS plus a pbuf header, each aligned to
 * MEM_ALIGNMENT, and mem_malloc() adds its own pool bookkeeping on top. With
 * IPv6 enabled and 16-byte alignment that totals 1600 bytes, so the former
 * 1536-byte class could not serve a single normal segment: every one of them
 * skipped it and fell forward into the far smaller classes above. The static
 * assert below is what keeps a future headroom or alignment change from
 * silently invalidating it again.
 *
 * Division is rounded up and floored at one entry: a small override must shrink
 * a class, never delete it, because MEM_USE_POOLS_TRY_BIGGER_POOL can only fall
 * forward into classes that exist.
 */
#define WW_LWIP_FULL_MSS_ALLOC                                                                                         \
    (LWIP_MEM_ALIGN_SIZE(PBUF_TRANSPORT_HLEN + PBUF_IP_HLEN + PBUF_LINK_HLEN + PBUF_LINK_ENCAPSULATION_HLEN) +         \
     LWIP_MEM_ALIGN_SIZE(TCP_MSS) + LWIP_MEM_ALIGN_SIZE(sizeof(struct pbuf)) +                                         \
     LWIP_MEM_ALIGN_SIZE(sizeof(struct memp_malloc_helper)))
#define WW_LWIP_FULL_MSS_BLOCK 1664
#if WW_LWIP_DYNAMIC_POOLS
/* Descriptor counts do not reserve storage or limit production payload classes.
 * Their slabs share the configured byte budget. */
#define WW_LWIP_HEAP_CLASS(divisor) 1
#else
#define WW_LWIP_HEAP_FLOWS     (WW_LWIP_MAX_TCP_FLOWS + WW_LWIP_MAX_UDP_FLOWS)
#define WW_LWIP_HEAP_CLASS(divisor)                                                                                    \
    ((((WW_LWIP_HEAP_FLOWS) + (divisor) - 1) / (divisor)) > 1 ? (((WW_LWIP_HEAP_FLOWS) + (divisor) - 1) / (divisor))   \
                                                              : 1)
#endif

#if MEM_USE_POOLS
#if ! WW_LWIP_DYNAMIC_POOLS && (WW_LWIP_HEAP_CLASS(4) * 4) > 65535
#error "WW_LWIP_MAX_TCP_FLOWS / WW_LWIP_MAX_UDP_FLOWS exceed what lwIP's malloc-pool counts can index"
#endif
LWIP_MALLOC_MEMPOOL_START
LWIP_MALLOC_MEMPOOL((WW_LWIP_HEAP_CLASS(4) * 4), 256)
LWIP_MALLOC_MEMPOOL((WW_LWIP_HEAP_CLASS(8) * 4), 512)
LWIP_MALLOC_MEMPOOL((WW_LWIP_HEAP_CLASS(8) * 4), 1024)
LWIP_MALLOC_MEMPOOL((WW_LWIP_HEAP_CLASS(4) * 4), WW_LWIP_FULL_MSS_BLOCK)
LWIP_MALLOC_MEMPOOL((WW_LWIP_HEAP_CLASS(16) * 4), 2048)
LWIP_MALLOC_MEMPOOL((WW_LWIP_HEAP_CLASS(32) * 4), 4160)
LWIP_MALLOC_MEMPOOL((WW_LWIP_HEAP_CLASS(64) * 4), 8192)
LWIP_MALLOC_MEMPOOL((WW_LWIP_HEAP_CLASS(128) * 4), 16384)
LWIP_MALLOC_MEMPOOL_END
#endif /* MEM_USE_POOLS */

/* Optional: Your custom pools can go here if you would like to use
 * lwIP's memory pools for anything else.
 */
LWIP_MEMPOOL(SYS_MBOX, 22, 100, "SYS_MBOX")
