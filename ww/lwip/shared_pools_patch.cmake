# Shared allocator accounting and per-family reassembly reservations.
function(ww_apply_lwip_shared_pools_patch lwip_dir)
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv4/ip4_frag.c"
[=[#include "lwip/opt.h"]=]
[=[#include "lwip/opt.h"
#if WW_LWIP_WORKER_ENGINES
#include "shared_pools.h"
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv4/ip4_frag.c"
[=[  if ((ww_ctx_ip_reass_pbufcount + clen) > IP_REASS_MAX_PBUFS) {
#if IP_REASS_FREE_OLDEST
    if (!ip_reass_remove_oldest_datagram(fraghdr, clen, input_netif_idx) ||
        ((ww_ctx_ip_reass_pbufcount + clen) > IP_REASS_MAX_PBUFS))
#endif /* IP_REASS_FREE_OLDEST */
    {
      /* No datagram could be freed and still too many pbufs enqueued */
      LWIP_DEBUGF(IP_REASS_DEBUG, ("ip4_reass: Overflow condition: pbufct=%d, clen=%d, MAX=%d\n",
                                   ww_ctx_ip_reass_pbufcount, clen, IP_REASS_MAX_PBUFS));
      IPFRAG_STATS_INC(ip_frag.memerr);
      /* @todo: send ICMP time exceeded here? */
      /* drop this pbuf */
      goto nullreturn;
    }
  }]=]
[=[#if WW_LWIP_WORKER_ENGINES
  if (!wwLwipReassemblyReserve(4, clen)) {
#if IP_REASS_FREE_OLDEST
    if (!ip_reass_remove_oldest_datagram(fraghdr, clen, input_netif_idx) ||
        (!wwLwipReassemblyReserve(4, clen)))
#endif /* IP_REASS_FREE_OLDEST */
    {
      /* No datagram could be freed and still too many pbufs enqueued */
      LWIP_DEBUGF(IP_REASS_DEBUG, ("ip4_reass: Overflow condition: pbufct=%d, clen=%d, MAX=%d\n",
                                   ww_ctx_ip_reass_pbufcount, clen, IP_REASS_MAX_PBUFS));
      IPFRAG_STATS_INC(ip_frag.memerr);
      /* @todo: send ICMP time exceeded here? */
      /* drop this pbuf */
      goto nullreturn;
    }
  }
  ww_reserved = 1;
#else
  if ((ww_ctx_ip_reass_pbufcount + clen) > IP_REASS_MAX_PBUFS) {
#if IP_REASS_FREE_OLDEST
    if (!ip_reass_remove_oldest_datagram(fraghdr, clen, input_netif_idx) ||
        ((ww_ctx_ip_reass_pbufcount + clen) > IP_REASS_MAX_PBUFS))
#endif /* IP_REASS_FREE_OLDEST */
    {
      /* No datagram could be freed and still too many pbufs enqueued */
      LWIP_DEBUGF(IP_REASS_DEBUG, ("ip4_reass: Overflow condition: pbufct=%d, clen=%d, MAX=%d\n",
                                   ww_ctx_ip_reass_pbufcount, clen, IP_REASS_MAX_PBUFS));
      IPFRAG_STATS_INC(ip_frag.memerr);
      /* @todo: send ICMP time exceeded here? */
      /* drop this pbuf */
      goto nullreturn;
    }
  }
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv4/ip4_frag.c"
[=[
ip4_reass(struct pbuf *p, struct netif *inp)
{]=]
[=[
ip4_reass(struct pbuf *p, struct netif *inp)
{
#if WW_LWIP_WORKER_ENGINES
  u8_t ww_reserved = 0;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv4/ip4_frag.c"
[=[  ww_ctx_ip_reass_pbufcount = (u16_t)(ww_ctx_ip_reass_pbufcount + clen);]=]
[=[  ww_ctx_ip_reass_pbufcount = (u16_t)(ww_ctx_ip_reass_pbufcount + clen);
#if WW_LWIP_WORKER_ENGINES
  ww_reserved = 0; /* the local reassembly list now owns the reservation */
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv4/ip4_frag.c"
[=[ww_ctx_ip_reass_pbufcount = (u16_t)(ww_ctx_ip_reass_pbufcount - clen);]=]
[=[ww_ctx_ip_reass_pbufcount = (u16_t)(ww_ctx_ip_reass_pbufcount - clen);
#if WW_LWIP_WORKER_ENGINES
  wwLwipReassemblyRelease(4, clen);
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv4/ip4_frag.c"
[=[ww_ctx_ip_reass_pbufcount = (u16_t)(ww_ctx_ip_reass_pbufcount - pbufs_freed);]=]
[=[ww_ctx_ip_reass_pbufcount = (u16_t)(ww_ctx_ip_reass_pbufcount - pbufs_freed);
#if WW_LWIP_WORKER_ENGINES
  wwLwipReassemblyRelease(4, pbufs_freed);
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv4/ip4_frag.c"
[=[nullreturn:
]=]
[=[nullreturn:
#if WW_LWIP_WORKER_ENGINES
  if (ww_reserved) { wwLwipReassemblyRelease(4, clen); }
#endif
]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv6/ip6_frag.c"
[=[#include "lwip/opt.h"]=]
[=[#include "lwip/opt.h"
#if WW_LWIP_WORKER_ENGINES
#include "shared_pools.h"
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv6/ip6_frag.c"
[=[  if ((ww_ctx_ip6_reass_pbufcount + clen) > IP_REASS_MAX_PBUFS) {
#if IP_REASS_FREE_OLDEST
    ip6_reass_remove_oldest_datagram(ipr, clen);
    if ((ww_ctx_ip6_reass_pbufcount + clen) <= IP_REASS_MAX_PBUFS) {
      /* re-search ipr_prev since it might have been removed */
      for (ipr_prev = ww_ctx_reassdatagrams; ipr_prev != NULL; ipr_prev = ipr_prev->next) {
        if (ipr_prev->next == ipr) {
          break;
        }
      }
    } else
#endif /* IP_REASS_FREE_OLDEST */
    {
      /* @todo: send ICMPv6 time exceeded here? */
      /* drop this pbuf */
      IP6_FRAG_STATS_INC(ip6_frag.memerr);
      goto nullreturn;
    }
  }]=]
[=[#if WW_LWIP_WORKER_ENGINES
  if (!wwLwipReassemblyReserve(6, clen)) {
#if IP_REASS_FREE_OLDEST
    ip6_reass_remove_oldest_datagram(ipr, clen);
    if (wwLwipReassemblyReserve(6, clen)) {
      /* re-search ipr_prev since it might have been removed */
      for (ipr_prev = ww_ctx_reassdatagrams; ipr_prev != NULL; ipr_prev = ipr_prev->next) {
        if (ipr_prev->next == ipr) {
          break;
        }
      }
    } else
#endif /* IP_REASS_FREE_OLDEST */
    {
      /* @todo: send ICMPv6 time exceeded here? */
      /* drop this pbuf */
      IP6_FRAG_STATS_INC(ip6_frag.memerr);
      goto nullreturn;
    }
  }
  ww_reserved = 1;
#else
  if ((ww_ctx_ip6_reass_pbufcount + clen) > IP_REASS_MAX_PBUFS) {
#if IP_REASS_FREE_OLDEST
    ip6_reass_remove_oldest_datagram(ipr, clen);
    if ((ww_ctx_ip6_reass_pbufcount + clen) <= IP_REASS_MAX_PBUFS) {
      /* re-search ipr_prev since it might have been removed */
      for (ipr_prev = ww_ctx_reassdatagrams; ipr_prev != NULL; ipr_prev = ipr_prev->next) {
        if (ipr_prev->next == ipr) {
          break;
        }
      }
    } else
#endif /* IP_REASS_FREE_OLDEST */
    {
      /* @todo: send ICMPv6 time exceeded here? */
      /* drop this pbuf */
      IP6_FRAG_STATS_INC(ip6_frag.memerr);
      goto nullreturn;
    }
  }
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv6/ip6_frag.c"
[=[
ip6_reass(struct pbuf *p)
{]=]
[=[
ip6_reass(struct pbuf *p)
{
#if WW_LWIP_WORKER_ENGINES
  u8_t ww_reserved = 0;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv6/ip6_frag.c"
[=[  ww_ctx_ip6_reass_pbufcount = (u16_t)(ww_ctx_ip6_reass_pbufcount + clen);]=]
[=[  ww_ctx_ip6_reass_pbufcount = (u16_t)(ww_ctx_ip6_reass_pbufcount + clen);
#if WW_LWIP_WORKER_ENGINES
  ww_reserved = 0; /* the local reassembly list now owns the reservation */
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv6/ip6_frag.c"
[=[ww_ctx_ip6_reass_pbufcount = (u16_t)(ww_ctx_ip6_reass_pbufcount - clen);]=]
[=[ww_ctx_ip6_reass_pbufcount = (u16_t)(ww_ctx_ip6_reass_pbufcount - clen);
#if WW_LWIP_WORKER_ENGINES
  wwLwipReassemblyRelease(6, clen);
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv6/ip6_frag.c"
[=[ww_ctx_ip6_reass_pbufcount = (u16_t)(ww_ctx_ip6_reass_pbufcount - pbufs_freed);]=]
[=[ww_ctx_ip6_reass_pbufcount = (u16_t)(ww_ctx_ip6_reass_pbufcount - pbufs_freed);
#if WW_LWIP_WORKER_ENGINES
  wwLwipReassemblyRelease(6, pbufs_freed);
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv6/ip6_frag.c"
[=[nullreturn:
]=]
[=[nullreturn:
#if WW_LWIP_WORKER_ENGINES
  if (ww_reserved) { wwLwipReassemblyRelease(6, clen); }
#endif
]=])
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/stats.h"
[=[#define MEM_STATS_INC(x) STATS_INC(mem.x)]=]
[=[#if WW_LWIP_WORKER_ENGINES
struct stats_ *wwLwipSharedStats(void);
#define WW_LWIP_HEAP_STATS (wwLwipSharedStats()->mem)
#else
#define WW_LWIP_HEAP_STATS lwip_stats.mem
#endif
#define MEM_STATS_INC(x) STATS_INC(mem.x)]=])
    ww_lwip_replace_all("${lwip_dir}/src/include/lwip/stats.h"
        "lwip_stats.mem." "WW_LWIP_HEAP_STATS." 3)
    ww_lwip_replace_all("${lwip_dir}/src/include/lwip/stats.h"
        "&lwip_stats.mem," "&WW_LWIP_HEAP_STATS," 1)
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/stats.h"
[=[#define MEM_STATS_INC(x) STATS_INC(mem.x)]=]
[=[#define MEM_STATS_INC(x) ++WW_LWIP_HEAP_STATS.x]=])
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/stats.h"
[=[#define MEM_STATS_INC_USED(x, y) STATS_INC_USED(mem, y, mem_size_t)]=]
[=[#define MEM_STATS_INC_USED(x, y) do { \
  WW_LWIP_HEAP_STATS.x = (mem_size_t)(WW_LWIP_HEAP_STATS.x + (y)); \
  if (WW_LWIP_HEAP_STATS.max < WW_LWIP_HEAP_STATS.x) { \
    WW_LWIP_HEAP_STATS.max = WW_LWIP_HEAP_STATS.x; \
  } \
} while (0)]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp.c"
[=[#include "lwip/opt.h"]=]
[=[#include "lwip/opt.h"
#include "lwip/sys.h"]=])
    ww_lwip_replace_all("${lwip_dir}/src/core/tcp.c"
        "MEMP_STATS_DEC(err, MEMP_TCP_PCB);" "SYS_ARCH_LOCKED(MEMP_STATS_DEC(err, MEMP_TCP_PCB));" 4)
    ww_lwip_replace_all("${lwip_dir}/src/core/ipv6/nd6.c"
        "ww_ctx_nd6_queue_size++;" "if (new_entry != NULL) { ww_ctx_nd6_queue_size++; }" 2)
    ww_lwip_replace_once("${lwip_dir}/src/core/stats.c"
[=[#include "lwip/debug.h"]=]
[=[#include "lwip/debug.h"
#include "lwip/sys.h"]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/stats.c"
[=[stats_display_mem(struct stats_mem *mem, const char *name)
{]=]
[=[stats_display_mem(struct stats_mem *mem, const char *name)
{
  struct stats_mem snapshot;
  SYS_ARCH_DECL_PROTECT(protection);
  SYS_ARCH_PROTECT(protection);
  snapshot = *mem;
  SYS_ARCH_UNPROTECT(protection);
  mem = &snapshot;]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/ipv6/ip6_frag.c"
[=[  iprh = (struct ip6_reass_helper *)ipr->p->payload;
  if (iprh->start == 0) {]=]
[=[  iprh = ipr->p != NULL ? (struct ip6_reass_helper *)ipr->p->payload : NULL;
  if (iprh != NULL && iprh->start == 0
#if WW_LWIP_WORKER_ENGINES
      && !wwLwipEngineIsReleasing()
#endif
      ) {]=])
    file(APPEND "${lwip_dir}/src/core/ipv4/ip4_frag.c" "
#if WW_LWIP_WORKER_ENGINES && IP_REASSEMBLY
void wwLwipReassemblyCleanup4(void) {
  while (ww_ctx_reassdatagrams != NULL) {
    ip_reass_free_complete_datagram_notify(ww_ctx_reassdatagrams, NULL, 0);
  }
}
#endif
")
    file(APPEND "${lwip_dir}/src/core/ipv6/ip6_frag.c" "
#if WW_LWIP_WORKER_ENGINES && LWIP_IPV6_REASS
void wwLwipReassemblyCleanup6(void) {
  while (ww_ctx_reassdatagrams != NULL) {
    ip6_reass_free_complete_datagram(ww_ctx_reassdatagrams);
  }
}
#endif
")
    # Keep the allocator's original capacity and nullable shared primitives.
    # Only normal pool mode uses the engine caches; allocator diagnostics retain
    # their per-operation checks and hooks.
    ww_lwip_replace_once("${lwip_dir}/src/core/memp.c"
[=[#include "lwip/sys.h"]=]
[=[#include "lwip/sys.h"
#include "pool_cache.h"]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/memp.c"
[=[  return do_memp_malloc_pool(desc);]=]
[=[#if WW_LWIP_POOL_CACHE_ENABLED
  return wwLwipPoolCacheMalloc(desc);
#else
  return do_memp_malloc_pool(desc);
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/memp.c"
[=[  memp = do_memp_malloc_pool(memp_pools[type]);]=]
[=[#if WW_LWIP_POOL_CACHE_ENABLED
  memp = wwLwipPoolCacheMalloc(memp_pools[type]);
#else
  memp = do_memp_malloc_pool(memp_pools[type]);
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/memp.c"
[=[  do_memp_free_pool(desc, mem);]=]
[=[#if WW_LWIP_POOL_CACHE_ENABLED
  wwLwipPoolCacheFree(desc, mem);
#else
  do_memp_free_pool(desc, mem);
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/memp.c"
[=[  do_memp_free_pool(memp_pools[type], mem);]=]
[=[#if WW_LWIP_POOL_CACHE_ENABLED
  wwLwipPoolCacheFree(memp_pools[type], mem);
#else
  do_memp_free_pool(memp_pools[type], mem);
#endif]=])
    file(APPEND "${lwip_dir}/src/core/memp.c" "
#if WW_LWIP_POOL_CACHE_ENABLED
void *wwLwipMempMallocShared(const struct memp_desc *pool) {
  return do_memp_malloc_pool(pool);
}
void wwLwipMempFreeShared(const struct memp_desc *pool, void *item) {
  do_memp_free_pool(pool, item);
}
#endif
")
    # Production pool descriptors retain stable identities, while their backing
    # storage grows in bounded slabs. The private small-capacity fixture selects
    # the original static implementation.
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/memp.h"
[=[#include "lwip/opt.h"]=]
[=[#include "lwip/opt.h"
#if WW_LWIP_DYNAMIC_POOLS
#include "capacity_internal.h"
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/memp.h"
[=[#define LWIP_MEMPOOL_DECLARE(name,num,size,desc) \
  LWIP_DECLARE_MEMORY_ALIGNED(memp_memory_ ## name ## _base, ((num) * (MEMP_SIZE + MEMP_ALIGN_SIZE(size))));]=]
[=[#if WW_LWIP_DYNAMIC_POOLS
#define LWIP_MEMPOOL_DECLARE(name,num,size,desc) \
  LWIP_MEMPOOL_DECLARE_STATS_INSTANCE(memp_stats_ ## name) \
  static struct memp *memp_tab_ ## name; \
  static ww_lwip_pool_state_t memp_state_ ## name; \
  const struct memp_desc memp_ ## name = { \
    DECLARE_LWIP_MEMPOOL_DESC(desc) \
    LWIP_MEMPOOL_DECLARE_STATS_REFERENCE(memp_stats_ ## name) \
    LWIP_MEM_ALIGN_SIZE(size), (num), NULL, &memp_tab_ ## name, &memp_state_ ## name \
  };
#else
#define LWIP_MEMPOOL_DECLARE(name,num,size,desc) \
  LWIP_DECLARE_MEMORY_ALIGNED(memp_memory_ ## name ## _base, ((num) * (MEMP_SIZE + MEMP_ALIGN_SIZE(size))));]=])
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/memp.h"
[=[#endif /* MEMP_MEM_MALLOC */]=]
[=[#endif /* WW_LWIP_DYNAMIC_POOLS */
#endif /* MEMP_MEM_MALLOC */]=])
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/priv/memp_priv.h"
[=[  u16_t num;]=]
[=[  u32_t num;]=])
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/priv/memp_priv.h"
[=[  struct memp **tab;]=]
[=[  struct memp **tab;
#if WW_LWIP_DYNAMIC_POOLS
  struct ww_lwip_pool_state_s *ww_pool;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/mem.h"
[=[#elif MEM_USE_POOLS

typedef u16_t mem_size_t;
#define MEM_SIZE_F U16_F]=]
[=[#elif MEM_USE_POOLS

#if WW_LWIP_DYNAMIC_POOLS
typedef size_t mem_size_t;
#define MEM_SIZE_F SZT_F
#else
typedef u16_t mem_size_t;
#define MEM_SIZE_F U16_F
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/memp.c"
[=[#include "pool_cache.h"]=]
[=[#include "pool_cache.h"
#include "capacity_internal.h"
#if WW_LWIP_DYNAMIC_POOLS && (MEMP_MEM_MALLOC || MEMP_OVERFLOW_CHECK || MEMP_SANITY_CHECK || !MEM_USE_POOLS || !MEMP_STATS || !LWIP_STATS_DISPLAY)
#error "Diagnostic allocator modes require WW_LWIP_DYNAMIC_POOLS=0"
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/memp.c"
[=[memp_init_pool(const struct memp_desc *desc)
{]=]
[=[memp_init_pool(const struct memp_desc *desc)
{
#if WW_LWIP_DYNAMIC_POOLS
  wwLwipCapacityPoolInitialize(desc);
  return;
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/memp.c"
[=[  struct memp *memp;
  SYS_ARCH_DECL_PROTECT(old_level);

#if MEMP_MEM_MALLOC]=]
[=[#if WW_LWIP_DYNAMIC_POOLS
  return wwLwipCapacityMalloc(desc);
#endif
  struct memp *memp;
  SYS_ARCH_DECL_PROTECT(old_level);

#if MEMP_MEM_MALLOC]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/memp.c"
[=[do_memp_free_pool(const struct memp_desc *desc, void *mem)
{]=]
[=[do_memp_free_pool(const struct memp_desc *desc, void *mem)
{
#if WW_LWIP_DYNAMIC_POOLS
  wwLwipCapacityFree(desc, mem);
  return;
#endif]=])
    # Widening mem_size_t must not let an oversized request wrap bookkeeping.
    ww_lwip_replace_once("${lwip_dir}/src/core/mem.c"
[=[  mem_size_t required_size = size + LWIP_MEM_ALIGN_SIZE(sizeof(struct memp_malloc_helper));]=]
[=[  mem_size_t required_size = size + LWIP_MEM_ALIGN_SIZE(sizeof(struct memp_malloc_helper));
  if (required_size < size) {
    return NULL;
  }]=])
    # Only the header allocation can spend recovery headroom. The scope ends
    # before any output, TCP sent callback, or application-data write executes.
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[#include "lwip/opt.h"]=]
[=[#include "lwip/opt.h"
#include "capacity_internal.h"]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[  p = tcp_output_alloc_header(pcb, optlen, 0, lwip_htonl(pcb->snd_nxt));]=]
[=[  p = tcp_output_alloc_header(pcb, optlen, 0, lwip_htonl(pcb->snd_nxt));
#if WW_LWIP_DYNAMIC_POOLS
  if (p == NULL) {
    wwLwipCapacityRecoveryBegin();
  p = tcp_output_alloc_header(pcb, optlen, 0, lwip_htonl(pcb->snd_nxt));
    wwLwipCapacityRecoveryEnd();
  }
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[  p = tcp_output_alloc_header(pcb, optlen, 0, lwip_htonl(pcb->snd_nxt - 1));]=]
[=[  p = tcp_output_alloc_header(pcb, optlen, 0, lwip_htonl(pcb->snd_nxt - 1));
#if WW_LWIP_DYNAMIC_POOLS
  if (p == NULL) {
    wwLwipCapacityRecoveryBegin();
  p = tcp_output_alloc_header(pcb, optlen, 0, lwip_htonl(pcb->snd_nxt - 1));
    wwLwipCapacityRecoveryEnd();
  }
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[  p = tcp_output_alloc_header_common(ackno, optlen, 0, lwip_htonl(seqno), local_port,
    remote_port, TCP_RST | TCP_ACK, wnd);]=]
[=[  p = tcp_output_alloc_header_common(ackno, optlen, 0, lwip_htonl(seqno), local_port,
    remote_port, TCP_RST | TCP_ACK, wnd);
#if WW_LWIP_DYNAMIC_POOLS
  if (p == NULL) {
    wwLwipCapacityRecoveryBegin();
  p = tcp_output_alloc_header_common(ackno, optlen, 0, lwip_htonl(seqno), local_port,
    remote_port, TCP_RST | TCP_ACK, wnd);
    wwLwipCapacityRecoveryEnd();
  }
#endif]=])
endfunction()
