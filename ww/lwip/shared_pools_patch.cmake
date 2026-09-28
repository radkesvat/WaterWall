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
[=[#define MEM_STATS_INC(x)]=]
[=[#if WW_LWIP_WORKER_ENGINES
struct stats_ *wwLwipSharedStats(void);
#define WW_LWIP_HEAP_STATS (wwLwipSharedStats()->mem)
#else
#define WW_LWIP_HEAP_STATS lwip_stats.mem
#endif
#define MEM_STATS_INC(x)]=])
    file(READ "${lwip_dir}/src/include/lwip/stats.h" content)
    string(REPLACE "lwip_stats.mem." "WW_LWIP_HEAP_STATS." content "${content}")
    string(REPLACE "&lwip_stats.mem," "&WW_LWIP_HEAP_STATS," content "${content}")
    file(WRITE "${lwip_dir}/src/include/lwip/stats.h" "${content}")
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
    file(READ "${lwip_dir}/src/core/tcp.c" content)
    string(REPLACE "MEMP_STATS_DEC(err, MEMP_TCP_PCB);" "SYS_ARCH_LOCKED(MEMP_STATS_DEC(err, MEMP_TCP_PCB));" content "${content}")
    file(WRITE "${lwip_dir}/src/core/tcp.c" "${content}")
    file(READ "${lwip_dir}/src/core/ipv6/nd6.c" content)
    string(REPLACE "ww_ctx_nd6_queue_size++;" "if (new_entry != NULL) { ww_ctx_nd6_queue_size++; }" content "${content}")
    file(WRITE "${lwip_dir}/src/core/ipv6/nd6.c" "${content}")
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
endfunction()
