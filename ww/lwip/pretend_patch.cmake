function(ww_lwip_replace_once file before after)
    file(READ "${file}" content)
    string(FIND "${content}" "${before}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "Waterwall lwIP pretend patch failed for ${file}")
    endif()

    string(LENGTH "${before}" before_len)
    string(SUBSTRING "${content}" 0 ${found} content_prefix)
    math(EXPR suffix_start "${found} + ${before_len}")
    string(SUBSTRING "${content}" ${suffix_start} -1 content_suffix)
    set(content "${content_prefix}${after}${content_suffix}")
    file(WRITE "${file}" "${content}")
endfunction()

function(ww_apply_lwip_pretend_patch lwip_dir)
    # RFC 791 identifies a datagram being reassembled by source, destination,
    # protocol, and identification. lwIP omits the protocol, so a TCP and a UDP
    # datagram between the same two addresses that happen to share an
    # identification are merged into one reassembly - which, once a node exposes
    # arbitrary peers to this stack, is reachable by a crafted sender and
    # produces either a checksum failure or a corrupted datagram.
    #
    # This only ever makes matching stricter, so no correct reassembly is lost.
    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4_frag.c"
        [=[#define IP_ADDRESSES_AND_ID_MATCH(iphdrA, iphdrB)  \
  (ip4_addr_eq(&(iphdrA)->src, &(iphdrB)->src) && \
   ip4_addr_eq(&(iphdrA)->dest, &(iphdrB)->dest) && \
   IPH_ID(iphdrA) == IPH_ID(iphdrB)) ? 1 : 0]=]
        [=[#define IP_ADDRESSES_AND_ID_MATCH(iphdrA, iphdrB)  \
  (ip4_addr_eq(&(iphdrA)->src, &(iphdrB)->src) && \
   ip4_addr_eq(&(iphdrA)->dest, &(iphdrB)->dest) && \
   (IPH_PROTO(iphdrA) == IPH_PROTO(iphdrB)) && \
   (IPH_ID(iphdrA) == IPH_ID(iphdrB)))]=])

    # The reassembly list is one process-global chain, but this process runs many
    # netifs that deliberately share a virtual address: ConnectionToPackets gives
    # every event worker its own netif carrying the same `source-ipv4`. Two
    # datagrams from one peer to that address, with the same protocol and the same
    # identification, routed to different workers, therefore match each other's
    # reassembly object and get spliced together - and the identification is a
    # 16-bit field a busy peer wraps in seconds.
    #
    # Adding the ingress netif to the key is what separates them. lwIP does not
    # pass the netif into ip4_reass(), and ip_data.current_input_netif is only
    # assigned *after* the reassembly call returns, so reading the "current" netif
    # from inside would see the previous packet's. The interface has to change.
    ww_lwip_replace_once(
        "${lwip_dir}/src/include/lwip/ip4_frag.h"
        [=[struct ip_reassdata {
  struct ip_reassdata *next;
  struct pbuf *p;
  struct ip_hdr iphdr;
  u16_t datagram_len;
  u8_t flags;
  u8_t timer;
};]=]
        [=[struct ip_reassdata {
  struct ip_reassdata *next;
  struct pbuf *p;
  struct ip_hdr iphdr;
  u16_t datagram_len;
  /* Exact number of chained pbufs retained for this datagram. */
  u16_t pbuf_count;
  u8_t flags;
  u8_t timer;
  /* Index of the netif this datagram's fragments arrived on. Datagrams from
     different netifs never reassemble into each other, even when their source,
     destination, protocol and identification all match. */
  u8_t input_netif_idx;
};]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/include/lwip/ip4_frag.h"
        [=[struct pbuf * ip4_reass(struct pbuf *p);]=]
        [=[struct pbuf * ip4_reass(struct pbuf *p, struct netif *inp);]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/include/lwip/ip4_frag.h"
        [=[struct pbuf * ip4_reass(struct pbuf *p, struct netif *inp);]=]
        [=[struct pbuf * ip4_reass(struct pbuf *p, struct netif *inp);
u16_t ip4_reass_purge(struct netif *inp, const ip4_addr_t *src, const ip4_addr_t *dest,
                      u8_t proto, u16_t ident);
u8_t ip4_reass_has(struct netif *inp, const ip4_addr_t *src, const ip4_addr_t *dest,
                   u8_t proto, u16_t ident);
u32_t ip4_reass_tmr_epoch(void);
u16_t ip4_reass_purge_netif(struct netif *inp);]=])

    # The quarantine clock counts actual lwIP timer passes. Elapsed wall time
    # alone is insufficient because a stalled core does not replay missed timer
    # callbacks. This atomic conveys only the counter value, so relaxed ordering
    # is sufficient; no other state is published through it.
    file(WRITE "${lwip_dir}/src/include/lwip/ww_atomic.h" [=[#ifndef LWIP_HDR_WW_ATOMIC_H
#define LWIP_HDR_WW_ATOMIC_H

#include <stdint.h>

#if defined(_WIN32) && defined(_MSC_VER)
#include <windows.h>
typedef volatile LONG ww_lwip_atomic_u32_t;

static __inline uint32_t
ww_lwip_atomic_u32_load_relaxed(const ww_lwip_atomic_u32_t *value)
{
  return (uint32_t)InterlockedCompareExchange((volatile LONG *)value, 0, 0);
}

static __inline void
ww_lwip_atomic_u32_increment_relaxed(ww_lwip_atomic_u32_t *value)
{
  (void)InterlockedIncrement(value);
}
#elif defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L) && !defined(__STDC_NO_ATOMICS__)
#include <stdatomic.h>
typedef atomic_uint_least32_t ww_lwip_atomic_u32_t;

static inline uint32_t
ww_lwip_atomic_u32_load_relaxed(const ww_lwip_atomic_u32_t *value)
{
  return (uint32_t)atomic_load_explicit(value, memory_order_relaxed);
}

static inline void
ww_lwip_atomic_u32_increment_relaxed(ww_lwip_atomic_u32_t *value)
{
  (void)atomic_fetch_add_explicit(value, 1, memory_order_relaxed);
}
#elif defined(__GNUC__) || defined(__clang__)
typedef uint_least32_t ww_lwip_atomic_u32_t;

static inline uint32_t
ww_lwip_atomic_u32_load_relaxed(const ww_lwip_atomic_u32_t *value)
{
  return (uint32_t)__atomic_load_n(value, __ATOMIC_RELAXED);
}

static inline void
ww_lwip_atomic_u32_increment_relaxed(ww_lwip_atomic_u32_t *value)
{
  (void)__atomic_add_fetch(value, 1, __ATOMIC_RELAXED);
}
#else
#error "WaterWall lwIP requires a supported 32-bit atomic backend"
#endif

#endif /* LWIP_HDR_WW_ATOMIC_H */
]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4_frag.c"
        [=[#include <string.h>]=]
        [=[#include <string.h>
#include "lwip/ww_atomic.h"]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4_frag.c"
        [=[static struct ip_reassdata *reassdatagrams;
static u16_t ip_reass_pbufcount;]=]
        [=[static struct ip_reassdata *reassdatagrams;
static u16_t ip_reass_pbufcount;
static ww_lwip_atomic_u32_t ip_reass_timer_epoch;]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4_frag.c"
        [=[static struct ip_reassdata *
ip_reass_enqueue_new_datagram(struct ip_hdr *fraghdr, int clen)
{]=]
        [=[static struct ip_reassdata *
ip_reass_enqueue_new_datagram(struct ip_hdr *fraghdr, int clen, u8_t input_netif_idx)
{]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4_frag.c"
        [=[  memset(ipr, 0, sizeof(struct ip_reassdata));
  ipr->timer = IP_REASS_MAXAGE;]=]
        [=[  memset(ipr, 0, sizeof(struct ip_reassdata));
  ipr->timer = IP_REASS_MAXAGE;
  ipr->input_netif_idx = input_netif_idx;]=])

    # The oldest-datagram eviction must exclude the datagram the current fragment
    # belongs to. With the netif in the key, "belongs to" means the same netif as
    # well, or a same-ID datagram on another netif could be treated as untouchable.
    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4_frag.c"
        [=[#endif /* IP_REASS_FREE_OLDEST */

#define IP_REASS_FLAG_LASTFRAG 0x01]=]
        [=[#endif /* IP_REASS_FREE_OLDEST */

/*
 * Applications may impose a fair-share limit below the global reassembly
 * pool. Upstream lwIP configurations that do not select one retain their
 * historical behavior by allowing one datagram to consume the global cap.
 */
#ifndef IP_REASS_MAX_PBUFS_PER_DATAGRAM
#define IP_REASS_MAX_PBUFS_PER_DATAGRAM IP_REASS_MAX_PBUFS
#endif

#define IP_REASS_FLAG_LASTFRAG 0x01]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4_frag.c"
        [=[#define IP_REASS_VALIDATE_TELEGRAM_FINISHED  1
#define IP_REASS_VALIDATE_PBUF_QUEUED        0
#define IP_REASS_VALIDATE_PBUF_DROPPED       -1]=]
        [=[#define IP_REASS_VALIDATE_TELEGRAM_FINISHED  1
#define IP_REASS_VALIDATE_PBUF_QUEUED        0
#define IP_REASS_VALIDATE_PBUF_DROPPED       -1
/* The new fragment is already linked when this is returned. The caller must
   account it and purge the complete malformed tuple rather than freeing only
   the new pbuf and leaving a dangling retained-list entry. */
#define IP_REASS_VALIDATE_DATAGRAM_INVALID   -2]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4_frag.c"
        [=[/**
 * Chain a new pbuf into the pbuf list that composes the datagram.  The pbuf list]=]
        [=[struct ip_reass_fragment_span {
  u16_t start;
  u16_t end;
  u16_t payload_len;
};

/* Complete structural admission before applying a resource budget or
 * mutating the retained list. A rejected fragment must not make an otherwise
 * valid retained datagram look over budget. */
static int
ip_reass_validate_fragment_span(const struct ip_reassdata *ipr, const struct pbuf *new_p,
                                struct ip_reass_fragment_span *span_out)
{
  const struct ip_hdr *fraghdr = (const struct ip_hdr *)new_p->payload;
  u16_t len = lwip_ntohs(IPH_LEN(fraghdr));
  const u8_t hlen = IPH_HL_BYTES(fraghdr);
  const u16_t start = IPH_OFFSET_BYTES(fraghdr);
  const int is_last = (IPH_OFFSET(fraghdr) & PP_NTOHS(IP_MF)) == 0;
  u32_t end;
  struct pbuf *q;

  if ((hlen < IP_HLEN) || (hlen > len)) {
    return 1;
  }
  len = (u16_t)(len - hlen);
  if ((len == 0) || (!is_last && ((len & 7U) != 0))) {
    return 1;
  }
  end = (u32_t)start + (u32_t)len;
  if (end > (u32_t)(0xFFFFU - IP_HLEN)) {
    return 1;
  }

  if (ipr != NULL && ((ipr->flags & IP_REASS_FLAG_LASTFRAG) != 0)) {
    if ((end > ipr->datagram_len) || (is_last && (end != ipr->datagram_len))) {
      return 1;
    }
  }

  if (ipr != NULL) {
    for (q = ipr->p; q != NULL;) {
      const struct ip_reass_helper *retained = (const struct ip_reass_helper *)q->payload;
      /* The first final fragment is authoritative. It may not declare an end
         below data that this tuple already retained. */
      if (is_last && ((u32_t)retained->end > end)) {
        return 1;
      }
      if (start == retained->start) {
        return 1;
      }
#if IP_REASS_CHECK_OVERLAP
      if ((start < retained->end) && (end > retained->start)) {
        return 1;
      }
#endif /* IP_REASS_CHECK_OVERLAP */
      q = retained->next_pbuf;
    }
  }
  if (span_out != NULL) {
    span_out->start = start;
    span_out->end = (u16_t)end;
    span_out->payload_len = len;
  }
  return 0;
}

/**
 * Chain a new pbuf into the pbuf list that composes the datagram.  The pbuf list]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4_frag.c"
        [=[  struct ip_reass_helper *iprh, *iprh_tmp, *iprh_prev = NULL;
  struct pbuf *q;
  u16_t offset, len;
  u8_t hlen;
  struct ip_hdr *fraghdr;
  int valid = 1;

  /* Extract length and fragment offset from current fragment */
  fraghdr = (struct ip_hdr *)new_p->payload;
  len = lwip_ntohs(IPH_LEN(fraghdr));
  hlen = IPH_HL_BYTES(fraghdr);
  if (hlen > len) {
    /* invalid datagram */
    return IP_REASS_VALIDATE_PBUF_DROPPED;
  }
  len = (u16_t)(len - hlen);
  offset = IPH_OFFSET_BYTES(fraghdr);]=]
        [=[  struct ip_reass_helper *iprh, *iprh_tmp, *iprh_prev = NULL;
  struct ip_reass_fragment_span span;
  struct pbuf *q;
  u16_t offset, len;
  int valid = 1;

  if (ip_reass_validate_fragment_span(ipr, new_p, &span)) {
    return IP_REASS_VALIDATE_PBUF_DROPPED;
  }
  offset = span.start;
  len = span.payload_len;]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4_frag.c"
        [=[        if (valid) {
          LWIP_ASSERT("sanity check", ipr->p != NULL);]=]
        [=[        if (valid && (iprh->end != (is_last ? span.end : ipr->datagram_len))) {
          /* Contiguity alone is insufficient: never return a pbuf chain whose
             retained tail contradicts the authoritative final endpoint. */
          return IP_REASS_VALIDATE_DATAGRAM_INVALID;
        }
        if (valid) {
          LWIP_ASSERT("sanity check", ipr->p != NULL);]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4_frag.c"
        [=[static int
ip_reass_remove_oldest_datagram(struct ip_hdr *fraghdr, int pbufs_needed)
{]=]
        [=[static int
ip_reass_remove_oldest_datagram(struct ip_hdr *fraghdr, int pbufs_needed, u8_t input_netif_idx)
{]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4_frag.c"
        [=[      if (!IP_ADDRESSES_AND_ID_MATCH(&r->iphdr, fraghdr)) {]=]
        [=[      if (!IP_ADDRESSES_AND_ID_MATCH(&r->iphdr, fraghdr) ||
          (r->input_netif_idx != input_netif_idx)) {]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4_frag.c"
        [=[ip4_reass(struct pbuf *p)
{
  struct pbuf *r;]=]
        [=[ip4_reass(struct pbuf *p, struct netif *inp)
{
  const u8_t input_netif_idx = (inp != NULL) ? netif_get_index(inp) : NETIF_NO_INDEX;
  struct pbuf *r;]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4_frag.c"
        [=[  struct ip_reassdata *ipr;
  struct ip_reass_helper *iprh;]=]
        [=[  struct ip_reassdata *ipr;
  struct ip_reassdata *budget_ipr;
  struct ip_reassdata *budget_prev;
  struct ip_reass_helper *iprh;]=])

    # Enforce the configured per-datagram pbuf budget before global eviction.
    # A fragment that would grow its own tuple past the cap purges only that
    # tuple, silently, and then drops the incoming pbuf.
    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4_frag.c"
        [=[  clen = pbuf_clen(p);
  if ((ip_reass_pbufcount + clen) > IP_REASS_MAX_PBUFS) {]=]
        [=[  clen = pbuf_clen(p);
  budget_prev = NULL;
  for (budget_ipr = reassdatagrams; budget_ipr != NULL; budget_ipr = budget_ipr->next) {
    if (IP_ADDRESSES_AND_ID_MATCH(&budget_ipr->iphdr, fraghdr) &&
        (budget_ipr->input_netif_idx == input_netif_idx)) {
      break;
    }
    budget_prev = budget_ipr;
  }
  if (ip_reass_validate_fragment_span(budget_ipr, p, NULL)) {
    goto nullreturn;
  }
  if ((clen > IP_REASS_MAX_PBUFS_PER_DATAGRAM) ||
      ((budget_ipr != NULL) &&
       (((u32_t)budget_ipr->pbuf_count + (u32_t)clen) > IP_REASS_MAX_PBUFS_PER_DATAGRAM))) {
    if (budget_ipr != NULL) {
      (void)ip_reass_free_complete_datagram_notify(budget_ipr, budget_prev, 0);
    }
    IPFRAG_STATS_INC(ip_frag.memerr);
    goto nullreturn;
  }
  if ((ip_reass_pbufcount + clen) > IP_REASS_MAX_PBUFS) {]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4_frag.c"
        [=[  ip_reass_pbufcount = (u16_t)(ip_reass_pbufcount + clen);
  if (is_last) {]=]
        [=[  ip_reass_pbufcount = (u16_t)(ip_reass_pbufcount + clen);
  ipr->pbuf_count = (u16_t)(ipr->pbuf_count + clen);
  if (is_last) {]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4_frag.c"
        [=[                 ipr->datagram_len));
  }

  if (valid == IP_REASS_VALIDATE_TELEGRAM_FINISHED) {]=]
        [=[                 ipr->datagram_len));
  }

  if (valid == IP_REASS_VALIDATE_DATAGRAM_INVALID) {
    struct ip_reassdata *invalid_prev = NULL;
    struct ip_reassdata *invalid_scan;
    for (invalid_scan = reassdatagrams; invalid_scan != ipr; invalid_scan = invalid_scan->next) {
      invalid_prev = invalid_scan;
    }
    (void)ip_reass_free_complete_datagram_notify(ipr, invalid_prev, 0);
    IPFRAG_STATS_INC(ip_frag.drop);
    return NULL;
  }

  if (valid == IP_REASS_VALIDATE_TELEGRAM_FINISHED) {]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4_frag.c"
        [=[      r = iprh->next_pbuf;
    }

    /* find the previous entry in the linked list */]=]
        [=[      r = iprh->next_pbuf;
    }

    LWIP_ASSERT("returned pbuf length agrees with final IPv4 length", p->tot_len == datagram_len);

    /* find the previous entry in the linked list */]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4_frag.c"
        [=[    /* release the sources allocate for the fragment queue entry */
    ip_reass_dequeue_datagram(ipr, ipr_prev);

    /* and adjust the number of pbufs currently queued for reassembly. */
    clen = pbuf_clen(p);]=]
        [=[    /* release the resources allocated for the fragment queue entry */
    clen = pbuf_clen(p);
    LWIP_ASSERT("completed pbuf count matches datagram accounting", ipr->pbuf_count == clen);
    ip_reass_dequeue_datagram(ipr, ipr_prev);

    /* and adjust the number of pbufs currently queued for reassembly. */]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4_frag.c"
        [=[    if (ip_reass_remove_oldest_datagram(fraghdr, clen) >= clen) {]=]
        [=[    if (ip_reass_remove_oldest_datagram(fraghdr, clen, input_netif_idx) >= clen) {]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4_frag.c"
        [=[    if (!ip_reass_remove_oldest_datagram(fraghdr, clen) ||]=]
        [=[    if (!ip_reass_remove_oldest_datagram(fraghdr, clen, input_netif_idx) ||]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4_frag.c"
        [=[  is_last = (IPH_OFFSET(fraghdr) & PP_NTOHS(IP_MF)) == 0;
  if (is_last) {
    u16_t datagram_len = (u16_t)(offset + len);
    if ((datagram_len < offset) || (datagram_len > (0xFFFF - IP_HLEN))) {
      /* u16_t overflow, cannot handle this */
      goto nullreturn_ipr;
    }
  }]=]
        [=[  /* Structural span admission above is the single authority for
     MF/length/end/final-endpoint validity. */
  is_last = (IPH_OFFSET(fraghdr) & PP_NTOHS(IP_MF)) == 0;]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4_frag.c"
        [=[    if (IP_ADDRESSES_AND_ID_MATCH(&ipr->iphdr, fraghdr)) {]=]
        [=[    if (IP_ADDRESSES_AND_ID_MATCH(&ipr->iphdr, fraghdr) &&
        (ipr->input_netif_idx == input_netif_idx)) {]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4_frag.c"
        [=[    ipr = ip_reass_enqueue_new_datagram(fraghdr, clen);]=]
        [=[    ipr = ip_reass_enqueue_new_datagram(fraghdr, clen, input_netif_idx);]=])

    # An administrative purge must not put a packet on the wire.
    #
    # ip_reass_free_complete_datagram() sends ICMP Time Exceeded whenever the
    # datagram it drops contains fragment zero, which is right for a real
    # reassembly timeout and wrong for both of WaterWall's uses. The exact purge
    # below is a correctness barrier - it rejects a reassembly this node decided
    # not to complete, which is not something the peer timed out on - and the
    # netif-wide purge runs during teardown, where synthesizing a packet means
    # calling an output callback belonging to an interface that is being removed.
    #
    # So the notification becomes a parameter. lwIP's own timeout and
    # oldest-eviction paths pass 1 and keep their behaviour exactly.
    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4_frag.c"
        [=[static int
ip_reass_free_complete_datagram(struct ip_reassdata *ipr, struct ip_reassdata *prev)
{
  u16_t pbufs_freed = 0;
  u16_t clen;
  struct pbuf *p;
  struct ip_reass_helper *iprh;

  LWIP_ASSERT("prev != ipr", prev != ipr);
  if (prev != NULL) {
    LWIP_ASSERT("prev->next == ipr", prev->next == ipr);
  }

  MIB2_STATS_INC(mib2.ipreasmfails);
#if LWIP_ICMP
  iprh = (struct ip_reass_helper *)ipr->p->payload;
  if (iprh->start == 0) {]=]
        [=[static int
ip_reass_free_complete_datagram(struct ip_reassdata *ipr, struct ip_reassdata *prev)
{
  return ip_reass_free_complete_datagram_notify(ipr, prev, 1);
}

/* notify_timeout == 0 releases the datagram silently: no ICMP, no output
   callback. Used by WaterWall's administrative purges, which are barriers and
   teardown rather than anything the peer should hear about as a timeout. */
static int
ip_reass_free_complete_datagram_notify(struct ip_reassdata *ipr, struct ip_reassdata *prev, int notify_timeout)
{
  u16_t pbufs_freed = 0;
  u16_t clen;
  struct pbuf *p;
  struct ip_reass_helper *iprh;

  LWIP_ASSERT("prev != ipr", prev != ipr);
  if (prev != NULL) {
    LWIP_ASSERT("prev->next == ipr", prev->next == ipr);
  }

  MIB2_STATS_INC(mib2.ipreasmfails);
#if LWIP_ICMP
  iprh = (struct ip_reass_helper *)ipr->p->payload;
  if (notify_timeout && (iprh->start == 0)) {]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4_frag.c"
        [=[static int ip_reass_free_complete_datagram(struct ip_reassdata *ipr, struct ip_reassdata *prev);]=]
        [=[static int ip_reass_free_complete_datagram(struct ip_reassdata *ipr, struct ip_reassdata *prev);
static int ip_reass_free_complete_datagram_notify(struct ip_reassdata *ipr, struct ip_reassdata *prev,
                                                  int notify_timeout);]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4_frag.c"
        [=[  /* Then, unchain the struct ip_reassdata from the list and free it. */
  ip_reass_dequeue_datagram(ipr, prev);]=]
        [=[  /* Then, unchain the struct ip_reassdata from the list and free it. */
  LWIP_ASSERT("freed pbuf count matches datagram accounting", ipr->pbuf_count == pbufs_freed);
  ip_reass_dequeue_datagram(ipr, prev);]=])

    # WaterWall queues return fragments to an owner worker. A final FIFO barrier
    # uses these narrow helpers to remove any partial reassembly left by a
    # rejected/stale queued fragment before the outer association releases the
    # IPv4 identification. Netif teardown purges all entries before its index can
    # be reused.
    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4_frag.c"
        [=[void
ip_reass_tmr(void)
{
  struct ip_reassdata *r, *prev = NULL;

  r = reassdatagrams;
  while (r != NULL) {
    /* Decrement the timer. Once it reaches 0,
     * clean up the incomplete fragment assembly */
    if (r->timer > 0) {
      r->timer--;
      LWIP_DEBUGF(IP_REASS_DEBUG, ("ip_reass_tmr: timer dec %"U16_F"\n", (u16_t)r->timer));
      prev = r;
      r = r->next;
    } else {
      /* reassembly timed out */
      struct ip_reassdata *tmp;
      LWIP_DEBUGF(IP_REASS_DEBUG, ("ip_reass_tmr: timer timed out\n"));
      tmp = r;
      /* get the next pointer before freeing */
      r = r->next;
      /* free the helper struct and all enqueued pbufs */
      ip_reass_free_complete_datagram(tmp, prev);
    }
  }
}]=]
        [=[void
ip_reass_tmr(void)
{
  struct ip_reassdata *r, *prev = NULL;

  r = reassdatagrams;
  while (r != NULL) {
    /* Decrement the timer. Once it reaches 0,
     * clean up the incomplete fragment assembly */
    if (r->timer > 0) {
      r->timer--;
      LWIP_DEBUGF(IP_REASS_DEBUG, ("ip_reass_tmr: timer dec %"U16_F"\n", (u16_t)r->timer));
      prev = r;
      r = r->next;
    } else {
      /* reassembly timed out */
      struct ip_reassdata *tmp;
      LWIP_DEBUGF(IP_REASS_DEBUG, ("ip_reass_tmr: timer timed out\n"));
      tmp = r;
      /* get the next pointer before freeing */
      r = r->next;
      /* free the helper struct and all enqueued pbufs */
      ip_reass_free_complete_datagram(tmp, prev);
    }
  }
  ww_lwip_atomic_u32_increment_relaxed(&ip_reass_timer_epoch);
}

u32_t
ip4_reass_tmr_epoch(void)
{
  return (u32_t)ww_lwip_atomic_u32_load_relaxed(&ip_reass_timer_epoch);
}

u16_t
ip4_reass_purge(struct netif *inp, const ip4_addr_t *src, const ip4_addr_t *dest,
                u8_t proto, u16_t ident)
{
  const u8_t input_netif_idx = (inp != NULL) ? netif_get_index(inp) : NETIF_NO_INDEX;
  struct ip_reassdata *r = reassdatagrams;
  struct ip_reassdata *prev = NULL;

  while (r != NULL) {
    if ((r->input_netif_idx == input_netif_idx) &&
        ip4_addr_eq(&r->iphdr.src, src) && ip4_addr_eq(&r->iphdr.dest, dest) &&
        (IPH_PROTO(&r->iphdr) == proto) && (lwip_ntohs(IPH_ID(&r->iphdr)) == ident)) {
      /* Silent: this is a barrier rejecting a reassembly WaterWall chose not to
         complete, not a timeout the peer should be told about. */
      return (u16_t)ip_reass_free_complete_datagram_notify(r, prev, 0);
    }
    prev = r;
    r = r->next;
  }
  return 0;
}

u8_t
ip4_reass_has(struct netif *inp, const ip4_addr_t *src, const ip4_addr_t *dest,
              u8_t proto, u16_t ident)
{
  const u8_t input_netif_idx = (inp != NULL) ? netif_get_index(inp) : NETIF_NO_INDEX;
  const struct ip_reassdata *r;

  LWIP_ASSERT_CORE_LOCKED();

  for (r = reassdatagrams; r != NULL; r = r->next) {
    if ((r->input_netif_idx == input_netif_idx) &&
        ip4_addr_eq(&r->iphdr.src, src) && ip4_addr_eq(&r->iphdr.dest, dest) &&
        (IPH_PROTO(&r->iphdr) == proto) && (lwip_ntohs(IPH_ID(&r->iphdr)) == ident)) {
      return 1;
    }
  }
  return 0;
}

u16_t
ip4_reass_purge_netif(struct netif *inp)
{
  const u8_t input_netif_idx = (inp != NULL) ? netif_get_index(inp) : NETIF_NO_INDEX;
  struct ip_reassdata *r = reassdatagrams;
  struct ip_reassdata *prev = NULL;
  u16_t purged = 0;

  while (r != NULL) {
    if (r->input_netif_idx == input_netif_idx) {
      struct ip_reassdata *next = r->next;
      /* Silent: emitting here would call the output callback of the very netif
         being torn down. */
      purged = (u16_t)(purged + ip_reass_free_complete_datagram_notify(r, prev, 0));
      r = next;
    } else {
      prev = r;
      r = r->next;
    }
  }
  return purged;
}]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4.c"
        [=[    p = ip4_reass(p);]=]
        [=[    p = ip4_reass(p, inp);]=])

    # TCP requires its complete declared header to be contiguous in the first pbuf. IPv4
    # legally permits a first fragment with only the four tuple bytes, while
    # upstream reassembly preserves each fragment as one element of a pbuf
    # chain. Read the data offset from a bounded fixed prefix and pull up exactly
    # the declared 40..80-byte IP+TCP prefix. pbuf_coalesce() would copy the
    # complete datagram into one bounded heap class and would silently return the
    # still-short chain when that allocation was refused.
    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4.c"
        [=[/**
 * This function is called by the network interface device driver when]=]
        [=[/** Validate and make the complete IPv4 and TCP headers contiguous. */
static struct pbuf *
ww_ip4_reass_pullup_tcp_header(struct pbuf *p)
{
  u8_t fixed_headers[IP_HLEN + TCP_HLEN];
  u16_t tcp_header_len;
  u16_t prefix_len;
  struct pbuf *head;
  struct pbuf *tail;

  if ((p == NULL) || (p->tot_len < sizeof(fixed_headers)) ||
      (pbuf_copy_partial(p, fixed_headers, sizeof(fixed_headers), 0) != sizeof(fixed_headers))) {
    pbuf_free(p);
    IP_STATS_INC(ip.lenerr);
    IP_STATS_INC(ip.drop);
    MIB2_STATS_INC(mib2.ipindiscards);
    return NULL;
  }

  tcp_header_len = (u16_t)(((fixed_headers[IP_HLEN + 12] >> 4) & 0x0f) * 4);
  if ((tcp_header_len < TCP_HLEN) || (tcp_header_len > 60)) {
    pbuf_free(p);
    IP_STATS_INC(ip.lenerr);
    IP_STATS_INC(ip.drop);
    MIB2_STATS_INC(mib2.ipindiscards);
    return NULL;
  }
  prefix_len = (u16_t)(IP_HLEN + tcp_header_len);
  if (p->tot_len < prefix_len) {
    pbuf_free(p);
    IP_STATS_INC(ip.lenerr);
    IP_STATS_INC(ip.drop);
    MIB2_STATS_INC(mib2.ipindiscards);
    return NULL;
  }
  if (p->len >= prefix_len) {
    return p;
  }

  head = pbuf_alloc(PBUF_RAW, prefix_len, PBUF_RAM);
  if (head == NULL) {
    pbuf_free(p);
    IP_STATS_INC(ip.memerr);
    IP_STATS_INC(ip.drop);
    MIB2_STATS_INC(mib2.ipindiscards);
    return NULL;
  }
  if (pbuf_copy_partial(p, head->payload, prefix_len, 0) != prefix_len) {
    pbuf_free(head);
    pbuf_free(p);
    IP_STATS_INC(ip.err);
    IP_STATS_INC(ip.drop);
    MIB2_STATS_INC(mib2.ipindiscards);
    return NULL;
  }

  /* Mutate the original chain only after allocation and copying succeeded. */
  tail = pbuf_free_header(p, prefix_len);
  if (tail != NULL) {
    pbuf_cat(head, tail);
  }
  return head;
}

/**
 * This function is called by the network interface device driver when]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4.c"
        [=[    p = ip4_reass(p, inp);
    /* packet not fully reassembled yet? */
    if (p == NULL) {
      return ERR_OK;
    }
    iphdr = (const struct ip_hdr *)p->payload;]=]
        [=[    p = ip4_reass(p, inp);
    /* packet not fully reassembled yet? */
    if (p == NULL) {
      return ERR_OK;
    }
    if (IPH_PROTO((const struct ip_hdr *)p->payload) == IP_PROTO_TCP) {
      p = ww_ip4_reass_pullup_tcp_header(p);
      if (p == NULL) {
        return ERR_OK;
      }
    }
    iphdr = (const struct ip_hdr *)p->payload;]=])

    # Identity-aware netif teardown.
    #
    # Upstream cleans up after a removed netif by *address*: netif_remove() calls
    # netif_do_ip_addr_changed(), and tcp_netif_ip_addr_changed() aborts every pcb
    # whose local_ip matches. That is wrong in both directions for this process.
    #
    # Too much: ConnectionToPackets gives every event worker its own netif
    # carrying the same configured `source-ipv4`, and several CTP instances may
    # share one address; PacketsToConnection's per-worker route netifs all use
    # loopback. Stopping one of them therefore aborts live connections belonging
    # to another worker, another route, or another instance entirely.
    #
    # Too little: the address scan covers only the active and bound lists. A pcb
    # in TIME_WAIT survives netif removal holding a one-byte netif index that the
    # next netif_add() can hand straight back out, so it can match - and consume -
    # traffic belonging to whatever interface inherits that number.
    #
    # These helpers match the exact removed index instead, across every list. A
    # pcb that is genuinely unbound is left to the address path, which is what
    # upstream users of this stack still rely on.
    ww_lwip_replace_once(
        "${lwip_dir}/src/include/lwip/priv/tcp_priv.h"
        [=[void tcp_netif_ip_addr_changed(const ip_addr_t* old_addr, const ip_addr_t* new_addr);]=]
        [=[void tcp_netif_ip_addr_changed(const struct netif *netif, const ip_addr_t* old_addr, const ip_addr_t* new_addr);
int tcp_netif_can_remove(const struct netif *netif);
void tcp_netif_removed(const struct netif *netif);]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/include/lwip/udp.h"
        [=[void udp_netif_ip_addr_changed(const ip_addr_t* old_addr, const ip_addr_t* new_addr);]=]
        [=[void udp_netif_ip_addr_changed(const struct netif *netif, const ip_addr_t* old_addr, const ip_addr_t* new_addr);
int udp_netif_can_remove(const struct netif *netif);
void udp_netif_removed(const struct netif *netif);]=])

    # Ordinary address changes apply upstream semantics to unbound pcbs selected
    # by address. Exact pcbs additionally match the changed netif, old address,
    # and address family. Wildcard exact pcbs remain wildcard listeners/binds.
    ww_lwip_replace_once(
        "${lwip_dir}/src/core/tcp.c"
        [=[/** Helper function for tcp_netif_ip_addr_changed() that iterates a pcb list */
static void
tcp_netif_ip_addr_changed_pcblist(const ip_addr_t *old_addr, struct tcp_pcb *pcb_list)
{
  struct tcp_pcb *pcb;
  pcb = pcb_list;

  LWIP_ASSERT("tcp_netif_ip_addr_changed_pcblist: invalid old_addr", old_addr != NULL);

  while (pcb != NULL) {
    /* PCB bound to current local interface address? */
    if (ip_addr_eq(&pcb->local_ip, old_addr)
#if LWIP_AUTOIP
        /* connections to link-local addresses must persist (RFC3927 ch. 1.9) */
        && (!IP_IS_V4_VAL(pcb->local_ip) || !ip4_addr_islinklocal(ip_2_ip4(&pcb->local_ip)))
#endif /* LWIP_AUTOIP */
       ) {
      /* this connection must be aborted */
      struct tcp_pcb *next = pcb->next;
      LWIP_DEBUGF(NETIF_DEBUG | LWIP_DBG_STATE, ("netif_set_ipaddr: aborting TCP pcb %p\n", (void *)pcb));
      tcp_abort(pcb);
      pcb = next;
    } else {
      pcb = pcb->next;
    }
  }
}]=]
        [=[/** Does this pcb name the given netif as its one interface? */
static u32_t ww_tcp_reconcile_epoch;

static int
tcp_pcb_is_on_netif(const struct tcp_pcb *pcb, const struct netif *netif)
{
  const u8_t netif_idx = netif_get_index(netif);
  return (((pcb->netif_idx == netif_idx) && (pcb->netif_generation == netif->ww_generation)) ||
          ((pcb->pretend_netif_idx == netif_idx) &&
           (pcb->pretend_netif_generation == netif->ww_generation)));
}

static int
tcp_pcb_ip_addr_changed_matches(const struct netif *netif, const ip_addr_t *old_addr,
                                const struct tcp_pcb *pcb)
{
  const int exact = (pcb->netif_idx != NETIF_NO_INDEX) ||
                    (pcb->pretend_netif_idx != NETIF_NO_INDEX);

  if ((IP_GET_TYPE(&pcb->local_ip) != IP_GET_TYPE(old_addr)) || ip_addr_isany(&pcb->local_ip) ||
      !ip_addr_eq(&pcb->local_ip, old_addr)) {
    return 0;
  }
#if LWIP_AUTOIP
  if (IP_IS_V4_VAL(pcb->local_ip) && ip4_addr_islinklocal(ip_2_ip4(&pcb->local_ip))) {
    return 0;
  }
#endif /* LWIP_AUTOIP */
  return (exact == 0) || ((netif != NULL) && tcp_pcb_is_on_netif(pcb, netif));
}

static u32_t
tcp_netif_ip_addr_changed_mark(const struct netif *netif, const ip_addr_t *old_addr)
{
  struct tcp_pcb *pcb;
  struct tcp_pcb_listen *lpcb;
  u32_t epoch = ++ww_tcp_reconcile_epoch;

  if (epoch == 0) {
    epoch = ++ww_tcp_reconcile_epoch;
  }

  for (pcb = tcp_active_pcbs; pcb != NULL; pcb = pcb->next) {
    if (tcp_pcb_ip_addr_changed_matches(netif, old_addr, pcb)) {
      pcb->ww_reconcile_epoch = epoch;
    }
  }
  for (pcb = tcp_bound_pcbs; pcb != NULL; pcb = pcb->next) {
    if (tcp_pcb_ip_addr_changed_matches(netif, old_addr, pcb)) {
      pcb->ww_reconcile_epoch = epoch;
    }
  }
  for (lpcb = tcp_listen_pcbs.listen_pcbs; lpcb != NULL; lpcb = lpcb->next) {
    pcb = (struct tcp_pcb *)lpcb;
    if (tcp_pcb_ip_addr_changed_matches(netif, old_addr, pcb)) {
      pcb->ww_reconcile_epoch = epoch;
    }
  }
  return epoch;
}

/** Abort only candidates marked before the first callback ran. */
static void
tcp_netif_ip_addr_changed_abort_marked(u32_t epoch)
{
  struct tcp_pcb *pcb;

  for (;;) {
    for (pcb = tcp_active_pcbs; pcb != NULL; pcb = pcb->next) {
      if (pcb->ww_reconcile_epoch == epoch) {
        break;
      }
    }
    if (pcb == NULL) {
      for (pcb = tcp_bound_pcbs; pcb != NULL; pcb = pcb->next) {
        if (pcb->ww_reconcile_epoch == epoch) {
          break;
        }
      }
      if (pcb == NULL) {
        break;
      }
    }
    LWIP_DEBUGF(NETIF_DEBUG | LWIP_DBG_STATE, ("netif_set_ipaddr: aborting TCP pcb %p\n", (void *)pcb));
    tcp_abort(pcb);
    /* Never retain pcb->next across tcp_abort(): the error callback may free it. */
  }
}
]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/tcp.c"
        [=[/** This function is called from netif.c when address is changed or netif is removed
 *
 * @param old_addr IP address of the netif before change
 * @param new_addr IP address of the netif after change or NULL if netif has been removed
 */
void
tcp_netif_ip_addr_changed(const ip_addr_t *old_addr, const ip_addr_t *new_addr)]=]
        [=[/** Helper for tcp_netif_removed() that empties one pcb list.
 *
 * tcp_abort() removes the pcb from whichever list holds it - active, bound or
 * TIME_WAIT - and runs the application's error callback, which may touch the
 * same list, so each removal restarts the scan instead of caching a next
 * pointer. Every pass removes one entry, so this terminates.
 */
static void
tcp_netif_removed_pcblist(struct tcp_pcb **pcblist, const struct netif *netif)
{
  struct tcp_pcb *pcb = *pcblist;

  while (pcb != NULL) {
    if (tcp_pcb_is_on_netif(pcb, netif)) {
      tcp_abort(pcb);
      pcb = *pcblist;
    } else {
      pcb = pcb->next;
    }
  }
}

/** WaterWall: remove every pcb that named one exact netif, before its index can
 * be reused. Covers the active, bound and TIME_WAIT lists. Listener owners must
 * remove their raw pcbs first because lwIP has no invalidation callback for a
 * retained listener pointer.
 *
 * @param netif the netif being removed
 */
void
tcp_netif_removed(const struct netif *netif)
{
  u8_t netif_idx;

  LWIP_ASSERT_CORE_LOCKED();

  if (netif == NULL) {
    return;
  }
  netif_idx = netif_get_index(netif);
  if (netif_idx == NETIF_NO_INDEX) {
    return;
  }

  tcp_netif_removed_pcblist(&tcp_active_pcbs, netif);
  tcp_netif_removed_pcblist(&tcp_bound_pcbs, netif);
  /* TIME_WAIT sends no RST and runs no error callback; tcp_abort() dequeues and
     frees it, which is all this list needs. */
  tcp_netif_removed_pcblist(&tcp_tw_pcbs, netif);
}

int
tcp_netif_can_remove(const struct netif *netif)
{
  const struct tcp_pcb_listen *lpcb;

  LWIP_ASSERT_CORE_LOCKED();
  if (netif == NULL) {
    return 1;
  }
  for (lpcb = tcp_listen_pcbs.listen_pcbs; lpcb != NULL; lpcb = lpcb->next) {
    if (tcp_pcb_is_on_netif((const struct tcp_pcb *)lpcb, netif)) {
      return 0;
    }
  }
  return 1;
}

/** This function is called from netif.c when address is changed or netif is removed
 *
 * @param old_addr IP address of the netif before change
 * @param new_addr IP address of the netif after change or NULL if netif has been removed
 */
void
tcp_netif_ip_addr_changed(const struct netif *netif, const ip_addr_t *old_addr, const ip_addr_t *new_addr)]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/tcp.c"
        [=[    tcp_netif_ip_addr_changed_pcblist(old_addr, tcp_active_pcbs);
    tcp_netif_ip_addr_changed_pcblist(old_addr, tcp_bound_pcbs);]=]
        [=[    u32_t reconcile_epoch = tcp_netif_ip_addr_changed_mark(netif, old_addr);
    tcp_netif_ip_addr_changed_abort_marked(reconcile_epoch);]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/tcp.c"
        [=[        if (ip_addr_eq(&lpcb->local_ip, old_addr)) {]=]
        [=[        const struct tcp_pcb *pcb = (const struct tcp_pcb *)lpcb;
        const int exact = (pcb->netif_idx != NETIF_NO_INDEX) ||
                          (pcb->pretend_netif_idx != NETIF_NO_INDEX);
        if ((pcb->ww_reconcile_epoch == reconcile_epoch) &&
            (((exact != 0) && (netif != NULL) && tcp_pcb_is_on_netif(pcb, netif) &&
             (IP_GET_TYPE(&lpcb->local_ip) == IP_GET_TYPE(old_addr)) && !ip_addr_isany(&lpcb->local_ip) &&
             ip_addr_eq(&lpcb->local_ip, old_addr)) ||
            ((exact == 0) && (IP_GET_TYPE(&lpcb->local_ip) == IP_GET_TYPE(old_addr)) &&
             ip_addr_eq(&lpcb->local_ip, old_addr)))) {]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/tcp.c"
        [=[          ip_addr_copy(lpcb->local_ip, *new_addr);]=]
        [=[          ip_addr_copy(lpcb->local_ip, *new_addr);
          ((struct tcp_pcb *)lpcb)->ww_reconcile_epoch = 0;]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/udp.c"
        [=[/** This function is called from netif.c when address is changed
 *
 * @param old_addr IP address of the netif before change
 * @param new_addr IP address of the netif after change
 */
void udp_netif_ip_addr_changed(const ip_addr_t *old_addr, const ip_addr_t *new_addr)]=]
        [=[/** WaterWall: raw UDP owners must detach exact pcbs before netif removal.
 * lwIP has no callback that can invalidate an owner's retained udp_pcb pointer,
 * so silently freeing it here would turn correct later cleanup into a UAF.
 *
 * @param netif the netif being removed
 */
void
udp_netif_removed(const struct netif *netif)
{
  LWIP_ASSERT_CORE_LOCKED();
  LWIP_ASSERT("udp owner cleanup precondition", udp_netif_can_remove(netif));
}

int
udp_netif_can_remove(const struct netif *netif)
{
  const struct udp_pcb *pcb;
  u8_t netif_idx;

  LWIP_ASSERT_CORE_LOCKED();
  if (netif == NULL) {
    return 1;
  }
  netif_idx = netif_get_index(netif);
  for (pcb = udp_pcbs; pcb != NULL; pcb = pcb->next) {
    if (((pcb->netif_idx == netif_idx) && (pcb->netif_generation == netif->ww_generation)) ||
        ((pcb->pretend_netif_idx == netif_idx) &&
         (pcb->pretend_netif_generation == netif->ww_generation))) {
      return 0;
    }
  }
  return 1;
}

/** This function is called from netif.c when address is changed
 *
 * @param old_addr IP address of the netif before change
 * @param new_addr IP address of the netif after change
 */
void udp_netif_ip_addr_changed(const struct netif *netif, const ip_addr_t *old_addr, const ip_addr_t *new_addr)]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/udp.c"
        [=[      if (ip_addr_eq(&upcb->local_ip, old_addr)) {]=]
        [=[      const int exact = (upcb->netif_idx != NETIF_NO_INDEX) ||
                        (upcb->pretend_netif_idx != NETIF_NO_INDEX);
      if (((exact != 0) && (netif != NULL) &&
           (((upcb->netif_idx == netif_get_index(netif)) &&
             (upcb->netif_generation == netif->ww_generation)) ||
            ((upcb->pretend_netif_idx == netif_get_index(netif)) &&
             (upcb->pretend_netif_generation == netif->ww_generation))) &&
           (IP_GET_TYPE(&upcb->local_ip) == IP_GET_TYPE(old_addr)) && !ip_addr_isany(&upcb->local_ip) &&
           ip_addr_eq(&upcb->local_ip, old_addr)) ||
          ((exact == 0) && (IP_GET_TYPE(&upcb->local_ip) == IP_GET_TYPE(old_addr)) &&
           ip_addr_eq(&upcb->local_ip, old_addr))) {]=])

    # Mark a netif while its removal callbacks run. Raw API calls that could
    # publish a replacement PCB for that exact identity fail with ERR_IF until
    # the removal has either been rejected cleanly or completed.
    ww_lwip_replace_once(
        "${lwip_dir}/src/include/lwip/netif.h"
        [=[  /** flags (@see @ref netif_flags) */
  u8_t flags;]=]
        [=[  /** flags (@see @ref netif_flags) */
  u8_t flags;
  /** WaterWall: exact-PCB admission is closed while netif_remove callbacks run. */
  u8_t ww_removing;
  /** Exact binds are also closed while address-change callbacks reconcile PCBs. */
  u8_t ww_reconciling;
  /** Non-reusable identity for this successful netif_add lifetime; zero is invalid. */
  u32_t ww_generation;]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[  netif->flags = 0;]=]
        [=[  netif->flags = 0;
  netif->ww_removing = 0;
  netif->ww_reconciling = 0;
  netif->ww_generation = 0;]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[static u8_t netif_num;]=]
        [=[static u8_t netif_num;
static u32_t ww_netif_generation;
static u8_t ww_netif_add_in_progress;]=])

    # Reject identity exhaustion before netif_set_addr() or the caller's init
    # callback can mutate driver-owned state. A successful init receives its
    # generation later, immediately before publication.
    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[  LWIP_ERROR("netif_add: invalid netif", netif != NULL, return NULL);
  LWIP_ERROR("netif_add: No init function given", init != NULL, return NULL);]=]
        [=[  LWIP_ERROR("netif_add: invalid netif", netif != NULL, return NULL);
  LWIP_ERROR("netif_add: No init function given", init != NULL, return NULL);

#if !LWIP_SINGLE_NETIF
  {
    const struct netif *ww_capacity_cursor;
    u16_t ww_netif_count = 0;

    for (ww_capacity_cursor = netif_list; ww_capacity_cursor != NULL;
         ww_capacity_cursor = ww_capacity_cursor->next) {
      /* Re-adding an object that is already a list member is only caught later
         by an assertion inside the index search, which Release compiles out;
         the search then meets the same live object and can spin forever or
         corrupt the list. Reject it before one field of it is reset. */
      if (ww_capacity_cursor == netif) {
        return NULL;
      }
      ww_netif_count++;
    }
    if (ww_netif_count >= 255) {
      return NULL;
    }
  }
#endif /* !LWIP_SINGLE_NETIF */
  if (ww_netif_generation == 0xffffffffUL) {
    return NULL;
  }
  /* Capacity and generation are tested here but consumed only after init().
     A nested netif_add() from that driver callback would take the last index or
     the last generation behind this call's back: the outer index search would
     then never terminate, and the outer increment would wrap to the reserved
     value zero. lwIP defines no nested-add contract, so the reservation is a
     refusal rather than a second reserved slot. */
  if (ww_netif_add_in_progress != 0) {
    return NULL;
  }
  ww_netif_add_in_progress = 1;]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[  /* add this netif to the list */
  netif->next = netif_list;]=]
        [=[  netif->ww_generation = ++ww_netif_generation;

  /* add this netif to the list */
  netif->next = netif_list;]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[  /* call user specified initialization function for netif */
  if (init(netif) != ERR_OK) {
    return NULL;
  }]=]
        [=[  /* call user specified initialization function for netif */
  if (init(netif) != ERR_OK) {
    ww_netif_add_in_progress = 0;
    return NULL;
  }]=])

    # Published: the index and the generation are consumed, so a netif_add() from
    # the LWIP_NSC_NETIF_ADDED callback below is an ordinary outer add again.
    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[  mib2_netif_added(netif);]=]
        [=[  ww_netif_add_in_progress = 0;
  mib2_netif_added(netif);]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/include/lwip/ip.h"
        [=[  /* Bound netif index */                  \
  u8_t netif_idx;                          \
  /* Socket options */]=]
        [=[  /* Bound netif index and non-reusable add-lifetime identity */ \
  u8_t netif_idx;                          \
  u32_t netif_generation;                  \
  /* Socket options */]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/include/lwip/tcp.h"
        [=[void             tcp_bind_netif(struct tcp_pcb *pcb, const struct netif *netif);]=]
        [=[err_t            tcp_bind_netif(struct tcp_pcb *pcb, const struct netif *netif);]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/include/lwip/udp.h"
        [=[void             udp_bind_netif (struct udp_pcb *pcb, const struct netif* netif);]=]
        [=[err_t            udp_bind_netif (struct udp_pcb *pcb, const struct netif* netif);]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/udp.c"
        [=[#include "lwip/udp.h"]=]
        [=[#include "lwip/udp.h"

static int udp_pcb_netif_identity_invalid(const struct udp_pcb *pcb);]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/tcp.c"
        [=[err_t
tcp_bind(struct tcp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port)
{]=]
        [=[static int
tcp_pcb_netif_identity_invalid(const struct tcp_pcb *pcb)
{
  struct netif *netif;

  if (pcb->netif_idx != NETIF_NO_INDEX) {
    netif = netif_get_by_index(pcb->netif_idx);
    if ((netif == NULL) || (pcb->netif_generation == 0) ||
        (netif->ww_generation != pcb->netif_generation) ||
        (netif->ww_removing != 0) || (netif->ww_reconciling != 0)) {
      return 1;
    }
  } else if (pcb->netif_generation != 0) {
    return 1;
  }
  if (pcb->pretend_netif_idx != NETIF_NO_INDEX) {
    netif = netif_get_by_index(pcb->pretend_netif_idx);
    if ((netif == NULL) || (pcb->pretend_netif_generation == 0) ||
        (netif->ww_generation != pcb->pretend_netif_generation) ||
        (netif->ww_removing != 0) || (netif->ww_reconciling != 0)) {
      return 1;
    }
  } else if (pcb->pretend_netif_generation != 0) {
    return 1;
  }
  return 0;
}

err_t
tcp_bind(struct tcp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port)
{]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/tcp.c"
        [=[  LWIP_ERROR("tcp_bind: invalid pcb", pcb != NULL, return ERR_ARG);

  LWIP_ERROR("tcp_bind: can only bind in state CLOSED", pcb->state == CLOSED, return ERR_VAL);]=]
        [=[  /* WaterWall validates pcb state and exact identity before pretend binding. */]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/tcp.c"
        [=[void
tcp_bind_netif(struct tcp_pcb *pcb, const struct netif *netif)
{
  LWIP_ASSERT_CORE_LOCKED();
  if (netif != NULL) {
    pcb->netif_idx = netif_get_index(netif);
  } else {
    pcb->netif_idx = NETIF_NO_INDEX;
  }
}]=]
        [=[err_t
tcp_bind_netif(struct tcp_pcb *pcb, const struct netif *netif)
{
  LWIP_ASSERT_CORE_LOCKED();
  if (netif != NULL) {
    const u8_t netif_idx = netif_get_index(netif);
    if ((netif_idx == NETIF_NO_INDEX) || (netif_get_by_index(netif_idx) != netif) ||
        (netif->ww_generation == 0) || (netif->ww_removing != 0) || (netif->ww_reconciling != 0)) {
      return ERR_IF;
    }
    pcb->netif_idx = netif_idx;
    pcb->netif_generation = netif->ww_generation;
  } else {
    pcb->netif_idx = NETIF_NO_INDEX;
    pcb->netif_generation = 0;
  }
  return ERR_OK;
}]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/tcp.c"
        [=[  LWIP_ERROR("tcp_connect: can only connect from state CLOSED", pcb->state == CLOSED, return ERR_ISCONN);]=]
        [=[  LWIP_ERROR("tcp_connect: can only connect from state CLOSED", pcb->state == CLOSED, return ERR_ISCONN);
  if (tcp_pcb_netif_identity_invalid(pcb)) {
    return ERR_IF;
  }]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/tcp.c"
        [=[  LWIP_ERROR("tcp_listen_with_backlog_and_err: pcb already connected", pcb->state == CLOSED, res = ERR_CLSD; goto done);]=]
        [=[  LWIP_ERROR("tcp_listen_with_backlog_and_err: pcb already connected", pcb->state == CLOSED, res = ERR_CLSD; goto done);
  if (tcp_pcb_netif_identity_invalid(pcb)) {
    res = ERR_IF;
    goto done;
  }]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/udp.c"
        [=[err_t
udp_bind(struct udp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port)
{]=]
        [=[static int
udp_pcb_netif_identity_invalid(const struct udp_pcb *pcb)
{
  struct netif *netif;

  if (pcb->netif_idx != NETIF_NO_INDEX) {
    netif = netif_get_by_index(pcb->netif_idx);
    if ((netif == NULL) || (pcb->netif_generation == 0) ||
        (netif->ww_generation != pcb->netif_generation) ||
        (netif->ww_removing != 0) || (netif->ww_reconciling != 0)) {
      return 1;
    }
  } else if (pcb->netif_generation != 0) {
    return 1;
  }
  if (pcb->pretend_netif_idx != NETIF_NO_INDEX) {
    netif = netif_get_by_index(pcb->pretend_netif_idx);
    if ((netif == NULL) || (pcb->pretend_netif_generation == 0) ||
        (netif->ww_generation != pcb->pretend_netif_generation) ||
        (netif->ww_removing != 0) || (netif->ww_reconciling != 0)) {
      return 1;
    }
  } else if (pcb->pretend_netif_generation != 0) {
    return 1;
  }
  return 0;
}

err_t
udp_bind(struct udp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port)
{]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/udp.c"
        [=[  LWIP_ERROR("udp_bind: invalid pcb", pcb != NULL, return ERR_ARG);]=]
        [=[  /* WaterWall validates the pcb before pretend binding. */]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/udp.c"
        [=[void
udp_bind_netif(struct udp_pcb *pcb, const struct netif *netif)
{
  LWIP_ASSERT_CORE_LOCKED();

  if (netif != NULL) {
    pcb->netif_idx = netif_get_index(netif);
  } else {
    pcb->netif_idx = NETIF_NO_INDEX;
  }
}]=]
        [=[err_t
udp_bind_netif(struct udp_pcb *pcb, const struct netif *netif)
{
  LWIP_ASSERT_CORE_LOCKED();

  if (netif != NULL) {
    const u8_t netif_idx = netif_get_index(netif);
    if ((netif_idx == NETIF_NO_INDEX) || (netif_get_by_index(netif_idx) != netif) ||
        (netif->ww_generation == 0) || (netif->ww_removing != 0) || (netif->ww_reconciling != 0)) {
      return ERR_IF;
    }
    pcb->netif_idx = netif_idx;
    pcb->netif_generation = netif->ww_generation;
  } else {
    pcb->netif_idx = NETIF_NO_INDEX;
    pcb->netif_generation = 0;
  }
  return ERR_OK;
}]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/udp.c"
        [=[  LWIP_ERROR("udp_connect: invalid ipaddr", ipaddr != NULL, return ERR_ARG);]=]
        [=[  LWIP_ERROR("udp_connect: invalid ipaddr", ipaddr != NULL, return ERR_ARG);
  if (udp_pcb_netif_identity_invalid(pcb)) {
    return ERR_IF;
  }]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/udp.c"
        [=[  LWIP_ERROR("udp_sendto_if_src: invalid netif", netif != NULL, return ERR_ARG);]=]
        [=[  LWIP_ERROR("udp_sendto_if_src: invalid netif", netif != NULL, return ERR_ARG);
  if (udp_pcb_netif_identity_invalid(pcb)) {
    return ERR_IF;
  }
  if ((pcb->netif_idx != NETIF_NO_INDEX) &&
      ((pcb->netif_idx != netif_get_index(netif)) ||
       (pcb->netif_generation != netif->ww_generation))) {
    return ERR_IF;
  }]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/udp.c"
        [=[  pcb->remote_port = 0;
  pcb->netif_idx = NETIF_NO_INDEX;
  /* mark PCB as unconnected */]=]
        [=[  pcb->remote_port = 0;
  pcb->netif_idx = NETIF_NO_INDEX;
  pcb->netif_generation = 0;
  pcb->pretend_netif_idx = NETIF_NO_INDEX;
  pcb->pretend_netif_generation = 0;
  /* mark PCB as unconnected */]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[static void
netif_do_ip_addr_changed(const ip_addr_t *old_addr, const ip_addr_t *new_addr)
{
#if LWIP_TCP
  tcp_netif_ip_addr_changed(old_addr, new_addr);
#endif /* LWIP_TCP */
#if LWIP_UDP
  udp_netif_ip_addr_changed(old_addr, new_addr);
#endif /* LWIP_UDP */]=]
        [=[static void
netif_do_ip_addr_changed(struct netif *netif, const ip_addr_t *old_addr, const ip_addr_t *new_addr)
{
  if (netif != NULL) {
    if (netif->ww_reconciling != 0) {
      return;
    }
    netif->ww_reconciling = 1;
  }
#if LWIP_TCP
  tcp_netif_ip_addr_changed(netif, old_addr, new_addr);
#endif /* LWIP_TCP */
#if LWIP_UDP
  udp_netif_ip_addr_changed(netif, old_addr, new_addr);
#endif /* LWIP_UDP */
]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[#if LWIP_RAW
  raw_netif_ip_addr_changed(old_addr, new_addr);
#endif /* LWIP_RAW */]=]
        [=[#if LWIP_RAW
  raw_netif_ip_addr_changed(old_addr, new_addr);
#endif /* LWIP_RAW */
  if (netif != NULL) {
    netif->ww_reconciling = 0;
  }]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[  /* address is actually being changed? */
  if (ip4_addr_eq(ipaddr, netif_ip4_addr(netif)) == 0) {]=]
        [=[  /* A callback may not recursively mutate this netif's address. */
  if (netif->ww_reconciling != 0) {
    return 0;
  }

  /* address is actually being changed? */
  if (ip4_addr_eq(ipaddr, netif_ip4_addr(netif)) == 0) {]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[  LWIP_ASSERT("invalid index", addr_idx < LWIP_IPV6_NUM_ADDRESSES);

  ip6_addr_copy(*ip_2_ip6(&old_addr), *netif_ip6_addr(netif, addr_idx));]=]
        [=[  LWIP_ASSERT("invalid index", addr_idx < LWIP_IPV6_NUM_ADDRESSES);

  if (netif->ww_reconciling != 0) {
    return;
  }

  ip6_addr_copy(*ip_2_ip6(&old_addr), *netif_ip6_addr(netif, addr_idx));]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[  old_state = netif_ip6_addr_state(netif, addr_idx);]=]
        [=[  if (netif->ww_reconciling != 0) {
    return;
  }

  old_state = netif_ip6_addr_state(netif, addr_idx);]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[    netif_do_ip_addr_changed(old_addr, &new_addr);]=]
        [=[    netif_do_ip_addr_changed(netif, old_addr, &new_addr);]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[      netif_do_ip_addr_changed(netif_ip_addr6(netif, addr_idx), &new_ipaddr);]=]
        [=[      netif_do_ip_addr_changed(netif, netif_ip_addr6(netif, addr_idx), &new_ipaddr);]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[      netif_do_ip_addr_changed(netif_ip_addr6(netif, addr_idx), NULL);]=]
        [=[      netif_do_ip_addr_changed(netif, netif_ip_addr6(netif, addr_idx), NULL);]=])

    # Removal preflights raw owners before invoking callbacks or mutating any
    # list, then clears exact active/bound/TIME_WAIT identity before the ordinary
    # address-change scan sees the remaining unbound pcbs.
    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[#include "lwip/priv/raw_priv.h"]=]
        [=[#include "lwip/priv/raw_priv.h"
#include "lwip/ip4_frag.h"]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[  if (netif == NULL) {
    return;
  }

  netif_invoke_ext_callback(netif, LWIP_NSC_NETIF_REMOVED, NULL);]=]
        [=[  if (netif == NULL) {
    return;
  }

  /* Recursive removal is a rejected inner operation. The outer owner keeps
     the flag through its one callback/removal sequence. */
  if (netif->ww_removing != 0) {
    return;
  }
  {
    struct netif *ww_cursor;
    int ww_member = 0;
    NETIF_FOREACH(ww_cursor) {
      if (ww_cursor == netif) {
        ww_member = 1;
        break;
      }
    }
    if (!ww_member) {
      return;
    }
  }

  netif_invoke_ext_callback(netif, LWIP_NSC_NETIF_REMOVED, NULL);]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[  netif_invoke_ext_callback(netif, LWIP_NSC_NETIF_REMOVED, NULL);

#if LWIP_IPV4
  if (!ip4_addr_isany_val(*netif_ip4_addr(netif))) {
    netif_do_ip_addr_changed(netif_ip_addr4(netif), NULL);
  }]=]
        [=[#if LWIP_TCP
  if (!tcp_netif_can_remove(netif)) {
    LWIP_PLATFORM_ASSERT("netif_remove requires listener owner cleanup");
    return;
  }
#endif /* LWIP_TCP */
#if LWIP_UDP
  if (!udp_netif_can_remove(netif)) {
    LWIP_PLATFORM_ASSERT("netif_remove requires UDP owner cleanup");
    return;
  }
#endif /* LWIP_UDP */

  /* WaterWall removal admission barrier: callbacks cannot replace exact PCBs. */
  netif->ww_removing = 1;
  netif_invoke_ext_callback(netif, LWIP_NSC_NETIF_REMOVED, NULL);

#if LWIP_TCP
  if (!tcp_netif_can_remove(netif)) {
    LWIP_PLATFORM_ASSERT("netif_remove callback created an exact TCP listener");
    goto ww_remove_rejected;
  }
#endif /* LWIP_TCP */
#if LWIP_UDP
  if (!udp_netif_can_remove(netif)) {
    LWIP_PLATFORM_ASSERT("netif_remove callback created an exact UDP pcb");
    goto ww_remove_rejected;
  }
#endif /* LWIP_UDP */

#if LWIP_TCP
  tcp_netif_removed(netif);
#endif /* LWIP_TCP */
#if LWIP_UDP
  udp_netif_removed(netif);
#endif /* LWIP_UDP */
#if LWIP_IPV4 && IP_REASSEMBLY
  /* Reassembly state is keyed by the one-byte netif index, which the next
     netif_add() may hand straight back out. Purging here rather than leaving it
     to each caller makes that a property of removal instead of a convention. */
  ip4_reass_purge_netif(netif);
#endif /* LWIP_IPV4 && IP_REASSEMBLY */

#if LWIP_IPV4
  if (!ip4_addr_isany_val(*netif_ip4_addr(netif))) {
      netif_do_ip_addr_changed(netif, netif_ip_addr4(netif), NULL);
  }]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[  LWIP_DEBUGF( NETIF_DEBUG, ("netif_remove: removed netif\n") );]=]
        [=[  /* The ordinary removal callback is the final object access: it may
     free an owner allocation that embeds this netif. netif_add() resets the
     guard before publishing a deliberately reused object. */
  LWIP_DEBUGF( NETIF_DEBUG, ("netif_remove: removed netif\n") );
  return;

ww_remove_rejected:
  netif->ww_removing = 0;]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[    if (tmp_netif == NULL) {
      return; /* netif is not on the list */
    }]=]
        [=[    if (tmp_netif == NULL) {
      goto ww_remove_rejected; /* defensive: membership was checked above */
    }]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[      netif_do_ip_addr_changed(netif_ip_addr6(netif, i), NULL);]=]
        [=[      netif_do_ip_addr_changed(netif, netif_ip_addr6(netif, i), NULL);]=])

    # ip4_frag() discards netif->output()'s result: it counts every fragment as
    # transmitted, keeps emitting the rest of the datagram, and returns ERR_OK.
    #
    # For an ordinary driver that is nearly harmless. For WaterWall it is not -
    # ConnectionToPackets' output callback fails when it cannot allocate an
    # emission message or the owner worker's queue refuses one, and udp_send()
    # then reports success for a datagram the peer will never be able to
    # reassemble. Capturing the result stops the pointless work after the first
    # failure and makes the partial loss visible to the caller that logs it.
    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4_frag.c"
        [=[  int last;
  u16_t poff = IP_HLEN;]=]
        [=[  int last;
  err_t out_err = ERR_OK;
  u16_t poff = IP_HLEN;]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4_frag.c"
        [=[    netif->output(netif, rambuf, dest);
    IPFRAG_STATS_INC(ip_frag.xmit);]=]
        [=[    out_err = netif->output(netif, rambuf, dest);
    if (out_err != ERR_OK) {
      /* Earlier fragments cannot be retracted, but the rest of this datagram is
         now guaranteed useless: stop, and report the failure upward. */
      IPFRAG_STATS_INC(ip_frag.err);
      pbuf_free(rambuf);
      MIB2_STATS_INC(mib2.ipfragfails);
      return out_err;
    }
    IPFRAG_STATS_INC(ip_frag.xmit);]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/include/lwip/netif.h"
        [=[#define NETIF_FLAG_MLD6         0x40U

/**
 * @}
 */]=]
        [=[#define NETIF_FLAG_MLD6         0x40U
/** If set, the netif accepts TCP/UDP packets for arbitrary destination hosts.
 * This is used by tun2socks-style gateways to preserve the original destination. */
#define NETIF_FLAG_PRETEND      0x80U
#define NETIF_FLAG_PRETEND_TCP  NETIF_FLAG_PRETEND
#define NETIF_FLAG_PRETEND_UDP  NETIF_FLAG_PRETEND

/**
 * @}
 */]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/include/lwip/tcp.h"
        [=[  TCP_PCB_EXTARGS \
  enum tcp_state state; /* TCP state */ \
  u8_t prio; \
  /* ports are in host byte order */ \
  u16_t local_port]=]
        [=[  TCP_PCB_EXTARGS \
  enum tcp_state state; /* TCP state */ \
  u8_t prio; \
  u8_t pretend_netif_idx; \
  u32_t pretend_netif_generation; \
  u32_t ww_reconcile_epoch; \
  /* ports are in host byte order */ \
  u16_t local_port]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/include/lwip/udp.h"
        [=[  struct udp_pcb *next;

  u8_t flags;
  /** ports are in host byte order */
  u16_t local_port, remote_port;]=]
        [=[  struct udp_pcb *next;

  u8_t flags;
  u8_t pretend_netif_idx;
  u32_t pretend_netif_generation;
  /** ports are in host byte order */
  u16_t local_port, remote_port;]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/include/lwip/udp.h"
        [=[err_t            udp_sendto_if_src(struct udp_pcb *pcb, struct pbuf *p,
                                 const ip_addr_t *dst_ip, u16_t dst_port,
                                 struct netif *netif, const ip_addr_t *src_ip);
err_t            udp_sendto     (struct udp_pcb *pcb, struct pbuf *p,]=]
        [=[err_t            udp_sendto_if_src(struct udp_pcb *pcb, struct pbuf *p,
                                 const ip_addr_t *dst_ip, u16_t dst_port,
                                 struct netif *netif, const ip_addr_t *src_ip);
err_t            udp_sendfrom   (struct udp_pcb *pcb, struct pbuf *p,
                                 const ip_addr_t *src_ip, u16_t src_port);
err_t            udp_sendto     (struct udp_pcb *pcb, struct pbuf *p,]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4.c"
        [=[ip4_input_accept(struct netif *netif)]=]
        [=[ip4_input_accept(struct netif *netif, const struct ip_hdr *iphdr)]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4.c"
        [=[#endif /* LWIP_NETIF_LOOPBACK && !LWIP_HAVE_LOOPIF */
       ) {]=]
        [=[#endif /* LWIP_NETIF_LOOPBACK && !LWIP_HAVE_LOOPIF */
        || (netif_is_flag_set(netif, NETIF_FLAG_PRETEND) &&
            ((IPH_PROTO(iphdr) == IP_PROTO_TCP) || (IPH_PROTO(iphdr) == IP_PROTO_UDP)))
       ) {]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4.c"
        [=[if (ip4_input_accept(inp)) {]=]
        [=[if (ip4_input_accept(inp, iphdr)) {]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv4/ip4.c"
        [=[          if (ip4_input_accept(netif)) {]=]
        [=[          if (ip4_input_accept(netif, iphdr)) {]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv6/ip6.c"
        [=[ip6_input_accept(struct netif *netif)]=]
        [=[ip6_input_accept(struct netif *netif, const struct ip6_hdr *ip6hdr)]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv6/ip6.c"
        [=[  if (netif_is_up(netif)) {
    u8_t i;]=]
        [=[  if (netif_is_up(netif)) {
    u8_t i;
    if (netif_is_flag_set(netif, NETIF_FLAG_PRETEND) &&
        ((IP6H_NEXTH(ip6hdr) == IP6_NEXTH_TCP) || (IP6H_NEXTH(ip6hdr) == IP6_NEXTH_UDP))) {
      return 1;
    }]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv6/ip6.c"
        [=[if (ip6_input_accept(inp)) {]=]
        [=[if (ip6_input_accept(inp, ip6hdr)) {]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/ipv6/ip6.c"
        [=[        if (ip6_input_accept(netif)) {]=]
        [=[        if (ip6_input_accept(netif, ip6hdr)) {]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/tcp.c"
        [=[      if (pcb->local_port != 0) {
        TCP_RMV(&tcp_bound_pcbs, pcb);
      }
      tcp_free(pcb);]=]
        [=[      if ((pcb->local_port != 0) || (pcb->pretend_netif_idx != NETIF_NO_INDEX)) {
        TCP_RMV(&tcp_bound_pcbs, pcb);
      }
      tcp_free(pcb);]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/tcp.c"
        [=[    if (pcb->state == CLOSED) {
      if (pcb->local_port != 0) {
        /* bound, not yet opened */
        TCP_RMV(&tcp_bound_pcbs, pcb);
      }]=]
        [=[    if (pcb->state == CLOSED) {
      if ((pcb->local_port != 0) || (pcb->pretend_netif_idx != NETIF_NO_INDEX)) {
        /* bound, not yet opened */
        TCP_RMV(&tcp_bound_pcbs, pcb);
      }]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/tcp.c"
        [=[  struct tcp_pcb *cpcb;
#if LWIP_IPV6 && LWIP_IPV6_SCOPES]=]
        [=[  struct tcp_pcb *cpcb;
  struct netif *netif;
#if LWIP_IPV6 && LWIP_IPV6_SCOPES]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/tcp.c"
        [=[  LWIP_ASSERT_CORE_LOCKED();

#if LWIP_IPV4]=]
        [=[  LWIP_ASSERT_CORE_LOCKED();

  LWIP_ERROR("tcp_bind: invalid pcb", pcb != NULL, return ERR_ARG);
  LWIP_ERROR("tcp_bind: can only bind in state CLOSED", pcb->state == CLOSED, return ERR_VAL);
  if (tcp_pcb_netif_identity_invalid(pcb)) {
    return ERR_IF;
  }

  if ((ipaddr == NULL) && (port == 0) && (pcb->netif_idx != NETIF_NO_INDEX)) {
    /* Check if the pretend binding is already in use. */
    for (i = 0; i < NUM_TCP_PCB_LISTS; i++) {
      for (cpcb = *tcp_pcb_lists[i]; cpcb; cpcb = cpcb->next) {
        if ((cpcb->pretend_netif_idx == pcb->netif_idx) &&
            (cpcb->pretend_netif_generation == pcb->netif_generation)) {
          return ERR_USE;
        }
      }
    }

    netif = netif_get_by_index(pcb->netif_idx);
    if (netif_is_flag_set(netif, NETIF_FLAG_PRETEND_TCP)) {
      pcb->pretend_netif_idx = pcb->netif_idx;
      pcb->pretend_netif_generation = pcb->netif_generation;
      goto done;
    }
  }

#if LWIP_IPV4]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/tcp.c"
        [=[  pcb->local_port = port;
  TCP_REG(&tcp_bound_pcbs, pcb);]=]
        [=[done:
  pcb->local_port = port;
  TCP_REG(&tcp_bound_pcbs, pcb);]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/tcp.c"
        [=[  lpcb->netif_idx = pcb->netif_idx;
  lpcb->ttl = pcb->ttl;]=]
        [=[  lpcb->netif_idx = pcb->netif_idx;
  lpcb->netif_generation = pcb->netif_generation;
  lpcb->pretend_netif_idx = pcb->pretend_netif_idx;
  lpcb->pretend_netif_generation = pcb->pretend_netif_generation;
  lpcb->ttl = pcb->ttl;]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/tcp.c"
        [=[  if (pcb->local_port != 0) {
    TCP_RMV(&tcp_bound_pcbs, pcb);
  }]=]
        [=[  if ((pcb->local_port != 0) || (pcb->pretend_netif_idx != NETIF_NO_INDEX)) {
    TCP_RMV(&tcp_bound_pcbs, pcb);
  }]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/tcp_in.c"
        [=[      if (lpcb->local_port == tcphdr->dest) {]=]
        [=[      if ((lpcb->pretend_netif_idx != NETIF_NO_INDEX) &&
          (lpcb->pretend_netif_idx == netif_get_index(inp)) &&
          (lpcb->pretend_netif_generation == inp->ww_generation)) {
        if (IP_ADDR_PCB_VERSION_MATCH(lpcb, ip_current_dest_addr())) {
          break;
        }
      } else if (lpcb->local_port == tcphdr->dest) {]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/tcp_in.c"
        [=[    npcb->local_port = pcb->local_port;]=]
        [=[    npcb->local_port = tcphdr->dest;]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/tcp_in.c"
        [=[    npcb->netif_idx = pcb->netif_idx;]=]
        [=[    npcb->netif_idx = pcb->netif_idx;
    npcb->netif_generation = pcb->netif_generation;
    npcb->pretend_netif_idx = pcb->pretend_netif_idx;
    npcb->pretend_netif_generation = pcb->pretend_netif_generation;]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/udp.c"
        [=[  pcb = NULL;
  prev = NULL;
  uncon_pcb = NULL;]=]
        [=[again:
  pcb = NULL;
  prev = NULL;
  uncon_pcb = NULL;]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/udp.c"
        [=[    /* compare PCB local addr+port to UDP destination addr+port */]=]
        [=[    if ((pcb->pretend_netif_idx != NETIF_NO_INDEX) &&
        (pcb->pretend_netif_idx == netif_get_index(inp)) &&
        (pcb->pretend_netif_generation == inp->ww_generation)) {
      if (((pcb->flags & UDP_FLAGS_CONNECTED) != 0) &&
          (pcb->remote_port == src) &&
          ip_addr_cmp(&pcb->remote_ip, ip_current_src_addr()) &&
          (pcb->local_port == dest) &&
          ip_addr_cmp(&pcb->local_ip, ip_current_dest_addr())) {
        break;
      }
      /* The wildcard pretend listener is selected only by the listener scan
       * below, which retains p while it creates a child and redispatches it. */
      prev = pcb;
      continue;
    }

    /* compare PCB local addr+port to UDP destination addr+port */]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/udp.c"
        [=[                if (q != NULL) {]=]
        [=[                if ((q != NULL) && (pcb->pretend_netif_idx == NETIF_NO_INDEX)) {]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/udp.c"
        [=[        pcb->recv(pcb->recv_arg, pcb, p, ip_current_src_addr(), src);]=]
        [=[        if (pcb->pretend_netif_idx != NETIF_NO_INDEX) {
          ip_addr_set_ipaddr(&pcb->local_ip, ip_current_dest_addr());
          pcb->local_port = dest;
        }
        pcb->recv(pcb->recv_arg, pcb, p, ip_current_src_addr(), src);]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/udp.c"
        [=[  } else {
    pbuf_free(p);
  }
end:]=]
        [=[  } else {
    for (pcb = udp_pcbs; pcb != NULL; pcb = pcb->next) {
      if ((pcb->pretend_netif_idx != NETIF_NO_INDEX) &&
          (pcb->pretend_netif_idx == netif_get_index(inp)) &&
          (pcb->pretend_netif_generation == inp->ww_generation) &&
          ((pcb->flags & UDP_FLAGS_CONNECTED) == 0) &&
          (pcb->recv != NULL) &&
          IP_ADDR_PCB_VERSION_MATCH(pcb, ip_current_dest_addr())) {
        struct udp_pcb *npcb = udp_new_ip_type(pcb->local_ip.type);
        if (npcb != NULL) {
          ip_addr_set_ipaddr(&npcb->local_ip, ip_current_dest_addr());
          ip_addr_set_ipaddr(&npcb->remote_ip, ip_current_src_addr());
          npcb->local_port = dest;
          npcb->remote_port = src;
          npcb->flags |= UDP_FLAGS_CONNECTED;
          npcb->netif_idx = pcb->netif_idx;
          npcb->netif_generation = pcb->netif_generation;
          npcb->pretend_netif_idx = pcb->pretend_netif_idx;
          npcb->pretend_netif_generation = pcb->pretend_netif_generation;
          npcb->next = udp_pcbs;
          udp_pcbs = npcb;
          pcb->recv(pcb->recv_arg, npcb, p, ip_current_dest_addr(), dest);
          goto again;
        }
        break;
      }
    }

    pbuf_free(p);
  }
end:]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/udp.c"
        [=[#endif /* LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_UDP */

/**
 * @ingroup udp_raw
 * Send data to a specified address using UDP.]=]
        [=[#endif /* LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_UDP */

/**
 * @ingroup udp_raw
 * Send data from a specified address using UDP.
 */
err_t
udp_sendfrom(struct udp_pcb *pcb, struct pbuf *p,
             const ip_addr_t *src_ip, u16_t src_port)
{
  err_t err;
  ip_addr_t addr;
  u16_t port;

  ip_addr_set_ipaddr(&addr, &pcb->local_ip);
  port = pcb->local_port;

  ip_addr_set_ipaddr(&pcb->local_ip, src_ip);
  pcb->local_port = src_port;

  err = udp_send(pcb, p);

  ip_addr_set_ipaddr(&pcb->local_ip, &addr);
  pcb->local_port = port;

  return err;
}

/**
 * @ingroup udp_raw
 * Send data to a specified address using UDP.]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/udp.c"
        [=[      if (netif_get_ip6_addr_match(netif, ip_2_ip6(&pcb->local_ip)) < 0) {]=]
        [=[      if (!netif_is_flag_set(netif, NETIF_FLAG_PRETEND_UDP) &&
          netif_get_ip6_addr_match(netif, ip_2_ip6(&pcb->local_ip)) < 0) {]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/udp.c"
        [=[      if (!ip4_addr_eq(ip_2_ip4(&(pcb->local_ip)), netif_ip4_addr(netif))) {]=]
        [=[      if (!netif_is_flag_set(netif, NETIF_FLAG_PRETEND_UDP) &&
          !ip4_addr_eq(ip_2_ip4(&(pcb->local_ip)), netif_ip4_addr(netif))) {]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/udp.c"
        [=[  struct udp_pcb *ipcb;
  u8_t rebind;]=]
        [=[  struct udp_pcb *ipcb;
  struct netif *netif;
  u8_t rebind = 0;]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/udp.c"
        [=[  LWIP_ASSERT_CORE_LOCKED();

#if LWIP_IPV4]=]
        [=[  LWIP_ASSERT_CORE_LOCKED();

  LWIP_ERROR("udp_bind: invalid pcb", pcb != NULL, return ERR_ARG);

  if (udp_pcb_netif_identity_invalid(pcb)) {
    return ERR_IF;
  }

  if ((ipaddr == NULL) && (port == 0) && (pcb->netif_idx != NETIF_NO_INDEX)) {
    for (ipcb = udp_pcbs; ipcb != NULL; ipcb = ipcb->next) {
      if ((ipcb->pretend_netif_idx == pcb->netif_idx) &&
          (ipcb->pretend_netif_generation == pcb->netif_generation)) {
        return ERR_USE;
      }
    }

    netif = netif_get_by_index(pcb->netif_idx);
    if (netif_is_flag_set(netif, NETIF_FLAG_PRETEND_UDP)) {
      pcb->pretend_netif_idx = pcb->netif_idx;
      pcb->pretend_netif_generation = pcb->netif_generation;
      goto done;
    }
  }

#if LWIP_IPV4]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/udp.c"
        [=[  rebind = 0;
  /* Check for double bind and rebind of the same pcb */]=]
        [=[  /* Check for double bind and rebind of the same pcb */]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/udp.c"
        [=[  pcb->local_port = port;
  mib2_udp_bind(pcb);]=]
        [=[done:
  pcb->local_port = port;
  mib2_udp_bind(pcb);]=])

    # Upstream lwIP 2.2 has no threaded shutdown API. WaterWall must stop and
    # join tcpip_thread before destroying the pseudo-worker pools that its
    # callbacks can still reach.
    ww_lwip_replace_once(
        "${lwip_dir}/src/include/lwip/tcpip.h"
        [=[void   tcpip_init(tcpip_init_done_fn tcpip_init_done, void *arg);

err_t  tcpip_inpkt]=]
        [=[void   tcpip_init(tcpip_init_done_fn tcpip_init_done, void *arg);
err_t  tcpip_shutdown(tcpip_callback_fn shutdown_fn, void *ctx);

err_t  tcpip_inpkt]=])

    # Propagate exact-netif admission failures through every public generated
    # caller instead of reporting a bind that did not occur.
    ww_lwip_replace_once(
        "${lwip_dir}/src/api/sockets.c"
        [=[            case NETCONN_TCP:
              tcp_bind_netif(sock->conn->pcb.tcp, n);
              break;]=]
        [=[            case NETCONN_TCP:
              if (tcp_bind_netif(sock->conn->pcb.tcp, n) != ERR_OK) {
                done_socket(sock);
                return ENODEV;
              }
              break;]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/api/sockets.c"
        [=[            case NETCONN_UDP:
              udp_bind_netif(sock->conn->pcb.udp, n);
              break;]=]
        [=[            case NETCONN_UDP:
              if (udp_bind_netif(sock->conn->pcb.udp, n) != ERR_OK) {
                done_socket(sock);
                return ENODEV;
              }
              break;]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/api/api_msg.c"
        [=[      case NETCONN_UDP:
        udp_bind_netif(msg->conn->pcb.udp, netif);
        break;]=]
        [=[      case NETCONN_UDP:
        err = udp_bind_netif(msg->conn->pcb.udp, netif);
        break;]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/api/api_msg.c"
        [=[      case NETCONN_TCP:
        tcp_bind_netif(msg->conn->pcb.tcp, netif);
        break;]=]
        [=[      case NETCONN_TCP:
        err = tcp_bind_netif(msg->conn->pcb.tcp, netif);
        break;]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/netif/zepif.c"
        [=[  if (state->init.zep_netif != NULL) {
    udp_bind_netif(state->pcb, state->init.zep_netif);
  }]=]
        [=[  if (state->init.zep_netif != NULL) {
    err = udp_bind_netif(state->pcb, state->init.zep_netif);
    if (err != ERR_OK) {
      goto err_ret;
    }
  }]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/api/tcpip.c"
        [=[static void *tcpip_init_done_arg;
static sys_mbox_t tcpip_mbox;]=]
        [=[static void *tcpip_init_done_arg;
static sys_mbox_t tcpip_mbox;
static sys_thread_t tcpip_thread_handle;
static u8_t tcpip_shutdown_requested;
static u8_t tcpip_shutdown_posted;
static tcpip_callback_fn tcpip_shutdown_fn;
static void *tcpip_shutdown_ctx;]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/api/tcpip.c"
        [=[    tcpip_thread_handle_msg(msg);
  }
}]=]
        [=[    tcpip_thread_handle_msg(msg);
    if (tcpip_shutdown_requested) {
      break;
    }
  }
  UNLOCK_TCPIP_CORE();
}]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/api/tcpip.c"
        [=[  sys_thread_new(TCPIP_THREAD_NAME, tcpip_thread, NULL, TCPIP_THREAD_STACKSIZE, TCPIP_THREAD_PRIO);
}

/**
 * Simple callback function used with tcpip_callback to free a pbuf]=]
        [=[  tcpip_shutdown_requested = 0;
  tcpip_shutdown_posted = 0;
  tcpip_shutdown_fn = NULL;
  tcpip_shutdown_ctx = NULL;
  tcpip_thread_handle =
    sys_thread_new(TCPIP_THREAD_NAME, tcpip_thread, NULL, TCPIP_THREAD_STACKSIZE, TCPIP_THREAD_PRIO);
}

static void
tcpip_request_shutdown(void *ctx)
{
  LWIP_UNUSED_ARG(ctx);
  if (tcpip_shutdown_fn != NULL) {
    tcpip_shutdown_fn(tcpip_shutdown_ctx);
  }
  tcpip_shutdown_requested = 1;
}

/**
 * Cooperatively stop and join tcpip_thread after all application users have
 * detached and released their protocol state.
 */
err_t
tcpip_shutdown(tcpip_callback_fn shutdown_fn, void *ctx)
{
  err_t err;

  if (tcpip_thread_handle == NULL) {
    return ERR_OK;
  }

  if (!tcpip_shutdown_posted) {
    tcpip_shutdown_fn = shutdown_fn;
    tcpip_shutdown_ctx = ctx;
    err = tcpip_callback(tcpip_request_shutdown, NULL);
    if (err != ERR_OK) {
      tcpip_shutdown_fn = NULL;
      tcpip_shutdown_ctx = NULL;
      return err;
    }
    tcpip_shutdown_posted = 1;
  }
  if (!sys_thread_join(tcpip_thread_handle)) {
    return ERR_IF;
  }

  tcpip_thread_handle = NULL;
  tcpip_shutdown_posted = 0;
  tcpip_shutdown_fn = NULL;
  tcpip_shutdown_ctx = NULL;
  sys_mbox_free(&tcpip_mbox);
#if LWIP_TCPIP_CORE_LOCKING
  sys_mutex_free(&lock_tcpip_core);
#endif
  return ERR_OK;
}

/**
 * Simple callback function used with tcpip_callback to free a pbuf]=])

    # Reconciliation markers must survive a PCB shape change and must not
    # be inherited by a listener that was never a candidate.
    #
    # memp_malloc() returns uninitialized storage and the conversion copies only
    # named fields, so ww_reconcile_epoch was neither carried over nor cleared.
    # A bound PCB marked by the stable-candidate pass and converted to a listener
    # inside one of that pass's callbacks silently left the candidate set; a
    # listener allocated into a freed marked slot could just as silently join it.
    # Only the rewrite path cleared the marker, so a candidate the pass declined
    # to rewrite kept a stale epoch into the next reconciliation.
    ww_lwip_replace_once(
        "${lwip_dir}/src/core/tcp.c"
        [=[  lpcb->callback_arg = pcb->callback_arg;
  lpcb->local_port = pcb->local_port;]=]
        [=[  /* memp pools hand back uninitialized storage, and only named fields are
     copied below. Reset first so nothing - least of all a reconciliation
     epoch - is inherited from whatever last occupied this slot. */
  memset(lpcb, 0, sizeof(*lpcb));
  lpcb->callback_arg = pcb->callback_arg;
  lpcb->local_port = pcb->local_port;
  /* A normal source PCB carries epoch zero; an original candidate carries the
     active one and must stay in the candidate set across the conversion. */
  ((struct tcp_pcb *)lpcb)->ww_reconcile_epoch = pcb->ww_reconcile_epoch;]=])

    # Clear every surviving marker at the end of the pass, not only the ones the
    # rewrite happened to reach.
    ww_lwip_replace_once(
        "${lwip_dir}/src/core/tcp.c"
        [=[/** Abort only candidates marked before the first callback ran. */
static void
tcp_netif_ip_addr_changed_abort_marked(u32_t epoch)]=]
        [=[/** Drop the epoch from every listener that still carries it.
 *
 * A marked listener is not always rewritten - the address may be removed rather
 * than replaced, or a callback may have changed it underneath the pass - and a
 * marker left behind would make it a candidate of the next reconciliation too.
 * Listeners are never freed by this walk, so no next pointer is retained across
 * anything that could free one. */
static void
tcp_netif_ip_addr_changed_clear_marks(u32_t epoch)
{
  struct tcp_pcb_listen *lpcb;

  for (lpcb = tcp_listen_pcbs.listen_pcbs; lpcb != NULL; lpcb = lpcb->next) {
    if (((struct tcp_pcb *)lpcb)->ww_reconcile_epoch == epoch) {
      ((struct tcp_pcb *)lpcb)->ww_reconcile_epoch = 0;
    }
  }
}

/** Abort only candidates marked before the first callback ran. */
static void
tcp_netif_ip_addr_changed_abort_marked(u32_t epoch)]=])

    # The pass owns its epoch from the first mark to here, so no marker outlives
    # it - not a listener the rewrite declined, and not one whose address a
    # callback changed underneath the walk.
    ww_lwip_replace_once(
        "${lwip_dir}/src/core/tcp.c"
        [=[          ip_addr_copy(lpcb->local_ip, *new_addr);
          ((struct tcp_pcb *)lpcb)->ww_reconcile_epoch = 0;
        }
      }
    }
  }
}]=]
        [=[          ip_addr_copy(lpcb->local_ip, *new_addr);
          ((struct tcp_pcb *)lpcb)->ww_reconcile_epoch = 0;
        }
      }
    }
    tcp_netif_ip_addr_changed_clear_marks(reconcile_epoch);
  }
}]=])

    # Removal and address/config reconciliation must exclude each other.
    #
    # A TCP error callback raised while an address change reconciles PCBs could
    # call netif_remove(): removal only rejected a nested removal. The outer
    # setter then resumed on an object that was no longer in netif_list, wrote to
    # it, invoked callbacks with it, and finally cleared ww_reconciling on
    # storage its owner may already have freed.
    #
    # The reverse direction is the same bug read backwards: every public address,
    # netmask, gateway and IPv6 setter rejected only ww_reconciling, so a
    # LWIP_NSC_NETIF_REMOVED callback could mutate a netif mid-removal - and
    # netmask/gateway had no guard at all, so netif_set_addr() could complete
    # half of its transition while refusing the other half.
    #
    # Removal's own reconciliation calls netif_do_ip_addr_changed() directly and
    # is unaffected: only the public entry points are gated.
    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[  /* Recursive removal is a rejected inner operation. The outer owner keeps
     the flag through its one callback/removal sequence. */
  if (netif->ww_removing != 0) {
    return;
  }]=]
        [=[  /* Recursive removal is a rejected inner operation. The outer owner keeps
     the flag through its one callback/removal sequence. */
  if (netif->ww_removing != 0) {
    return;
  }
  /* An address reconciliation is walking PCBs that name this netif and will
     resume writing to it; removing it underneath that pass is what turns an
     owner callback into a use-after-free. */
  if (netif->ww_reconciling != 0) {
    return;
  }]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[  /* A callback may not recursively mutate this netif's address. */
  if (netif->ww_reconciling != 0) {
    return 0;
  }]=]
        [=[  /* A callback may not recursively mutate this netif's address, and a
     removal in progress owns every remaining transition this netif will make. */
  if ((netif->ww_reconciling != 0) || (netif->ww_removing != 0)) {
    return 0;
  }]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[static int
netif_do_set_netmask(struct netif *netif, const ip4_addr_t *netmask, ip_addr_t *old_nm)
{
  /* address is actually being changed? */]=]
        [=[static int
netif_do_set_netmask(struct netif *netif, const ip4_addr_t *netmask, ip_addr_t *old_nm)
{
  /* Refused before any partial mutation, so netif_set_addr() cannot apply the
     netmask half of a transition whose address half was rejected. */
  if ((netif->ww_reconciling != 0) || (netif->ww_removing != 0)) {
    return 0;
  }

  /* address is actually being changed? */]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[static int
netif_do_set_gw(struct netif *netif, const ip4_addr_t *gw, ip_addr_t *old_gw)
{
  /* address is actually being changed? */]=]
        [=[static int
netif_do_set_gw(struct netif *netif, const ip4_addr_t *gw, ip_addr_t *old_gw)
{
  if ((netif->ww_reconciling != 0) || (netif->ww_removing != 0)) {
    return 0;
  }

  /* address is actually being changed? */]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[  LWIP_ASSERT("invalid index", addr_idx < LWIP_IPV6_NUM_ADDRESSES);

  if (netif->ww_reconciling != 0) {
    return;
  }

  ip6_addr_copy(*ip_2_ip6(&old_addr), *netif_ip6_addr(netif, addr_idx));]=]
        [=[  LWIP_ASSERT("invalid index", addr_idx < LWIP_IPV6_NUM_ADDRESSES);

  if ((netif->ww_reconciling != 0) || (netif->ww_removing != 0)) {
    return;
  }

  ip6_addr_copy(*ip_2_ip6(&old_addr), *netif_ip6_addr(netif, addr_idx));]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[  LWIP_ASSERT("invalid index", addr_idx < LWIP_IPV6_NUM_ADDRESSES);

  if (netif->ww_reconciling != 0) {
    return;
  }

  old_state = netif_ip6_addr_state(netif, addr_idx);]=]
        [=[  LWIP_ASSERT("invalid index", addr_idx < LWIP_IPV6_NUM_ADDRESSES);

  if ((netif->ww_reconciling != 0) || (netif->ww_removing != 0)) {
    return;
  }

  old_state = netif_ip6_addr_state(netif, addr_idx);]=])

    # ww_reconciling protects only the PCB walk inside an address
    # change. Public mutation must remain closed through every later state write,
    # report, status callback and extended callback as well.
    ww_lwip_replace_once(
        "${lwip_dir}/src/include/lwip/netif.h"
        [=[  /** Exact binds are also closed while address-change callbacks reconcile PCBs. */
  u8_t ww_reconciling;
  /** Non-reusable identity for this successful netif_add lifetime; zero is invalid. */]=]
        [=[  /** Exact binds are also closed while address-change callbacks reconcile PCBs. */
  u8_t ww_reconciling;
  /** Full public IPv4/IPv6 mutation, including its final callback. */
  u8_t ww_mutating;
  /** Non-reusable identity for this successful netif_add lifetime; zero is invalid. */]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[  netif->ww_removing = 0;
  netif->ww_reconciling = 0;
  netif->ww_generation = 0;]=]
        [=[  netif->ww_removing = 0;
  netif->ww_reconciling = 0;
  netif->ww_mutating = 0;
  netif->ww_generation = 0;]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[static void
netif_do_ip_addr_changed(struct netif *netif, const ip_addr_t *old_addr, const ip_addr_t *new_addr)]=]
        [=[static int
netif_ww_mutation_begin(struct netif *netif)
{
  if ((netif->ww_removing != 0) || (netif->ww_reconciling != 0) ||
      (netif->ww_mutating != 0)) {
    return 0;
  }
  netif->ww_mutating = 1;
  return 1;
}

static void
netif_ww_mutation_end(struct netif *netif)
{
  LWIP_ASSERT("netif mutation owner", netif->ww_mutating != 0);
  netif->ww_mutating = 0;
}

static void
netif_do_ip_addr_changed(struct netif *netif, const ip_addr_t *old_addr, const ip_addr_t *new_addr)]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[  /* An address reconciliation is walking PCBs that name this netif and will
     resume writing to it; removing it underneath that pass is what turns an
     owner callback into a use-after-free. */
  if (netif->ww_reconciling != 0) {
    return;
  }]=]
        [=[  /* An address reconciliation or public mutation will resume using this
     object after callbacks return. Removal may not enter either operation. */
  if ((netif->ww_reconciling != 0) || (netif->ww_mutating != 0)) {
    return;
  }]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[  LWIP_ASSERT_CORE_LOCKED();

  if (netif_do_set_ipaddr(netif, ipaddr, &old_addr)) {
#if LWIP_NETIF_EXT_STATUS_CALLBACK
    netif_ext_callback_args_t args;
    args.ipv4_changed.old_address = &old_addr;
    netif_invoke_ext_callback(netif, LWIP_NSC_IPV4_ADDRESS_CHANGED, &args);
#endif
  }
}]=]
        [=[  LWIP_ASSERT_CORE_LOCKED();

  if (!netif_ww_mutation_begin(netif)) {
    return;
  }
  if (netif_do_set_ipaddr(netif, ipaddr, &old_addr)) {
#if LWIP_NETIF_EXT_STATUS_CALLBACK
    netif_ext_callback_args_t args;
    args.ipv4_changed.old_address = &old_addr;
    netif_invoke_ext_callback(netif, LWIP_NSC_IPV4_ADDRESS_CHANGED, &args);
#endif
  }
  netif_ww_mutation_end(netif);
}]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[  if (netif_do_set_netmask(netif, netmask, old_nm)) {
#if LWIP_NETIF_EXT_STATUS_CALLBACK
    netif_ext_callback_args_t args;
    args.ipv4_changed.old_netmask = old_nm;
    netif_invoke_ext_callback(netif, LWIP_NSC_IPV4_NETMASK_CHANGED, &args);
#endif
  }
}]=]
        [=[  if (!netif_ww_mutation_begin(netif)) {
    return;
  }
  if (netif_do_set_netmask(netif, netmask, old_nm)) {
#if LWIP_NETIF_EXT_STATUS_CALLBACK
    netif_ext_callback_args_t args;
    args.ipv4_changed.old_netmask = old_nm;
    netif_invoke_ext_callback(netif, LWIP_NSC_IPV4_NETMASK_CHANGED, &args);
#endif
  }
  netif_ww_mutation_end(netif);
}]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[  if (netif_do_set_gw(netif, gw, old_gw)) {
#if LWIP_NETIF_EXT_STATUS_CALLBACK
    netif_ext_callback_args_t args;
    args.ipv4_changed.old_gw = old_gw;
    netif_invoke_ext_callback(netif, LWIP_NSC_IPV4_GATEWAY_CHANGED, &args);
#endif
  }
}]=]
        [=[  if (!netif_ww_mutation_begin(netif)) {
    return;
  }
  if (netif_do_set_gw(netif, gw, old_gw)) {
#if LWIP_NETIF_EXT_STATUS_CALLBACK
    netif_ext_callback_args_t args;
    args.ipv4_changed.old_gw = old_gw;
    netif_invoke_ext_callback(netif, LWIP_NSC_IPV4_GATEWAY_CHANGED, &args);
#endif
  }
  netif_ww_mutation_end(netif);
}]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[  LWIP_ASSERT_CORE_LOCKED();

  /* Don't propagate NULL pointer (IPv4 ANY) to subsequent functions */
  if (ipaddr == NULL) {]=]
        [=[  LWIP_ASSERT_CORE_LOCKED();

  if (!netif_ww_mutation_begin(netif)) {
    return;
  }

  /* Don't propagate NULL pointer (IPv4 ANY) to subsequent functions */
  if (ipaddr == NULL) {]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[  if (change_reason != LWIP_NSC_NONE) {
    netif_invoke_ext_callback(netif, change_reason, &cb_args);
  }
#endif
}
#endif /* LWIP_IPV4*/]=]
        [=[  if (change_reason != LWIP_NSC_NONE) {
    netif_invoke_ext_callback(netif, change_reason, &cb_args);
  }
#endif
  netif_ww_mutation_end(netif);
}
#endif /* LWIP_IPV4*/]=])

    # The IPv6 state implementation becomes a private helper so composite
    # link-local/add operations can hold one outer mutation admission while it
    # performs their final state transition and callbacks.
    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[void
netif_ip6_addr_set_state(struct netif *netif, s8_t addr_idx, u8_t state)
{]=]
        [=[static void
netif_ip6_addr_set_state_internal(struct netif *netif, s8_t addr_idx, u8_t state)
{]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[/**
 * Checks if a specific local address is present on the netif and returns its
 * index. Depending on its state, it may or may not be assigned to the]=]
        [=[void
netif_ip6_addr_set_state(struct netif *netif, s8_t addr_idx, u8_t state)
{
  LWIP_ASSERT_CORE_LOCKED();
  LWIP_ASSERT("netif != NULL", netif != NULL);
  LWIP_ASSERT("invalid index", addr_idx < LWIP_IPV6_NUM_ADDRESSES);

  if (!netif_ww_mutation_begin(netif)) {
    return;
  }
  netif_ip6_addr_set_state_internal(netif, addr_idx, state);
  netif_ww_mutation_end(netif);
}

/**
 * Checks if a specific local address is present on the netif and returns its
 * index. Depending on its state, it may or may not be assigned to the]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[  if ((netif->ww_reconciling != 0) || (netif->ww_removing != 0)) {
    return;
  }

  ip6_addr_copy(*ip_2_ip6(&old_addr), *netif_ip6_addr(netif, addr_idx));]=]
        [=[  if (!netif_ww_mutation_begin(netif)) {
    return;
  }

  ip6_addr_copy(*ip_2_ip6(&old_addr), *netif_ip6_addr(netif, addr_idx));]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[  LWIP_DEBUGF(NETIF_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("netif: IPv6 address %d of interface %c%c set to %s/0x%"X8_F"\n",
              addr_idx, netif->name[0], netif->name[1], ip6addr_ntoa(netif_ip6_addr(netif, addr_idx)),
              netif_ip6_addr_state(netif, addr_idx)));
}

/**
 * @ingroup netif_ip6
 * Change the state of an IPv6 address]=]
        [=[  LWIP_DEBUGF(NETIF_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("netif: IPv6 address %d of interface %c%c set to %s/0x%"X8_F"\n",
              addr_idx, netif->name[0], netif->name[1], ip6addr_ntoa(netif_ip6_addr(netif, addr_idx)),
              netif_ip6_addr_state(netif, addr_idx)));
  netif_ww_mutation_end(netif);
}

/**
 * @ingroup netif_ip6
 * Change the state of an IPv6 address]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[  LWIP_ASSERT("netif_create_ip6_linklocal_address: invalid netif", netif != NULL);

  /* Link-local prefix. */]=]
        [=[  LWIP_ASSERT("netif_create_ip6_linklocal_address: invalid netif", netif != NULL);

  if (!netif_ww_mutation_begin(netif)) {
    return;
  }

  /* Link-local prefix. */]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[  netif_ip6_addr_set_state(netif, 0, IP6_ADDR_TENTATIVE);
#else
  /* Consider address valid. */
  netif_ip6_addr_set_state(netif, 0, IP6_ADDR_PREFERRED);
#endif /* LWIP_IPV6_AUTOCONFIG */
}]=]
        [=[  netif_ip6_addr_set_state_internal(netif, 0, IP6_ADDR_TENTATIVE);
#else
  /* Consider address valid. */
  netif_ip6_addr_set_state_internal(netif, 0, IP6_ADDR_PREFERRED);
#endif /* LWIP_IPV6_AUTOCONFIG */
  netif_ww_mutation_end(netif);
}]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[  LWIP_ASSERT("netif_add_ip6_address: invalid ip6addr", ip6addr != NULL);

  i = netif_get_ip6_addr_match(netif, ip6addr);]=]
        [=[  LWIP_ASSERT("netif_add_ip6_address: invalid ip6addr", ip6addr != NULL);

  if (chosen_idx != NULL) {
    *chosen_idx = -1;
  }
  if (!netif_ww_mutation_begin(netif)) {
    return ERR_IF;
  }

  i = netif_get_ip6_addr_match(netif, ip6addr);]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[    if (chosen_idx != NULL) {
      *chosen_idx = i;
    }
    return ERR_OK;
  }

  /* Find a free slot. The first one is reserved for link-local addresses. */]=]
        [=[    if (chosen_idx != NULL) {
      *chosen_idx = i;
    }
    netif_ww_mutation_end(netif);
    return ERR_OK;
  }

  /* Find a free slot. The first one is reserved for link-local addresses. */]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[      netif_ip6_addr_set_state(netif, i, IP6_ADDR_TENTATIVE);
      if (chosen_idx != NULL) {
        *chosen_idx = i;
      }
      return ERR_OK;]=]
        [=[      netif_ip6_addr_set_state_internal(netif, i, IP6_ADDR_TENTATIVE);
      if (chosen_idx != NULL) {
        *chosen_idx = i;
      }
      netif_ww_mutation_end(netif);
      return ERR_OK;]=])

    ww_lwip_replace_once(
        "${lwip_dir}/src/core/netif.c"
        [=[  if (chosen_idx != NULL) {
    *chosen_idx = -1;
  }
  return ERR_VAL;
}]=]
        [=[  netif_ww_mutation_end(netif);
  return ERR_VAL;
}]=])

endfunction()
