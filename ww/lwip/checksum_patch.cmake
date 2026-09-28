# Scoped checksum policy layered after the pinned engine/lifetime patches.
function(ww_apply_lwip_checksum_patch lwip_dir)
    ww_lwip_replace_once("${lwip_dir}/src/include/lwip/netif.h"
[=[  u8_t ww_removing;]=]
[=[  u8_t ww_removing;
  /* Immutable direct-pair policy, set only by the netif initializer. */
  u8_t ww_partial_transport_checksum;]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/netif.c"
[=[  netif->flags = 0;]=]
[=[  netif->flags = 0;
  netif->ww_partial_transport_checksum = 0;]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[#include "lwip/inet_chksum.h"]=]
[=[#include "lwip/inet_chksum.h"
#include "trusted_checksum.h"]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/udp.c"
[=[#include "lwip/inet_chksum.h"]=]
[=[#include "lwip/inet_chksum.h"
#include "trusted_checksum.h"]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[#define TCP_DATA_COPY(dst, src, len, seg) do { \
  tcp_seg_add_chksum(LWIP_CHKSUM_COPY(dst, src, len), \
                     len, &seg->chksum, &seg->chksum_swapped); \
  seg->flags |= TF_SEG_DATA_CHECKSUMMED; } while(0)
#define TCP_DATA_COPY2(dst, src, len, chksum, chksum_swapped)  \
  tcp_seg_add_chksum(LWIP_CHKSUM_COPY(dst, src, len), len, chksum, chksum_swapped);
]=]
[=[#define TCP_DATA_COPY(dst, src, len, seg) do { \
  if (ww_checksum_copy && ((seg)->flags & TF_SEG_DATA_CHECKSUMMED)) { \
    tcp_seg_add_chksum(LWIP_CHKSUM_COPY(dst, src, len), \
                       len, &(seg)->chksum, &(seg)->chksum_swapped); \
  } else { \
    MEMCPY(dst, src, len); \
    (seg)->flags &= (u8_t)~TF_SEG_DATA_CHECKSUMMED; \
  } } while (0)
#define TCP_DATA_COPY2(dst, src, len, chksum, chksum_swapped) do { \
  if (ww_checksum_copy) { \
    tcp_seg_add_chksum(LWIP_CHKSUM_COPY(dst, src, len), len, chksum, chksum_swapped); \
  } else { \
    MEMCPY(dst, src, len); \
  } } while (0)
]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[  LWIP_ERROR("tcp_write: invalid pcb", pcb != NULL, return ERR_ARG);]=]
[=[  LWIP_ERROR("tcp_write: invalid pcb", pcb != NULL, return ERR_ARG);
#if TCP_CHECKSUM_ON_COPY
  const int ww_checksum_copy = wwLwipTcpChecksumOnCopy(pcb);
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[tcp_split_unsent_seg(struct tcp_pcb *pcb, u16_t split)
{]=]
[=[tcp_split_unsent_seg(struct tcp_pcb *pcb, u16_t split)
{
#if TCP_CHECKSUM_ON_COPY
  const int ww_checksum_copy = wwLwipTcpChecksumOnCopy(pcb);
#endif]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[        /* calculate the checksum of nocopy-data */
        tcp_seg_add_chksum(~inet_chksum((const u8_t *)arg + pos, seglen), seglen,
                           &concat_chksum, &concat_chksum_swapped);
        concat_chksummed += seglen;
]=]
[=[  if (ww_checksum_copy) {
        /* calculate the checksum of nocopy-data */
        tcp_seg_add_chksum(~inet_chksum((const u8_t *)arg + pos, seglen), seglen,
                           &concat_chksum, &concat_chksum_swapped);
        concat_chksummed += seglen;
  }
]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[      /* calculate the checksum of nocopy-data */
      chksum = ~inet_chksum((const u8_t *)arg + pos, seglen);
      if (seglen & 1) {
        chksum_swapped = 1;
        chksum = SWAP_BYTES_IN_WORD(chksum);
      }]=]
[=[      if (ww_checksum_copy) {
        /* calculate the checksum of nocopy-data */
        chksum = ~inet_chksum((const u8_t *)arg + pos, seglen);
        if (seglen & 1) {
          chksum_swapped = 1;
          chksum = SWAP_BYTES_IN_WORD(chksum);
        }
      }]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[  /* calculate the checksum on remainder data */
  tcp_seg_add_chksum(~inet_chksum((const u8_t *)p->payload + optlen, remainder), remainder,
                     &chksum, &chksum_swapped);
]=]
[=[  if (ww_checksum_copy) {
  /* calculate the checksum on remainder data */
  tcp_seg_add_chksum(~inet_chksum((const u8_t *)p->payload + optlen, remainder), remainder,
                     &chksum, &chksum_swapped);
  }
]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[    seg->flags |= TF_SEG_DATA_CHECKSUMMED;]=]
[=[    if (ww_checksum_copy) { seg->flags |= TF_SEG_DATA_CHECKSUMMED; }]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[  seg->flags |= TF_SEG_DATA_CHECKSUMMED;]=]
[=[  if (ww_checksum_copy) { seg->flags |= TF_SEG_DATA_CHECKSUMMED; }]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[  if (concat_chksummed) {]=]
[=[  if (!ww_checksum_copy && last_unsent != NULL && (concat_p != NULL || extendlen > 0)) {
    last_unsent->flags &= (u8_t)~TF_SEG_DATA_CHECKSUMMED;
  }
  if (ww_checksum_copy && concat_chksummed && (last_unsent->flags & TF_SEG_DATA_CHECKSUMMED)) {]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[  /* The checksum on the split segment is now incorrect. We need to re-run it over the split */
  useg->chksum = 0;
  useg->chksum_swapped = 0;
  q = useg->p;
  offset = q->tot_len - useg->len; /* Offset due to exposed headers */

  /* Advance to the pbuf where the offset ends */
  while (q != NULL && offset > q->len) {
    offset -= q->len;
    q = q->next;
  }
  LWIP_ASSERT("Found start of payload pbuf", q != NULL);
  /* Checksum the first payload pbuf accounting for offset, then other pbufs are all payload */
  for (; q != NULL; offset = 0, q = q->next) {
    tcp_seg_add_chksum(~inet_chksum((const u8_t *)q->payload + offset, q->len - offset), q->len - offset,
                       &useg->chksum, &useg->chksum_swapped);
  }
]=]
[=[  useg->flags &= (u8_t)~TF_SEG_DATA_CHECKSUMMED;
  if (ww_checksum_copy) {
  /* The checksum on the split segment is now incorrect. We need to re-run it over the split */
  useg->chksum = 0;
  useg->chksum_swapped = 0;
  q = useg->p;
  offset = q->tot_len - useg->len; /* Offset due to exposed headers */

  /* Advance to the pbuf where the offset ends */
  while (q != NULL && offset > q->len) {
    offset -= q->len;
    q = q->next;
  }
  LWIP_ASSERT("Found start of payload pbuf", q != NULL);
  /* Checksum the first payload pbuf accounting for offset, then other pbufs are all payload */
  for (; q != NULL; offset = 0, q = q->next) {
    tcp_seg_add_chksum(~inet_chksum((const u8_t *)q->payload + offset, q->len - offset), q->len - offset,
                       &useg->chksum, &useg->chksum_swapped);
  }
    useg->flags |= TF_SEG_DATA_CHECKSUMMED;
  }
]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[  IF__NETIF_CHECKSUM_ENABLED(netif, NETIF_CHECKSUM_GEN_TCP) {]=]
[=[  if (NETIF_CHECKSUM_ENABLED(netif, NETIF_CHECKSUM_GEN_TCP) &&
      !wwLwipPartialTransportOutput(netif, seg->p, &pcb->local_ip, &pcb->remote_ip, IP_HLEN)) {]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[  IF__NETIF_CHECKSUM_ENABLED(netif, NETIF_CHECKSUM_GEN_TCP) {]=]
[=[  if (NETIF_CHECKSUM_ENABLED(netif, NETIF_CHECKSUM_GEN_TCP) &&
      !wwLwipPartialTransportOutput(netif, p, src, dst, IP_HLEN)) {]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[    if ((seg->flags & TF_SEG_DATA_CHECKSUMMED) == 0) {
      LWIP_ASSERT("data included but not checksummed",
                  seg->p->tot_len == TCPH_HDRLEN_BYTES(seg->tcphdr));
    }
]=]
[=[    if ((seg->flags & TF_SEG_DATA_CHECKSUMMED) == 0) {
      /* Cache absent (including a formerly partial segment): sum the actual
       * pbuf chain before ordinary output or IP fragmentation. */
      seg->tcphdr->chksum = ip_chksum_pseudo(seg->p, IP_PROTO_TCP,
                                           seg->p->tot_len, &pcb->local_ip, &pcb->remote_ip);
    } else {
]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_out.c"
[=[    seg->tcphdr->chksum = (u16_t)~FOLD_U32T(acc);
#if TCP_CHECKSUM_ON_COPY_SANITY_CHECK]=]
[=[    seg->tcphdr->chksum = (u16_t)~FOLD_U32T(acc);
    }
#if TCP_CHECKSUM_ON_COPY_SANITY_CHECK]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/udp.c"
[=[    udphdr->len = lwip_htons(q->tot_len);
    /* calculate checksum */
#if CHECKSUM_GEN_UDP
    IF__NETIF_CHECKSUM_ENABLED(netif, NETIF_CHECKSUM_GEN_UDP) {]=]
[=[    udphdr->len = lwip_htons(q->tot_len);
    /* ip_output_if below supplies no IPv4 options; oversized datagrams retain
     * the complete checksum before ip4_frag sees their first fragment. */
#if CHECKSUM_GEN_UDP
    if (NETIF_CHECKSUM_ENABLED(netif, NETIF_CHECKSUM_GEN_UDP) &&
        !wwLwipPartialTransportOutput(netif, q, src_ip, dst_ip, IP_HLEN)) {]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/tcp_in.c"
[=[  IF__NETIF_CHECKSUM_ENABLED(inp, NETIF_CHECKSUM_CHECK_TCP) {]=]
[=[  if (NETIF_CHECKSUM_ENABLED(inp, NETIF_CHECKSUM_CHECK_TCP) ||
      (inp->ww_partial_transport_checksum && ip_current_is_v6())) {]=])
    ww_lwip_replace_once("${lwip_dir}/src/core/udp.c"
[=[    IF__NETIF_CHECKSUM_ENABLED(inp, NETIF_CHECKSUM_CHECK_UDP) {]=]
[=[    if (NETIF_CHECKSUM_ENABLED(inp, NETIF_CHECKSUM_CHECK_UDP) ||
        (inp->ww_partial_transport_checksum &&
         (ip_current_is_v6() || ip_current_header_proto() == IP_PROTO_UDPLITE))) {]=])
endfunction()
