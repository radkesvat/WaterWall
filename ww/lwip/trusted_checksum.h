#pragma once

#include "lwip/ip.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/prot/ip4.h"
#include "lwip/tcp.h"

/* TCP/UDP below call ip_output_if, which generates IP_HLEN bytes and supplies
 * no IPv4 options. Pass the actual header length explicitly: callers of the
 * options/HDRINCL APIs cannot reuse this decision with a guessed base header.
 * The MTU comparison matches ip4_output_if_opt_src, before any fragmentation. */
static inline int wwLwipPartialTransportOutput(const struct netif *netif, const struct pbuf *p, const ip_addr_t *src,
                                               const ip_addr_t *dst, u16_t ip_header_length)
{
    const u32_t length = (u32_t) p->tot_len + ip_header_length;
    return netif->ww_partial_transport_checksum && IP_IS_V4(src) && IP_IS_V4(dst) && ip_header_length >= IP_HLEN &&
           ip_header_length <= IP_HLEN_MAX && length <= 65535U && (netif->mtu == 0 || length <= netif->mtu);
}

/* A route lookup is not permission to disable cache work. Require the PCB's
 * exact bound netif lifetime in the already selected owner engine. */
static inline int wwLwipTcpChecksumOnCopy(const struct tcp_pcb *pcb)
{
    WW_LWIP_ASSERT_PCB_OWNER(pcb);
    if (pcb->netif_idx != NETIF_NO_INDEX && IP_IS_V4_VAL(pcb->local_ip) && IP_IS_V4_VAL(pcb->remote_ip))
    {
        const struct netif *netif = netif_get_by_index(pcb->netif_idx);
        if (netif != NULL && netif->ww_generation == pcb->netif_generation && netif->ww_partial_transport_checksum)
        {
            return 0;
        }
    }
    return 1;
}
