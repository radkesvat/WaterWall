/*
 * Copyright (c) 2018 Russ Dill <russ.dill@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */
#include <lwip/icmp.h>
#include <lwip/ip.h>
#include <lwip/ip4.h>

#include "nat.h"
#include "nat_proto_icmp4.h"
#include "nat_proto_ip4.h"
#include "nat_proto_tcp.h"
#include "nat_proto_udp.h"

#if LWIP_IPV4 && LWIP_NAT

#if LWIP_ICMP && LWIP_NAT_ICMP && LWIP_NAT_ICMP_IP
/**
 * Find or generate a NAT entry for an encapsulated IPv4 packet.
 *
 * Packets incapsulated within ICMP messages need the same NAT rules applied,
 * but with source and destination swapped.
 *
 * @param p Incoming encapsulated IPv4 packet
 * @param inp Network interface packet was received on
 * @param forwardp Network interface packet is to be routed out on (NULL if none)
 *
 * @return Matching NAT entry, NULL otherwise
 */
struct nat_pcb *icmp4_ip4_prerouting_pcb(struct pbuf *p, struct netif *inp, struct netif *forwardp)
{
    struct ip_hdr  *iphdr = (struct ip_hdr *) p->payload;
    u16_t           iphdr_hlen;
    struct nat_pcb *pcb;
    ip_addr_t       iphdr_src;
    ip_addr_t       iphdr_dest;

    if (p->len < IP_HLEN)
        return NULL;

    /*
     * ICMP stipulates that the IP header plus at least 8 bytes of the
     * proto packet will be
     * present.
     */
    iphdr_hlen = IPH_HL_BYTES(iphdr);
    if (p->len < iphdr_hlen + 8)
        return NULL;

    ip_addr_copy_from_ip4(iphdr_src, iphdr->src);
    ip_addr_copy_from_ip4(iphdr_dest, iphdr->dest);

    if (pbuf_remove_header(p, iphdr_hlen))
        return NULL;

    switch (IPH_PROTO(iphdr))
    {
#if LWIP_TCP
    case IP_PROTO_TCP:
        pcb = icmp_tcp_prerouting_pcb(&iphdr_src, &iphdr_dest, p, inp, forwardp);
        break;
#endif
#if LWIP_UDP
    case IP_PROTO_UDP:
        pcb = icmp_udp_prerouting_pcb(&iphdr_src, &iphdr_dest, p, inp, forwardp);
        break;
#endif
    case IP_PROTO_ICMP:
        pcb = icmp_icmp4_prerouting_pcb(&iphdr_src, &iphdr_dest, p, inp, forwardp);
        break;
    default:
        pcb = NULL;
    }

    pbuf_add_header_force(p, iphdr_hlen);

    return pcb;
}

/**
 * Prerouting hook for IPv4 DNAT for ICMP encapsulated packets.
 *
 * @param icmp_chksum Pointer to encapsulating ICMP header checksum
 * @param p Incoming encapsulated IPv4 packet
 * @param pcb NAT entry
 */
void icmp4_ip4_prerouting_nat(u16_t *icmp_chksum, struct pbuf *p, struct nat_pcb *pcb, int forward)
{
    struct ip_hdr *iphdr      = (struct ip_hdr *) p->payload;
    u16_t          iphdr_hlen = IPH_HL_BYTES(iphdr);
    ip_addr_t      iphdr_src;
    ip_addr_t      iphdr_dest;
    u16_t          orig_chksum;

    ip_addr_copy_from_ip4(iphdr_src, iphdr->src);
    ip_addr_copy_from_ip4(iphdr_dest, iphdr->dest);

    pbuf_remove_header(p, iphdr_hlen);

    switch (IPH_PROTO(iphdr))
    {
#if LWIP_TCP
    case IP_PROTO_TCP:
        icmp_tcp_prerouting_nat(icmp_chksum, &iphdr_src, &iphdr_dest, p, pcb, forward);
        break;
#endif
#if LWIP_UDP
    case IP_PROTO_UDP:
        icmp_udp_prerouting_nat(icmp_chksum, &iphdr_src, &iphdr_dest, p, pcb, forward);
        break;
#endif
    case IP_PROTO_ICMP:
        icmp_icmp4_prerouting_nat(icmp_chksum, &iphdr_src, &iphdr_dest, p, pcb, forward);
        break;
    }

    pbuf_add_header_force(p, iphdr_hlen);

    orig_chksum = iphdr->_chksum;
    if (forward)
    {
        update_chksum(&iphdr->_chksum, &iphdr->dest, &pcb->ip.local_ip, 2);
        update_chksum(icmp_chksum, &iphdr->dest, &pcb->ip.local_ip, 2);
        ip4_addr_copy(iphdr->dest, pcb->ip.local_ip);
    }
    else
    {
        update_chksum(&iphdr->_chksum, &iphdr->src, &pcb->nat_local_ip, 2);
        update_chksum(icmp_chksum, &iphdr->src, &pcb->nat_local_ip, 2);
        ip4_addr_copy(iphdr->src, pcb->nat_local_ip);
    }
    update_chksum(icmp_chksum, &orig_chksum, &iphdr->_chksum, 1);
}
#endif

/**
 * Find or generate a NAT entry for a given IPv4 packet.
 *
 * @param p Incoming IPv4 packet to be forwarded
 * @param inp Network interface packet was received on
 * @param forwardp Network interface packet is to be routed out on (NULL if none)
 *
 * @return NAT entry or NULL
 */
struct nat_pcb *ip4_prerouting_pcb(struct pbuf *p, struct netif *inp, struct netif *forwardp)
{
    struct ip_hdr  *iphdr      = (struct ip_hdr *) p->payload;
    u16_t           iphdr_hlen = IPH_HL_BYTES(iphdr);
    struct nat_pcb *pcb;

    if (pbuf_remove_header(p, iphdr_hlen))
        return NULL;

    switch (IPH_PROTO(iphdr))
    {
#if LWIP_TCP
    case IP_PROTO_TCP:
        pcb = tcp_prerouting_pcb(p, inp, forwardp);
        break;
#endif
#if LWIP_UDP
    case IP_PROTO_UDP:
        pcb = udp_prerouting_pcb(p, inp, forwardp);
        break;
#endif
#if LWIP_ICMP && LWIP_NAT_ICMP
    case IP_PROTO_ICMP:
        pcb = icmp4_prerouting_pcb(p, inp, forwardp);
        break;
#endif
    default:
        pcb = NULL;
    }

    pbuf_add_header_force(p, iphdr_hlen);

    return pcb;
}

/**
 * Perform IPv4 packet modifications for a given NAT entry.
 *
 * @param p Packet to be modified
 * @param pcb NAT entry
 */
void ip4_prerouting_nat(struct pbuf *p, struct nat_pcb *pcb, int forward)
{
    struct ip_hdr *iphdr      = (struct ip_hdr *) p->payload;
    u16_t          iphdr_hlen = IPH_HL_BYTES(iphdr);

    pbuf_remove_header(p, iphdr_hlen);
    switch (IPH_PROTO(iphdr))
    {
#if LWIP_TCP
    case IP_PROTO_TCP:
        tcp_prerouting_nat(p, pcb, forward);
        break;
#endif
#if LWIP_UDP
    case IP_PROTO_UDP:
        udp_prerouting_nat(p, pcb, forward);
        break;
#endif
#if LWIP_ICMP && LWIP_NAT_ICMP
    case IP_PROTO_ICMP:
        icmp4_prerouting_nat(p, pcb, forward);
        break;
#endif
    }
    pbuf_add_header_force(p, iphdr_hlen);

    if (forward)
    {
        /* Update source address for packets from local NAT network */
        update_chksum(&iphdr->_chksum, &iphdr->src, &pcb->ip.local_ip, 2);
        ip4_addr_copy(iphdr->src, pcb->ip.local_ip.u_addr.ip4);
    }
    else
    {
        /* Update destination address for returning packets */
        update_chksum(&iphdr->_chksum, &iphdr->dest, &pcb->nat_local_ip, 2);
        ip4_addr_copy(iphdr->dest, pcb->nat_local_ip.u_addr.ip4);
    }
}
#endif
