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
#include <lwip/inet_chksum.h>
#include <lwip/udp.h>

#include "nat.h"
#include "nat_proto_udp.h"

#if LWIP_UDP && LWIP_NAT

#define LWIP_NAT_UDP_PCB_SZ offsetof(struct nat_pcb, nat_udp.end)

static int  nat_udp_pcbs_initialized;
static u8_t nat_udp_storage[LWIP_NAT_UDP_PCB_SZ * LWIP_NAT_UDP_MAX];

static struct nat_pcb *nat_udp_used;
static struct nat_pcb *nat_udp_free;

static u16_t nat_udp_port = LWIP_NAT_UDP_LOCAL_PORT_RANGE_START;

static void udp_unlink(struct udp_pcb *pcb)
{
    struct udp_pcb *curr, **prev;
    prev = &udp_pcbs;
    for (curr = udp_pcbs; curr; curr = curr->next)
    {
        if (curr == pcb)
        {
            *prev      = curr->next;
            curr->next = NULL;
            break;
        }
        prev = &curr->next;
    }
}

static struct nat_pcb *nat_udp_new(u8_t ext_netif_idx, u8_t int_netif_idx, const ip_addr_t *remote, u16_t remote_port,
                                   const ip_addr_t *local, const ip_addr_t *nat, u16_t nat_port)
{
    struct nat_pcb *pcb;
    err_t           err;
    u16_t           n = LWIP_NAT_UDP_LOCAL_PORT_RANGE_END - LWIP_NAT_UDP_LOCAL_PORT_RANGE_START;

    if (! nat_udp_pcbs_initialized)
    {
        nat_udp_free             = nat_pcb_init_mem(nat_udp_storage, LWIP_NAT_UDP_PCB_SZ, LWIP_NAT_UDP_MAX);
        nat_udp_pcbs_initialized = 1;
    }

#if LWIP_NAT_USE_OLDEST
    if (! nat_udp_free)
    {
        nat_pcb_take_oldest(&nat_udp_free, &nat_udp_used, LWIP_NAT_UDP_TICKS - LWIP_NAT_UDP_USE_OLDEST_LIMIT);
        if (nat_udp_free)
            udp_unlink(&nat_udp_free->udp);
    }
#endif
    if (! nat_udp_free)
        return NULL;
    pcb = nat_udp_free;

    /* Initialize LWIP fields to make this a valid udp_pcb */
    pcb->udp.next      = NULL;
    pcb->udp.flags     = 0;
    pcb->udp.netif_idx = 0xff; /* Give LWIP an invalid netif */

again:
    /* Find a free outgoing port */
    if (nat_udp_port > LWIP_NAT_UDP_LOCAL_PORT_RANGE_END)
        nat_udp_port = LWIP_NAT_UDP_LOCAL_PORT_RANGE_START;
    err = udp_bind(&pcb->udp, local, nat_udp_port++);
    if (err == ERR_USE)
    {
        if (! --n)
            return NULL;
        goto again;
    }
    else if (err != ERR_OK)
        return NULL;

    /* Add the rest of the data for tracking this connection */
    pcb->udp.remote_port        = remote_port;
    pcb->nat_udp.nat_local_port = nat_port;
    pcb->ext_netif_idx          = ext_netif_idx;
    pcb->int_netif_idx          = int_netif_idx;
    ip_addr_set(&pcb->nat_local_ip, nat);
    ip_addr_set(&pcb->ip.remote_ip, remote);

    /* Remove from free list, add to used list */
    nat_udp_free = pcb->next;
    pcb->next    = nat_udp_used;
    nat_udp_used = pcb;

    return pcb;
}

/* Search for the matching NAT entry, removing stale ones as we go */
static struct nat_pcb *nat_udp_walk(u8_t ext_netif_idx, u8_t int_netif_idx, const ip_addr_t *remote, u16_t remote_port,
                                    const ip_addr_t *local, u16_t local_port, const ip_addr_t *nat, u16_t nat_port)
{
    struct nat_pcb *pcb, *next, **prev = &nat_udp_used;
    int             n = 0;

    for (pcb = nat_udp_used; pcb; pcb = next)
    {
        next = pcb->next;
        if (nat_pcb_timedout(pcb))
        {
            udp_unlink(&pcb->udp);
            *prev        = next;
            pcb->next    = nat_udp_free;
            nat_udp_free = pcb;
            continue;
        }
        n++;
        if (ext_netif_idx == pcb->ext_netif_idx && (! int_netif_idx || int_netif_idx == pcb->int_netif_idx) &&
            (! local || (ip_addr_cmp(local, &pcb->ip.local_ip) && local_port == pcb->udp.local_port)) &&
            (! nat || (ip_addr_cmp(nat, &pcb->nat_local_ip) && nat_port == pcb->nat_udp.nat_local_port)) &&
            ip_addr_cmp(remote, &pcb->ip.remote_ip) && remote_port == pcb->udp.remote_port)
        {
            if (n > 16)
            {
                /* If it's far down the list, move it to head */
                *prev        = next;
                pcb->next    = nat_udp_used;
                nat_udp_used = pcb;
            }
            break;
        }
        prev = &pcb->next;
    }
    return pcb;
}

void nat_udp_expire(void)
{
    nat_udp_walk(0xff, 0xff, NULL, 0, NULL, 0, NULL, 0);
}

#if LWIP_ICMP && LWIP_NAT_ICMP_IP
struct nat_pcb *icmp_udp_prerouting_pcb(const ip_addr_t *iphdr_src, const ip_addr_t *iphdr_dest, struct pbuf *p,
                                        struct netif *inp, struct netif *forwardp)
{
    struct udp_hdr *udphdr        = (struct udp_hdr *) p->payload;
    u16_t           dest_port     = lwip_ntohs(udphdr->dest);
    u16_t           src_port      = lwip_ntohs(udphdr->src);
    u8_t            inp_netif_idx = netif_get_index(inp);

    if (forwardp)
        return nat_udp_walk(netif_get_index(forwardp), inp_netif_idx, iphdr_src, src_port, NULL, 0, iphdr_dest,
                            dest_port);
    else
        return nat_udp_walk(inp_netif_idx, 0, iphdr_dest, dest_port, iphdr_src, src_port, NULL, 0);
}

/* Reverse NAT changes to port numbers for ICMP encapsulated packets */
void icmp_udp_prerouting_nat(u16_t *icmp_chksum, const ip_addr_t *iphdr_src, const ip_addr_t *iphdr_dest,
                             struct pbuf *p, struct nat_pcb *pcb, int forward)
{
    struct udp_hdr *udphdr      = (struct udp_hdr *) p->payload;
    u16_t           orig_chksum = udphdr->chksum;

    if (forward)
    {
        u16_t dest_port = lwip_htons(pcb->udp.local_port);
        update_chksum_udp(&udphdr->chksum, &udphdr->dest, &dest_port, 1);
        update_chksum(icmp_chksum, &udphdr->dest, &dest_port, 1);
        udphdr->dest = dest_port;

        update_chksum_udp(&udphdr->chksum, iphdr_dest, &pcb->ip.local_ip, IP_IS_V4(&pcb->ip.local_ip) ? 2 : 8);

        update_chksum(icmp_chksum, &orig_chksum, &udphdr->chksum, 1);
    }
    else
    {
        u16_t src_port = lwip_htons(pcb->nat_udp.nat_local_port);
        update_chksum_udp(&udphdr->chksum, &udphdr->src, &src_port, 1);
        update_chksum(icmp_chksum, &udphdr->src, &src_port, 1);
        udphdr->src = src_port;

        update_chksum_udp(&udphdr->chksum, iphdr_src, &pcb->nat_local_ip, IP_IS_V4(&pcb->nat_local_ip) ? 2 : 8);
    }
    update_chksum(icmp_chksum, &orig_chksum, &udphdr->chksum, 1);
}
#endif

/* Find the associated NAT entry or make a new one if appropriate */
struct nat_pcb *udp_prerouting_pcb(struct pbuf *p, struct netif *inp, struct netif *forwardp)
{
    struct udp_hdr *udphdr = (struct udp_hdr *) p->payload;
    u16_t           dest_port;
    u16_t           src_port;
    u8_t            inp_netif_idx = netif_get_index(inp);
    struct nat_pcb *pcb;

    if (p->len < UDP_HLEN)
        return NULL;

        /*
         * NAT RFCs indicate that checksums should be verified before
         * performing NAT.
         */
#if CHECKSUM_CHECK_UDP
    IF__NETIF_CHECKSUM_ENABLED(inp, NETIF_CHECKSUM_CHECK_UDP)
    if (udphdr->chksum != 0)
        if (ip_chksum_pseudo(p, IP_PROTO_UDP, p->tot_len, ip_current_src_addr(), ip_current_dest_addr()) != 0)
            return NULL;
#endif

    dest_port = lwip_ntohs(udphdr->dest);
    src_port  = lwip_ntohs(udphdr->src);

    if (forwardp)
    {
        u8_t forwardp_netif_idx = netif_get_index(forwardp);
        pcb = nat_udp_walk(forwardp_netif_idx, inp_netif_idx, ip_current_dest_addr(), dest_port, NULL, 0,
                           ip_current_src_addr(), src_port);
        if (! pcb)
            pcb = nat_udp_new(forwardp_netif_idx, inp_netif_idx, ip_current_dest_addr(), dest_port, &forwardp->ip_addr,
                              ip_current_src_addr(), src_port);
    }
    else
        pcb =
            nat_udp_walk(inp_netif_idx, 0, ip_current_src_addr(), src_port, ip_current_dest_addr(), dest_port, NULL, 0);

    return pcb;
}

/* Rewrite the port numbers */
void udp_prerouting_nat(struct pbuf *p, struct nat_pcb *pcb, int forward)
{
    struct udp_hdr *udphdr = (struct udp_hdr *) p->payload;

    nat_pcb_refresh(pcb, LWIP_NAT_UDP_TICKS);

    if (forward)
    {
        u16_t src_port = lwip_htons(pcb->udp.local_port);
        update_chksum_udp(&udphdr->chksum, &udphdr->src, &src_port, 1);
        udphdr->src = src_port;
        /* TCP/UDP checksums cover IP addresses in IP header */
        update_chksum_udp(&udphdr->chksum, ip_current_src_addr(), &pcb->ip.local_ip,
                          IP_IS_V4(&pcb->ip.local_ip) ? 2 : 8);
    }
    else
    {
        u16_t dest_port = lwip_htons(pcb->nat_udp.nat_local_port);
        update_chksum_udp(&udphdr->chksum, &udphdr->dest, &dest_port, 1);
        udphdr->dest = dest_port;
        update_chksum_udp(&udphdr->chksum, ip_current_dest_addr(), &pcb->nat_local_ip,
                          IP_IS_V4(&pcb->nat_local_ip) ? 2 : 8);
    }
}
#endif
