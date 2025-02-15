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
#include <lwip/priv/tcp_priv.h>
#include <lwip/tcp.h>

#include "nat.h"
#include "nat_proto_tcp.h"

#if LWIP_TCP && LWIP_NAT

#define LWIP_NAT_TCP_PCB_SZ offsetof(struct nat_pcb, nat_tcp.end)

static int  nat_tcp_pcbs_initialized;
static u8_t nat_tcp_storage[LWIP_NAT_TCP_PCB_SZ * LWIP_NAT_TCP_MAX];

static struct nat_pcb *nat_tcp_used;
static struct nat_pcb *nat_tcp_free;

static u16_t nat_tcp_port = LWIP_NAT_TCP_LOCAL_PORT_RANGE_START;

static void tcp_unlink(struct tcp_pcb *pcb)
{
    TCP_RMV(&tcp_listen_pcbs.pcbs, pcb);
}

static struct nat_pcb *nat_tcp_new(u8_t ext_netif_idx, u8_t int_netif_idx, const ip_addr_t *remote, u16_t remote_port,
                                   const ip_addr_t *local, const ip_addr_t *nat, u16_t nat_port)
{
    struct nat_pcb *pcb;
    err_t           err;
    u16_t           n = LWIP_NAT_TCP_LOCAL_PORT_RANGE_END - LWIP_NAT_TCP_LOCAL_PORT_RANGE_START;

    if (! nat_tcp_pcbs_initialized)
    {
        nat_tcp_free             = nat_pcb_init_mem(nat_tcp_storage, LWIP_NAT_TCP_PCB_SZ, LWIP_NAT_TCP_MAX);
        nat_tcp_pcbs_initialized = 1;
    }

#if LWIP_NAT_USE_OLDEST
    if (! nat_tcp_free)
    {
        nat_pcb_take_oldest(&nat_tcp_free, &nat_tcp_used, LWIP_NAT_TCP_TICKS - LWIP_NAT_TCP_USE_OLDEST_LIMIT);
        if (nat_tcp_free)
            tcp_unlink(&nat_tcp_free->tcp);
    }
#endif
    if (! nat_tcp_free)
        return NULL;
    pcb = nat_tcp_free;

    /* Initialize fields used by LWIP */
    pcb->tcp.next       = NULL;
    pcb->tcp.flags      = CLOSED;
    pcb->tcp.so_options = 0;
    pcb->tcp.netif_idx  = 0xff; /* Give LWIP an invalid netif */

again:
    if (nat_tcp_port > LWIP_NAT_TCP_LOCAL_PORT_RANGE_END)
        nat_tcp_port = LWIP_NAT_TCP_LOCAL_PORT_RANGE_START;
    err = tcp_bind(&pcb->tcp, local, nat_tcp_port++);
    if (err == ERR_USE)
    {
        if (! --n)
            return NULL;
        goto again;
    }
    else if (err != ERR_OK)
        return NULL;

    /*
     * We move to the listen list because the bound list
     * because tcp_remove_listener calls beyond our runt
     * pcb allocation for bounb_pcbs but not listen_pcbs.
     */
    TCP_RMV(&tcp_bound_pcbs, &pcb->tcp);
    TCP_REG(&tcp_listen_pcbs.pcbs, &pcb->tcp);

    pcb->tcp.remote_port        = remote_port;
    pcb->nat_tcp.nat_local_port = nat_port;
    pcb->ext_netif_idx          = ext_netif_idx;
    pcb->int_netif_idx          = int_netif_idx;
    ip_addr_set(&pcb->nat_local_ip, nat);
    ip_addr_set(&pcb->ip.remote_ip, remote);

    /* Remove from free list, add to used list */
    nat_tcp_free = pcb->next;
    pcb->next    = nat_tcp_used;
    nat_tcp_used = pcb;

    return pcb;
}

static struct nat_pcb *nat_tcp_walk(u8_t ext_netif_idx, u8_t int_netif_idx, const ip_addr_t *remote, u16_t remote_port,
                                    const ip_addr_t *local, u16_t local_port, const ip_addr_t *nat, u16_t nat_port)
{
    struct nat_pcb *pcb, *next, **prev = &nat_tcp_used;
    int             n = 0;

    for (pcb = nat_tcp_used; pcb; pcb = next)
    {
        next = pcb->next;
        if (nat_pcb_timedout(pcb))
        {
            tcp_unlink(&pcb->tcp);
            *prev        = next;
            pcb->next    = nat_tcp_free;
            nat_tcp_free = pcb;
            continue;
        }
        n++;
        if (ext_netif_idx == pcb->ext_netif_idx && (! int_netif_idx || int_netif_idx == pcb->int_netif_idx) &&
            (! local || (ip_addr_cmp(local, &pcb->ip.local_ip) && local_port == pcb->tcp.local_port)) &&
            (! nat || (ip_addr_cmp(nat, &pcb->nat_local_ip) && nat_port == pcb->nat_tcp.nat_local_port)) &&
            ip_addr_cmp(remote, &pcb->ip.remote_ip) && remote_port == pcb->tcp.remote_port)
        {
            if (n > 16)
            {
                /* If it's far down the list, move it to head */
                *prev        = next;
                pcb->next    = nat_tcp_used;
                nat_tcp_used = pcb;
            }
            break;
        }
        prev = &pcb->next;
    }
    return pcb;
}

void nat_tcp_expire(void)
{
    nat_tcp_walk(0xff, 0xff, NULL, 0, NULL, 0, NULL, 0);
}

#if LWIP_ICMP && LWIP_NAT_ICMP_IP
struct nat_pcb *icmp_tcp_prerouting_pcb(const ip_addr_t *iphdr_src, const ip_addr_t *iphdr_dest, struct pbuf *p,
                                        struct netif *inp, struct netif *forwardp)
{
    struct tcp_hdr *tcphdr        = (struct tcp_hdr *) p->payload;
    u16_t           dest_port     = lwip_ntohs(tcphdr->dest);
    u16_t           src_port      = lwip_ntohs(tcphdr->src);
    u8_t            inp_netif_idx = netif_get_index(inp);

    if (forwardp)
        return nat_tcp_walk(netif_get_index(forwardp), inp_netif_idx, iphdr_src, src_port, NULL, 0, iphdr_dest,
                            dest_port);
    else
        return nat_tcp_walk(inp_netif_idx, 0, iphdr_dest, dest_port, iphdr_src, src_port, NULL, 0);
}

void icmp_tcp_prerouting_nat(u16_t *icmp_chksum, const ip_addr_t *iphdr_src, const ip_addr_t *iphdr_dest,
                             struct pbuf *p, struct nat_pcb *pcb, int forward)
{
    struct tcp_hdr *tcphdr      = (struct tcp_hdr *) p->payload;
    u16_t           orig_chksum = 0;

    /*
     * NB: If a packet only contains half a chksum, we can't
     * updated it but it also can't be verified. If someone stored
     * the original packet, they'll see that it doesn't match
     * though.
     */
    int has_chksum = p->len >= offsetof(struct tcp_hdr, chksum) + 2;

    if (has_chksum)
        orig_chksum = tcphdr->chksum;
    if (forward)
    {
        u16_t dest_port = lwip_htons(pcb->tcp.local_port);
        if (has_chksum)
            update_chksum(&tcphdr->chksum, &tcphdr->dest, &dest_port, 1);
        update_chksum(icmp_chksum, &tcphdr->dest, &dest_port, 1);
        tcphdr->dest = dest_port;

        update_chksum(icmp_chksum, &iphdr_dest, &pcb->ip.local_ip, IP_IS_V4(&pcb->ip.local_ip) ? 2 : 8);
        if (has_chksum)
            update_chksum(&tcphdr->chksum, &iphdr_dest, &pcb->ip.local_ip, IP_IS_V4(&pcb->ip.local_ip) ? 2 : 8);
    }
    else
    {
        u16_t src_port = lwip_htons(pcb->nat_tcp.nat_local_port);
        if (has_chksum)
            update_chksum(&tcphdr->chksum, &tcphdr->src, &src_port, 1);
        update_chksum(icmp_chksum, &tcphdr->src, &src_port, 1);
        tcphdr->src = src_port;

        update_chksum(icmp_chksum, &iphdr_src, &pcb->nat_local_ip, IP_IS_V4(&pcb->nat_local_ip) ? 2 : 8);
        if (has_chksum)
            update_chksum(&tcphdr->chksum, &iphdr_src, &pcb->nat_local_ip, IP_IS_V4(&pcb->nat_local_ip) ? 2 : 8);
    }
    if (has_chksum)
        update_chksum(icmp_chksum, &orig_chksum, &tcphdr->chksum, 1);
}
#endif

struct nat_pcb *tcp_prerouting_pcb(struct pbuf *p, struct netif *inp, struct netif *forwardp)
{
    struct tcp_hdr *tcphdr = (struct tcp_hdr *) p->payload;
    u16_t           dest_port;
    u16_t           src_port;
    u8_t            inp_netif_idx = netif_get_index(inp);
    struct nat_pcb *pcb;

    if (p->len < TCP_HLEN)
        return NULL;

#if CHECKSUM_CHECK_TCP
    IF__NETIF_CHECKSUM_ENABLED(inp, NETIF_CHECKSUM_CHECK_TCP)
    if (ip_chksum_pseudo(p, IP_PROTO_TCP, p->tot_len, ip_current_src_addr(), ip_current_dest_addr()))
        return NULL;
#endif

    dest_port = lwip_ntohs(tcphdr->dest);
    src_port  = lwip_ntohs(tcphdr->src);

    if (forwardp)
    {
        u8_t forwardp_netif_idx = netif_get_index(forwardp);
        pcb = nat_tcp_walk(forwardp_netif_idx, inp_netif_idx, ip_current_dest_addr(), dest_port, NULL, 0,
                           ip_current_src_addr(), src_port);
        if (! pcb)
            pcb = nat_tcp_new(forwardp_netif_idx, inp_netif_idx, ip_current_dest_addr(), dest_port, &forwardp->ip_addr,
                              ip_current_src_addr(), src_port);
    }
    else
        pcb =
            nat_tcp_walk(inp_netif_idx, 0, ip_current_src_addr(), src_port, ip_current_dest_addr(), dest_port, NULL, 0);

    return pcb;
}

void tcp_prerouting_nat(struct pbuf *p, struct nat_pcb *pcb, int forward)
{
    struct tcp_hdr *tcphdr = (struct tcp_hdr *) p->payload;

    nat_pcb_refresh(pcb, LWIP_NAT_TCP_TICKS);

    {
        u16_t tmp_chksum = tcphdr->chksum;
        if (forward)
        {
            u16_t src_port = lwip_htons(pcb->tcp.local_port);
            update_chksum(&tmp_chksum, &tcphdr->src, &src_port, 1);
            tcphdr->src = src_port;

            update_chksum(&tmp_chksum, ip_current_src_addr(), &pcb->ip.local_ip, IP_IS_V4(&pcb->ip.local_ip) ? 2 : 8);
        }
        else
        {
            u16_t dest_port = lwip_htons(pcb->nat_tcp.nat_local_port);
            update_chksum(&tmp_chksum, &tcphdr->dest, &dest_port, 1);
            tcphdr->dest = dest_port;

            update_chksum(&tmp_chksum, ip_current_dest_addr(), &pcb->nat_local_ip,
                          IP_IS_V4(&pcb->nat_local_ip) ? 2 : 8);
        }
        tcphdr->chksum = tmp_chksum;
    }
}
#endif
