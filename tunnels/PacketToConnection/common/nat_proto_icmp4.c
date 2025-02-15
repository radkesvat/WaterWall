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
#include <lwip/prot/icmp.h>

#include "nat.h"
#include "nat_proto_icmp4.h"
#include "nat_proto_ip4.h"

#define LWIP_NAT_ICMP_PCB_SZ offsetof(struct nat_pcb, icmp.end)

#if LWIP_ICMP && LWIP_NAT && LWIP_NAT_ICMP
static int  nat_icmp4_pcbs_initialized;
static u8_t nat_icmp4_storage[LWIP_NAT_ICMP_PCB_SZ * LWIP_NAT_ICMP4_MAX];

static struct nat_pcb *nat_icmp4_used;
static struct nat_pcb *nat_icmp4_free;

static const u8_t icmp_type_map[] = {
    [ICMP_ECHO] = ICMP_ER,
    [ICMP_TS]   = ICMP_TSR,
    [ICMP_AM]   = ICMP_AMR,
    [ICMP_IRQ]  = ICMP_IR,
};

#define ICMP4_TYPE_COOKIE(type, code) (((u16_t) (type) << 8) | (u16_t) (code))
#define ICMP4_ID_COOKIE(id, seqno)    (((u32_t) (id) << 16) | (u32_t) (seqno))

static struct nat_pcb *nat_icmp4_new(u8_t ext_netif_idx, u8_t int_netif_idx, const ip_addr_t *remote,
                                     const ip_addr_t *local, const ip_addr_t *nat, u16_t type, u32_t id)
{
    struct nat_pcb *pcb;

    if (! nat_icmp4_pcbs_initialized)
    {
        nat_icmp4_free             = nat_pcb_init_mem(nat_icmp4_storage, LWIP_NAT_ICMP_PCB_SZ, LWIP_NAT_ICMP4_MAX);
        nat_icmp4_pcbs_initialized = 1;
    }

#if LWIP_NAT_USE_OLDEST
    if (! nat_icmp4_free)
        nat_pcb_take_oldest(&nat_icmp4_free, &nat_icmp4_used, LWIP_NAT_ICMP_TICKS - LWIP_NAT_ICMP_USE_OLDEST_LIMIT);
#endif
    if (! nat_icmp4_free)
        return NULL;
    pcb = nat_icmp4_free;

    pcb->icmp.type = type;
    pcb->icmp.id   = id;

    pcb->ext_netif_idx = ext_netif_idx;
    pcb->int_netif_idx = int_netif_idx;
    ip_addr_set(&pcb->nat_local_ip, nat);
    ip_addr_set(&pcb->ip.remote_ip, remote);
    ip_addr_set(&pcb->ip.local_ip, local);

    nat_icmp4_free = pcb->next;
    pcb->next      = nat_icmp4_used;
    nat_icmp4_used = pcb;

    return pcb;
}

static struct nat_pcb *nat_icmp4_walk(u8_t ext_netif_idx, u8_t int_netif_idx, const ip_addr_t *remote,
                                      const ip_addr_t *local, const ip_addr_t *nat, u16_t type, u32_t id)
{
    struct nat_pcb *pcb, *next, **prev = &nat_icmp4_used;
    int             n = 0;

    for (pcb = nat_icmp4_used; pcb; pcb = next)
    {
        next = pcb->next;
        if (nat_pcb_timedout(pcb))
        {
            *prev          = next;
            pcb->next      = nat_icmp4_free;
            nat_icmp4_free = pcb;
            continue;
        }
        n++;
        if (ext_netif_idx == pcb->ext_netif_idx && (! int_netif_idx || int_netif_idx == pcb->int_netif_idx) &&
            type == pcb->icmp.type && id == pcb->icmp.id && (! local || ip_addr_cmp(local, &pcb->ip.local_ip)) &&
            (! nat || ip_addr_cmp(nat, &pcb->nat_local_ip)) && ip_addr_cmp(remote, &pcb->ip.remote_ip))
        {
            if (n > 16)
            {
                /* If it's far down the list, move it to head */
                *prev          = next;
                pcb->next      = nat_icmp4_used;
                nat_icmp4_used = pcb;
            }
            break;
        }
        prev = &pcb->next;
    }
    return pcb;
}

void nat_icmp4_expire(void)
{
    nat_icmp4_walk(0xff, 0xff, NULL, NULL, NULL, 0, 0);
}

#if LWIP_NAT_ICMP_IP
struct nat_pcb *icmp_icmp4_prerouting_pcb(const ip_addr_t *iphdr_src, const ip_addr_t *iphdr_dest, struct pbuf *p,
                                          struct netif *inp, struct netif *forwardp)
{
    struct icmp_echo_hdr *icmphdr       = (struct icmp_echo_hdr *) p->payload;
    u8_t                  inp_netif_idx = netif_get_index(inp);
    struct nat_pcb       *pcb           = NULL;
    u16_t                 type;
    u32_t                 id;

    switch (icmphdr->type)
    {
    case ICMP_ECHO:
    case ICMP_TS:
    case ICMP_AM:
    case ICMP_IRQ:
        if (forwardp)
            break;
        type = ICMP4_TYPE_COOKIE(icmp_type_map[icmphdr->type], icmphdr->code);
        id   = ICMP4_ID_COOKIE(icmphdr->id, icmphdr->seqno);
        pcb  = nat_icmp4_walk(inp_netif_idx, 0, iphdr_dest, iphdr_src, NULL, type, id);
        break;

    case ICMP_ER:
    case ICMP_TSR:
    case ICMP_AMR:
    case ICMP_IR:
        if (! forwardp)
            break;
        type = ICMP4_TYPE_COOKIE(icmphdr->type, icmphdr->code);
        id   = ICMP4_ID_COOKIE(icmphdr->id, icmphdr->seqno);
        pcb  = nat_icmp4_walk(netif_get_index(forwardp), inp_netif_idx, iphdr_src, NULL, iphdr_dest, type, id);
        break;

    /* NB: Don't bother going down any further encapsulation steps */
    default:
        break;
    }

    return pcb;
}

void icmp_icmp4_prerouting_nat(u16_t *icmp_chksum, const ip_addr_t *src_addr, const ip_addr_t *iphdr_dest,
                               struct pbuf *p, struct nat_pcb *pcb, int forward)
{
    /* No modifications necessary */
}
#endif

struct nat_pcb *icmp4_prerouting_pcb(struct pbuf *p, struct netif *inp, struct netif *forwardp)
{
    struct icmp_echo_hdr *icmphdr            = (struct icmp_echo_hdr *) p->payload;
    u8_t                  inp_netif_idx      = netif_get_index(inp);
    u8_t                  forwardp_netif_idx = forwardp ? netif_get_index(forwardp) : 0;
    struct nat_pcb       *pcb                = NULL;
    u16_t                 type;
    u32_t                 id;

    if (p->len < sizeof(*icmphdr))
        return NULL;

#if CHECKSUM_CHECK_ICMP
    IF__NETIF_CHECKSUM_ENABLED(inp, NETIF_CHECKSUM_CHECK_ICMP)
    if (inet_chksum_pbuf(p) != 0)
        return NULL;
#endif

    switch (icmphdr->type)
    {
    /* ICMP Query Messages - expire in 60s */
    case ICMP_ECHO:
    case ICMP_TS:
    case ICMP_AM:
    case ICMP_IRQ:
        if (! forwardp) /* Only allow outbound requests */
            break;
        type = ICMP4_TYPE_COOKIE(icmp_type_map[icmphdr->type], icmphdr->code);
        id   = ICMP4_ID_COOKIE(icmphdr->id, icmphdr->seqno);
        pcb  = nat_icmp4_walk(forwardp_netif_idx, inp_netif_idx, ip_current_dest_addr(), NULL, ip_current_src_addr(),
                              type, id);
        if (! pcb)
            pcb = nat_icmp4_new(forwardp_netif_idx, inp_netif_idx, ip_current_dest_addr(), &forwardp->ip_addr,
                                ip_current_src_addr(), type, id);
        if (pcb)
            nat_pcb_refresh(pcb, LWIP_NAT_ICMP_TICKS);
        break;

    case ICMP_ER:
    case ICMP_TSR:
    case ICMP_AMR:
    case ICMP_IR:
        if (forwardp) /* Any replies should be inbound */
            break;
        type = ICMP4_TYPE_COOKIE(icmphdr->type, icmphdr->code);
        id   = ICMP4_ID_COOKIE(icmphdr->id, icmphdr->seqno);
        pcb  = nat_icmp4_walk(inp_netif_idx, 0, ip_current_src_addr(), ip_current_dest_addr(), NULL, type, id);
        break;

#if LWIP_NAT_ICMP_IP
    /* ICMP Error Messages */
    case ICMP_RD:
        if (forwardp) /* Private network, don't forward */
            break;
    case ICMP_SQ:
    case ICMP_TE:
    case ICMP_DUR:
    case ICMP_PP:
        /* Figure out what to do with our encapsulated IP packet */
        if (pbuf_remove_header(p, sizeof(*icmphdr)))
            return NULL;
        pcb = icmp4_ip4_prerouting_pcb(p, inp, forwardp);
        pbuf_add_header_force(p, sizeof(*icmphdr));
        break;
#endif
    default:
        /* Don't forward unknown ICMP types */
        break;
    }

    return pcb;
}

void icmp4_prerouting_nat(struct pbuf *p, struct nat_pcb *pcb, int forward)
{
#if LWIP_NAT_ICMP_IP
    struct icmp_echo_hdr *icmphdr = (struct icmp_echo_hdr *) p->payload;

    switch (icmphdr->type)
    {
    case ICMP_RD:
    case ICMP_SQ:
    case ICMP_TE:
    case ICMP_DUR:
    case ICMP_PP:
        /* Modify our encapsulated IP packet */
        pbuf_remove_header(p, sizeof(*icmphdr));
        icmp4_ip4_prerouting_nat(&icmphdr->chksum, p, pcb, forward);
        pbuf_add_header_force(p, sizeof(*icmphdr));
        break;
    }
#else
    LWIP_UNUSED_ARG(p);
    LWIP_UNUSED_ARG(pcb);
    LWIP_UNUSED_ARG(forward);
#endif
}

#endif
