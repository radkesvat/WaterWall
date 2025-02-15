/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
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
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */
#include <lwip/inet_chksum.h>
#include <lwip/ip.h>
#include <lwip/ip4.h>
#include <lwip/ip4_frag.h>

#include "lwip/autoip.h"
#include "ip4_prerouting_hook.h"
#include "nat.h"

#if LWIP_NAT && LWIP_IPV4
static int ip4_canforward(struct pbuf *p)
{
    u32_t addr = lwip_htonl(ip4_addr_get_u32(ip4_current_dest_addr()));

#ifdef LWIP_HOOK_IP4_CANFORWARD
    int ret = LWIP_HOOK_IP4_CANFORWARD(p, addr);
    if (ret >= 0)
    {
        return ret;
    }
#endif /* LWIP_HOOK_IP4_CANFORWARD */

    if (p->flags & PBUF_FLAG_LLBCAST)
    {
        /* don't route link-layer broadcasts */
        return 0;
    }
    if ((p->flags & PBUF_FLAG_LLMCAST) || IP_MULTICAST(addr))
    {
        /* don't route link-layer multicasts (use LWIP_HOOK_IP4_CANFORWARD instead) */
        return 0;
    }
    if (IP_EXPERIMENTAL(addr))
    {
        return 0;
    }
    if (IP_CLASSA(addr))
    {
        u32_t net = addr & IP_CLASSA_NET;
        if ((net == 0) || (net == ((u32_t) IP_LOOPBACKNET << IP_CLASSA_NSHIFT)))
        {
            /* don't route loopback packets */
            return 0;
        }
    }
    return 1;
}

static struct netif *ip4_forward(struct pbuf *p, struct ip_hdr *iphdr, struct netif *inp)
{
    (void) iphdr;
    
    struct netif *netif;

    LWIP_UNUSED_ARG(inp);

    if (! ip4_canforward(p))
        return NULL;

    /* Find network interface where to forward this IP packet to. */
    netif = ip4_route_src(ip4_current_src_addr(), ip4_current_dest_addr());
#if ! IP_FORWARD_ALLOW_TX_ON_RX_NETIF
    /* Do not forward packets onto the same network interface on which
     * they arrived. */
    if (netif == inp)
        netif = NULL;
#endif /* IP_FORWARD_ALLOW_TX_ON_RX_NETIF */

    return netif;
}

static int ip4_input_accept(struct netif *netif)
{
    /* interface is up and configured? */
    if ((netif_is_up(netif)) && (! ip4_addr_isany_val(*netif_ip4_addr(netif))))
    {
        /* unicast to this interface address? */
        if (ip4_addr_cmp(ip4_current_dest_addr(), netif_ip4_addr(netif)) ||
            /* or broadcast on this interface network address? */
            ip4_addr_isbroadcast(ip4_current_dest_addr(), netif)
#if LWIP_NETIF_LOOPBACK && ! LWIP_HAVE_LOOPIF
            || (ip4_addr_get_u32(ip4_current_dest_addr()) == PP_HTONL(IPADDR_LOOPBACK))
#endif /* LWIP_NETIF_LOOPBACK && !LWIP_HAVE_LOOPIF */
        )
        {
            /* accept on this netif */
            return 1;
        }
#if LWIP_AUTOIP
        /* connections to link-local addresses must persist after changing
            the netif's address (RFC3927 ch. 1.9) */
        if (autoip_accept_packet(netif, ip4_current_dest_addr()))
        {
            /* accept on this netif */
            return 1;
        }
#endif /* LWIP_AUTOIP */
    }
    return 0;
}

static err_t ip4_input_nat(struct pbuf *p, struct netif *inp)
{
    const struct ip_hdr *iphdr;
    struct netif        *netif;
    struct netif        *forwardif = NULL;
    u16_t                iphdr_hlen;
    u16_t                iphdr_len;

    /* identify the IP header */
    iphdr = (struct ip_hdr *) p->payload;

    /* obtain IP header length in bytes */
    iphdr_hlen = IPH_HL_BYTES(iphdr);
    /* obtain ip length in bytes */
    iphdr_len = lwip_ntohs(IPH_LEN(iphdr));

    /* Trim pbuf. This is especially required for packets < 60 bytes. */
    if (iphdr_len < p->tot_len)
    {
        pbuf_realloc(p, iphdr_len);
    }

    /* header length exceeds first pbuf length, or ip length exceeds total pbuf length? */
    if ((iphdr_hlen > p->len) || (iphdr_len > p->tot_len) || (iphdr_hlen < IP_HLEN))
    {
        return 0; /* Let real ip4_input log it. */
    }

    /* verify checksum */
#if CHECKSUM_CHECK_IP
    IF__NETIF_CHECKSUM_ENABLED(inp, NETIF_CHECKSUM_CHECK_IP)
    {
        if (inet_chksum(iphdr, iphdr_hlen) != 0)
        {
            return 0;
        }
    }
#endif

    /* copy IP addresses to aligned ip_addr_t */
    ip_addr_copy_from_ip4(ip_data.current_iphdr_dest, iphdr->dest);
    ip_addr_copy_from_ip4(ip_data.current_iphdr_src, iphdr->src);

    /* Ignore multicast */
    if (ip4_addr_ismulticast(ip4_current_dest_addr()))
        return 0;

    /* Ignore loopback */
    if (ip4_addr_isloopback(ip4_current_dest_addr()))
        return 0;

    /* Ignore broadcast */
    if (ip4_addr_isbroadcast(ip4_current_dest_addr(), inp))
        return 0;

    /* Move packet reassembly to pre-routing */
    /* packet consists of multiple fragments? */
    if ((IPH_OFFSET(iphdr) & PP_HTONS(IP_OFFMASK | IP_MF)) != 0)
    {
#if IP_REASSEMBLY /* packet fragment reassembly code present? */
        LWIP_DEBUGF(IP_DEBUG, ("IP packet is a fragment (id=0x%04" X16_F " tot_len=%" U16_F " len=%" U16_F " MF=%" U16_F
                               " offset=%" U16_F "), calling ip4_reass()\n",
                               lwip_ntohs(IPH_ID(iphdr)), p->tot_len, lwip_ntohs(IPH_LEN(iphdr)),
                               (u16_t) ! ! (IPH_OFFSET(iphdr) & PP_HTONS(IP_MF)),
                               (u16_t) ((lwip_ntohs(IPH_OFFSET(iphdr)) & IP_OFFMASK) * 8)));
        /* reassemble the packet*/
        /*
         * Ugh, ip4_input has a local copy of the p pointer and a local pointer to
         * iphdr. When we are done, those pointers still need to be valid.
         */
        struct pbuf *rp;
        rp = ip4_reass(p);
        /* packet not fully reassembled yet? */
        if (rp == NULL)
        {
            return 1; /* Eat packet */
        }
        if (rp != p || iphdr != rp->payload)
        {
            /*
             * ok, the pointers are different. There's no real easy way to fix this.
             * We could try swapping data, but one likely has less space than the
             * other. Just call ip4_input again and eat the packet. It's super bad
             * for the stack, but it avoids having to patch ip4_input.
             */
            STATS_DEC(ip.recv); /* Don't double stat */
#if MIB2_STATS
            STATS_DEC(mib2.ipinreceives);
#endif
            ip4_input(rp, inp);
            return 1; /* ip4_input eats packet */
        }
#else  /* IP_REASSEMBLY == 0, no packet fragment reassembly code present */
        pbuf_free(p);
        LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                    ("IP packet dropped since it was fragmented (0x%" X16_F ") (while IP_REASSEMBLY == 0).\n",
                     lwip_ntohs(IPH_OFFSET(iphdr))));
        IP_STATS_INC(ip.opterr);
        IP_STATS_INC(ip.drop);
        /* unsupported protocol feature */
        MIB2_STATS_INC(mib2.ipinunknownprotos);
        return 1; /* Eat packet */
#endif /* IP_REASSEMBLY */
    }

    /* start trying with inp. if that's not acceptable, start walking the
       list of configured netifs. */
    if (ip4_input_accept(inp))
    {
        netif = inp;
    }
    else
    {
        netif = NULL;
#if ! LWIP_SINGLE_NETIF
        NETIF_FOREACH(netif)
        {
            if (netif == inp)
            {
                /* we checked that before already */
                continue;
            }
            if (ip4_input_accept(netif))
            {
                break;
            }
        }
#endif /* !LWIP_SINGLE_NETIF */
    }

    /* packet not for us? */
    if (netif == NULL)
    {
        /* try to forward IP packet on (other) interfaces */
        forwardif = ip4_forward(p, (struct ip_hdr *) p->payload, inp);
    }

    if (ip4_prerouting_hook(p, inp, netif, forwardif))
    {
        pbuf_free(p);
        return 1;
    }

    return 0;
}

#endif
