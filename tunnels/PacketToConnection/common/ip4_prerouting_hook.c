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

#include "ip4_prerouting_hook.h"
#include "nat.h"
#include "nat_proto_ip4.h"

#if LWIP_NAT && LWIP_IPV4
/**
 * Prerouting hook for IPv4 DNAT.
 *
 * Packets arriving with inp and localp set are destined for an IP address
 * of one of the local interfaces. If there is a NAT entry for these packets
 * they need their destination address translated so they are instead routed
 * out via the local NAT interface.
 *
 * Packets arriving with inp an forwardp set are destined to be routed from
 * one network interface to another. If the interface pair matches a NAT rule,
 * the packet needs it source address translated so that return packets arrive
 * at the forwardp interface.
 *
 * @param p Incoming IPv4 packet to be forwarded
 * @param inp Network interface packet was received on
 * @param localp Local network interface that will process packet (NULL otherwise)
 * @param forwardp Network interface packet is to be routed out on (NULL if none)
 *
 * @return 1 Drop packet, 0 continue processing packet (forward)
 */
int ip4_prerouting_hook(struct pbuf *p, struct netif *inp, struct netif *localp, struct netif *forwardp)
{
    struct ip_hdr  *iphdr = (struct ip_hdr *) p->payload;
    struct nat_pcb *pcb;

    LWIP_DEBUGF(NAT_DEBUG, ("%s: Incoming packet on %c%c%u, ", __func__, inp->name[0], inp->name[1], inp->num));
    if (forwardp) {
        LWIP_DEBUGF(NAT_DEBUG, ("forward destination %c%c%u\n", forwardp->name[0], forwardp->name[1], forwardp->num));
    } else if (localp) {
        LWIP_DEBUGF(NAT_DEBUG, ("local destination %c%c%u\n", localp->name[0], localp->name[1], localp->num));
    } else {
        LWIP_DEBUGF(NAT_DEBUG, ("no destination\n"));
    }
    ip4_debug_print(p);

    if (forwardp)
    {
        int ret = nat_rule_check(inp, forwardp);
        if (ret == 1)
        {
            /* Packet is attempting to route in reverse direction
             * of existing NAT rule, eat it.
             */
            return 1;
        }
        else if (ret < 0)
        {
            /* No rule found */
            return 0;
        }

        if (IPH_TTL(iphdr) == 1)
        {
            /* Packet cannot be forwarded. To allow LWIP to send
             * an expired message to the correct destination
             * don't modify anything.
             */
            return 0;
        }

        if (forwardp->mtu && (p->tot_len > forwardp->mtu) && (IPH_OFFSET(iphdr) & PP_NTOHS(IP_DF))) {
            /* Same as above, but for frag needed */
            return 0;
        }
    }
    else if (localp && localp == inp)
    {
        /* Will try to find a matching NAT rule */
    }
    else
    {
        /* Ignore */
        return 0;
    }

    pcb = ip4_prerouting_pcb(p, inp, forwardp);
    if (!pcb)
    {
        /* Drop outbound packets that did not get NAT'd, allow
         * others to continue.
         */
        return forwardp ? 1 : 0;
    }

    if (localp)
    {
        struct netif *natp = netif_get_by_index(pcb->int_netif_idx);
        if (IPH_TTL(iphdr) == 1)
        {
#if LWIP_ICMP
            if (IPH_PROTO(iphdr) != IP_PROTO_ICMP) {
                icmp_time_exceeded(p, ICMP_TE_TTL);
            }
#endif
            return 1;
        }

        if (natp->mtu && (p->tot_len > natp->mtu) && (IPH_OFFSET(iphdr) & PP_NTOHS(IP_DF)))
        {
#if LWIP_ICMP
            icmp_dest_unreach(p, ICMP_DUR_FRAG);
#endif
            return 1;
        }
    }

    LWIP_DEBUGF(NAT_DEBUG, ("%s: Modifying packet:\n", __func__));
    /* Modify packet */
    ip4_prerouting_nat(p, pcb, forwardp != 0);
    ip4_debug_print(p);

    return 0;
}
#endif
