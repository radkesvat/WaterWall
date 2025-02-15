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
#ifndef __NAT_NAT_H__
#define __NAT_NAT_H__

#include <lwip/ip.h>
#include <lwip/tcp.h>
#include <lwip/udp.h>

#include "natopts.h"

struct netif;
struct udp_pcb;

struct nat_rule
{
    struct netif    *inp;
    struct netif    *outp;
    struct nat_rule *next;
};

/*
 * IP_PCB
 *  - ip_addr_t local_ip (Local IP)
 *  - ip_addr_t remote_ip (Remote IP)
 *  - u8 netif_idx (Set to 255 to avoid actual receive/listen)
 *  - u8 so_options (Needs to be zero to avoid SO_REUSEADDR)
 *  - u8 tos (unused)
 *  - u8 ttl (unused)
 *  - netif_hints (Core, optional. Unused)
 */
struct nat_ip_pcb
{
    IP_PCB;
};

#if LWIP_TCP
/*
 * TCP_PCB_COMMON
 *  - ptr next (Used by core)
 *  - ptr callback_arg (unused)
 *  - ptr/ptr array TCP_PCB_EXTARGS (optional, unused)
 *  - enum state (unused)
 *  - u8 prio (unused)
 *  - u16 local_port (Outbound mapped port)
 */
struct nat_tcp_pcb
{
    IP_PCB;
    TCP_PCB_COMMON(struct tcp_pcb);
    u16_t remote_port;

    /* Removed flexible array member */
    u16_t nat_local_port;

    u8_t end;
    // void *end[]; // removed to avoid flexible array error
};
#endif

#if LWIP_UDP
struct nat_udp_pcb
{
    IP_PCB;
    struct udp_pcb *next;
    u8_t            flags;
    u16_t           local_port, remote_port;

    /* Removed flexible array member */
    u16_t nat_local_port;

    u8_t end;
    // void *end[]; // removed to avoid flexible array error
};
#endif

#if LWIP_ICMP && LWIP_NAT_ICMP
struct nat_icmp_pcb
{
    /* No actual ICMP pcb */
    IP_PCB;
    u16_t type;
    u32_t id;
    
    u8_t end;
    // void *end[]; // removed to avoid flexible array error
};
#endif

struct nat_pcb
{
    struct nat_pcb *next;
    ip_addr_t       nat_local_ip;
    u8_t            ext_netif_idx;
    u8_t            int_netif_idx;
    u8_t            timeout;
    union {
#if LWIP_TCP
        struct nat_tcp_pcb nat_tcp;
        struct tcp_pcb     tcp;
#endif
#if LWIP_UDP
        struct nat_udp_pcb nat_udp;
        struct udp_pcb     udp;
#endif
#if LWIP_ICMP && LWIP_NAT_ICMP
        struct nat_icmp_pcb icmp;
#endif
        struct nat_ip_pcb ip;
    };
};

void nat_init(void);
void nat_timer_tick(void);
void nat_pcb_take_oldest(struct nat_pcb **free, struct nat_pcb **used, u8_t limit);
int  nat_pcb_timedout(struct nat_pcb *pcb);
void nat_pcb_refresh(struct nat_pcb *pcb, u8_t ticks);

void update_chksum(u16_t *hc, const void *orig, const void *new, int short_words);
void update_chksum_udp(u16_t *hc, const void *orig, const void *new, int short_words);

struct nat_pcb *nat_pcb_init_mem(u8_t *storage, size_t len, size_t count);

int   nat_rule_check(struct netif *inp, struct netif *forwardp);
err_t nat_rule_add(struct nat_rule *new_rule);
err_t nat_rule_remove(struct nat_rule *old_rule);

#endif
