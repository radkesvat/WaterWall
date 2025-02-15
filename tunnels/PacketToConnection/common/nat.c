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
#include "nat.h"
#include "lwip/sys.h"
#include "lwip/timeouts.h"
#include "nat_proto_icmp4.h"
#include "nat_proto_tcp.h"
#include "nat_proto_udp.h"

#if LWIP_NAT
static u8_t             nat_timeout_tick;
static struct nat_rule *nat_rules;

void update_chksum(u16_t *_hc, const void *_orig, const void *_new, int n)
{
    const u16_t *orig = _orig;
    const u16_t *new  = _new;
    u16_t hc          = ~*_hc;
    while (n--)
    {
        /* HC' = ~(~HC + ~m + m') */
        u32_t s;
        s = (u32_t) hc + ((~*orig) & 0xffff) + *new;
        while (s & 0xffff0000)
            s = (s & 0xffff) + (s >> 16);
        hc = (u16_t)s;
        orig++;
        new ++;
    }
    *_hc = ~hc;
}

void update_chksum_udp(u16_t *hc, const void *orig, const void *new, int n)
{
    if (! *hc)
        return;
    update_chksum(hc, orig, new, n);
    if (! *hc)
        *hc = 0xffff;
}

#if LWIP_NAT_USE_OLDEST
static u8_t nat_pcb_remaining(struct nat_pcb *pcb)
{
    return pcb->timeout - nat_timeout_tick;
}

void nat_pcb_take_oldest(struct nat_pcb **free, struct nat_pcb **used, u8_t limit)
{
    struct nat_pcb  *pcb, **prev = used;
    struct nat_pcb **oldest_prev = NULL, *oldest = NULL;
    u8_t             oldest_remaining = 0;

    for (pcb = *used; pcb; prev = &pcb->next, pcb = pcb->next)
    {
        u8_t remaining = nat_pcb_remaining(pcb);
        if (remaining < limit && oldest_remaining < remaining)
        {
            oldest           = pcb;
            oldest_remaining = remaining;
            oldest_prev      = prev;
        }
    }

    if (oldest)
    {
        *oldest_prev = oldest->next;
        oldest->next = *free;
        *free        = oldest;
    }
}
#endif

int nat_pcb_timedout(struct nat_pcb *pcb)
{
    u8_t tick_remaining = pcb->timeout - nat_timeout_tick;
    return tick_remaining >= 0x80;
}

void nat_pcb_refresh(struct nat_pcb *pcb, u8_t ticks)
{
    pcb->timeout = nat_timeout_tick + ticks;
}

void nat_timer_tick(void)
{
    nat_timeout_tick++;
    if (! (nat_timeout_tick & 0x7f))
    {
#if LWIP_TCP
        nat_tcp_expire();
#endif
#if LWIP_UDP
        nat_udp_expire();
#endif
#if LWIP_IPV4 && LWIP_ICMP && LWIP_NAT_ICMP
        nat_icmp4_expire();
#endif
    }
}

#if LWIP_TIMERS
static void nat_timer(void *arg)
{
    u32_t interval = (u32_t)(mem_ptr_t) arg;
    nat_timer_tick();
    sys_timeout(interval, nat_timer, arg);
}
#endif

void nat_init(void)
{
#if LWIP_TIMERS
    SYS_ARCH_DECL_PROTECT(lev);
    SYS_ARCH_PROTECT(lev);
    sys_timeout(LWIP_NAT_TICK_PERIOD_MS, nat_timer, (u32_t *) LWIP_NAT_TICK_PERIOD_MS);
    SYS_ARCH_UNPROTECT(lev);
#endif
}

struct nat_pcb *nat_pcb_init_mem(u8_t *storage, size_t len, size_t count)
{
    struct nat_pcb *pcb, *first;
    size_t             i;
    first = (struct nat_pcb *) storage;
    pcb   = first;
    for (i = 1; i < count; i++)
    {
        pcb->next = (struct nat_pcb *) (((u8_t *) pcb) + len);
        pcb       = pcb->next;
    }
    pcb->next = NULL;

    return first;
}

int nat_rule_check(struct netif *inp, struct netif *forwardp)
{
    struct nat_rule *rule, *found = NULL;

    for (rule = nat_rules; rule; rule = rule->next)
    {
        if ((! rule->inp || (rule->inp == forwardp)) && (! rule->outp || (rule->outp == inp)))
            /* Packet is attempting to route through NAT, eat it */
            return 1;
        if ((! rule->inp || (rule->inp == inp)) && (! rule->outp || (rule->outp == forwardp)))
            found = rule;
    }
    return found ? 0 : -1;
}

err_t nat_rule_add(struct nat_rule *new_rule)
{
    struct nat_rule *rule;
    if (! new_rule->inp && ! new_rule->outp)
        return ERR_ARG;

    for (rule = nat_rules; rule; rule = rule->next)
    {
        if (new_rule->inp == rule->inp && new_rule->outp == rule->outp)
            return ERR_ALREADY;
    }
    new_rule->next = nat_rules;
    nat_rules      = new_rule;
    return ERR_OK;
}

err_t nat_rule_remove(struct nat_rule *old_rule)
{
    struct nat_rule *rule, **prev = &nat_rules;
    for (rule = nat_rules; rule; rule = rule->next)
    {
        if (rule == old_rule)
        {
            /* FIXME: Remove any associated connections */
            *prev      = rule->next;
            rule->next = NULL;
            return ERR_OK;
        }
        prev = &rule->next;
    }
    return ERR_ARG;
}
#endif
