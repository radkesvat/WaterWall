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
#ifndef __NAT_NATOPTS_H__
#define __NAT_NATOPTS_H__

#include <lwip/opt.h>

#ifndef LWIP_NAT
#define LWIP_NAT 0
#endif

/* Perform NAT for ICMP */
#ifndef LWIP_NAT_ICMP
#define LWIP_NAT_ICMP 0
#endif

/* NAT ICMP packets with encapsulated IP packets */
#ifndef LWIP_NAT_ICMP_IP
#define LWIP_NAT_ICMP_IP 0
#endif

/*
 * The NAT tick value is updated every tick period. Each time it passes
 * 128, all the NAT entries are walked and anything past expiration is
 * proactively removed. Default is 15 seconds, giving a max timeout of
 * 32 minutes.
 */
#ifndef LWIP_NAT_TICK_PERIOD_MS
#define LWIP_NAT_TICK_PERIOD_MS 15000
#endif

/* If NAT table is full, expire oldest entry */
#ifndef LWIP_NAT_USE_OLDEST
#define LWIP_NAT_USE_OLDEST 0
#endif

#ifndef LWIP_NAT_TCP_LOCAL_PORT_RANGE_START
#define LWIP_NAT_TCP_LOCAL_PORT_RANGE_START 0x8000
#endif

#ifndef LWIP_NAT_TCP_LOCAL_PORT_RANGE_END
#define LWIP_NAT_TCP_LOCAL_PORT_RANGE_END 0xbfff
#endif

/* Maximum number of TCP NAT entries */
#ifndef LWIP_NAT_TCP_MAX
#define LWIP_NAT_TCP_MAX 1024
#endif

/*
 * How long a TCP NAT entry lives, defaults to 30 minutes. NB, tick number
 * must be less than 128
 */
#ifndef LWIP_NAT_TCP_TICKS
#define LWIP_NAT_TCP_TICKS (30 * 60 * 1000 / LWIP_NAT_TICK_PERIOD_MS)
#endif

/* Limit below which to not steal entries, defaults to 5 minutes */
#ifndef LWIP_NAT_TCP_USE_OLDEST_LIMIT
#define LWIP_NAT_TCP_USE_OLDEST_LIMIT (5 * 60 * 1000 / LWIP_NAT_TICK_PERIOD_MS)
#endif

#ifndef LWIP_NAT_UDP_LOCAL_PORT_RANGE_START
#define LWIP_NAT_UDP_LOCAL_PORT_RANGE_START 0x8000
#endif

#ifndef LWIP_NAT_UDP_LOCAL_PORT_RANGE_END
#define LWIP_NAT_UDP_LOCAL_PORT_RANGE_END 0xbfff
#endif

#ifndef LWIP_NAT_UDP_MAX
#define LWIP_NAT_UDP_MAX 1024
#endif

#ifndef LWIP_NAT_UDP_TICKS
#define LWIP_NAT_UDP_TICKS (30 * 60 * 1000 / LWIP_NAT_TICK_PERIOD_MS)
#endif

#ifndef LWIP_NAT_UDP_USE_OLDEST_LIMIT
#define LWIP_NAT_UDP_USE_OLDEST_LIMIT (5 * 60 * 1000 / LWIP_NAT_TICK_PERIOD_MS)
#endif

#ifndef LWIP_NAT_ICMP4_MAX
#define LWIP_NAT_ICMP4_MAX 64
#endif

/* How long an ICMP NAT entry lives, defaults to 30 seconds */
#ifndef LWIP_NAT_ICMP_TICKS
#define LWIP_NAT_ICMP_TICKS (30 * 1000 / LWIP_NAT_TICK_PERIOD_MS)
#endif

/* Let at least one tick pass */
#ifndef LWIP_NAT_ICMP_USE_OLDEST_LIMIT
#define LWIP_NAT_ICMP_USE_OLDEST_LIMIT 1
#endif

#ifndef NAT_DEBUG
#define NAT_DEBUG LWIP_DBG_OFF
#endif

#endif
